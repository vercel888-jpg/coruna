#!/usr/bin/env node
/**
 * interactive_shell.js — WebSocket 交互式 Shell 服务
 * 
 * 功能：
 * - 通过 WebSocket 提供持久化 Shell 会话
 * - 支持多设备同时连接
 * - 实时输入/输出流式传输
 * - 会话保持（伪终端 pty）
 * 
 * 依赖：
 *   npm install ws node-pty
 * 
 * 集成到 admin_server.js：
 *   const shellServer = require('./interactive_shell');
 *   shellServer.attach(httpServer, sessionValid);
 */

'use strict';

const WebSocket = require('ws');
const pty = require('node-pty');
const crypto = require('crypto');

// 活跃会话存储
const activeSessions = new Map(); // deviceId → { pty, ws, createdAt }

/**
 * 附加 WebSocket 服务到现有 HTTP 服务器
 * @param {http.Server} server - HTTP 服务器实例
 * @param {Function} authCheck - 认证检查函数 (req) => boolean
 */
function attach(server, authCheck) {
  const wss = new WebSocket.Server({ 
    noServer: true,
    perMessageDeflate: false, // 禁用压缩以减少延迟
    maxPayload: 10 * 1024 * 1024  // 限制消息大小为 10MB
  });

  // HTTP 升级处理
  server.on('upgrade', (req, socket, head) => {
    const pathname = new URL(req.url, 'http://localhost').pathname;
    
    if (pathname.startsWith('/ws/shell/')) {
      // 验证认证
      if (!authCheck(req)) {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return;
      }

      wss.handleUpgrade(req, socket, head, (ws) => {
        wss.emit('connection', ws, req);
      });
    } else {
      socket.destroy();
    }
  });

  // WebSocket 连接处理
  wss.on('connection', (ws, req) => {
    const url = new URL(req.url, 'http://localhost');
    const deviceId = url.pathname.split('/').pop();
    
    if (!deviceId) {
      ws.close(1008, 'Device ID required');
      return;
    }

    console.log(`[Shell] Device ${deviceId} connected`);
    
    // 检查是否已有活跃会话 - 原子性替换避免竞态
    let existingToCleanup = null;
    if (activeSessions.has(deviceId)) {
      const existing = activeSessions.get(deviceId);
      existingToCleanup = {
        ws: existing.ws,
        pty: existing.pty
      };
      // 立即从 Map 中移除旧会话，避免竞态窗口
      activeSessions.delete(deviceId);
    }

    // 创建伪终端
    const shell = process.platform === 'win32' ? 'powershell.exe' : 'bash';
    const args = process.platform === 'win32' ? [] : ['-l']; // login shell
    
    let ptyProcess;
    try {
      ptyProcess = pty.spawn(shell, args, {
      name: 'xterm-256color',
        cols: 80,
        rows: 24,
        cwd: process.env.HOME || process.cwd(),
        env: process.env
      });
    } catch (e) {
      console.error(`[Shell] Failed to spawn PTY: ${e.message}`);
      ws.send(JSON.stringify({ type: 'error', message: 'Failed to create shell' }));
      ws.close(1011, 'PTY spawn failed');
      return;
    }

    activeSessions.set(deviceId, {
      pty: ptyProcess,
      ws: ws,
      createdAt: Date.now(),
      lastActiveAt: Date.now()
    });

    // 延迟清理旧会话（在新会话已设置之后）
    if (existingToCleanup) {
      setImmediate(() => {
        existingToCleanup.ws.close(1000, 'Replaced by new connection');
        try {
          existingToCleanup.pty.kill();
        } catch (e) {
          console.warn(`[Shell] Failed to kill existing PTY: ${e.message}`);
        }
      });
    }

    // PTY 输出 → WebSocket
    ptyProcess.onData((data) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ 
          type: 'output', 
          data: Buffer.from(data).toString('base64') 
        }));
      }
    });

    // PTY 退出处理
    ptyProcess.onExit(({ exitCode, signal }) => {
      console.log(`[Shell] PTY exited: code=${exitCode}, signal=${signal}`);
      // 检查是否是当前会话，避免删除已被替换的新会话
      const currentSession = activeSessions.get(deviceId);
      if (currentSession && currentSession.pty === ptyProcess) {
        activeSessions.delete(deviceId);
      }
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ 
          type: 'exit', 
          exitCode, 
          signal 
        }));
        ws.close(1000, 'Shell exited');
      }
    });

    // WebSocket 消息处理
    ws.on('message', (message) => {
      // 额外的消息大小检查
      if (message.length > 10 * 1024 * 1024) {
        console.warn(`[Shell] Message too large: ${message.length} bytes from ${deviceId}`);
        ws.close(1009, 'Message too large');
        return;
      }
      
      try {
        const msg = JSON.parse(message);
        
        switch (msg.type) {
          case 'input':
            // 客户端输入 → PTY
            if (msg.data) {
              try {
                const input = Buffer.from(msg.data, 'base64').toString('utf8');
                ptyProcess.write(input);
                // 更新最后活跃时间
                const sess = activeSessions.get(deviceId);
                if (sess) sess.lastActiveAt = Date.now();
              } catch (e) {
                console.error(`[Shell] Failed to decode input: ${e.message}`);
              }
            }
            break;
            
          case 'resize':
            // 终端尺寸调整
            if (msg.cols && msg.rows) {
              ptyProcess.resize(msg.cols, msg.rows);
            }
            break;
            
          case 'ping':
            // 心跳
            ws.send(JSON.stringify({ type: 'pong' }));
            break;
            
          default:
            console.warn(`[Shell] Unknown message type: ${msg.type}`);
        }
      } catch (e) {
        console.error('[Shell] Message parse error:', e);
      }
    });

    // WebSocket 关闭处理
    ws.on('close', () => {
      console.log(`[Shell] Device ${deviceId} disconnected`);
      const session = activeSessions.get(deviceId);
      // 只有当前 WebSocket 才清理会话，避免删除已被替换的新会话
      if (session && session.ws === ws) {
        activeSessions.delete(deviceId);
        try {
          session.pty.kill();
        } catch (e) {
          console.warn(`[Shell] Failed to kill PTY on close: ${e.message}`);
        }
      }
    });

    // WebSocket 错误处理
    ws.on('error', (error) => {
      console.error(`[Shell] WebSocket error for ${deviceId}:`, error);
    });

    // 发送欢迎消息
    ws.send(JSON.stringify({ 
      type: 'welcome', 
      message: `Interactive shell for device ${deviceId}\n`,
      shell: shell
    }));
  });

  // 定期清理超时会话（1小时无输入活动）
  setInterval(() => {
    const now = Date.now();
    const timeout = 60 * 60 * 1000; // 1 hour of inactivity

    for (const [deviceId, session] of activeSessions.entries()) {
      const idleSince = session.lastActiveAt || session.createdAt;
      if (now - idleSince > timeout) {
        console.log(`[Shell] Cleaning up idle session: ${deviceId}`);
        session.ws.close(1000, 'Session timeout');
        try { session.pty.kill(); } catch (e) {}
        activeSessions.delete(deviceId);
      }
    }
  }, 10 * 60 * 1000); // 每10分钟检查一次

  console.log('[Shell] Interactive shell WebSocket server attached');
}

/**
 * 获取活跃会话列表
 */
function getActiveSessions() {
  const sessions = [];
  for (const [deviceId, session] of activeSessions.entries()) {
    sessions.push({
      deviceId,
      createdAt: session.createdAt,
      uptime: Date.now() - session.createdAt
    });
  }
  return sessions;
}

/**
 * 强制关闭指定会话
 */
function killSession(deviceId) {
  if (activeSessions.has(deviceId)) {
    const session = activeSessions.get(deviceId);
    session.ws.close(1000, 'Killed by admin');
    session.pty.kill();
    activeSessions.delete(deviceId);
    return true;
  }
  return false;
}

module.exports = {
  attach,
  getActiveSessions,
  killSession
};