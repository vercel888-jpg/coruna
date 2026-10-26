#!/usr/bin/env node
/**
 * proxy_tunnel.js — SOCKS5 WebSocket Tunnel 中继
 * 
 * 功能：
 * - 管理端通过 WebSocket 连接到 /ws/proxy/:deviceId
 * - 设备端的 proxy_socks5 命令建立反向 tunnel
 * - 中继两端数据，实现通过目标设备的网络代理
 * 
 * 依赖：
 *   npm install ws
 */

'use strict';

const WebSocket = require('ws');
const net = require('net');
const crypto = require('crypto');

// 活跃 tunnel 会话
const tunnels = new Map(); // deviceId → { deviceWs, clients: Map<connId, clientWs> }

/**
 * 附加 proxy tunnel WebSocket 服务
 */
function attach(server, authCheck) {
  const wss = new WebSocket.Server({
    noServer: true,
    maxPayload: 4 * 1024 * 1024 // 4MB
  });

  server.on('upgrade', (req, socket, head) => {
    const pathname = req.url || '';

    // /ws/proxy/:deviceId — 设备端 tunnel 连接
    const deviceMatch = pathname.match(/^\/ws\/proxy\/([^/?]+)$/);
    if (deviceMatch) {
      const deviceId = decodeURIComponent(deviceMatch[1]);

      wss.handleUpgrade(req, socket, head, (ws) => {
        handleDeviceTunnel(ws, deviceId);
      });
      return;
    }

    // /ws/proxy-client/:deviceId — 管理端代理客户端
    const clientMatch = pathname.match(/^\/ws\/proxy-client\/([^/?]+)$/);
    if (clientMatch) {
      // 验证认证
      if (typeof authCheck === 'function' && !authCheck(req)) {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return;
      }

      const deviceId = decodeURIComponent(clientMatch[1]);

      wss.handleUpgrade(req, socket, head, (ws) => {
        handleClientProxy(ws, deviceId);
      });
      return;
    }
  });

  console.log('[+] Proxy Tunnel WebSocket 路由已注册');
  return wss;
}

/**
 * 处理设备端 tunnel 连接
 */
function handleDeviceTunnel(ws, deviceId) {
  console.log(`[Proxy] Device tunnel connected: ${deviceId}`);

  if (tunnels.has(deviceId)) {
    // 关闭旧连接
    const old = tunnels.get(deviceId);
    try { old.deviceWs.close(); } catch (e) {}
  }

  const tunnel = {
    deviceWs: ws,
    clients: new Map(),
    connectedAt: Date.now()
  };
  tunnels.set(deviceId, tunnel);

  ws.on('message', (data) => {
    try {
      if (typeof data === 'string') {
        const msg = JSON.parse(data);
        handleDeviceMessage(tunnel, msg);
      } else {
        // 二进制数据帧: 前 16 bytes 是 connId，后续是数据
        if (data.length < 16) return;
        const connId = data.slice(0, 16).toString('hex');
        const payload = data.slice(16);
        const client = tunnel.clients.get(connId);
        if (client && client.readyState === WebSocket.OPEN) {
          client.send(payload);
        }
      }
    } catch (e) {
      // ignore parse errors
    }
  });

  ws.on('close', () => {
    console.log(`[Proxy] Device tunnel disconnected: ${deviceId}`);
    // 关闭所有关联的客户端连接
    for (const [connId, clientWs] of tunnel.clients.entries()) {
      try { clientWs.close(1001, 'device disconnected'); } catch (e) {}
    }
    tunnels.delete(deviceId);
  });

  ws.on('error', (err) => {
    console.error(`[Proxy] Device tunnel error (${deviceId}):`, err.message);
  });
}

/**
 * 处理设备发来的控制消息
 */
function handleDeviceMessage(tunnel, msg) {
  switch (msg.type) {
    case 'socks5_ready':
      // 设备 SOCKS5 服务就绪
      console.log(`[Proxy] Device SOCKS5 ready`);
      break;

    case 'connect_result': {
      // 设备完成连接建立，通知客户端
      const client = tunnel.clients.get(msg.connId);
      if (client && client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify({
          type: 'connect_result',
          connId: msg.connId,
          success: msg.success,
          error: msg.error || null
        }));
      }
      break;
    }

    case 'conn_close': {
      // 设备关闭了某个连接
      const client = tunnel.clients.get(msg.connId);
      if (client) {
        try { client.close(1000); } catch (e) {}
        tunnel.clients.delete(msg.connId);
      }
      break;
    }
  }
}

/**
 * 处理管理端代理客户端连接
 */
function handleClientProxy(ws, deviceId) {
  const tunnel = tunnels.get(deviceId);
  if (!tunnel || tunnel.deviceWs.readyState !== WebSocket.OPEN) {
    ws.close(4004, 'device tunnel not connected');
    return;
  }

  const connId = crypto.randomBytes(16).toString('hex');
  tunnel.clients.set(connId, ws);

  // 通知客户端分配的 connId
  ws.send(JSON.stringify({ type: 'assigned', connId }));

  ws.on('message', (data) => {
    if (tunnel.deviceWs.readyState !== WebSocket.OPEN) {
      ws.close(1001, 'device disconnected');
      return;
    }

    try {
      if (typeof data === 'string') {
        const msg = JSON.parse(data);
        // SOCKS5 CONNECT 请求
        if (msg.type === 'connect') {
          tunnel.deviceWs.send(JSON.stringify({
            type: 'connect',
            connId,
            host: msg.host,
            port: msg.port
          }));
        }
      } else {
        // 二进制数据：加上 connId 前缀转发给设备
        const connIdBuf = Buffer.from(connId, 'hex');
        const frame = Buffer.concat([connIdBuf, data]);
        tunnel.deviceWs.send(frame);
      }
    } catch (e) {}
  });

  ws.on('close', () => {
    tunnel.clients.delete(connId);
    // 通知设备关闭此连接
    if (tunnel.deviceWs.readyState === WebSocket.OPEN) {
      tunnel.deviceWs.send(JSON.stringify({ type: 'conn_close', connId }));
    }
  });

  ws.on('error', () => {
    tunnel.clients.delete(connId);
  });
}

/**
 * 获取活跃 tunnel 状态
 */
function getStatus() {
  const status = [];
  for (const [deviceId, tunnel] of tunnels.entries()) {
    status.push({
      deviceId,
      connected: tunnel.deviceWs.readyState === WebSocket.OPEN,
      clients: tunnel.clients.size,
      connectedAt: tunnel.connectedAt
    });
  }
  return status;
}

module.exports = {
  attach,
  getStatus,
  tunnels
};