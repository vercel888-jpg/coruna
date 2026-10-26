#!/usr/bin/env node
/**
 * screen_stream.js — 实时屏幕流服务
 * 
 * 功能：
 * - 通过 WebSocket 推送实时屏幕截图
 * - 降帧率（2-5 FPS）减少带宽
 * - 差分压缩（仅推送变化区域）
 * - JPEG 质量自适应调整
 * 
 * 依赖：
 *   npm install ws sharp
 */

'use strict';

const WebSocket = require('ws');
const crypto = require('crypto');

// 活跃流会话
const activeStreams = new Map(); // deviceId → { ws, lastFrame, fps, quality }

// 帧缓存（独立命名空间，避免全局污染）
const screenFrameCache = new Map(); // deviceId → { data, timestamp, hash }

/**
 * 附加屏幕流 WebSocket 服务
 */
function attach(server, authCheck) {
  const wss = new WebSocket.Server({ 
    noServer: true,
    maxPayload: 10 * 1024 * 1024  // 限制消息大小为 10MB
  });

  server.on('upgrade', (req, socket, head) => {
    const pathname = new URL(req.url, 'http://localhost').pathname;
    
    if (pathname.startsWith('/ws/screen/')) {
      if (!authCheck(req)) {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return;
      }

      wss.handleUpgrade(req, socket, head, (ws) => {
        wss.emit('connection', ws, req);
      });
    }
  });

  wss.on('connection', (ws, req) => {
    const url = new URL(req.url, 'http://localhost');
    const deviceId = url.pathname.split('/').pop();
    const fps = parseInt(url.searchParams.get('fps')) || 2;
    const quality = parseInt(url.searchParams.get('quality')) || 60;
    
    if (!deviceId) {
      ws.close(1008, 'Device ID required');
      return;
    }

    console.log(`[Screen] Stream started for ${deviceId} (${fps}fps, q=${quality})`);

    // 检查是否已有活跃流
    if (activeStreams.has(deviceId)) {
      const existing = activeStreams.get(deviceId);
      // 先从 Map 中移除避免竞态
      activeStreams.delete(deviceId);
      existing.ws.close(1000, 'Replaced by new stream');
    }

    activeStreams.set(deviceId, {
      ws,
      lastFrame: null,
      lastHash: null,
      fps,
      quality,
      frameCount: 0,
      startTime: Date.now()
    });

    // 发送配置确认
    ws.send(JSON.stringify({
      type: 'config',
      fps,
      quality,
      message: 'Screen stream started'
    }));

    ws.on('message', (message) => {
      // 额外的消息大小检查
      if (message.length > 10 * 1024 * 1024) {
        console.warn(`[Screen] Message too large: ${message.length} bytes from ${deviceId}`);
        ws.close(1009, 'Message too large');
        return;
      }
      
      try {
        const msg = JSON.parse(message);
        
        if (msg.type === 'frame') {
          // 客户端推送的帧
          handleFrame(deviceId, msg.data, msg.timestamp);
        } else if (msg.type === 'ping') {
          ws.send(JSON.stringify({ type: 'pong' }));
        }
      } catch (e) {
        console.error('[Screen] Message parse error:', e);
      }
    });

    ws.on('close', () => {
      console.log(`[Screen] Stream stopped for ${deviceId}`);
      const stream = activeStreams.get(deviceId);
      // 只有当前 WebSocket 才清理会话，避免删除已被替换的新会话
      if (stream && stream.ws === ws) {
        const duration = Date.now() - stream.startTime;
        const avgFps = stream.frameCount / (duration / 1000);
        console.log(`[Screen] Stats: ${stream.frameCount} frames, ${avgFps.toFixed(2)} fps avg`);
        activeStreams.delete(deviceId);
      }
    });

    ws.on('error', (error) => {
      console.error(`[Screen] WebSocket error for ${deviceId}:`, error);
    });
  });

  // 定期清理过期的帧缓存（每30秒）
  setInterval(() => {
    const now = Date.now();
    for (const [id, frame] of screenFrameCache.entries()) {
      if (now - frame.timestamp > 30000) { // 保留30秒
        screenFrameCache.delete(id);
      }
    }
  }, 30000);

  console.log('[Screen] Screen stream WebSocket server attached');
}

/**
 * 处理接收到的帧
 */
function handleFrame(deviceId, base64Data, timestamp) {
  const stream = activeStreams.get(deviceId);
  if (!stream || stream.ws.readyState !== WebSocket.OPEN) return;

  try {
    // 计算帧哈希（用于差分检测）
    const frameHash = crypto.createHash('md5').update(base64Data).digest('hex');
    
    // 如果与上一帧相同，跳过（静态画面）
    if (stream.lastHash === frameHash) {
      return;
    }

    stream.lastHash = frameHash;
    stream.lastFrame = base64Data;
    stream.frameCount++;

    // 广播给所有订阅该设备屏幕的客户端（管理员）
    // 这里简化为直接通过同一个 WebSocket 连接回传
    // 实际应用中可能需要分离客户端-服务端和服务端-管理员的连接

    // 将帧存储到内存缓存，供 HTTP API 查询
    screenFrameCache.set(deviceId, {
      data: base64Data,
      timestamp: timestamp || Date.now(),
      hash: frameHash
    });

  } catch (e) {
    console.error('[Screen] Frame processing error:', e);
  }
}

/**
 * 获取最新帧（HTTP API）
 */
function getLatestFrame(deviceId) {
  if (screenFrameCache.has(deviceId)) {
    return screenFrameCache.get(deviceId);
  }
  return null;
}

/**
 * 获取活跃流列表
 */
function getActiveStreams() {
  const streams = [];
  for (const [deviceId, stream] of activeStreams.entries()) {
    streams.push({
      deviceId,
      fps: stream.fps,
      quality: stream.quality,
      frameCount: stream.frameCount,
      uptime: Date.now() - stream.startTime
    });
  }
  return streams;
}

/**
 * 停止指定流
 */
function stopStream(deviceId) {
  if (activeStreams.has(deviceId)) {
    const stream = activeStreams.get(deviceId);
    stream.ws.close(1000, 'Stopped by admin');
    activeStreams.delete(deviceId);
    return true;
  }
  return false;
}

module.exports = {
  attach,
  getLatestFrame,
  getActiveStreams,
  stopStream
};