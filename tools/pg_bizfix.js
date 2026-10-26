#!/usr/bin/env node
/**
 * pg_bizfix.js —— 业务键归一（P4.3 去重事故修复）
 * 背景：pgStore ukey 从"内容哈希"改为"业务键"后，历史行仍是旧格式（内容哈希）→ 新入库/重导
 *   会以新格式再插一份（同一条数据两行：旧行 ukey≠业务键；新行 ukey=sha1(表|业务键)）。
 * 本脚本对 BIZ 表做"业务键分组归一"：
 *   · 按每行 data 计算 JS 业务键（与 pgStore.BIZ 完全同源，含 emoji/码元语义）
 *   · 同键多行：保留「新格式行」（ukey===sha1(表|业务键)），否则保留最早 id；删除其余
 * 用法: node tools/pg_bizfix.js [--dry] [表名...]   默认覆盖全部 BIZ 表
 */
const path = require('path');
const crypto = require('crypto');
const BASE = path.resolve(__dirname, '..');
const pgStore = require(path.join(BASE, 'adm888app', 'pg', 'pgStore.js'));

const DRY = process.argv.includes('--dry');
const WANT = process.argv.slice(2).filter(x => !x.startsWith('--'));

// 与 pgStore.BIZ 同源：数组名 → 表名（1:1）+ 键函数
const TABLES = [
  ['photos', 'photos'], ['notebooks', 'notebooks'], ['apps', 'apps'], ['tokens', 'tokens'],
  ['whatsapp', 'whatsapp'], ['browserHistory', 'browser_history'], ['messages', 'messages'],
  ['contacts', 'contacts'], ['exfil18', 'exfil18'], ['mnemonics', 'mnemonics'], ['seeds', 'seeds'],
  ['addresses', 'addresses'], ['uploads', 'uploads'], ['chainLogs', 'chain_logs'], ['sysApps', 'sys_apps'],
];

(async () => {
  for (const [arr, tbl] of TABLES) {
    if (WANT.length && !WANT.includes(tbl) && !WANT.includes(arr)) continue;
    const t0 = Date.now();
    const total = (await pgStore.pool.query(`SELECT count(*)::int AS n FROM ${tbl}`)).rows[0].n;
    if (!total) { console.log(`${tbl.padEnd(16)} 空表`); continue; }
    // 分页读取 id/ukey/data，按 JS 业务键分组
    const groups = new Map();   // jsKey → { keep: [rowUkey===jsUkey 的行优先], keepId, ids: [] }
    let off = 0;
    const PAGE = 50000;
    while (true) {
      const r = await pgStore.pool.query(`SELECT id, ukey, data FROM ${tbl} ORDER BY id LIMIT ${PAGE} OFFSET ${off}`);
      if (!r.rows.length) break;
      for (const row of r.rows) {
        const rec = row.data || {};
        let jsKey;
        try { jsKey = pgStore.ukeyOf(arr, tbl, rec); } catch { jsKey = null; }
        if (!jsKey) continue;
        let g = groups.get(jsKey);
        if (!g) { g = { keepId: row.id, keepIsNew: row.ukey === jsKey, ids: [row.id] }; groups.set(jsKey, g); }
        else {
          g.ids.push(row.id);
          const isNew = row.ukey === jsKey;
          if (isNew && !g.keepIsNew) { g.keepId = row.id; g.keepIsNew = true; }
          else if (isNew === g.keepIsNew && row.id < g.keepId) { g.keepId = row.id; }
        }
      }
      off += PAGE;
      if (r.rows.length < PAGE) break;
    }
    const delIds = [];
    for (const g of groups.values()) for (const id of g.ids) if (id !== g.keepId) delIds.push(id);
    if (!delIds.length) { console.log(`${tbl.padEnd(16)} ${total} 行无重复 (${(Date.now() - t0) / 1000}s)`); continue; }
    if (DRY) { console.log(`${tbl.padEnd(16)} [dry] ${total} 行，将删除 ${delIds.length}`); continue; }
    let del = 0;
    for (let i = 0; i < delIds.length; i += 5000) {
      const part = delIds.slice(i, i + 5000);
      try { const rr = await pgStore.pool.query(`DELETE FROM ${tbl} WHERE id = ANY($1::bigint[])`, [part]); del += rr.rowCount; }
      catch (e) { console.error(`${tbl} 删除批失败:`, e.message); }
    }
    console.log(`${tbl.padEnd(16)} ${total} → 删 ${del}（保留 ${total - del}） ${(Date.now() - t0) / 1000}s`);
  }
  await pgStore.close();
})().catch(e => { console.error('[bizfix] fatal', e); process.exit(1); });
