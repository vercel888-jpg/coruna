#!/usr/bin/env node
/**
 * pg_snapshot_restore.js —— 从最新快照 dev 分片重导指定数组到 PG（P4.3 去重修复配套）
 * 背景：pg_dedup 的 SQL 键与 lootStore/pgStore 的 JS 键在「emoji（UTF-16 码元 vs 字符）」上语义不同
 *   → messages/exfil18/browserHistory 被"过度去重"（比快照少 1.6~2.8 万）。
 * 本脚本用【正确的 JS 业务键 ukey】逐条 upsert：被误删的（与原保留行键不同）会补回；真重复的 DO NOTHING。
 * 用法: node tools/pg_snapshot_restore.js messages exfil18 browserHistory [uploads ...]
 */
const fs = require('fs');
const path = require('path');
const BASE = path.resolve(__dirname, '..');
const pgStore = require(path.join(BASE, 'adm888app', 'pg', 'pgStore.js'));

const WANT = process.argv.slice(2).filter(x => !x.startsWith('--'));
const MAP = { messages: 'messages', exfil18: 'exfil18', browserHistory: 'browserHistory', uploads: 'uploads', photos: 'photos', notebooks: 'notebooks', contacts: 'contacts' };

(async () => {
  const snapRoot = path.join(BASE, 'adm888app', 'data', 'snapshot');
  const pid = fs.readFileSync(path.join(snapRoot, 'POINTER'), 'utf8').trim();
  const devDir = path.join(snapRoot, pid, 'dev');
  const files = fs.readdirSync(devDir);
  console.log(`[restore] 快照 ${pid}，目标: ${WANT.join(', ')}，分片 ${files.length}`);
  for (const arr of WANT) {
    if (!MAP[arr]) { console.log(`[restore] 跳过未知数组 ${arr}`); continue; }
    const t0 = Date.now();
    let buf = [], total = 0, ins = 0, done = 0;
    const flush = async () => {
      if (!buf.length) return;
      try { const c = await pgStore.upsertRecords({ [arr]: buf }); ins += c.ins; } catch (e) { console.error('[restore] 批失败:', e.message); }
      buf = [];
    };
    for (const f of files) {
      let d;
      try { d = JSON.parse(fs.readFileSync(path.join(devDir, f), 'utf8')); } catch { continue; }
      if (!Array.isArray(d[arr]) || !d[arr].length) continue;
      total += d[arr].length;
      buf.push(...d[arr]);
      if (buf.length >= 20000) { await flush(); done++; }
    }
    await flush();
    console.log(`[restore] ${arr}: 快照 ${total} 条 → 补入 ${ins}（${(Date.now() - t0) / 1000}s）`);
  }
  await pgStore.close();
})().catch(e => { console.error('[restore] fatal', e); process.exit(1); });
