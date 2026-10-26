#!/usr/bin/env node
/**
 * pg_backfill.js —— PG 历史回填（P3）
 * 遍历 loot 全部桶 → ingestd.processOne（冷启动=全量解析；已有 state 且无变化=秒级跳过）
 * · 按目录 mtime 降序（最近活跃的桶优先补齐）
 * · 空目录跳过（不建 state）；中断可续（state 落盘，重跑自动跳过已处理桶）
 * · 与常驻 ingestd 并行安全：共享 state 目录，偶发重复处理由 PG ukey 幂等兜底
 *
 * 用法:
 *   node tools/pg_backfill.js                 # 全量回填
 *   node tools/pg_backfill.js --limit 100     # 只跑前 100 个桶（试跑）
 *   node tools/pg_backfill.js --dry           # 只列桶清单与统计，不处理
 */
const fs = require('fs');
const path = require('path');
const BASE = path.resolve(__dirname, '..');
process.env.LOOT_SCAN_CACHE = process.env.LOOT_SCAN_CACHE || '1';
process.env.LOOT_DIR = process.env.LOOT_DIR || path.join(BASE, 'loot');
const { processOne } = require(path.join(BASE, 'adm888app', 'pg', 'ingestd.js'));
const pgStore = require(path.join(BASE, 'adm888app', 'pg', 'pgStore.js'));

const LOOT_DIR = process.env.LOOT_DIR;
const args = process.argv.slice(2);
const argOf = (name, dflt) => { const i = args.indexOf(name); return i >= 0 ? Number(args[i + 1]) : dflt; };
const LIMIT = argOf('--limit', 0);
const OFFSET = argOf('--offset', 0);
const DRY = args.includes('--dry');

async function main() {
  const t0 = Date.now();
  const dirs = [];
  for (const e of fs.readdirSync(LOOT_DIR, { withFileTypes: true })) {
    if (!e.isDirectory() || e.name.startsWith('_')) continue;
    try {
      const st = fs.statSync(path.join(LOOT_DIR, e.name));
      const n = fs.readdirSync(path.join(LOOT_DIR, e.name)).length;
      if (n === 0) continue;                     // 空桶跳过（不建 state）
      dirs.push({ name: e.name, mtime: st.mtimeMs, files: n });
    } catch { /* 不可读：跳过 */ }
  }
  dirs.sort((a, b) => b.mtime - a.mtime);        // 最近活跃优先
  const targets = dirs.slice(OFFSET, LIMIT > 0 ? OFFSET + LIMIT : dirs.length);
  console.log(`[backfill] 非空桶 ${dirs.length} 个, 本轮处理 ${targets.length} 个 (offset=${OFFSET}), 文件总量 ${dirs.reduce((s, d) => s + d.files, 0)}`);
  if (DRY) return;

  const stat = { buckets: 0, recs: 0, ins: 0, skip: 0, errs: 0, failed: [] };
  for (const d of targets) {
    try {
      const r = await processOne(d.name);
      stat.buckets++; stat.recs += r.recs; stat.ins += r.ins;
      if (r.skipped) stat.skip++;
      if (r.err) { stat.errs++; stat.failed.push(d.name); }
      if (stat.buckets % 100 === 0) {
        const el = (Date.now() - t0) / 1000;
        console.log(`[backfill] ${stat.buckets}/${targets.length} | 记录=${stat.recs} 新增=${stat.ins} 跳过=${stat.skip} 错误=${stat.errs} | ${el.toFixed(0)}s (${(stat.buckets / el).toFixed(1)} 桶/s)`);
      }
    } catch (e) {
      stat.errs++; stat.failed.push(d.name);
      console.error('[backfill] 失败', d.name, String((e && e.message) || e).slice(0, 150));
    }
  }
  const el = ((Date.now() - t0) / 1000).toFixed(0);
  console.log(`[backfill] 完成: 桶=${stat.buckets} 记录=${stat.recs} 新增=${stat.ins} 跳过=${stat.skip} 错误=${stat.errs} 用时=${el}s`);
  if (stat.failed.length) console.log('[backfill] 失败桶:', stat.failed.slice(0, 30).join(', ') + (stat.failed.length > 30 ? ` ...共${stat.failed.length}` : ''));
  await pgStore.close();
}

main().catch(e => { console.error('[backfill] fatal', e); process.exit(1); });
