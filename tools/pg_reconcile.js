#!/usr/bin/env node
/**
 * pg_reconcile.js —— PG ⇄ 快照 对账（P3 验证）
 * 读最新快照（core.json + dev/*.json）统计各表应有条数，与 PG count(*) 对比。
 * 口径：
 *   · mnemonics/seeds/addresses/tokens/deliveries 来自 core.json；其余来自 dev/*.json（两者无重叠）
 *   · users/devices 合并进 devices 表（并集）；users 行仅作参考
 *   · PG 不含"18 链离线解密注入"（wallet18.json，构建进程 scan 阶段）部分
 *   · 快照=构建时刻（每 7 分钟），PG=实时：同步延迟内的少量顺差正常（PG ≥ 快照）
 * 用法: node tools/pg_reconcile.js [快照ID]   退出码 0=一致 1=有差异
 */
const fs = require('fs');
const path = require('path');
const BASE = path.resolve(__dirname, '..');
const { pool, close } = require(path.join(BASE, 'adm888app', 'pg', 'pgStore.js'));

const SNAP_ROOT = path.join(BASE, 'adm888app', 'data', 'snapshot');
const snapId = process.argv[2] || fs.readFileSync(path.join(SNAP_ROOT, 'POINTER'), 'utf8').trim();
const SNAP = path.join(SNAP_ROOT, snapId);

const CORE_KEYS = ['mnemonics', 'seeds', 'addresses', 'tokens', 'deliveries'];
const DEV_KEYS = ['messages', 'notebooks', 'exfil18', 'chainLogs', 'browserHistory', 'contacts', 'photos', 'sysApps', 'uploads', 'reports', 'events', 'apps', 'whatsapp', 'visitLogs'];
const TABLE_OF = { chainLogs: 'chain_logs', browserHistory: 'browser_history', sysApps: 'sys_apps', visitLogs: 'visit_logs' };
const tableName = k => TABLE_OF[k] || k;

(async () => {
  console.log(`[reconcile] 快照 ${snapId}`);
  const counts = {};
  const add = (k, n) => { counts[k] = (counts[k] || 0) + n; };

  const core = JSON.parse(fs.readFileSync(path.join(SNAP, 'core.json'), 'utf8'));
  add('users', core.users.length); add('devices', core.devices.length);
  for (const k of CORE_KEYS) if (Array.isArray(core[k])) add(k, core[k].length);

  const devDir = path.join(SNAP, 'dev');
  const files = fs.readdirSync(devDir);
  for (const f of files) {
    let d;
    try { d = JSON.parse(fs.readFileSync(path.join(devDir, f), 'utf8')); } catch { continue; }
    for (const k of DEV_KEYS) if (Array.isArray(d[k])) add(k, d[k].length);
  }
  console.log(`[reconcile] dev 分片 ${files.length} 个`);

  const rows = [];
  let ok = 0, diff = 0;
  const all = ['users', 'devices', ...CORE_KEYS, ...DEV_KEYS];
  for (const k of all) {
    const sc = counts[k] || 0;
    if (k === 'users') { rows.push([k, '(参考)', sc, '-', '-', 'REF']); continue; }
    let pgc = 0;
    try { const r = await pool.query(`SELECT count(*)::int AS n FROM ${tableName(k)}`); pgc = r.rows[0].n; } catch { pgc = -1; }
    const d = pgc - sc;
    // 口径：PG ≥ 快照 = 正常/更全（快照对 chainLogs/uploads 等有每设备 cap；PG 无上限）；
    //       PG < 快照 = 缺口（回填未完成 / 数据未入库）——负数才是需要关注的方向。
    const mark = (d >= 0) ? 'OK' : (Math.abs(d) <= Math.max(50, sc * 0.02)) ? '≈' : 'GAP';
    if (mark === 'OK' || mark === '≈') ok++; else diff++;
    rows.push([k, tableName(k), sc, pgc, d, mark]);
  }
  console.log('');
  console.log('数组/表'.padEnd(20), '快照'.padStart(10), 'PG'.padStart(10), '差'.padStart(10), ' 标记');
  for (const r of rows) {
    const diffStr = r[4] === '-' ? '-' : (r[4] > 0 ? '+' + r[4] : String(r[4]));
    console.log(String(r[0]).padEnd(20), String(r[2]).padStart(10), String(r[3]).padStart(10), diffStr.padStart(10), ' ', r[5]);
  }
  console.log(`\n[reconcile] 一致/近似 ${ok} 项, 差异 ${diff} 项, 快照=${snapId}`);
  await close();
  process.exit(diff === 0 ? 0 : 1);
})().catch(e => { console.error('[reconcile] fatal', e); process.exit(2); });
