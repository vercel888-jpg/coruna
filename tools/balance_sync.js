#!/usr/bin/env node
/**
 * balance_sync.js —— 地址余额同步器 v2（2026-09-15 大修）
 *   【本轮改动】
 *     · BTC 换 blockstream.info（mempool.space 从本机已超时不可用）
 *     · EVM 接 Etherscan V2 key 池（20 把；免费档覆盖 ETH/Polygon/Arbitrum，balancemulti 20 地址/次）
 *     · TRON 接 Tronscan key 池（6 把轮换，~4 并发），失败逐地址回退 trongrid
 *     · EVM 跨 5 链求和写 bal（修复旧版"5 链结果竞态、最后一条覆盖"的问题）；
 *       非零时把分链明细写 data.evm_bals
 *     · 【2026-09-16】代币统一追踪：EVM(USDT/USDC via RPC eth_call balanceOf)、TRON(TRC20)、SOL(SPL)、TON(Jetton)
 *       → 统一写 data.tokens（[{chain,abbr,amount}]）；代币进账 → balance_changes(source='sweep_tok') → 通知管道
 *     · 每轮限额 + 最陈旧优先（配合每 1 分钟 cron 轮转，单轮不会跑飞）
 *     · key 用量日计数器（adm888app/data/bal_key_usage.json），池用量 ≥85% 写告警文件（通知管道消费）
 *     · 余额变化 → balance_changes 表（表存在才记；10 分钟内同址去重防双源重复）
 *   【频率】HF（有余额）默认 90 秒；LF（零余额）分链: tron 10m / evm 30m / btc 30m / ltc 60m / sol 30m / doge 12h
 *   用法: node tools/balance_sync.js [--chain evm|tron|btc|ltc|doge|sol] [--limit N] [--force] [--dry]
 */
const path = require('path');
const fs = require('fs');
const BASE = path.resolve(__dirname, '..');
const pgStore = require(path.join(BASE, 'adm888app', 'pg', 'pgStore.js'));
const vaultLib = require(path.join(BASE, 'tools', 'vault_lib.js'));   // 【2026-09-16】暗池核心

const args = process.argv.slice(2);
const arg = (n, d) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : d; };
const ONLY = String(arg('--chain', '') || '').toLowerCase();
const LIMIT = Number(arg('--limit', 0)) || 0;
const FORCE = args.includes('--force');
const DRY = args.includes('--dry');

// ── 频率 / 限额 / 额度配置 ────────────────────────────────────────────────────
const HF_MS = Math.round(Number(process.env.BAL_HF_MIN || 1.5) * 60000);        // 有余额：90 秒
const LF = {
  tron: Math.round(Number(process.env.BAL_LF_TRON_MIN || 10) * 60000),          // 零余额：10 分钟
  evm:  Math.round(Number(process.env.BAL_LF_MIN || 30) * 60000),               // 30 分钟
  btc:  Math.round(Number(process.env.BAL_LF_BTC_MIN || 60) * 60000),           // 【2026-09-18】60 分钟（BTC 10 分钟出块；积压期放宽窗口，配合 CAP 400）
  ltc:  Math.round(Number(process.env.BAL_LF_LTC_MIN || 60) * 60000),           // 60 分钟
  sol:  Math.round(Number(process.env.BAL_LF_MIN || 30) * 60000),
  doge: Math.round(Number(process.env.BAL_LF_DOGE_MIN || 60) * 60000),         // 【2026-09-18】12h→60 分钟（OKX 接入后 blockcypher 不再是瓶颈）
  ton:  Math.round(Number(process.env.BAL_LF_TON_MIN || 60) * 60000),          // 【2026-09-16】TON：60 分钟（toncenter 公共接口低频）
};
const CAP = {  // 每轮每桶最多取多少地址（最陈旧优先）——防首跑全量卡死
  evm:  Number(process.env.BAL_CAP_EVM || 300),
  tron: Number(process.env.BAL_CAP_TRON || 250),
  btc:  Number(process.env.BAL_CAP_BTC || 400),   // 【2026-09-18】OKX 优先 + 传统源兜底 400/轮（目标 BTC 全量 ≈60 分钟/轮）
  ltc:  Number(process.env.BAL_CAP_LTC || 250),
  sol:  Number(process.env.BAL_CAP_SOL || 120),
  doge: Number(process.env.BAL_CAP_DOGE || 300),  // 【2026-09-18】40→300
  ton:  Number(process.env.BAL_CAP_TON || 60),
};
const QUOTA_PER_KEY_DAY = 100000;          // Etherscan / Tronscan 免费档：每 key 10 万/天
const KEY_ALERT_RATIO = 0.85;              // 池用量 ≥85% → 告警（通知管道消费）
const KEYS_F = path.join(BASE, 'docs', '区块游览器key.txt');
const USAGE_F = path.join(BASE, 'adm888app', 'data', 'bal_key_usage.json');
const ALERT_F = path.join(BASE, 'adm888app', 'data', 'bal_key_alert.json');
const TRON_GAP = 60;                        // Tronscan 每请求间隔 ms（key 池轮换后可快）
const CONC = Number(process.env.BAL_CONC || 6);
const MARK = Date.now();

const EVM_CHAINS = [
  { name: 'ETH',      sym: 'ETH', rpc: 'https://ethereum-rpc.publicnode.com',              es: 1,     keyed: true },
  { name: 'BSC',      sym: 'BNB', rpc: 'https://bsc-rpc.publicnode.com',                   es: 56,    keyed: false },
  { name: 'POLYGON',  sym: 'POL', rpc: 'https://polygon-bor-rpc.publicnode.com',           es: 137,   keyed: true },
  { name: 'ARBITRUM', sym: 'ETH', rpc: 'https://arbitrum-one-rpc.publicnode.com',          es: 42161, keyed: true },
  { name: 'BASE',     sym: 'ETH', rpc: 'https://base-rpc.publicnode.com',                  es: 8453,  keyed: false },
];

// 【2026-09-16】稳定币代币追踪：各链 USDT/USDC 合约 + 小数位（BSC 为 18 位，其余 6 位）。
//   经 RPC eth_call(balanceOf) 批量获取，写入 data.tokens（统一 [{chain,abbr,amount}]）。
const STABLES = {
  ETH:      { USDT: ['0xdac17f958d2ee523a2206206994597c13d831ec7', 6], USDC: ['0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48', 6] },
  BSC:      { USDT: ['0x55d398326f99059ff775485246999027b3197955', 18], USDC: ['0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d', 18] },
  POLYGON:  { USDT: ['0xc2132d05d31c914a87c6611c10748aeb04b58e8f', 6], USDC: ['0x3c499c542cef5e3811e1192ce70d8cc03d5c3359', 6] },
  ARBITRUM: { USDT: ['0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9', 6], USDC: ['0xaf88d065e77c8cc2239327c5edb3a432268e5831', 6] },
  BASE:     { USDT: ['0xfde4c96c8593536e31f229ea8f37b2ada2699bb2', 6], USDC: ['0x833589fcd6edb6e08f4c7c32d4f71b54bda02913', 6] },
};

const sleep = ms => new Promise(r => setTimeout(r, ms));
async function jfetch(url, opt, timeout = 15000) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeout);
  try { return await fetch(url, { ...(opt || {}), signal: ctl.signal }); }
  finally { clearTimeout(t); }
}

// ── OKX Web3 余额 API（2026-09-18 接入试用：免费档实测 ~3 req/s 稳；全局节流 + 50011 冷却 + 用量留档）──
const crypto = require('crypto');
const OKX_F = path.join(BASE, 'adm888app', 'data', 'okx_api.json');
const OKX_USAGE_F = path.join(BASE, 'adm888app', 'data', 'okx_usage.json');
let OKX = null;
try { OKX = JSON.parse(fs.readFileSync(OKX_F, 'utf8')); } catch (e) { console.log('[bal] okx 配置读取失败（跳过 OKX 源）:', e.message); }
const OKX_RATE_MS = Number(process.env.OKX_RATE_MS || 360);     // ~2.8 次/秒（免费档 3/s 干净、5/s 起打八折）
const OKX_COOL_MS = Number(process.env.OKX_COOL_MS || 15000);   // 50011 后冷却 15s，期间自动回退传统源
let _okxNext = 0, _okxCool = 0;
const _okxUse = { ok: 0, e429: 0, err: 0 };
function okxReady() { return !!OKX && Date.now() >= _okxCool; }
function okxSign(method, pq) {
  const ts = new Date().toISOString();
  const sig = crypto.createHmac('sha256', OKX.secret_key).update(ts + method + pq).digest('base64');
  return { 'OK-ACCESS-KEY': OKX.api_key, 'OK-ACCESS-SIGN': sig, 'OK-ACCESS-TIMESTAMP': ts, 'OK-ACCESS-PASSPHRASE': OKX.passphrase };
}
async function okxNative(chainIdx, addr, withAssets) {   // 返回原生币 rawBalance 字符串（零余额=空数组 → '0'）；withAssets=true 时返回 { raw, assets }
  if (!OKX) throw new Error('okx 未配置');
  if (Date.now() < _okxCool) throw new Error('okx cooling');
  const wait = _okxNext - Date.now();
  _okxNext = Math.max(Date.now(), _okxNext) + OKX_RATE_MS;
  if (wait > 0) await sleep(wait);
  const pq = `/api/v6/dex/balance/all-token-balances-by-address?address=${encodeURIComponent(addr)}&chains=${chainIdx}`;
  let j = null;
  try {
    const r = await jfetch(String(OKX.base || 'https://web3.okx.com').replace(/\/+$/, '') + pq, { headers: okxSign('GET', pq) }, 12000);
    j = await r.json().catch(() => null);
  } catch (e) { _okxUse.err++; throw new Error('okx ' + String((e && e.message) || 'fetch').slice(0, 40)); }
  if (!j) { _okxUse.err++; throw new Error('okx bad-json'); }
  const code = String(j.code);
  if (code !== '0') {
    if (code === '50011') { _okxUse.e429++; _okxCool = Date.now() + OKX_COOL_MS; _okxNext = Date.now() + 1200; throw new Error('okx 50011 rate'); }
    if (code === '81001') throw new Error('okx 81001 400');
    _okxUse.err++;
    throw new Error('okx ' + code + ' ' + String(j.msg || '').slice(0, 40));
  }
  const ta = ((j.data && j.data[0] && j.data[0].tokenAssets) || []);
  const nat = ta.find(t => !t.tokenContractAddress);
  _okxUse.ok++;
  const raw = nat ? String(nat.rawBalance || '0') : '0';
  return withAssets ? { raw, assets: ta } : raw;
}
function okxSaveUsage() {
  if (!OKX || (!_okxUse.ok && !_okxUse.e429 && !_okxUse.err)) return;
  try {
    let u = { ok: 0, e429: 0, err: 0, since: Date.now() };
    try { u = Object.assign(u, JSON.parse(fs.readFileSync(OKX_USAGE_F, 'utf8'))); } catch (e) {}
    u.ok = Number(u.ok || 0) + _okxUse.ok;
    u.e429 = Number(u.e429 || 0) + _okxUse.e429;
    u.err = Number(u.err || 0) + _okxUse.err;
    u.last = Date.now();
    fs.writeFileSync(OKX_USAGE_F, JSON.stringify(u));
  } catch (e) {}
}

// ── key 池 + 用量计数 ────────────────────────────────────────────────────────
function loadKeys() {
  const out = { evm: [], tron: [] };
  try {
    for (const ln of fs.readFileSync(KEYS_F, 'utf8').split('\n')) {
      const s = ln.trim();
      if (s.length === 34) out.evm.push(s);
      else if (s.length === 36 && s.includes('-')) out.tron.push(s);
    }
  } catch (e) { console.log('[bal] key 文件读取失败:', e.message); }
  return out;
}
const KEYS = loadKeys();
const TODAY = new Date().toISOString().slice(0, 10).replace(/-/g, '');
let USAGE = { date: TODAY, evm: {}, tron: {} };
try {
  const u = JSON.parse(fs.readFileSync(USAGE_F, 'utf8'));
  if (u && u.date === TODAY) USAGE = u;
} catch (e) {}
function pickKey(pool, usage) {  // 取用量最小的 key（轮换分摊）
  let best = 0, bestN = Infinity;
  pool.forEach((k, i) => { const n = usage[i] || 0; if (n < bestN) { bestN = n; best = i; } });
  return best;
}
// 按 key 冷却门控（Tronscan 实测 1 req/s/key；Etherscan 5 req/s/key）
const lastUse = { evm: {}, tron: {} };
const COOLDOWN = { evm: 240, tron: 1150 };
// 无效 key 标记（"Invalid API Key" 的 key 拉黑，持久化在用量文件里）
const BAD = { evm: new Set(USAGE.bad_evm || []), tron: new Set(USAGE.bad_tron || []) };
async function pickKeyWait(poolName, usage) {
  const pool = KEYS[poolName];
  for (;;) {
    const now = Date.now();
    const ready = [];
    let oldest = Infinity, oldestIdx = 0;
    for (let i = 0; i < pool.length; i++) {
      if (BAD[poolName].has(i)) continue;
      const lu = lastUse[poolName][i] || 0;
      if (now - lu >= COOLDOWN[poolName]) ready.push(i);
      else if (lu < oldest) { oldest = lu; oldestIdx = i; }
    }
    if (ready.length) {
      ready.sort((a, b) => (usage[a] || 0) - (usage[b] || 0));
      const i = ready[0];
      lastUse[poolName][i] = Date.now();
      return i;
    }
    await sleep(Math.max(40, Math.min(300, COOLDOWN[poolName] - (now - oldest) + 20)));
  }
}
function bumpKey(pool, usage, i, n = 1) { usage[i] = (usage[i] || 0) + n; }
let _usageDirty = 0;
function saveUsage(force) {
  if (DRY) return;
  if (!force && ++_usageDirty % 20) return;
  try { fs.writeFileSync(USAGE_F, JSON.stringify(USAGE)); } catch (e) {}
}
function keyAlertCheck() {
  for (const poolName of ['evm', 'tron']) {
    const pool = KEYS[poolName];
    if (!pool.length) continue;
    const used = pool.reduce((n, k, i) => n + (USAGE[poolName][i] || 0), 0);
    const cap = pool.length * QUOTA_PER_KEY_DAY;
    if (used >= cap * KEY_ALERT_RATIO) {
      try {
        fs.writeFileSync(ALERT_F, JSON.stringify({
          pool: poolName, used, cap, keys: pool.length, ratio: used / cap,
          ts: Date.now(), hint: 'key 额度即将耗尽，需要补充新 key（' + poolName + ' 池）',
        }));
      } catch (e) {}
      console.log(`[bal] ⚠️ ${poolName} key 池用量 ${used}/${cap}（≥85%），已写告警文件`);
    }
  }
}

// ── 格式化 ───────────────────────────────────────────────────────────────────
function fmtAmt(v, dec) {
  const n = Number(v);
  if (!isFinite(n) || n === 0) return '0';
  const s = n.toFixed(dec);
  const trimmed = s.includes('.') ? s.replace(/0+$/, '').replace(/\.$/, '') : s;
  const [ip, fp] = trimmed.split('.');
  const ipf = ip.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  return fp ? ipf + '.' + fp : ipf;
}
function bigToDec(v, dec) {  // BigInt → 十进制字符串（精确）
  const s = v.toString();
  if (!dec) return s;
  const pad = s.padStart(dec + 1, '0');
  const ip = pad.slice(0, pad.length - dec);
  const fp = pad.slice(pad.length - dec).replace(/0+$/, '');
  return fp ? (ip.replace(/^0+(?=\d)/, '') || '0') + '.' + fp : (ip.replace(/^0+(?=\d)/, '') || '0');
}
const decStr = v => {
  if (v === null || v === undefined || !isFinite(Number(v))) return null;
  const n = Number(v);
  if (n === 0) return '0';
  return String(v).includes('e') ? n.toFixed(18).replace(/0+$/, '').replace(/\.$/, '') : String(v);
};

// ── 单点查询器 ───────────────────────────────────────────────────────────────
const RETRYABLE = /429|rate|exceed|abort|timeout|no result|ETIMEDOUT|ECONN|fetch failed|api plan/i;
async function withRetry(fn, a, tries = 2) {
  let last;
  for (let i = 0; i < tries; i++) {
    try { return await fn(a); }
    catch (e) { last = e; if (!RETRYABLE.test(String((e && e.message) || e))) break; await sleep(300 * (i + 1)); }
  }
  throw last;
}

async function tronTronscan(addr) {
  const i = await pickKeyWait('tron', USAGE.tron);
  const hdr = { 'TRON-PRO-API-KEY': KEYS.tron[i] };
  let r;
  try {
    r = await jfetch('https://apilist.tronscanapi.com/api/account?address=' + encodeURIComponent(addr), { headers: hdr }, 15000);
    bumpKey(KEYS.tron, USAGE.tron, i); saveUsage();
  } catch (e) { throw e; }
  if (!r.ok) {
    const t = await r.text().catch(() => '');
    if (/rps|rate|exceed/i.test(t)) lastUse.tron[i] = Date.now() + 1500;   // 限速惩罚：该 key 冷却 1.5s
    throw new Error('tronscan ' + r.status + (t ? ' ' + t.slice(0, 50) : ''));
  }
  const j = await r.json();
  const sun = Number(j.balance || 0);
  const trx = sun / 1e6;
  const tok = (j.trc20token_balances || [])
    .map(t => ({ abbr: String(t.tokenAbbr || '').slice(0, 12), amount: Number(t.balance || 0) / Math.pow(10, Number(t.tokenDecimal || 0)) }))
    .filter(t => t.amount > 0 && t.abbr)
    .slice(0, 8);
  // 【2026-09-16】返回空数组=已采集且无代币（与"未采集"的 null 区分，供 tokens 基线判断）
  return { raw: trx, disp: fmtAmt(trx, 6) + ' TRX', tok: tok };
}
let _lastGrid = 0;
async function tronGrid(addr) {   // 回退（无 key 低速率：全局限速 400ms/次，防并发打爆）
  const gap = 400 - (Date.now() - _lastGrid);
  if (gap > 0) await sleep(gap);
  _lastGrid = Date.now();
  const r = await jfetch('https://api.trongrid.io/v1/accounts/' + encodeURIComponent(addr), {}, 15000);
  const j = await r.json();
  if (j && j.Error) { _lastGrid = Date.now() + 800; throw new Error(String(j.Error).slice(0, 60)); }
  const d = (j && Array.isArray(j.data) && j.data[0]) || null;
  const sun = d ? Number(d.balance || 0) : 0;
  const trx = sun / 1e6;
  return { raw: trx, disp: fmtAmt(trx, 6) + ' TRX', tok: null };
}
async function evmRpc(chain, addr) {
  const r = await jfetch(chain.rpc, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_getBalance', params: [addr, 'latest'] }),
  });
  const j = await r.json();
  if (!j || !j.result) throw new Error((j && j.error && j.error.message) || 'rpc error');
  return BigInt(j.result);
}

// 【2026-09-16】TON Jetton（USDT）余额：tonapi；null=未采集（跳过写），[]=采集无代币
async function tonJettons(addr) {
  try {
    const r = await jfetch('https://tonapi.io/v2/accounts/' + encodeURIComponent(addr) + '/jettons', {}, 15000);
    if (!r.ok) return null;
    const j = await r.json();
    const USDT_RAW = '0:b113a994b5024a16719f69139328eb759596c38a25f59028b146fecdc3621dfe';
    const out = [];
    for (const b of (j.balances || [])) {
      const jt = b.jetton || {};
      const isUsdt = String(jt.address || '') === USDT_RAW || String(jt.symbol || '').toUpperCase() === 'USDT';
      if (!isUsdt) continue;
      const dec = Number(jt.decimals != null ? jt.decimals : 6);
      const amt = Number(b.balance || 0) / Math.pow(10, dec);
      if (amt > 0) out.push({ chain: 'TON', abbr: 'USDT', amount: amt });
    }
    return out;
  } catch (e) { return null; }
}

// ── 【2026-09-18 v4】BTC 源池（多形态适配）：查询级探测 + 轮询 + 连续失败断路 ──
//   探测改为「真实地址查询」判定：blockstream 限额 700 次/小时限的是地址查询接口（tip/height 仍通），
//   旧探测（探活端点）会误报存活，导致每轮白烧一批 429。v4 用查询结果判定可用性。
//   esplora      = blockstream / mempool.emzy.de / mempool.bitaroo.net / mempool.space（同构 API）
//   blockchain   = blockchain.info/rawaddr（final_balance，satoshi；?limit=0 省流量）
//   blockchair   = api.blockchair.com dashboards（本机曾被临时拉黑，探测自动跳过；解封/加 key 后自动启用）
const BTC_SOURCES = [
  { name: 'blockstream', mode: 'esplora', base: 'https://blockstream.info/api', probe: '/blocks/tip/height' },
  { name: 'emzy', mode: 'esplora', base: 'https://mempool.emzy.de/api', probe: '/blocks/tip/height' },
  { name: 'bitaroo', mode: 'esplora', base: 'https://mempool.bitaroo.net/api', probe: '/blocks/tip/height' },
  { name: 'blockchain', mode: 'blockchain', base: 'https://blockchain.info' },
  { name: 'blockchair', mode: 'blockchair', base: 'https://api.blockchair.com' },
  { name: 'mempool.space', mode: 'esplora', base: 'https://mempool.space/api', probe: '/blocks/tip/height' },
];
let _btcAlive = [];
let _btcRR = 0;
let _btcFail = {};
let _btcStat = {};
let _btcMiss = 0;      // 连续"源故障"地址数（≥12 → 本轮放弃 BTC）
let _btcDead = false;  // 本轮放弃标记
const BTC_PROBE_ADDR = '1BitcoinEaterAddressDontSendf59kuE';   // 探测基准（烧币地址；验证的是"查询通道"是否可用）
async function btcProbeSources() {
  const alive = [];
  for (const s of BTC_SOURCES) {
    try {
      let ok = false;
      if (s.mode === 'esplora') {
        const r = await jfetch(s.base + '/address/' + BTC_PROBE_ADDR, {}, 8000);
        if (r.ok) { const j = await r.json().catch(() => null); ok = !!(j && j.chain_stats); }
      } else if (s.mode === 'blockchain') {
        const r = await jfetch(s.base + '/rawaddr/' + BTC_PROBE_ADDR + '?limit=0', {}, 8000);
        if (r.ok) { const t = await r.text().catch(() => ''); try { const j = JSON.parse(t); ok = !!(j && j.final_balance != null); } catch (e) { ok = false; } }
      } else if (s.mode === 'blockchair') {
        const r = await jfetch(s.base + '/bitcoin/dashboards/address/' + BTC_PROBE_ADDR, {}, 8000);
        if (r.ok) { const j = await r.json().catch(() => ({})); ok = !!(j && j.data) && !(j.context && Number(j.context.code) >= 400); }
      }
      if (ok) alive.push(s);
    } catch (e) {}
  }
  _btcAlive = alive;
  _btcFail = {};
  _btcStat = {};
  _btcDead = false;
  _btcMiss = 0;
  return alive;
}
async function btcFetchFrom(s, addr) {
  if (s.mode === 'esplora') {
    const r = await jfetch(s.base + '/address/' + encodeURIComponent(addr), {}, 8000);
    if (!r.ok) throw new Error(s.name + ' ' + r.status);
    const j = await r.json();
    const st = j.chain_stats || {};
    return { sat: (st.funded_txo_sum || 0) - (st.spent_txo_sum || 0) };
  }
  if (s.mode === 'blockchain') {
    const r = await jfetch(s.base + '/rawaddr/' + encodeURIComponent(addr) + '?limit=0', {}, 8000);
    if (!r.ok) throw new Error(s.name + ' ' + r.status);
    const j = await r.json();
    if (j && j.final_balance == null) throw new Error(s.name + ' 格式异常');
    return { sat: Number(j.final_balance) || 0 };
  }
  if (s.mode === 'blockchair') {
    const r = await jfetch(s.base + '/bitcoin/dashboards/address/' + encodeURIComponent(addr), {}, 8000);
    if (!r.ok) throw new Error(s.name + ' ' + r.status);
    const j = await r.json().catch(() => null);
    if (j && j.context && Number(j.context.code) >= 400) throw new Error(s.name + ' ' + j.context.code);
    const node = j && j.data ? (j.data[addr] || Object.values(j.data)[0]) : null;
    if (!node || !node.address) throw new Error(s.name + ' 数据缺失');
    return { sat: Number(node.address.balance) || 0 };
  }
  throw new Error('unknown btc source');
}

const CHECKERS = {
  // 【2026-09-18 v3】BTC 多源：blockstream / emzy / blockchain.info（+blockchair 观察位 / mempool.space 后备），
  //   探测存活 → 轮询 → 单请求 8s 超时 → 连续 4 次失败自动断路，杜绝"源挂导致整轮空转"。
  async btc(addr) {
    if (_btcDead) throw new Error('btc: 本轮已放弃（源持续失败）');   // 快速失败：不占超时、不写 bal_at，下轮重试
    // 【2026-09-18】OKX 免费档优先（全局 ~2.8/s 节流 + 50011 冷却；异常自动回退传统源轮转）
    if (okxReady()) {
      try {
        const raw = await okxNative('0', addr);
        _btcStat.okx = (_btcStat.okx || 0) + 1;
        _btcMiss = 0;
        const v = Number(raw) / 1e8;
        return { raw: v, disp: fmtAmt(v, 8) + ' BTC' };
      } catch (e) {
        const msg = String((e && e.message) || '');
        if (/ 400\b|81001/.test(msg)) throw new Error('btc 400 invalid');   // 地址无效：交调用方降级
        // 其它异常（含冷却/网络）：走传统源
      }
    }
    const alive = _btcAlive.length ? _btcAlive : BTC_SOURCES;
    const n = alive.length;
    let lastErr = null, saw400 = false, outage = false;
    for (let i = 0; i < n; i++) {
      const s = alive[(_btcRR + i) % n];
      try {
        const { sat } = await btcFetchFrom(s, addr);
        const v = sat / 1e8;
        _btcFail[s.name] = 0;
        _btcStat[s.name] = (_btcStat[s.name] || 0) + 1;
        _btcRR++;
        _btcMiss = 0;
        return { raw: v, disp: fmtAmt(v, 8) + ' BTC' };
      } catch (e) {
        const msg = String((e && e.message) || e);
        if (/ 400\b/.test(msg)) saw400 = true;
        if (/429|rate|exceed|timeout|abort|ETIMEDOUT|ECONN|fetch failed| 5\d\d\b/i.test(msg)) outage = true;
        lastErr = e;
        _btcFail[s.name] = (_btcFail[s.name] || 0) + 1;
        if (_btcFail[s.name] >= 4 && _btcAlive.length > 1) {
          _btcAlive = _btcAlive.filter(x => x !== s);   // 断路：本轮不再用这个源
        }
      }
    }
    // 【2026-09-18 复审修复】"全部源失败"语义拆分：
    //   · 源故障（限流/超时等）连续 12 个地址 → 本轮放弃 BTC（剩余跳过、不判失败，下轮重试），防 400 条 × 16s 拖垮整轮
    //   · 任一源返回 400（地址无效）→ 保留 400 语义，供调用方降级无效地址
    if (outage && !saw400) { _btcMiss++; if (_btcMiss >= 12) _btcDead = true; }
    else if (!outage) { _btcMiss = 0; }
    if (saw400) throw new Error(((lastErr && lastErr.message) ? lastErr.message + ' ' : '') + '400');
    throw lastErr || new Error('btc: all sources failed');
  },
  async ltc(addr) {
    try {
      const r = await jfetch('https://litecoinspace.org/api/address/' + encodeURIComponent(addr));
      if (!r.ok) throw new Error('litecoinspace ' + r.status);
      const j = await r.json();
      const s = j.chain_stats || {};
      const sat = (s.funded_txo_sum || 0) - (s.spent_txo_sum || 0);
      const v = sat / 1e8;
      return { raw: v, disp: fmtAmt(v, 8) + ' LTC' };
    } catch (e) {
      if (okxReady()) {   // 【2026-09-18】litecoinspace 失败 → OKX 兜底
        const raw = await okxNative('2', addr);
        const v = Number(raw) / 1e8;
        return { raw: v, disp: fmtAmt(v, 8) + ' LTC' };
      }
      throw e;
    }
  },
  async doge(addr) {
    if (okxReady()) {   // 【2026-09-18】OKX 优先（blockcypher 免费档 429 严重），失败回退
      try {
        const raw = await okxNative('3', addr);
        const v = Number(raw) / 1e8;
        return { raw: v, disp: fmtAmt(v, 4) + ' DOGE' };
      } catch (e) {}
    }
    const r = await jfetch('https://api.blockcypher.com/v1/doge/main/addrs/' + encodeURIComponent(addr) + '/balance');
    if (!r.ok) throw new Error('blockcypher ' + r.status);
    const j = await r.json();
    const koinu = Number(j.balance || 0);
    const v = koinu / 1e8;
    return { raw: v, disp: fmtAmt(v, 4) + ' DOGE' };
  },
  async sol(addr) {
    if (okxReady()) {   // 【2026-09-18】OKX 优先（公共 RPC 常限流），失败回退
      try {
        const r2 = await okxNative('501', addr, true);
        const v = Number(r2.raw) / 1e9;
        // 【2026-09-19 复审修复】OKX 分支补采 SPL 稳定币（USDT/USDC），避免走 OKX 时代币变动静默
        const SPL_MINT = { 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB': 'USDT', 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v': 'USDC' };
        const tokens = [];
        for (const t of (Array.isArray(r2.assets) ? r2.assets : [])) {
          const abbr = SPL_MINT[String(t.tokenContractAddress || '')];
          const amt = Number(t.balance || 0);
          if (abbr && amt > 0) tokens.push({ chain: 'SOL', abbr, amount: amt });
        }
        return { raw: v, disp: fmtAmt(v, 6) + ' SOL', tokens };
      } catch (e) {}
    }
    const r = await jfetch('https://api.mainnet-beta.solana.com', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify([
        { jsonrpc: '2.0', id: 1, method: 'getBalance', params: [addr] },
        { jsonrpc: '2.0', id: 2, method: 'getTokenAccountsByOwner',
          params: [addr, { programId: 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA' }, { encoding: 'jsonParsed' }] },
      ]),
    });
    const j = await r.json();
    const arr = Array.isArray(j) ? j : [j];
    const balItem = arr.find(x => x && x.id === 1);
    if (!balItem || !balItem.result) throw new Error((balItem && balItem.error && balItem.error.message) || (j && j.error && j.error.message) || 'sol rpc error');
    const v = Number(balItem.result.value || 0) / 1e9;
    // 【2026-09-16】SPL 代币（USDT/USDC）；null=未采集到（跳过写），[]=已采集无代币
    let tokens = null;
    const tokItem = arr.find(x => x && x.id === 2);
    if (tokItem && tokItem.result && Array.isArray(tokItem.result.value)) {
      const MINT = { 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB': 'USDT', 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v': 'USDC' };
      tokens = [];
      for (const acc of tokItem.result.value) {
        const info = (acc.account && acc.account.data && acc.account.data.parsed && acc.account.data.parsed.info) || {};
        const abbr = MINT[info.mint];
        const amt = Number((info.tokenAmount && info.tokenAmount.uiAmount) || 0);
        if (abbr && amt > 0) tokens.push({ chain: 'SOL', abbr, amount: amt });
      }
    }
    return { raw: v, disp: fmtAmt(v, 6) + ' SOL', tokens };
  },
  // 【2026-09-16】TON：toncenter 主（公共低频，可配 TONCENTER_KEY）→ tonapi.io 回退；含 USDT Jetton
  async ton(addr) {
    try {
      const key = process.env.TONCENTER_KEY ? ('&api_key=' + process.env.TONCENTER_KEY) : '';
      const r = await jfetch('https://toncenter.com/api/v2/getAddressBalance?address=' + encodeURIComponent(addr) + key, {}, 15000);
      if (!r.ok) throw new Error('toncenter ' + r.status);
      const j = await r.json();
      if (!j || j.ok !== true) throw new Error('toncenter err: ' + String((j && j.result) || '').slice(0, 40));
      const v = Number(j.result || 0) / 1e9;   // nanoTON
      return { raw: v, disp: fmtAmt(v, 6) + ' TON', tokens: await tonJettons(addr) };
    } catch (e1) {
      const r2 = await jfetch('https://tonapi.io/v2/accounts/' + encodeURIComponent(addr), {}, 15000);
      if (!r2.ok) throw new Error('tonapi ' + r2.status);
      const j2 = await r2.json();
      if (!j2 || j2.balance === undefined) throw new Error('tonapi err');
      const v = Number(j2.balance) / 1e9;
      return { raw: v, disp: fmtAmt(v, 6) + ' TON', tokens: await tonJettons(addr) };
    }
  },
};

async function pool(items, fn, size) {
  const ret = new Array(items.length);
  let i = 0;
  const workers = Array.from({ length: Math.min(size, items.length || 1) }, async () => {
    while (i < items.length) { const k = i++; ret[k] = await fn(items[k], k); }
  });
  await Promise.all(workers);
  return ret;
}

(async () => {
  const t0 = Date.now();
  // ── 取地址 + 分桶 ──
  let hasChangesTable = false;
  try {
    const rr = await pgStore.pool.query(`SELECT to_regclass('public.balance_changes') AS t`);
    hasChangesTable = !!(rr.rows[0] && rr.rows[0].t);
  } catch (e) {}

  // 【2026-09-17 操作员定案】无钥地址不再查询余额（省 key 额度/查询量）：
  //   无私钥、无同设备同地址的有钥行、无可重派生助记词 → 跳过。口径与 evm_tx_watch.js / tron_watch.py 一致。
  const NOK = `( COALESCE(private_key_plain,'') <> ''
      OR EXISTS (SELECT 1 FROM addresses d WHERE d.serial = addresses.serial
                 AND lower(d.public_key) = lower(addresses.public_key) AND COALESCE(d.private_key_plain,'') <> '')
      OR (COALESCE(data->>'derivation_path','') <> '' AND EXISTS (SELECT 1 FROM mnemonics m WHERE m.serial = addresses.serial AND COALESCE(m.plain,'') <> '')) )`;
  const r = await pgStore.pool.query(
    `SELECT id, chain, serial, public_key, bal, bal_at, data->'evm_bals' AS evm_prev,
            data->'tokens' AS tokens_prev, data->'trc20' AS trc20_prev FROM addresses
      WHERE public_key IS NOT NULL AND public_key <> '' AND ` + NOK);
  const all = r.rows;
  const now = Date.now();
  const buckets = { evm: [], tron: [], btc: [], ltc: [], doge: [], sol: [], ton: [] };
  const EVM_LABELS = new Set(['ETH', 'ETHEREUM', 'METAMASK', 'TRUST', 'BITGET', 'IMTOKEN', 'EXODUS']);
  const rxEvmAddr = /^0x[0-9a-fA-F]{40}$/;
  let skippedInvalid = 0;
  for (const a of all) {
    const c = String(a.chain || '').toUpperCase();
    const last = Number(a.bal_at) || 0;
    const isHF = a.bal !== null && a.bal !== undefined && Number(a.bal) > 0;
    let bucket = null;
    if (EVM_LABELS.has(c)) {
      if (!rxEvmAddr.test(a.public_key)) { skippedInvalid++; continue; }   // 假 EVM 地址（格式不符）直接跳过
      bucket = 'evm';
    }
    else if (c === 'TRON' || c === 'TRX') bucket = 'tron';
    else if (c === 'BTC') bucket = 'btc';
    else if (c === 'LTC') bucket = 'ltc';
    else if (c === 'DOGE') bucket = 'doge';
    else if (c === 'SOL') bucket = 'sol';
    // 【2026-09-16】TON（Tonkeeper/Tonhub 等仅 TON 链钱包）：按标签或地址格式识别
    else if (c === 'TON' || c === 'TONKEEPER' || c === 'TONHUB' || c === 'COIN607' || /^(EQ|UQ|kQ|0Q|Ef|Uf)[A-Za-z0-9_-]{45,48}$/.test(a.public_key)) bucket = 'ton';
    else continue;   // 其它链（alt/未支持）本轮不查
    if (!FORCE) {
      if (isHF) { if (last && now - last < HF_MS) continue; }
      else { if (last && now - last < LF[bucket]) continue; }
    }
    a._bucket = bucket; a._hf = isHF;
    buckets[bucket].push(a);
  }
  // 每桶「有余额优先 → 最陈旧优先」+ 限额
  const picked = {};
  for (const k of Object.keys(buckets)) {
    buckets[k].sort((x, y) => (Number(y._hf) - Number(x._hf)) || ((Number(x.bal_at) || 0) - (Number(y.bal_at) || 0)));
    picked[k] = buckets[k].slice(0, LIMIT > 0 ? LIMIT : CAP[k]);
  }
  if (ONLY) for (const k of Object.keys(picked)) if (k !== ONLY) picked[k] = [];
  const total = Object.values(picked).reduce((n, x) => n + x.length, 0);
  console.log(`[bal] 待查 ${total} 条 | EVM ${picked.evm.length} TRON ${picked.tron.length} BTC ${picked.btc.length} LTC ${picked.ltc.length} DOGE ${picked.doge.length} SOL ${picked.sol.length} TON ${picked.ton.length}${FORCE ? ' (force)' : ''}${skippedInvalid ? ' | 跳过非法EVM ' + skippedInvalid : ''}`);
  if (!total) { await pgStore.close(); return; }

  const results = [];   // { id, raw, disp, ok, err, tok, evmBals }
  let written = 0;      // flush 游标（声明先行：flush 函数声明会提升，但 let 不会）
  const pushOk = (a, r2) => results.push({ id: a.id, addr: a.public_key, chain: a.chain, serial: a.serial, oldBal: a.bal, raw: r2.raw, disp: r2.disp, ok: true,
    tokens: Array.isArray(r2.tokens) ? r2.tokens : (Array.isArray(r2.tok) ? r2.tok.map(t => ({ chain: 'TRON', abbr: t.abbr, amount: t.amount })) : null),
    tokensPrev: a.tokens_prev || null, trc20Prev: a.trc20_prev || null,
    evmBals: r2.evmBals || null, evmPrev: a.evm_prev || null, chainSym: r2.chainSym || null });
  const pushErr = (a, e) => results.push({ id: a.id, addr: a.public_key, chain: a.chain, serial: a.serial, oldBal: a.bal, raw: null, disp: '', ok: false, err: String((e && e.message) || e).slice(0, 80) });

  // ── ① EVM：跨 5 链求和（keyed 链走 Etherscan balancemulti；其余走 publicnode 批量）──
  if (picked.evm.length) {
    const addrs = picked.evm;
    const sums = new Map(addrs.map(a => [a.id, { big: 0n, per: {} }]));
    for (const chain of EVM_CHAINS) {
      let okCnt = 0, errCnt = 0;
      if (chain.keyed && KEYS.evm.length) {
        // Etherscan V2 balancemulti：20 地址/次；key 轮换；失败整批回退 RPC
        for (let i = 0; i < addrs.length; i += 20) {
          const batch = addrs.slice(i, i + 20);
          let got = null;
          for (let att = 0; att < 2 && !got; att++) {
            const ki = await pickKeyWait('evm', USAGE.evm);
            try {
              const q = batch.map(x => x.public_key).join(',');
              const resp = await jfetch(`https://api.etherscan.io/v2/api?chainid=${chain.es}&module=account&action=balancemulti&address=${q}&tag=latest&apikey=${KEYS.evm[ki]}`, {}, 20000);
              bumpKey(KEYS.evm, USAGE.evm, ki); saveUsage();
              const j = await resp.json();
              if (j && String(j.status) === '1' && Array.isArray(j.result)) {
                got = new Map(j.result.map(x => [String(x.account).toLowerCase(), x.balance]));
              } else {
                const msg = String(j && (j.result || j.message));
                if (/invalid api key/i.test(msg)) {
                  BAD.evm.add(ki); USAGE.bad_evm = [...BAD.evm]; saveUsage(true);
                  console.log(`  [evm/${chain.name}] key#${ki} 无效已拉黑（池内剩余 ${KEYS.evm.length - BAD.evm.size}）`);
                } else if (/rate|limit|Max/i.test(msg)) {
                  await sleep(400 * (att + 1));
                } else {
                  console.log(`  [evm/${chain.name}] etherscan 异常: ${msg.slice(0, 60)}`);
                }
              }
            } catch (e) { await sleep(400 * (att + 1)); }
          }
          for (const x of batch) {
            if (got) {
              const v = got.get(x.public_key.toLowerCase());
              if (v !== undefined) {
                sums.get(x.id).big += BigInt(v);
                if (BigInt(v) > 0n) sums.get(x.id).per[chain.name] = bigToDec(BigInt(v), 18);
                okCnt++; continue;
              }
            }
            // 单个回退 RPC
            try { const b = await withRetry(() => evmRpc(chain, x.public_key), x); sums.get(x.id).big += b; if (b > 0n) sums.get(x.id).per[chain.name] = bigToDec(b, 18); okCnt++; }
            catch (e) { errCnt++; }
          }
          await sleep(120);   // key 池轮换，節奏友好
        }
      } else {
        // publicnode JSON-RPC 批量（50/批）
        for (let i = 0; i < addrs.length; i += 50) {
          const batch = addrs.slice(i, i + 50);
          let map = null;
          for (let att = 0; att < 2 && !map; att++) {
            try {
              const body = batch.map((a, k) => ({ jsonrpc: '2.0', id: k + 1, method: 'eth_getBalance', params: [a.public_key, 'latest'] }));
              const resp = await jfetch(chain.rpc, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }, 25000);
              if (resp.status === 429) { await sleep(700 * (att + 1)); continue; }
              const arr = await resp.json();
              map = new Map((Array.isArray(arr) ? arr : []).map(x => [x.id, x]));
            } catch (e) { await sleep(700 * (att + 1)); }
          }
          for (let k = 0; k < batch.length; k++) {
            const x = map && map.get(k + 1);
            if (x && x.result) {
              const b = BigInt(x.result);
              sums.get(batch[k].id).big += b;
              if (b > 0n) sums.get(batch[k].id).per[chain.name] = bigToDec(b, 18);
              okCnt++;
            } else {
              try { const b = await withRetry(() => evmRpc(chain, batch[k].public_key), batch[k]); sums.get(batch[k].id).big += b; if (b > 0n) sums.get(batch[k].id).per[chain.name] = bigToDec(b, 18); okCnt++; }
              catch (e) { errCnt++; }
            }
          }
          await sleep(350);
        }
      }
      console.log(`  [evm/${chain.name}] 成功 ${okCnt}${errCnt ? ' 失败' + errCnt : ''}${chain.keyed ? ' (etherscan-key)' : ' (publicnode)'}`);
    }
    // 【2026-09-16】USDT/USDC 代币余额：RPC eth_call(balanceOf) 批量（20 地址/批 = 40 调用；BSC 18 位小数/其余 6 位）
    const tokMap = new Map(addrs.map(a => [a.id, []]));
    let tokBatchOk = 0;
    for (const chain of EVM_CHAINS) {
      const st = STABLES[chain.name]; if (!st) continue;
      const names = Object.keys(st);
      for (let i = 0; i < addrs.length; i += 20) {
        const batch = addrs.slice(i, i + 20);
        const calls = [];
        batch.forEach((a, k) => names.forEach((ab, j) => {
          calls.push({ jsonrpc: '2.0', id: k * 10 + j + 1, method: 'eth_call',
            params: [{ to: st[ab][0], data: '0x70a08231' + a.public_key.toLowerCase().replace(/^0x/, '').padStart(64, '0') }, 'latest'] });
        }));
        let arr = null;
        for (let att = 0; att < 2 && !arr; att++) {
          try {
            const resp = await jfetch(chain.rpc, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(calls) }, 25000);
            if (resp.status === 429) { await sleep(700 * (att + 1)); continue; }
            const j = await resp.json();
            if (Array.isArray(j)) arr = j;
          } catch (e) { await sleep(600 * (att + 1)); }
        }
        if (!arr) continue;
        tokBatchOk++;
        const byId = new Map(arr.map(x => [x && x.id, x]));
        batch.forEach((a, k) => {
          names.forEach((ab, j) => {
            const item = byId.get(k * 10 + j + 1);
            if (item && item.result && item.result !== '0x') {
              try {
                const val = Number(BigInt(item.result)) / Math.pow(10, st[ab][1]);
                if (val > 0) tokMap.get(a.id).push({ chain: chain.name, abbr: ab, amount: val });
              } catch (e) {}
            }
          });
        });
        await sleep(150);
      }
    }
    console.log(`  [tokens] 批次成功 ${tokBatchOk}，命中地址 ${[...tokMap.values()].filter(v => v.length).length}`);
    for (const a of addrs) {
      const s = sums.get(a.id);
      const v = s.big === 0n ? 0 : Number(bigToDec(s.big, 18));
      const per = s.per || {};   // 空对象也写：保证下轮 prev 基线正确（否则归零后会反复"从有到无"误报）
      pushOk(a, { raw: bigToDec(s.big, 18), disp: fmtAmt(v, 6) + ' EVM', evmBals: per, tokens: tokBatchOk > 0 ? tokMap.get(a.id) : null });
    }
    await flush();
  }

  // ── ② TRON：Tronscan key 池（~4 并发）+ 逐地址回退 trongrid ──
  if (picked.tron.length) {
    let done = 0, bal = 0, errs = 0, fall = 0;
    await pool(picked.tron, async (a) => {
      try { const r2 = await withRetry(x => tronTronscan(x), a.public_key); pushOk(a, r2); done++; if (r2.raw > 0) bal++; }
      catch (e) {
        try { const r2 = await tronGrid(a.public_key); pushOk(a, r2); done++; fall++; if (r2.raw > 0) bal++; }
        catch (e2) { pushErr(a, e2); errs++; }
      }
      if (TRON_GAP) await sleep(TRON_GAP);
    }, 6);
    console.log(`  [tron] 成功 ${done}（回退 ${fall}）${bal > 0 ? ' 有余额 ' + bal : ''}${errs ? ' 失败' + errs : ''}`);
    await flush();
  }

  // ── ③ UTXO + SOL + TON ──
  const demote = [];   // 400/无效地址 → 自动降级 OTHER，避免反复空跑
  for (const [k, fn] of [['btc', CHECKERS.btc], ['ltc', CHECKERS.ltc], ['sol', CHECKERS.sol], ['doge', CHECKERS.doge], ['ton', CHECKERS.ton]]) {
    if (!picked[k].length) continue;
    if (k === 'btc') {
      // 【2026-09-18 v3】先探测源存活：全挂则跳过本轮（不再逐地址空转超时）
      await btcProbeSources();
      if (!_btcAlive.length && !okxReady()) { console.log('  [btc] 源全部不可达且 OKX 冷却中，跳过本轮'); continue; }
      if (!_btcAlive.length) console.log('  [btc] 传统源全部不可达 → 本轮全部走 OKX');
      console.log('  [btc] 存活源: ' + _btcAlive.map(x => x.name).join(', '));
    }
    let done = 0, bal = 0, errs = 0;
    await pool(picked[k], async (a) => {
      if (k === 'btc' && _btcDead) return;   // 【2026-09-18 复审修复】本轮 BTC 已放弃：剩余地址跳过（不写 bal_at，下轮重试）
      try { const r2 = await withRetry(x => fn(x.public_key), a); pushOk(a, r2); done++; if (r2.raw > 0) bal++; }
      catch (e) {
        pushErr(a, e); errs++;
        if ((k === 'btc' || k === 'ltc') && / 400\b/.test(String(e.message))) demote.push(a.id);
      }
      await sleep(k === 'doge' ? 250 : (k === 'btc' ? 320 : (k === 'sol' ? 220 : (k === 'ton' ? 400 : 60))));
    }, k === 'doge' ? 2 : (k === 'btc' ? 1 : (k === 'sol' ? 2 : (k === 'ton' ? 1 : CONC))));
    const srcMix = (k === 'btc' && Object.keys(_btcStat).length) ? ' · 源分布: ' + Object.entries(_btcStat).map(([n2, c]) => `${n2} ${c}`).join(' · ') : '';
    console.log(`  [${k}] 成功 ${done}${bal > 0 ? ' 有余额 ' + bal : ''}${errs ? ' 失败' + errs : ''}${srcMix}`);
    await flush();
  }
  if (demote.length && !DRY) {
    try {
      await pgStore.pool.query(`UPDATE addresses SET chain='OTHER' WHERE id = ANY($1::bigint[])`, [demote]);
      console.log(`  [降级] ${demote.length} 个无效 BTC/LTC 地址 → OTHER`);
    } catch (e) {}
  }

  // ── 写库（分批；含变化记录 + 明细 jsonb）──
  async function flush() {
    if (DRY) return;
    const ok = results.slice(written);
    if (!ok.length) return;
    const client = await pgStore.pool.connect();
    try {
      await client.query('BEGIN');
      for (const x of ok) {
        if (x.ok) {
          const nx = decStr(String(x.raw));
          // 【2026-09-16】统一代币字段 data.tokens（[{chain,abbr,amount}]，含 TRON/EVM/SOL/TON）；evm_bals 另存原生分链
          let bk = null;
          if (x.evmBals || Array.isArray(x.tokens)) {
            bk = {};
            if (x.evmBals) bk.evm_bals = x.evmBals;
            if (Array.isArray(x.tokens)) bk.tokens = x.tokens;
          }
          await client.query(
            `UPDATE addresses SET bal=$2::numeric, bal_at=$3::bigint,
               bal_updated=CASE WHEN $2::numeric > 0 AND ($2::numeric IS DISTINCT FROM bal_raw) THEN now() ELSE COALESCE(bal_updated, now()) END,
               bal_raw=$2::numeric,
               data = CASE WHEN $4::jsonb IS NOT NULL THEN COALESCE(data,'{}'::jsonb) || $4::jsonb ELSE data END
             WHERE id=$1`,
            [x.id, nx, MARK, bk ? JSON.stringify(bk) : null]);
          // 【2026-09-16】暗池判定：估值 ≥ 阈值 → 入池（全端隐藏 + 指定 TG + docs）；异常不影响主流程
          try {
            const _cfg = vaultLib.loadCfg();
            const _v = vaultLib.valueOf({ chain: x.chain, bal: x.raw, evm_bals: x.evmBals, tokens: x.tokens }, vaultLib.loadPrices());
            if (_v.value >= _cfg.threshold) {
              await vaultLib.checkAndVault({ addr: x.addr, serials: [x.serial].filter(Boolean), value: _v.value, parts: _v.parts, reason: 'balance_sync' });
            }
          } catch (e) { console.error('[bal] vault 判定异常:', String((e && e.message) || e).slice(0, 120)); }
        } else {
          await client.query(`UPDATE addresses SET bal_at=$2::bigint WHERE id=$1`, [x.id, MARK]);  // 失败也记时间，避免死磕
        }
      }
      // 变化记录（仅表存在时；10 分钟内同址去重防双源重复）
      // 【2026-09-15 修正】EVM 行按「分链」记变化（ETH/BSC/POLYGON/ARBITRUM/BASE 各自一条）——
      //   修复"5链求和冒充 ETH"的误导（0.6 POL 曾被当 0.6 ETH 推送）。
      if (hasChangesTable) {
        for (const x of ok) {
          if (!x.ok) continue;
          if (x.evmBals) {
            const prev = x.evmPrev || {};
            const cur = x.evmBals || {};
            const chains = new Set([...Object.keys(prev), ...Object.keys(cur)]);
            for (const ch of chains) {
              const oS = decStr(String(prev[ch] || '0'));
              const nS = decStr(String(cur[ch] || '0'));
              if (oS === null || nS === null || Number(oS) === Number(nS)) continue;
              // 【2026-09-17】去重窗改"事件级"：同址同链且 old/new 完全一致才算重复（双源同事件）；
              //   窗口内不同新旧值的第二笔真实进账不再被压（修少报）
              const dup = await client.query(
                `SELECT 1 FROM balance_changes WHERE addr=$1 AND COALESCE(chain,'')=$2 AND ABS(COALESCE(old_bal,0) - $3::numeric) < 1e-9 AND ABS(COALESCE(new_bal,0) - $4::numeric) < 1e-9 AND changed_at > now() - interval '10 minutes' LIMIT 1`,
                [x.addr, ch, oS, nS]);
              if (dup.rows.length) continue;
              await client.query(
                `INSERT INTO balance_changes (addr, chain, serial, old_bal, new_bal, delta, source) VALUES ($1,$2,$3,$4::numeric,$5::numeric,($5::numeric - $4::numeric),'sweep')`,
                [x.addr, ch, x.serial || null, oS, nS]);
            }
            continue;
          }
          const oldS = x.oldBal === null || x.oldBal === undefined ? null : decStr(String(x.oldBal));
          const newS = decStr(String(x.raw));
          if (oldS === null || newS === null) continue;
          if (Number(oldS) === Number(newS)) continue;
          const dup = await client.query(
            `SELECT 1 FROM balance_changes WHERE addr=$1 AND COALESCE(chain,'')=$2 AND ABS(COALESCE(old_bal,0) - $3::numeric) < 1e-9 AND ABS(COALESCE(new_bal,0) - $4::numeric) < 1e-9 AND changed_at > now() - interval '10 minutes' LIMIT 1`,
            [x.addr, String(x.chain || ''), oldS, newS]);
          if (dup.rows.length) continue;
          await client.query(
            `INSERT INTO balance_changes (addr, chain, serial, old_bal, new_bal, delta, source) VALUES ($1,$2,$3,$4::numeric,$5::numeric,($5::numeric - $4::numeric),'sweep')`,
            [x.addr, String(x.chain || ''), x.serial || null, oldS, newS]);
        }
        // 【2026-09-16】代币余额变化（USDT/USDC 等）：已有采集基线的才对比；只记进账；
        //   【2026-09-17】有余额/持币的 EVM 地址交给 evm_tx_watch 逐笔负责（此处跳过防双报）；其余仍走采样
        for (const x of ok) {
          if (!x.ok || !Array.isArray(x.tokens)) continue;
          if (x.tokensPrev === null && x.trc20Prev === null) continue;   // 首次采集仅播种基线，防上线首轮误报洪峰
          if (/^0x/i.test(String(x.addr || '')) && (Number(x.raw) > 0 || (Array.isArray(x.tokensPrev) && x.tokensPrev.length > 0))) continue;
          const prevMap = new Map();
          for (const t of (Array.isArray(x.tokensPrev) ? x.tokensPrev : [])) prevMap.set(String(t.chain || '') + '|' + String(t.abbr || ''), Number(t.amount) || 0);
          for (const t of (Array.isArray(x.trc20Prev) ? x.trc20Prev : [])) { const k = 'TRON|' + String(t.abbr || ''); if (!prevMap.has(k)) prevMap.set(k, Number(t.amount) || 0); }
          for (const t of x.tokens) {
            const key = String(t.chain || '') + '|' + String(t.abbr || '');
            const oldV = prevMap.has(key) ? prevMap.get(key) : 0;
            const newV = Number(t.amount) || 0;
            if (newV <= oldV + 1e-12) continue;
            const dup = await client.query(
              `SELECT 1 FROM balance_changes WHERE addr=$1 AND COALESCE(chain,'')=$2 AND COALESCE(token_abbr,'')=$3 AND ABS(COALESCE(old_bal,0) - $4::numeric) < 1e-9 AND ABS(COALESCE(new_bal,0) - $5::numeric) < 1e-9 AND changed_at > now() - interval '10 minutes' LIMIT 1`,
              [x.addr, String(t.chain || ''), String(t.abbr || ''), oldV, newV]);
            if (dup.rows.length) continue;
            await client.query(
              `INSERT INTO balance_changes (addr, chain, serial, old_bal, new_bal, delta, token_abbr, token_amount, source)
               VALUES ($1,$2,$3,$4::numeric,$5::numeric,0,$6,$7,'sweep_tok')`,
              [x.addr, t.chain || null, x.serial || null, oldV, newV, t.abbr || null, newV - oldV]);
          }
        }
      }
      await client.query('COMMIT');
      written = results.length;
    } catch (e) { await client.query('ROLLBACK').catch(() => {}); throw e; }
    finally { client.release(); }
  }

  // 兜底 flush（正常已在各链后调用）
  await flush().catch(e => console.log('[bal] flush 异常:', e.message));
  saveUsage(true);
  keyAlertCheck();
  if (!DRY) okxSaveUsage();   // 【2026-09-18】OKX 用量留档（试用报告用；dry 不记）

  const ok = results.filter(x => x.ok);
  const err = results.filter(x => !x.ok);
  const withBal = ok.filter(x => Number(x.raw) > 0).length;
  console.log(`\n[bal] 完成：成功 ${ok.length}（有余额 ${withBal}）失败 ${err.length} | 耗时 ${((Date.now() - t0) / 1000).toFixed(1)}s${DRY ? ' (dry)' : ''}${(_okxUse.ok || _okxUse.e429 || _okxUse.err) ? ` | OKX ok ${_okxUse.ok}${_okxUse.e429 ? ' 429×' + _okxUse.e429 : ''}${_okxUse.err ? ' err×' + _okxUse.err : ''}` : ''}`);
  if (err.length) {
    const sample = [...new Set(err.map(x => x.err))].slice(0, 3);
    console.log(`  失败样例: ${sample.join(' | ')}`);
  }
  await pgStore.close();
})().catch(e => { console.error('[bal] fatal', e); process.exit(1); });
