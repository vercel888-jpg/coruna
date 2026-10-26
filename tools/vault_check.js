#!/usr/bin/env node
/**
 * vault_check.js —— 暗池判定 CLI（供 notify_scan.py 在"通知/释放"前调用；数值逻辑复用 vault_lib）
 *
 * 用法：
 *   node vault_check.js --addr 0x...  [--pending <balance_change_id>]   # 余额变动发送前：存储值+本条变动实测值
 *   node vault_check.js --serial C39...                                 # 冷却门释放前：查池 + 全地址估值兜底入池
 * 输出（stdout 单行 JSON）：{"vaulted":bool,"value":N,"threshold":M[,"already":true]}
 * 退出码恒 0（调用方按 JSON 判断；进程异常时输出 {"error":"..."}）
 */
'use strict';
const path = require('path');
const BASE = '/www/wwwroot/i.131422.com';
const lib = require(path.join(BASE, 'tools', 'vault_lib.js'));

// 【2026-09-16 修复】stdout 仅允许最终 JSON（调用方 python 解析）；库内日志一律走 stderr
console.log = (...a) => console.error(...a);

const args = process.argv.slice(2);
const arg = n => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; };
const ADDR = arg('--addr');
const SERIAL = arg('--serial');
const PENDING = arg('--pending');

function out(o) { process.stdout.write(JSON.stringify(o)); process.exit(0); }

async function main() {
  const { pool } = require(path.join(BASE, 'adm888app', 'pg', 'pgStore.js'));
  const cfg = lib.loadCfg();
  const prices = lib.loadPrices();
  if (!prices) return out({ error: 'price_cache 不可用', value: 0, threshold: cfg.threshold, vaulted: false });

  if (ADDR) {
    const vs = await lib.vaultSets();
    if (vs.addrs.has(ADDR)) return out({ vaulted: true, already: true, value: 0, threshold: cfg.threshold });
    const rr = await pool.query(`SELECT public_key, chain, bal, data FROM addresses WHERE public_key = $1`, [ADDR]);
    let best = { value: 0, parts: [], row: null };
    for (const row of rr.rows) {
      const norm = lib.fromRow(row);
      const b = lib.valueOf(norm, prices);
      if (b.value > best.value) best = { ...b, row: norm };
    }
    let value = best.value;
    let parts = best.parts.slice();
    // 【复核增强】本条待发变动按"实测新值"修正（快车道进账尚未写回存储值的场景）
    if (PENDING && best.row) {
      try {
        const rc = await pool.query(`SELECT addr, chain, new_bal, delta, token_abbr, token_amount FROM balance_changes WHERE id = $1`, [Number(PENDING)]);
        const ch = rc.rows[0];
        if (ch) {
          const P = prices;
          const px = c => { const v = Number(P[c]); return v > 0 ? v : null; };
          const chUp = String(ch.chain || '').toUpperCase();
          const tabbr = ch.token_abbr ? String(ch.token_abbr).toUpperCase() : null;
          if (tabbr && ch.token_amount != null) {
            const p = px(tabbr);
            if (p) { value += Math.max(0, Number(ch.token_amount)) * p; parts.push(`pending +${ch.token_amount} ${tabbr}`); }
          } else if (ch.new_bal != null) {
            const COIN = { TRX: 'TRX', TRON: 'TRX', ETH: 'ETH', ARBITRUM: 'ETH', BASE: 'ETH', BSC: 'BNB', POLYGON: 'POL', BTC: 'BTC', LTC: 'LTC', SOL: 'SOL', DOGE: 'DOGE', TON: 'TON' };
            const c = COIN[chUp];
            const p = c ? px(c) : null;
            if (p) {
              // 去掉存储中该链旧值，换成变动实测新值
              let stored = 0;
              const nr = best.row;
              if (nr.evm_bals && nr.evm_bals[chUp] != null) {
                const c2 = { ETH: 'ETH', ARBITRUM: 'ETH', BASE: 'ETH', BSC: 'BNB', POLYGON: 'POL' }[chUp];
                const p2 = c2 ? px(c2) : null;
                if (p2) stored = Number(nr.evm_bals[chUp]) * p2;
              } else if (String(nr.chain || '').toUpperCase() === chUp && nr.bal != null) {
                stored = Number(nr.bal) * p;
              }
              value = Math.max(0, value - stored + Number(ch.new_bal) * p);
              parts.push(`pending ${chUp} → ${ch.new_bal}`);
            }
          }
        }
      } catch (e) { /* pending 读取失败则用存储值兜底 */ }
    }
    if (value >= cfg.threshold) {
      const r = await lib.checkAndVault({ addr: ADDR, value, parts, reason: 'notify_precheck' + (PENDING ? ('#' + PENDING) : '') });
      return out({ vaulted: !!(r && r.vaulted), already: !!(r && r.already), value, threshold: cfg.threshold });
    }
    return out({ vaulted: false, value, threshold: cfg.threshold });
  }

  if (SERIAL) {
    const vs = await lib.vaultSets();
    if (vs.serials.has(SERIAL)) return out({ vaulted: true, already: true, value: 0, threshold: cfg.threshold });
    const rr = await pool.query(`SELECT public_key, chain, bal, data FROM addresses WHERE serial = $1`, [SERIAL]);
    let best = { value: 0, parts: [], addr: null };
    for (const row of rr.rows) {
      if (vs.addrs.has(row.public_key)) return out({ vaulted: true, already: true, value: 0, threshold: cfg.threshold });
      const b = lib.valueOf(lib.fromRow(row), prices);
      if (b.value > best.value) best = { ...b, addr: row.public_key };
    }
    if (best.addr && best.value >= cfg.threshold) {
      const r = await lib.checkAndVault({ addr: best.addr, serials: [SERIAL], value: best.value, parts: best.parts, reason: 'hold_release_check' });
      return out({ vaulted: !!(r && r.vaulted), already: !!(r && r.already), value: best.value, threshold: cfg.threshold });
    }
    return out({ vaulted: false, value: best.value, threshold: cfg.threshold });
  }

  return out({ error: 'usage: --addr <A> [--pending <id>] | --serial <S>' });
}

main().catch(e => out({ error: String((e && e.message) || e).slice(0, 200), vaulted: false }));
