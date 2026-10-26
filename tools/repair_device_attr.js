#!/usr/bin/env node
/**
 * repair_device_attr.js —— 全局修复"设备归属吸附"历史数据（2026-09-14）
 *
 * 背景：lootStore.pickSerial 旧实现读错机型字段（dd.device，实际在 dd.m）+ 兜底取桶内第一台
 *   设备 → 多设备共享出口 IP 的桶里，所有无序列号 payload（照片/备忘录/联系人/put 事件/上传）
 *   被吸附到第一台设备。修好的 lootStore 只管新数据；本脚本修历史：
 *
 *   身份源（唯一可信）：PG reports 表中 dec 带 s/d2 的单据（设备自报 序列号+机型+版本+ecid/udid）。
 *   映射： (ip,机型,版本)→serial / (ip,机型)→serial / ecid→serial / udid→serial（唯一命中才用）。
 *   迁移： photos / notebooks / contacts / events / reports / uploads 中，
 *          serial 空挂或与 payload 身份冲突、且能找到唯一目标 serial 的行：
 *          serial + data.serial 改写 + ukey 重算；ukey 撞已有正确行 → 删除本行（合并去重）。
 *   devices 主表：被污染机型/版本/出口 IP/最后活跃的串号按身份源纠偏。
 *
 * 用法：
 *   node tools/repair_device_attr.js            # dry-run：只统计 + 抽样（默认）
 *   node tools/repair_device_attr.js --apply    # 执行修复
 */
const fs = require('fs');
const path = require('path');
const BASE = path.resolve(__dirname, '..');
const pgStore = require(path.join(BASE, 'adm888app', 'pg', 'pgStore.js'));

const APPLY = process.argv.includes('--apply');
const DRY = !APPLY;
const LOGF = path.join(BASE, 'logs', 'repair_attr_' + new Date().toISOString().slice(0, 19).replace(/[:T]/g, '') + (DRY ? '.dryrun.log' : '.log'));
const log = (...a) => { const l = '[' + new Date().toISOString().slice(11, 19) + '] ' + a.join(' '); console.log(l); try { fs.appendFileSync(LOGF, l + '\n'); } catch {} };
const AUDIT = LOGF.replace(/\.log$/, '') + '.changes.jsonl';
const audit = o => { try { fs.appendFileSync(AUDIT, JSON.stringify(o) + '\n'); } catch {} };
const BATCH = 500;

const normEcid = v => String(v || '').replace(/[^0-9a-fA-F]/g, '').toUpperCase();
const normUdid = v => String(v || '').replace(/[^0-9a-fA-F]/g, '').toLowerCase();
function bump(m, k, v) { if (!k || !v) return; let mm = m.get(k); if (!mm) { mm = new Map(); m.set(k, mm); } mm.set(v, (mm.get(v) || 0) + 1); }
function unique(m) { const out = new Map(); for (const [k, mm] of m) { if (mm.size === 1) out.set(k, mm.keys().next().value); } return out; }

const TABLES = {
  photos: {
    candSql: `SELECT id, serial, coalesce(host(ip), data->>'ip') AS ip, data->'dec'->>'device' AS model, data->'dec'->>'pv' AS pv, NULL AS ecid, NULL AS udid
              FROM photos WHERE coalesce(data->'dec'->>'device','') <> '' ORDER BY id`,
    ukeyKey: 'photos',
  },
  notebooks: {
    candSql: `SELECT id, serial, coalesce(host(ip), data->>'ip') AS ip, data->'dec'->>'device' AS model, data->'dec'->>'pv' AS pv, NULL AS ecid, NULL AS udid
              FROM notebooks WHERE coalesce(data->'dec'->>'device','') <> '' ORDER BY id`,
    ukeyKey: 'notebooks',
  },
  contacts: {
    candSql: `SELECT id, serial, coalesce(host(ip), data->>'ip') AS ip, data->>'device' AS model, NULL AS pv, NULL AS ecid, NULL AS udid
              FROM contacts WHERE coalesce(data->>'device','') <> '' ORDER BY id`,
    ukeyKey: 'contacts',
  },
  events: {
    candSql: `SELECT id, serial, coalesce(host(ip), data->>'ip') AS ip, ctx->>'device' AS model, coalesce(ctx->>'pv', ctx->>'os') AS pv, NULL AS ecid, NULL AS udid
              FROM events WHERE coalesce(ctx->>'device','') <> '' ORDER BY id`,
    ukeyKey: 'events',
  },
  reports: {
    candSql: `SELECT id, serial, coalesce(host(ip), data->>'ip') AS ip, data->'dec'->>'device' AS model, data->'dec'->>'pv' AS pv, NULL AS ecid, NULL AS udid
              FROM reports
              WHERE coalesce(data->'dec'->>'device','') <> ''
                AND coalesce(data->'dec'->>'s','') = '' AND coalesce(data->'dec'->>'d2','') = ''
              ORDER BY id`,
    ukeyKey: 'reports',
  },
  uploads: {
    candSql: `SELECT id, serial, coalesce(host(ip), data->>'ip') AS ip, NULL AS model, NULL AS pv,
                     coalesce(nullif(data->>'ecid',''), data->>'d') AS ecid, coalesce(nullif(data->>'udid',''), data->>'u') AS udid
              FROM uploads
              WHERE coalesce(data->>'ecid', data->>'d','') <> '' OR coalesce(data->>'udid', data->>'u','') <> ''
              ORDER BY id`,
    ukeyKey: 'uploads',
  },
};

(async () => {
  log(`启动 repair_device_attr mode=${DRY ? 'DRY-RUN' : 'APPLY'} log=${LOGF}`);
  const pool = pgStore.pool;

  // ── 1) 身份源：reports 带 s/d2 的真实单据 ──
  const t0 = Date.now();
  const rs = await pool.query(`
    SELECT host(ip) AS ip,
           coalesce(nullif(data->'dec'->>'s',''), nullif(data->'dec'->>'d2','')) AS sn,
           coalesce(nullif(data->'dec'->>'m','apple'), nullif(data->'dec'->'deviceInfo'->>'productType',''), nullif(data->'dec'->>'device','')) AS model,
           coalesce(nullif(data->'dec'->>'pv',''), nullif(data->'dec'->'deviceInfo'->>'productVersion','')) AS pv,
           coalesce(data->'dec'->>'d', data->'dec'->>'f') AS ecid,
           data->'dec'->>'u' AS udid
    FROM reports
    WHERE (coalesce(data->'dec'->>'s','') <> '' OR coalesce(data->'dec'->>'d2','') <> '')`);
  const ipmp = new Map(), ipm = new Map(), ecidRaw = new Map(), udidRaw = new Map();
  const canon = new Map(), canonPv = new Map();
  for (const r of rs.rows) {
    const sn = String(r.sn || '').trim(); if (!sn) continue;
    const model = String(r.model || '').trim();
    const pv = String(r.pv || '').trim();
    const ip = String(r.ip || '').trim();
    if (model) {
      bump(canon, sn, model);
      if (ip && pv) bump(ipmp, ip + '|' + model + '|' + pv, sn);
      if (ip) bump(ipm, ip + '|' + model, sn);
    }
    if (pv) bump(canonPv, sn, pv);
    if (r.ecid) bump(ecidRaw, normEcid(r.ecid), sn);
    if (r.udid) bump(udidRaw, normUdid(r.udid), sn);
  }
  const IPMP = unique(ipmp), IPM = unique(ipm), ECID = unique(ecidRaw), UDID = unique(udidRaw);
  const CANON = new Map();
  for (const [sn, mm] of canon) { let best = '', bc = 0; for (const [m, c] of mm) if (c > bc) { bc = c; best = m; } CANON.set(sn, { model: best, models: new Set(mm.keys()) }); }
  const CANONPV = new Map();
  for (const [sn, mm] of canonPv) { let best = '', bc = 0; for (const [p, c] of mm) if (c > bc) { bc = c; best = p; } CANONPV.set(sn, best); }
  log(`身份源: reports 单据=${rs.rows.length} → ipmp=${IPMP.size} ipm=${IPM.size} ecid=${ECID.size} udid=${UDID.size} 串号=${CANON.size} (${((Date.now() - t0) / 1000).toFixed(1)}s)`);

  const target = (ip, model, pv, ecid, udid) => {
    if (ip && model && pv) { const t = IPMP.get(ip + '|' + model + '|' + pv); if (t) return t; }
    if (ip && model) { const t = IPM.get(ip + '|' + model); if (t) return t; }
    if (ecid) { const t = ECID.get(normEcid(ecid)); if (t) return t; }
    if (udid) { const t = UDID.get(normUdid(udid)); if (t) return t; }
    return '';
  };
  // 空挂 → 直接归位；非空 → 需 CANON 证明与 payload 冲突才迁移（不做无证据迁移）
  const needFix = (serial, model, tgt) => {
    if (!tgt || tgt === serial) return false;
    if (!serial) return true;
    const c = CANON.get(serial);
    if (!c) return false;
    if (model && c.models.has(model)) return false;
    return true;
  };

  // ── 批次落实：拉 data → ukey 重算 → 更新（dry-run 只计数）──
  const affectedSerials = new Set();
  const flushBatch = async (table, def, rows) => {
    if (!rows.length) return { fixed: 0, merged: 0 };
    for (const r of rows) { affectedSerials.add(r.tgt); if (r.serial) affectedSerials.add(r.serial); }
    if (DRY) return { fixed: rows.length, merged: 0 };
    let fixed = 0, merged = 0;
    const ids = rows.map(r => r.id);
    const dataRows = (await pool.query(`SELECT id, data FROM ${table} WHERE id = ANY($1)`, [ids])).rows;
    const byId = new Map(dataRows.map(r => [String(r.id), r.data]));
    for (const r of rows) {
      const rec = byId.get(String(r.id));
      if (!rec || typeof rec !== 'object') continue;
      const rec2 = Object.assign({}, rec, { serial: r.tgt });
      const uk = pgStore.ukeyOf(def.ukeyKey, table, rec2);
      try {
        await pool.query(`UPDATE ${table} SET serial=$1, data = jsonb_set(data, '{serial}', to_jsonb($1::text), true), ukey=$2 WHERE id=$3`,
          [r.tgt, uk, r.id]);
        audit({ t: table, id: r.id, from: r.serial, to: r.tgt, uk, act: 'u' });
        fixed++;
      } catch (e) {
        if (e && e.code === '23505') { await pool.query(`DELETE FROM ${table} WHERE id=$1`, [r.id]); audit({ t: table, id: r.id, from: r.serial, to: r.tgt, act: 'merge-del' }); merged++; }
        else log(`行修复失败 ${table}#${r.id}: ${e.message}`);
      }
    }
    return { fixed, merged };
  };

  // ── 2) 逐表扫描 + 迁移 ──
  const summary = {};
  for (const [table, def] of Object.entries(TABLES)) {
    const t1 = Date.now();
    log(`表 ${table}: 扫描中…`);
    const rows = (await pool.query(def.candSql)).rows;
    let cand = 0, fixed = 0, merged = 0, samples = 0;
    let pending = [];
    for (const row of rows) {
      const model = (row.model || '').trim();
      const tgt = target((row.ip || '').trim(), model, (row.pv || '').trim(), row.ecid, row.udid);
      if (!needFix(row.serial || '', model, tgt)) continue;
      cand++;
      if (samples < 8) { samples++; log(`  [cand] ${table}#${row.id}: ${row.serial || '(空)'} → ${tgt}  (ip=${row.ip || '?'} model=${model || '?'} pv=${row.pv || '?'}${row.ecid ? ' ecid=' + row.ecid : ''})`); }
      pending.push({ id: row.id, serial: row.serial || '', tgt });
      if (pending.length >= BATCH) { const r = await flushBatch(table, def, pending); fixed += r.fixed; merged += r.merged; pending = []; }
    }
    const r2 = await flushBatch(table, def, pending);
    fixed += r2.fixed; merged += r2.merged;
    summary[table] = { scanned: rows.length, cand, fixed, merged, ms: Date.now() - t1 };
    log(`表 ${table}: 扫描=${rows.length} 候选=${cand} 已修=${fixed} 合并删除=${merged} ${(Date.now() - t1) / 1000}s ${DRY ? '(dry-run)' : ''}`);
  }

  // ── 3) devices 主表元数据纠偏 ──
  let devFixed = 0;
  for (const sn of affectedSerials) {
    const c = CANON.get(sn); if (!c) continue;
    const pvBest = CANONPV.get(sn) || '';
    const drow = (await pool.query('SELECT serial, machine, ios_version, host(ip) AS ip, last_seen FROM devices WHERE serial=$1', [sn])).rows[0];
    if (!drow) continue;
    const lastR = (await pool.query(
      `SELECT host(ip) AS ip, max(ts) AS max_ts FROM reports
       WHERE serial=$1 AND (coalesce(data->'dec'->>'s','')<>'' OR coalesce(data->'dec'->>'d2','')<>'')
       GROUP BY host(ip) ORDER BY max_ts DESC LIMIT 1`, [sn])).rows[0];
    const lastTs = (await pool.query(
      `SELECT GREATEST(
         COALESCE((SELECT max(ts) FROM events   WHERE serial=$1), 0),
         COALESCE((SELECT max(ts) FROM reports  WHERE serial=$1), 0),
         COALESCE((SELECT max(ts) FROM uploads  WHERE serial=$1), 0),
         COALESCE((SELECT max(ts) FROM photos   WHERE serial=$1), 0),
         COALESCE((SELECT max(ts) FROM notebooks WHERE serial=$1), 0)) AS m`, [sn])).rows[0];
    const newMachine = c.model && drow.machine !== c.model ? c.model : null;
    const newIos = pvBest && drow.ios_version !== pvBest ? pvBest : null;
    const newIp = lastR && lastR.ip && lastR.ip !== drow.ip ? lastR.ip : null;
    const newLast = lastTs && Number(lastTs.m) > 0 && Number(lastTs.m) > Number(drow.last_seen || 0) ? Number(lastTs.m) : null;
    if (!newMachine && !newIos && !newIp && !newLast) continue;
    devFixed++;
    log(`devices 纠偏 ${sn}: machine ${drow.machine} → ${newMachine || '(keep)'} | ios ${drow.ios_version} → ${newIos || '(keep)'} | ip ${drow.ip} → ${newIp || '(keep)'} | last_seen → ${newLast ? new Date(newLast).toISOString() : '(keep)'}`);
    if (!DRY) {
      await pool.query(`UPDATE devices SET
          machine = COALESCE($2, machine), ios_version = COALESCE($3, ios_version),
          ip = COALESCE($4::inet, ip), last_seen = COALESCE($5, last_seen), updated_at = now()
        WHERE serial=$1`, [sn, newMachine, newIos, newIp, newLast]);
    }
  }
  summary._devices = { fixed: devFixed };
  log(`devices 元数据纠偏: ${devFixed} 台 ${DRY ? '(dry-run)' : ''}`);

  log('=== 汇总 ===\n' + JSON.stringify(summary, null, 2));
  await pgStore.close();
  log('完成。');
})().catch(e => { console.error('[repair] fatal', e); process.exit(1); });
