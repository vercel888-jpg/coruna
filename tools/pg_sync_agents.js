#!/usr/bin/env node
/**
 * pg_sync_agents.js —— 代理权限数据同步进 PG（P4 面板读层的数据基础）
 *  1) auth.json users → agents 表（id/username/parent_id/permissions/raw/role/status）
 *  2) auth.json device_agents → agent_device（serial → agent_id）
 *  3) data/ip_agents.json → agent_ip_map（ip → agent_id，6.9 万行）
 *  4) devices.owner_agent_id 物化（直接归属；IP 兜底查询在面板侧用 agent_ip_map 完成）
 * 全量镜像（DELETE+批量 INSERT，事务内）——表小、重复运行幂等。
 * 用法: node tools/pg_sync_agents.js
 */
const fs = require('fs');
const path = require('path');
const BASE = path.resolve(__dirname, '..');
const pgStore = require(path.join(BASE, 'adm888app', 'pg', 'pgStore.js'));

const AUTH = path.join(BASE, 'adm888app', 'data', 'auth.json');
const IPAG = path.join(BASE, 'adm888app', 'data', 'ip_agents.json');
const IPRE = /^[0-9a-fA-F:.]{3,45}$/;

async function batchInsert(client, table, cols, rows, chunk) {
  let ins = 0, bad = 0;
  for (let i = 0; i < rows.length; i += chunk) {
    const part = rows.slice(i, i + chunk);
    try {
      const params = []; const tuples = [];
      for (const r of part) {
        const ph = [];
        for (const v of r) { params.push(v); ph.push('$' + params.length); }
        tuples.push('(' + ph.join(',') + ')');
      }
      const sql = `INSERT INTO ${table} (${cols.join(',')}) VALUES ${tuples.join(',')} ON CONFLICT DO NOTHING`;
      const res = await client.query(sql, params);
      ins += res.rowCount;
    } catch (e) {
      // 批次失败（多为非法值行）→ 逐条重试，跳过坏行
      for (const r of part) {
        try {
          const ph = r.map((_, j) => '$' + (j + 1));
          await client.query(`INSERT INTO ${table} (${cols.join(',')}) VALUES (${ph.join(',')}) ON CONFLICT DO NOTHING`, r);
          ins++;
        } catch { bad++; }
      }
    }
  }
  return { ins, bad };
}

(async () => {
  const auth = JSON.parse(fs.readFileSync(AUTH, 'utf8'));
  const users = auth.users || [];
  const da = auth.device_agents || {};
  const ipAg = JSON.parse(fs.readFileSync(IPAG, 'utf8'));

  const client = await pgStore.pool.connect();
  try {
    await client.query('BEGIN');

    // ① users → agents
    for (const u of users) {
      if (u.id == null) continue;
      await client.query(
        `INSERT INTO agents (id, username, parent_id, permissions, raw, role, status)
         VALUES ($1,$2,$3,$4,$5,$6,$7)
         ON CONFLICT (id) DO UPDATE SET username=EXCLUDED.username, parent_id=EXCLUDED.parent_id,
           permissions=EXCLUDED.permissions, raw=EXCLUDED.raw, role=EXCLUDED.role, status=EXCLUDED.status, updated_at=now()`,
        [u.id, u.username || '', u.parent_id == null ? null : u.parent_id,
         JSON.stringify(u.permissions || []), JSON.stringify(u), u.role || '', u.status || 'active']);
    }

    // ② device_agents → agent_device（全量镜像）
    await client.query('DELETE FROM agent_device');
    const dRows = [];
    for (const [serial, uid] of Object.entries(da)) {
      if (serial && uid != null) dRows.push([serial, Number(uid)]);
    }
    const dr = await batchInsert(client, 'agent_device', ['serial', 'agent_id'], dRows, 1000);

    // ③ ip_agents → agent_ip_map（全量镜像；非法 IP 预过滤）
    await client.query('DELETE FROM agent_ip_map');
    const iRows = [];
    for (const [ip, uid] of Object.entries(ipAg)) {
      if (ip && uid != null && IPRE.test(ip)) iRows.push([ip, Number(uid)]);
    }
    const ir = await batchInsert(client, 'agent_ip_map', ['ip', 'agent_id'], iRows, 1000);

    // ④ devices.owner_agent_id 物化
    const m1 = await client.query(
      `UPDATE devices d SET owner_agent_id = ad.agent_id
       FROM agent_device ad WHERE d.serial = ad.serial AND d.owner_agent_id IS DISTINCT FROM ad.agent_id`);
    const m2 = await client.query(
      `UPDATE devices d SET owner_agent_id = NULL
       WHERE d.owner_agent_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM agent_device ad WHERE ad.serial = d.serial)`);

    // ⑤ 【2026-09-26 治本】清掉已删代理的 TG 绑定（删除代理后不再残留通知绑定；含孤儿行）
    const tb = await client.query(
      `DELETE FROM tg_bindings WHERE agent_id NOT IN
       (SELECT id FROM agents WHERE COALESCE(status, '') <> 'deleted')`);

    await client.query('COMMIT');
    console.log(`[agents] users=${users.length} → agents 表 ✓`);
    console.log(`[agents] device_agents=${dRows.length} → ins=${dr.ins} bad=${dr.bad}`);
    console.log(`[agents] ip_agents=${iRows.length} → ins=${ir.ins} bad=${ir.bad}`);
    console.log(`[agents] owner_agent_id 物化: 更新=${m1.rowCount} 清零=${m2.rowCount}`);
    console.log(`[agents] tg_bindings 清理已删代理绑定: 删除=${tb.rowCount}`);
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
  await pgStore.close();
})().catch(e => { console.error('[agents] fatal', e); process.exit(1); });
