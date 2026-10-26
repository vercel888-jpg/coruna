#!/usr/bin/env node
/**
 * pg_fill_ipgeo.js —— IP 归属地批量回填（ip-api /batch：100 IP/请求，15 请求/分 → 约 1500 IP/分）
 *   来源：devices.ip ∪ device_ip_map.ip 去重；只查 ip_geo 表中还没有的。
 *   一次性冷启动用；日常新 IP 由面板自身（串行限速）随手入库。
 * 用法: node tools/pg_fill_ipgeo.js [--limit N] [--dry]
 */
const path = require('path');
const BASE = path.resolve(__dirname, '..');
const pgStore = require(path.join(BASE, 'adm888app', 'pg', 'pgStore.js'));
const http = require('http');

const args = process.argv.slice(2);
const LIMIT = (() => { const i = args.indexOf('--limit'); return i >= 0 ? Number(args[i + 1]) : 0; })();
const DRY = args.includes('--dry');

function batchLookup(ips) {
  return new Promise((resolve) => {
    const body = JSON.stringify(ips);
    const req = http.request({
      host: 'ip-api.com',
      path: '/batch?lang=zh-CN&fields=status,country,regionName,city,isp,query',
      method: 'POST',
      timeout: 8000,
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    }, (resp) => {
      let d = '';
      resp.on('data', c => d += c);
      resp.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve(null); } });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.write(body);
    req.end();
  });
}

(async () => {
  await pgStore.pool.query('CREATE TABLE IF NOT EXISTS ip_geo (ip text PRIMARY KEY, geo text, updated_at timestamptz DEFAULT now())');
  const have = new Set((await pgStore.pool.query('SELECT ip FROM ip_geo')).rows.map(x => x.ip));
  const rows1 = (await pgStore.pool.query('SELECT host(ip) AS ip FROM devices WHERE ip IS NOT NULL')).rows.map(x => x.ip);
  const rows2 = (await pgStore.pool.query('SELECT host(ip) AS ip FROM device_ip_map')).rows.map(x => x.ip);
  const need = [...new Set([...rows1, ...rows2])].filter(ip => ip && !have.has(ip));
  const targets = LIMIT > 0 ? need.slice(0, LIMIT) : need;
  console.log(`[ipgeo] 已有 ${have.size} | 待查 ${targets.length}（缺口合计 ${need.length}）`);
  if (DRY) { console.log(targets.slice(0, 10).join('\n')); await pgStore.close(); return; }

  let ok = 0, fail = 0, done = 0;
  for (let i = 0; i < targets.length; i += 100) {
    const chunk = targets.slice(i, i + 100);
    const t0 = Date.now();
    let res = await batchLookup(chunk);
    if (!Array.isArray(res)) {   // 瞬时失败（限速/网络）→ 等 5s 重试一次
      await new Promise(r2 => setTimeout(r2, 5000));
      res = await batchLookup(chunk);
    }
    if (Array.isArray(res)) {
      const client = await pgStore.pool.connect();
      try {
        await client.query('BEGIN');
        for (const r of res) {
          if (r && r.status === 'success' && r.query) {
            const geo = (r.country + ' ' + (r.regionName || '') + ' ' + (r.city || '')).trim();
            await client.query('INSERT INTO ip_geo (ip, geo) VALUES ($1,$2) ON CONFLICT (ip) DO UPDATE SET geo = EXCLUDED.geo, updated_at = now()', [r.query, geo]);
            ok++;
          } else fail++;
        }
        await client.query('COMMIT');
      } catch (e) {
        await client.query('ROLLBACK').catch(() => {});
        console.error('[ipgeo] 批写入失败:', e.message);
        fail += chunk.length;
      } finally { client.release(); }
    } else {
      fail += chunk.length;
      console.error('[ipgeo] 批查询失败（限速/网络）:', chunk.length, '个');
    }
    done += chunk.length;
    console.log(`[ipgeo] ${done}/${targets.length} ok=${ok} fail=${fail}`);
    const wait = 4300 - (Date.now() - t0);   // 15 请求/分 → 4.3s/批
    if (wait > 0) await new Promise(r2 => setTimeout(r2, wait));
  }
  console.log(`[ipgeo] 完成：入库 ${ok}，失败 ${fail}`);
  await pgStore.close();
})().catch(e => { console.error('[ipgeo] fatal', e); process.exit(1); });
