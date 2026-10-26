#!/usr/bin/env node
/**
 * pg_panel_test.js —— 影子对比：authStore.filterByAgent（旧·快照） vs panelPg.deviceList（新·PG）
 * 对每个 active 用户比对：可见设备总数（pi.total）与集合包含关系。
 * 大代理超过 s=5000 上限时只校验"PG ⊆ 旧"（截断非语义差异）。
 */
process.env.LOOT_SCAN_CACHE = process.env.LOOT_SCAN_CACHE || '1';
process.env.LOOT_DELTA = process.env.LOOT_DELTA || '1';
const path = require('path');
const BASE = path.resolve(__dirname, '..');
const ls = require(path.join(BASE, 'adm888app', 'lootStore.js'));
const auth = require(path.join(BASE, 'adm888app', 'authStore.js'));
const panelPg = require(path.join(BASE, 'adm888app', 'pg', 'panelPg.js'));
const pgStore = require(path.join(BASE, 'adm888app', 'pg', 'pgStore.js'));

(async () => {
  auth.init();   // 加载 auth.json / ip_agents 等（filterByAgent 依赖）
  const store = ls.scan();
  const authJson = require(path.join(BASE, 'adm888app', 'data', 'auth.json'));
  const users = (authJson.users || []).filter(u => u.status !== 'deleted');
  const devs = [...store.devices.values()];
  console.log(`快照设备 ${devs.length} 台；active 用户 ${users.length} 个\n`);
  let pass = 0, diff = 0;
  for (const u of users) {
    const oldSet = new Set(auth.filterByAgent(u.id, devs, 'serial_id').map(d => d.serial_id));
    let pgRes;
    try {
      pgRes = await panelPg.deviceList({ id: u.id, role: u.role }, { s: 5000 });
    } catch (e) { console.log(`  FAIL u=${u.id}(${u.username}): ${e.message}`); diff++; continue; }
    const pgSet = new Set(pgRes.dis.map(d => d.serial_id));
    const onlyPg = [...pgSet].filter(s => !oldSet.has(s));
    const trunc = pgRes.pi.total > pgSet.size;
    const onlyOld = trunc ? [] : [...oldSet].filter(s => !pgSet.has(s));
    const totalOk = pgRes.pi.total === oldSet.size;
    const ok = totalOk && !onlyPg.length && !onlyOld.length;
    if (ok) pass++; else diff++;
    console.log(`  ${ok ? 'PASS' : 'DIFF'} u=${u.id}(${u.username},${u.role}) old=${oldSet.size} pg.total=${pgRes.pi.total} pg.page=${pgSet.size}` +
      (trunc ? ' [截断]' : '') +
      (onlyOld.length ? ` 仅旧=${onlyOld.slice(0, 5).join(',')}${onlyOld.length > 5 ? `…+${onlyOld.length - 5}` : ''}` : '') +
      (onlyPg.length ? ` 仅PG=${onlyPg.slice(0, 5).join(',')}${onlyPg.length > 5 ? `…+${onlyPg.length - 5}` : ''}` : ''));
  }
  console.log(`\n结果: PASS=${pass} DIFF=${diff}`);
  await pgStore.close();
  process.exit(diff === 0 ? 0 : 1);   // init() 的 setInterval 会挂住进程，强制退出
})().catch(e => { console.error('fatal', e); process.exit(1); });
