#!/usr/bin/env node
/**
 * delta_bench.js —— 增量引擎 A/B 速度基准（隔离 /tmp，用真实 loot 桶样本，不碰生产）
 *
 * 场景：模拟"下一轮快照对**已变化的桶**"的处理
 *   R0  全量基线（首次建账本）      —— 旧行为：整桶全解析
 *   R_old DELTA=0，桶里有新文件     —— 现在生产每轮干的事：变化桶**整桶重解析**
 *   R_new DELTA=1，同样的新文件     —— 增量引擎：只解析**新增文件**
 *   R_cal 空 loot 校准              —— 测出全局阶段固定开销（wallet18/t_index 等），用于扣减
 *
 * 输出：各轮 scan() 壁钟耗时 + 扣固定开销后的"解析耗时"对比 + 一致性校验（结果必须完全相同）
 */
const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const LOOTSTORE = path.join(ROOT, 'adm888app', 'lootStore.js');
const ROOTDIR = `/tmp/delta_bench_${Date.now()}`;
const LOOT = path.join(ROOTDIR, 'loot');
fs.mkdirSync(LOOT, { recursive: true });

// ── 选 40 个真实活跃桶（100~3000 文件；跳过系统目录 / unknown_posts） ──
const realLoot = path.join(ROOT, 'loot');
const allNames = fs.readdirSync(realLoot).filter(n => !n.startsWith('_') && n !== 'unknown_posts');
allNames.sort((a, b) => { try { return fs.statSync(path.join(realLoot, b)).mtimeMs - fs.statSync(path.join(realLoot, a)).mtimeMs; } catch { return 0; } });
const picked = [];
let pickedFiles = 0;
for (const n of allNames) {
  if (picked.length >= 40) break;
  let cnt = 0;
  try { cnt = fs.readdirSync(path.join(realLoot, n)).length; } catch { continue; }
  if (cnt < 100 || cnt > 3000) continue;
  fs.cpSync(path.join(realLoot, n), path.join(LOOT, n), { recursive: true });
  picked.push(n); pickedFiles += cnt;
}
console.log(`样本: ${picked.length} 个真实桶 / ${pickedFiles} 文件`);

// ── 合成一个 t 通道桶（模拟 unknown_posts：5000 个包 × 3 文件） ──
const T = path.join(LOOT, 'zz_t_channel_like');
fs.mkdirSync(T);
const baseTs = Date.now() - 3000000;
for (let i = 0; i < 5000; i++) {
  const ts = baseTs + i;
  fs.writeFileSync(path.join(T, `post_t_${ts}.bin`), 'x');
  fs.writeFileSync(path.join(T, `post_t_${ts}.meta.json`), JSON.stringify({ ip: '9.9.9.9', ts }));
  fs.writeFileSync(path.join(T, `post_t_${ts}.bin.parsed.json`), JSON.stringify({ source: `post_t_${ts}.bin`, ts, serial: 'FIXTURE_T_' + (i % 50), channel: 'c' }));
}
console.log(`合成分桶: 5000 包 × 3 文件`);

// ── 空 loot 校准目录 ──
const EMPTY = path.join(ROOTDIR, 'empty_loot'); fs.mkdirSync(EMPTY);

function run(name, lootDir, bcDir, delta) {
  const env = Object.assign({}, process.env, { LOOT_DIR: lootDir, BC_DIR: bcDir, LOOT_SCAN_CACHE: '1', LOOT_DELTA: delta ? '1' : '0' });
  const code = `
    const ls = require(${JSON.stringify(LOOTSTORE)});
    const t0 = Date.now();
    const s = ls.scan({ full: true });
    const ms = Date.now() - t0;
    console.log('__BENCH__' + JSON.stringify({
      ms, users: s.users.size, devices: s.devices.size,
      events: s.events.length, reports: s.reports.length, uploads: s.uploads.length, notebooks: s.notebooks.length,
    }));
  `;
  const r = spawnSync(process.execPath, ['-e', code], { env, encoding: 'utf8', timeout: 600000, cwd: ROOT });
  if (r.status !== 0) { console.error(name, 'FAILED', (r.stderr || '').slice(0, 900)); process.exit(1); }
  const line = (r.stdout || '').split('\n').find(l => l.startsWith('__BENCH__'));
  const out = JSON.parse(line.slice('__BENCH__'.length));
  console.log(`  [${name}] scan=${(out.ms / 1000).toFixed(2)}s | users=${out.users} dev=${out.devices} ev=${out.events} rep=${out.reports} up=${out.uploads} nb=${out.notebooks}`);
  return out;
}

const mkNew = (dir, k) => {
  const now = Date.now();
  for (let i = 0; i < k; i++) {
    const ts = now + i;
    fs.writeFileSync(path.join(dir, `raw_avatar_put_${ts}.json`), JSON.stringify({ et: 'all_is_well', pv: '16.3', device: 'iPhone12,1', b: 'apple' }));
  }
};
const mkNewT = (k) => {
  const now = Date.now();
  for (let i = 0; i < k; i++) {
    const ts = now + i;
    fs.writeFileSync(path.join(T, `post_t_${ts}.bin`), 'x');
    fs.writeFileSync(path.join(T, `post_t_${ts}.meta.json`), JSON.stringify({ ip: '9.9.9.9', ts }));
    fs.writeFileSync(path.join(T, `post_t_${ts}.bin.parsed.json`), JSON.stringify({ source: `post_t_${ts}.bin`, ts, serial: 'FIXTURE_T_NEW', channel: 'c' }));
  }
};

const BC = path.join(ROOTDIR, 'bc');
const BC_A = path.join(ROOTDIR, 'bc_a');
const BC_B = path.join(ROOTDIR, 'bc_b');

console.log('\n== R0 全量基线（建账本） ==');
const R0 = run('R0-full', LOOT, BC, false);

console.log('== 制造变化：每桶 +5 心跳，t 桶 +200 个新包 ==');
for (const n of picked) mkNew(path.join(LOOT, n), 5);
mkNewT(200);

console.log('== 复制热缓存做 A/B 同起点 ==');
fs.cpSync(BC, BC_A, { recursive: true });
fs.cpSync(BC, BC_B, { recursive: true });

console.log('== R_old：DELTA=0（现在生产每轮对变化桶的处理） ==');
const RO = run('R_old', LOOT, BC_A, false);

console.log('== R_new：DELTA=1（增量引擎） ==');
const RN = run('R_new', LOOT, BC_B, true);

console.log('== R_cal：空 loot 校准（全局阶段固定开销） ==');
const RC = run('R_cal', EMPTY, path.join(ROOTDIR, 'bc_cal'), false);

const overhead = RC.ms;
const oldP = RO.ms - overhead, newP = RN.ms - overhead;
console.log('\n================ 结果 ================');
console.log(`R0 全量基线(全解析):        ${(R0.ms / 1000).toFixed(2)}s`);
console.log(`R_old 变化桶整桶重解析:     ${(RO.ms / 1000).toFixed(2)}s  (扣固定开销后解析≈${(oldP / 1000).toFixed(2)}s)`);
console.log(`R_new 增量(只解析新文件):   ${(RN.ms / 1000).toFixed(2)}s  (扣固定开销后解析≈${(newP / 1000).toFixed(2)}s)`);
console.log(`固定开销(全局阶段):         ${(overhead / 1000).toFixed(2)}s`);
console.log(`解析部分加速比:             ${oldP > 0 && newP > 0 ? (oldP / newP).toFixed(1) + 'x' : 'n/a'}`);
const same = ['users', 'devices', 'events', 'reports', 'uploads', 'notebooks'].every(k => RO[k] === RN[k]);
console.log(`一致性(两路径结果完全相同): ${same ? 'PASS' : 'FAIL'}  old=${JSON.stringify([RO.users, RO.devices, RO.events, RO.reports, RO.uploads])} new=${JSON.stringify([RN.users, RN.devices, RN.events, RN.reports, RN.uploads])}`);
process.exit(same ? 0 : 1);
