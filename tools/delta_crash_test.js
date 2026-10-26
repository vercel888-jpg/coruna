#!/usr/bin/env node
/**
 * delta_crash_test.js —— 随机 kill -9 崩溃恢复测试 + 异常桶恢复一致性测试
 * 用法: node tools/delta_crash_test.js [K=24]     （K=随机崩溃次数，如 500）
 *
 * 覆盖（评审要求）：
 *   · 任意 crash point：SIGKILL 落在 扫描/解析/merge/JSONL 读取/persist(shard tmp→fsync→rename) 各阶段
 *   · 异常桶注入：NOOP 时 env LOOT_TEST_THROW_BUCKET 使指定桶在 put 分支后抛异常（partial state 场景）
 *   · 收敛判定：崩溃/异常后跑正常增量收敛，结果必须与"全新缓存全量重建"逐项 diff=0
 * 提速模式：子进程 nice + LOOT_SKIP_GLOBALS=1（跳过 t_index 94MB 全局注入；不影响夹具指标）
 */
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const LOOTSTORE = path.join(ROOT, 'adm888app', 'lootStore.js');
const ROOTDIR = `/tmp/crash_test_${Date.now()}`;
const LOOT = path.join(ROOTDIR, 'loot');
const BC = path.join(ROOTDIR, 'bc');
const BC_REF = path.join(ROOTDIR, 'bc_ref');
fs.mkdirSync(LOOT, { recursive: true });

const K = Math.max(1, parseInt(process.argv[2] || '24', 10) || 24);
const THROW_BUCKET = '9.9.9.7';

const NB = 36;
for (let i = 1; i <= NB; i++) {
  const d = path.join(LOOT, `9.9.9.${i}`);
  fs.mkdirSync(d);
  const sn = 'FIXCRASH' + String(i).padStart(3, '0');
  fs.writeFileSync(path.join(d, `report_event_100000000000${i}.dec.json`), JSON.stringify({ s: sn, m: 'iPhone12,1', et: 'system_status_check_completed', pv: '16.3' }));
  for (let k = 1; k <= 5; k++) fs.writeFileSync(path.join(d, `raw_avatar_put_10000000${String(i).padStart(2, '0')}${String(k).padStart(2, '0')}.json`), JSON.stringify({ et: 'all_is_well', pv: '16.3', device: 'iPhone12,1', b: 'apple' }));
  let jl = '';
  for (let k = 1; k <= 5; k++) jl += JSON.stringify({ ts: k, body: 'init-' + i + '-' + k }) + '\n';
  fs.writeFileSync(path.join(d, 'ext_logs.jsonl'), jl);
}

const SCAN_CODE = `
  const ls = require(${JSON.stringify(LOOTSTORE)});
  const s = ls.scan({ full: true });
  const fx = x => String(x || '').startsWith('FIXCRASH');
  const users = [...s.users.values()].filter(u => fx(u.serial_id)).map(u => [u.serial_id, u.machine, u.ios_version]).sort();
  const devs = [...s.devices.values()].filter(d => fx(d.serial_id)).map(d => [d.serial_id, d.hardware_model]).sort();
  const ev = {}, rep = {}, cl = {};
  for (const e of s.events) if (fx(e.serial)) ev[e.serial] = (ev[e.serial] || 0) + 1;
  for (const r of s.reports) if (fx(r.serial)) rep[r.serial] = (rep[r.serial] || 0) + 1;
  for (const c of s.chainLogs) if (String(c.ip || '').startsWith('9.9.9.')) cl[c.ip] = (cl[c.ip] || 0) + 1;
  console.log('__RESULT__' + JSON.stringify({ users, devs, ev, rep, cl }));
`;

function runScan(env2, killMs) {
  return new Promise(resolve => {
    const child = spawn('nice', ['-n', '10', process.execPath, '-e', SCAN_CODE], { env: Object.assign({ LOOT_SKIP_GLOBALS: '1' }, process.env, env2), cwd: ROOT });
    let out = '';
    child.stdout.on('data', d => out += d);
    let killed = false;
    const timer = (killMs != null) ? setTimeout(() => { killed = true; try { child.kill('SIGKILL'); } catch {} }, killMs) : null;
    child.on('exit', (code, signal) => {
      if (timer) clearTimeout(timer);
      const line = out.split('\n').find(l => l.startsWith('__RESULT__'));
      resolve({ code, signal, killed, metrics: line ? JSON.parse(line.slice('__RESULT__'.length)) : null });
    });
  });
}

const ENV_DELTA = { LOOT_DIR: LOOT, BC_DIR: BC, LOOT_SCAN_CACHE: '1', LOOT_DELTA: '1' };
const ENV_REF = { LOOT_DIR: LOOT, BC_DIR: BC_REF, LOOT_SCAN_CACHE: '1', LOOT_DELTA: '1' };

let seq = 0;
function mkNew() {
  const i = 1 + Math.floor(Math.random() * NB);
  const d = path.join(LOOT, `9.9.9.${i}`);
  const k = ++seq;
  fs.writeFileSync(path.join(d, `raw_avatar_put_17000000${String(i).padStart(2, '0')}${String(k).padStart(3, '0')}.json`), JSON.stringify({ et: 'all_is_well', pv: '16.3', device: 'iPhone12,1', b: 'apple' }));
  if (Math.random() < 0.4) {
    const half = Math.random() < 0.3;
    fs.appendFileSync(path.join(d, 'ext_logs.jsonl'), half ? '{"ts": 777, "bo' : JSON.stringify({ ts: 778, body: 'live-' + k }) + '\n');
  }
}
function shardsOkay() {
  try {
    for (const f of fs.readdirSync(BC)) {
      if (!f.startsWith('shard_') || !f.endsWith('.json')) continue;
      JSON.parse(fs.readFileSync(path.join(BC, f), 'utf8'));
    }
    return true;
  } catch (e) { return false; }
}

(async () => {
  let phaseFail = 0;
  console.log('1) 初始全量建账本…');
  const r0 = await runScan(ENV_DELTA, null);
  if (!r0.metrics) { console.error('初始扫描失败', r0); process.exit(1); }

  console.log(`2) 随机崩溃循环 x${K}（含约 15% 不击杀的正常完成轮）…`);
  let kills = 0, survived = 0, shardBad = 0;
  const t0 = Date.now();
  for (let t = 0; t < K; t++) {
    for (let m = 0; m < (2 + Math.floor(Math.random() * 4)); m++) mkNew();
    const killMs = (Math.random() < 0.15) ? null : (30 + Math.floor(Math.random() * 700));
    const r = await runScan(ENV_DELTA, killMs);
    if (r.killed) kills++; else survived++;
    if (!shardsOkay()) { shardBad++; console.log(`   [${t}] 分片损坏!`); }
    if (t % 50 === 49) console.log(`   …进度 ${t + 1}/${K}  kill=${kills}  用时 ${((Date.now() - t0) / 1000).toFixed(0)}s`);
  }
  console.log(`   完成：kill=${kills}  正常完成=${survived}  分片解析失败=${shardBad}  总用时 ${((Date.now() - t0) / 1000).toFixed(0)}s`);

  console.log('2.5) 异常桶注入（put 分支后抛异常 → partial state → 应被隔离且收敛）…');
  const rThrow = await runScan(Object.assign({}, ENV_DELTA, { LOOT_TEST_THROW_BUCKET: THROW_BUCKET }), null);
  if (!rThrow.metrics) { phaseFail++; console.log('   FAIL 异常桶拖垮了整轮'); }
  else console.log('   PASS 异常被隔离（整轮正常完成）');

  console.log('3) 收敛（连跑 3 轮增量）…');
  let last = null;
  for (let t = 0; t < 3; t++) { last = await runScan(ENV_DELTA, null); }
  const M_delta = last.metrics;

  console.log('4) 对照：全新缓存全量重建…');
  const rref = await runScan(ENV_REF, null);
  const M_ref = rref.metrics;

  console.log('5) 逐项比对：');
  const keys = ['users', 'devs', 'ev', 'rep', 'cl'];
  let fail = 0;
  for (const k of keys) {
    const a = JSON.stringify(M_delta[k]);
    const b = JSON.stringify(M_ref[k]);
    if (a === b) console.log(`   PASS ${k}`);
    else { fail++; console.log(`   FAIL ${k}\n     增量收敛: ${a.slice(0, 300)}\n     全量对照: ${b.slice(0, 300)}`); }
  }
  console.log(`\n结果: kill=${kills}/${K} · 分片损坏=${shardBad} · 异常桶=${phaseFail ? 'FAIL' : 'PASS'} · diff=${fail}  (夹具: ${ROOTDIR})`);
  process.exit(fail || shardBad || phaseFail ? 1 : 0);
})();
