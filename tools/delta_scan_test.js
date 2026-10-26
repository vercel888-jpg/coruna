#!/usr/bin/env node
/**
 * delta_scan_test.js —— 增量引擎（文件级账本）夹具测试（全部隔离在 /tmp，不碰生产）
 *
 * 覆盖：
 *  R1 全量基线（DELTA=0）：扫描建账本（led/meta/sig），断言用户/设备/事件/报告/链日志
 *  R2 无变化轮（DELTA=1）：全命中恢复，数据与 R1 一致
 *  R3 增量轮（DELTA=1）：只加 1 个心跳 + jsonl 追加 1 行 → 计数只 +1（不重复解析旧文件）
 *  R4 对照组（DELTA=0）同一状态全量重扫 → 与 R3 结果一致（增量/全量语义一致性）
 *  R5 关键回归：扫描后新增文件 → 缓存签名必须"不等于"当前目录（证明签名是扫描时盖章，尾巴不再被吞）
 */
const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const LOOTSTORE = path.join(ROOT, 'adm888app', 'lootStore.js');
const ROOTDIR = `/tmp/delta_test_${Date.now()}`;
const LOOT = path.join(ROOTDIR, 'loot');
const BC = path.join(ROOTDIR, 'bc');
fs.mkdirSync(LOOT, { recursive: true });
fs.mkdirSync(BC, { recursive: true });

const A = path.join(LOOT, '9.9.9.1');
const B = path.join(LOOT, '9.9.9.2');
fs.mkdirSync(A); fs.mkdirSync(B);

let pass = 0, fail = 0;
function eq(a, b, msg) {
  const sa = JSON.stringify(a), sb = JSON.stringify(b);
  if (sa === sb) { pass++; console.log('  PASS', msg); }
  else { fail++; console.log('  FAIL', msg, '\n    got:', sa, '\n    exp:', sb); }
}
function sigOf(dir) { const st = fs.statSync(dir); return fs.readdirSync(dir).length + '|' + Math.floor(st.mtimeMs); }
function mkHeartbeat(dir, ts, device) {
  fs.writeFileSync(path.join(dir, `raw_avatar_put_${ts}.json`), JSON.stringify({ et: 'all_is_well', pv: '16.3', device, b: 'apple' }));
}
function mkReport(dir, ts, sn, machine) {
  fs.writeFileSync(path.join(dir, `report_event_${ts}.dec.json`), JSON.stringify({ s: sn, m: machine, et: 'system_status_check_completed', pv: '16.3' }));
  fs.writeFileSync(path.join(dir, `report_event_${ts}.binom`), 'x');   // 注：非匹配模式的伴随文件，只为贴近真实目录形态
}

function runRound(delta, forceAll) {
  const env = Object.assign({}, process.env, {
    LOOT_DIR: LOOT, BC_DIR: BC, LOOT_SCAN_CACHE: '1', LOOT_DELTA: delta ? '1' : '0',
  });
  const code = `
    const ls = require(${JSON.stringify(LOOTSTORE)});
    const s = ls.scan({ full: true, forceAll: ${forceAll ? 'true' : 'false'} });
    const fx = x => String(x || '').startsWith('FIXTURE');
    const users = [...s.users.values()].filter(u => fx(u.serial_id)).map(u => [u.serial_id, u.machine, u.ios_version]).sort();
    const devs = [...s.devices.values()].filter(d => fx(d.serial_id)).map(d => [d.serial_id, d.hardware_model]).sort();
    const ev = {}, rep = {}, cl = {};
    for (const e of s.events) if (fx(e.serial)) ev[e.serial] = (ev[e.serial] || 0) + 1;
    for (const r of s.reports) if (fx(r.serial)) rep[r.serial] = (rep[r.serial] || 0) + 1;
    for (const c of s.chainLogs) if (String(c.ip || '').startsWith('9.9.9.')) cl[c.ip] = (cl[c.ip] || 0) + 1;
    console.log('__RESULT__' + JSON.stringify({ users, devs, ev, rep, cl }));
  `;
  const r = spawnSync(process.execPath, ['-e', code], { env, encoding: 'utf8', timeout: 180000, cwd: ROOT });
  if (r.status !== 0) { console.error('ROUND FAILED status=', r.status, '\n', (r.stderr || '').slice(0, 1200)); process.exit(1); }
  const line = (r.stdout || '').split('\n').find(l => l.startsWith('__RESULT__'));
  if (!line) { console.error('NO RESULT LINE\n', (r.stdout || '').slice(-800)); process.exit(1); }
  return JSON.parse(line.slice('__RESULT__'.length));
}

function readCache(bucket) {
  for (const f of fs.readdirSync(BC)) {
    if (!f.startsWith('shard_') || !f.endsWith('.json')) continue;
    try {
      const d = JSON.parse(fs.readFileSync(path.join(BC, f), 'utf8'));
      if (d[bucket]) return d[bucket];
    } catch {}
  }
  return null;
}

// ── 固定夹具 ──
mkReport(A, 1000000000001, 'FIXTUREAAA1', 'iPhone12,1');
mkHeartbeat(A, 1000000000001, 'iPhone12,1');
mkHeartbeat(A, 1000000000002, 'iPhone12,1');
fs.writeFileSync(path.join(A, 'ext_logs.jsonl'), JSON.stringify({ ts: 1, body: 'line-1' }) + '\n');
mkReport(B, 1000000000001, 'FIXTUREBBB2', 'iPhone13,2');
mkHeartbeat(B, 1000000000001, 'iPhone13,2');

console.log('== R1 全量基线（DELTA=0） ==');
const R1 = runRound(false);
eq(R1.users, [['FIXTUREAAA1', 'iPhone12,1', '16.3'], ['FIXTUREBBB2', 'iPhone13,2', '16.3']], 'R1 users 机型正确');
eq(R1.devs, [['FIXTUREAAA1', 'iPhone12,1'], ['FIXTUREBBB2', 'iPhone13,2']], 'R1 devices 机型正确');
eq(R1.ev, { FIXTUREAAA1: 3, FIXTUREBBB2: 2 }, 'R1 事件数（心跳2+报告1 / 心跳1+报告1）');
eq(R1.rep, { FIXTUREAAA1: 3, FIXTUREBBB2: 2 }, 'R1 报告数');
eq(R1.cl, { '9.9.9.1': 1 }, 'R1 链日志（jsonl 1 行）');

const cA1 = readCache('9.9.9.1');
eq(!!(cA1 && Array.isArray(cA1.led) && cA1.led.length), true, 'R1 缓存写入 led');
eq(cA1.led.length, fs.readdirSync(A).length, 'R1 led 覆盖全部文件');
eq(cA1.led.includes('raw_avatar_put_1000000000001.json'), true, 'R1 led 含心跳文件');
eq(cA1.meta && cA1.meta.serial, 'FIXTUREAAA1', 'R1 meta.serial');
eq(cA1.meta && cA1.meta.jsonlOffset, fs.statSync(path.join(A, 'ext_logs.jsonl')).size, 'R1 meta.jsonlOffset（=完整行尾=size）');
eq(cA1.sig, sigOf(A), 'R1 缓存签名=扫描时目录状态');

console.log('== R2 无变化轮（DELTA=1，应全命中恢复） ==');
const R2 = runRound(true);
eq(R2.users, R1.users, 'R2 users 一致');
eq(R2.ev, R1.ev, 'R2 事件数与 R1 一致（恢复路径）');
eq(R2.rep, R1.rep, 'R2 报告数一致');
eq(R2.cl, R1.cl, 'R2 链日志一致');

console.log('== R3 增量轮（DELTA=1：+1 心跳 + jsonl 追加 1 行） ==');
mkHeartbeat(A, 1000000000003, 'iPhone12,1');
// 关键回归前置断言：新增文件后，缓存签名必须与当前目录不同（签名=扫描时盖章，尾巴不被吞）
const cA1b = readCache('9.9.9.1');
eq(cA1b.sig !== sigOf(A), true, 'R3-pre 新增文件后缓存签名≠当前目录（尾巴修复核心）');
fs.appendFileSync(path.join(A, 'ext_logs.jsonl'), JSON.stringify({ ts: 2, body: 'line-2' }) + '\n');
const R3 = runRound(true);
eq(R3.users, R1.users, 'R3 users 不重复、不丢失');
eq(R3.ev, { FIXTUREAAA1: 4, FIXTUREBBB2: 2 }, 'R3 增量：A 事件 +1（旧文件不重复解析）');
eq(R3.rep, { FIXTUREAAA1: 4, FIXTUREBBB2: 2 }, 'R3 增量：A 报告 +1');
eq(R3.cl, { '9.9.9.1': 2 }, 'R3 增量：jsonl 追加 1 行 → 链日志 +1（字节级增量）');
const cA3 = readCache('9.9.9.1');
eq(cA3.led.includes('raw_avatar_put_1000000000003.json'), true, 'R3 led 收录新文件');
eq(cA3.meta.jsonlOffset, fs.statSync(path.join(A, 'ext_logs.jsonl')).size, 'R3 meta.jsonlOffset 更新');

console.log('== R4 对照组（DELTA=0 强制全量重扫同一状态）——增量/全量一致性 ==');
const R4 = runRound(false, true);
eq(R4.users, R3.users, 'R4 users 与 R3 一致');
eq(R4.ev, R3.ev, 'R4 事件数与 R3 一致');
eq(R4.rep, R3.rep, 'R4 报告数与 R3 一致');
eq(R4.cl, R3.cl, 'R4 链日志与 R3 一致');

console.log('== R5 无变化再跑一轮（DELTA=1 命中路径回归） ==');
const R5 = runRound(true);
eq(R5.ev, R4.ev, 'R5 事件数稳定');
eq(R5.cl, R4.cl, 'R5 链日志稳定');

console.log('== R6 jsonl 跨轮半行安全（评审必修项：半行不得被吃掉） ==');
fs.appendFileSync(path.join(A, 'ext_logs.jsonl'), '{"ts": 99, "bo');           // 半行（无换行）
const R6a = runRound(true);
eq(R6a.cl, R5.cl, 'R6a 半行不消费（链日志不变）');
const cA6 = readCache('9.9.9.1');
eq(cA6.meta.jsonlOffset, cA3.meta.jsonlOffset, 'R6a 游标停在半行之前（不推进）');
fs.appendFileSync(path.join(A, 'ext_logs.jsonl'), 'dy":"half-line"}\n');       // 补全该行
const R6b = runRound(true);
eq(R6b.cl['9.9.9.1'], (R5.cl['9.9.9.1'] || 0) + 1, 'R6b 补全后恰好消费一次');
const cA6b = readCache('9.9.9.1');
eq(cA6b.meta.jsonlOffset, fs.statSync(path.join(A, 'ext_logs.jsonl')).size, 'R6b 游标到位');

console.log('== R7 jsonl 大增量（>1MB）分块续传：不得跳读、不得丢中段 ==');
{
  const pad = 'x'.repeat(240);
  let big = '';
  for (let i = 0; i < 4200; i++) big += JSON.stringify({ ts: 1000 + i, body: 'blk-' + i + '-' + pad }) + '\n';
  fs.appendFileSync(path.join(A, 'ext_logs.jsonl'), big);
  const sz = fs.statSync(path.join(A, 'ext_logs.jsonl')).size;
  const off0 = cA6b.meta.jsonlOffset || 0;
  const R7a = runRound(true);
  const off1 = (readCache('9.9.9.1').meta || {}).jsonlOffset || 0;
  eq((off1 > off0) && (off1 - off0 <= 1048576 + 4096), true, 'R7a 单轮消费 ≤1MB（分块，有进度）');
  eq(off1 < sz, true, 'R7a 有余量待续（不跳跃、不丢中段）');
  const R7b = runRound(true);
  const off2 = (readCache('9.9.9.1').meta || {}).jsonlOffset || 0;
  eq(off2, sz, 'R7b 续传后游标到文件尾（完整消费）');
}

console.log(`\n结果: PASS=${pass} FAIL=${fail}  (夹具目录: ${ROOTDIR})`);
process.exit(fail ? 1 : 0);
