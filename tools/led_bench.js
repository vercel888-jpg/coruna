#!/usr/bin/env node
/** led_bench.js —— 量化 led（账本）实际成本：分片加载总时/字节、Top10 桶的 stringify/newSet/遍历耗时（只读生产 scan_cache） */
const fs = require('fs');
const path = require('path');
const BC = process.env.BC_DIR || path.join(__dirname, '..', 'adm888app', 'data', 'scan_cache');

const tAll0 = Date.now();
const files = fs.readdirSync(BC).filter(f => f.startsWith('shard_') && f.endsWith('.json'));
let totalBuckets = 0, withLed = 0, totalLed = 0, rawBytes = 0;
const top = [];
for (const f of files) {
  const p = path.join(BC, f);
  const raw = fs.readFileSync(p, 'utf8');
  rawBytes += Buffer.byteLength(raw);
  const o = JSON.parse(raw);
  for (const [b, e] of Object.entries(o)) {
    totalBuckets++;
    const n = (e && Array.isArray(e.led)) ? e.led.length : 0;
    if (n) { withLed++; totalLed += n; top.push([b, n, f]); }
  }
}
const loadMs = Date.now() - tAll0;
top.sort((a, b) => b[1] - a[1]);
console.log('== led 基准（生产缓存，只读） ==');
console.log('分片: %d 个 / %.1f MB / 加载+解析总耗时 %.0f ms', files.length, rawBytes / 1048576, loadMs);
console.log('桶总数 %d | 含 led 桶 %d | led 文件名总量 %d', totalBuckets, withLed, totalLed);

console.log('\n== Top10 最大账本桶 ==');
for (const [b, n, f] of top.slice(0, 10)) {
  const o = JSON.parse(fs.readFileSync(path.join(BC, f), 'utf8'));
  const e = o[b];
  const s0 = Date.now(); const str = JSON.stringify(e.led); const sMs = Date.now() - s0;
  const st0 = Date.now(); const set = new Set(e.led); const setMs = Date.now() - st0;
  const it0 = Date.now(); let c = 0; for (const x of e.led) c++; const itMs = Date.now() - it0;
  console.log('%s | led=%d 个 | JSON≈%.1f MB | stringify %dms | newSet %dms | 遍历 %dms', b, n, str.length / 1048576, sMs, setMs, itMs);
}
console.log('\n总用时 %.0f ms | RSS %.0f MB', Date.now() - tAll0, process.memoryUsage().rss / 1048576);
