#!/usr/bin/env node
/**
 * ingestd.js —— 入库服务 v1（P2 影子模式：只写 PG，面板不动）
 * 用法：
 *   node adm888app/pg/ingestd.js --bucket 9.9.9.1     # 手动处理单个桶（测试/补账）
 *   node adm888app/pg/ingestd.js --full  9.9.9.1      # 忽略已有账本，强制全量重解析该桶
 *   node adm888app/pg/ingestd.js                      # 常驻：tail spool → 处理脏桶
 * spool（写入侧提示）：adm888app/data/pg_spool.jsonl，每行一个桶名或 {"bucket":"..."}
 *
 * 架构（v1·完全独立）：
 *   · 自有账本 data/ingest_state/<桶>.json = {v, sig, led, meta}（每桶一个小文件，原子写）
 *   · 不加载/不读/不写快照构建进程的 scan_cache 分片缓存（ingestd 内存零占用、与构建零竞争）
 *   · processBucket(bcIngestCtx)：无基线增量——只解析 led 之外的新增文件，不做整桶恢复
 *   · 快路径：sig+jsonl 均无变化 → 直接跳过（一次 stat，零解析）
 *   · 幂等：PG ukey 内容哈希 ON CONFLICT DO NOTHING（重放/补账/双写安全）
 */
const fs = require('fs');
const path = require('path');
process.env.LOOT_SCAN_CACHE = '1';   // 依赖 bcBeginBucket/bcEndBucket/bcRunInfo（newRanges）；不调 bcShardInit
const BASE = path.resolve(__dirname, '..', '..');
process.env.LOOT_DIR = process.env.LOOT_DIR || path.join(BASE, 'loot');
const ls = require(path.join(BASE, 'adm888app', 'lootStore.js'));
const pgStore = require('./pgStore');

const LOOT_DIR = process.env.LOOT_DIR;
const STATE_DIR = process.env.INGEST_STATE_DIR || path.join(BASE, 'adm888app', 'data', 'ingest_state');
const SPOOL = process.env.PG_SPOOL || path.join(BASE, 'adm888app', 'data', 'pg_spool.jsonl');
const log = (...a) => console.log('[' + new Date().toISOString().slice(11, 19) + '][ingestd]', ...a);

const _state = new Map();   // 桶名 → {sig, led, meta}（内存镜像，懒加载）
function loadState(bucket) {
  if (_state.has(bucket)) return _state.get(bucket);
  let st = null;
  try { st = JSON.parse(fs.readFileSync(path.join(STATE_DIR, bucket + '.json'), 'utf8')); } catch { st = null; }
  _state.set(bucket, st);
  return st;
}
function saveState(bucket, st) {
  _state.set(bucket, st);
  try {
    fs.mkdirSync(STATE_DIR, { recursive: true });
    const f = path.join(STATE_DIR, bucket + '.json');
    const tmp = f + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(st));
    fs.renameSync(tmp, f);
  } catch (e) { log('state 写入失败', bucket, e.message); }
}
// 快路径：目录签名与 jsonl 均无变化 → 无新数据可入账
function quickSkip(bucket, st) {
  if (!st || !st.sig) return false;
  try {
    if (ls.bcBucketSig(path.join(LOOT_DIR, bucket)) !== st.sig) return false;
  } catch { return false; }
  if (st.meta) {
    try {
      const jst = fs.statSync(path.join(LOOT_DIR, bucket, 'ext_logs.jsonl'));
      const joff = (st.meta.jsonlOffset != null) ? st.meta.jsonlOffset : (st.meta.jsonlSize || 0);
      if (jst.size !== joff) return false;
    } catch { /* 无 jsonl：正常 */ }
  }
  return true;
}

/** 处理单个桶：账本比对 → processBucket（无基线增量）→ takeBucketNew → PG upsert → 落账本 */
async function processOne(bucket, opts) {
  const t0 = Date.now();
  if (!/^[A-Za-z0-9_.-]+$/.test(bucket) || bucket.startsWith('_')) return { bucket, ms: 0, recs: 0, ins: 0, devIns: 0, tables: {}, err: null, skipped: true };
  const force = !!(opts && opts.full);
  const st = force ? null : loadState(bucket);
  if (!force && quickSkip(bucket, st)) return { bucket, ms: Date.now() - t0, recs: 0, ins: 0, devIns: 0, tables: {}, err: null, skipped: true };
  // 【慢桶节流】sig=''（夹读失败/异常桶，实况 unknown_posts=176.9 万文件）：
  //   最快 10 分钟重试一次——否则高频 hint（parse_t_files 每分钟写）会把它拖成常驻重负载；期内 hint 直接跳过。
  if (!force && st && st.sig === '' && st.triedAt && (Date.now() - st.triedAt) < 600000) {
    return { bucket, ms: Date.now() - t0, recs: 0, ins: 0, devIns: 0, tables: {}, err: null, skipped: true };
  }

  const store = ls.newStore();
  const objBucket = new Map(), bucketIps = new Map();
  let err = null;
  try {
    ls.processBucket(store, bucket, false, objBucket, bucketIps, {
      led: (st && Array.isArray(st.led)) ? st.led : [],
      meta: (st && st.meta) ? st.meta : {},
    });
  } catch (e) { err = String((e && e.message) || e); }
  const fresh = ls.takeBucketNew(store);
  const ri = ls.takeBucketState(bucket);
  const counts = await pgStore.upsertRecords(fresh);
  const devIns = await pgStore.upsertDevices(store.users, store.devices);
  // 落账本：ri=null（异常早退）→ 存空账本（sig=''）→ 下轮全量重扫，PG 幂等兜重
  const _st = ri ? { v: 1, sig: ri.sig || '', led: ri.led, meta: ri.meta } : { v: 1, sig: '', led: null, meta: null };
  if (_st.sig === '') _st.triedAt = Date.now();   // 慢桶节流时间戳（sig 空缺时的重试间隔控制）
  saveState(bucket, _st);
  return { bucket, ms: Date.now() - t0, recs: counts.recs, ins: counts.ins, devIns, tables: counts.byTable, err };
}

async function main() {
  const args = process.argv.slice(2);
  const iB = args.indexOf('--bucket');
  if (iB >= 0) {
    const r = await processOne(args[iB + 1]);
    log('manual', JSON.stringify(r));
    await pgStore.close();
    return;
  }
  const iF = args.indexOf('--full');
  if (iF >= 0) {
    const r = await processOne(args[iF + 1], { full: true });
    log('manual-full', JSON.stringify(r));
    await pgStore.close();
    return;
  }

  // ── 常驻模式：字节级游标 tail spool → 脏桶去抖 → 串行处理 ──
  // 【游标持久化】doneOff 只在"已读行全部处理完（dirty 空）"后推进并落盘：
  //   进程中途挂掉 → 重启从上次 doneOff 重读未完成段（重复处理=PG 幂等安全，hint 不丢）。
  const OFFSET_FILE = path.join(STATE_DIR, '_spool_offset');
  let off = 0, doneOff = 0;
  try { doneOff = off = Math.max(0, parseInt(fs.readFileSync(OFFSET_FILE, 'utf8'), 10) || 0); } catch { doneOff = off = 0; }
  try {
    if (off > fs.statSync(SPOOL).size) { off = doneOff = 0; }   // spool 被 truncate/轮转 → 从头
  } catch { try { fs.writeFileSync(SPOOL, ''); } catch {} off = doneOff = 0; }
  try { fs.chmodSync(SPOOL, 0o666); } catch {}   // spool 必须对全部写入方（www/root）可写
  log(`常驻启动 spool=${SPOOL} state=${STATE_DIR} offset=${off}`);
  const saveDone = () => {
    try {
      fs.mkdirSync(STATE_DIR, { recursive: true });
      const tmp = OFFSET_FILE + '.tmp';
      fs.writeFileSync(tmp, String(doneOff));
      fs.renameSync(tmp, OFFSET_FILE);
    } catch {}
  };
  const dirty = new Set();
  let busy = false;
  const stat = { buckets: 0, recs: 0, ins: 0, errs: 0, skip: 0 };
  const FAILED_FILE = path.join(STATE_DIR, '_failed.jsonl');
  const noteFailed = (b, msg) => {
    try {
      fs.mkdirSync(STATE_DIR, { recursive: true });
      fs.appendFileSync(FAILED_FILE, JSON.stringify({ b, e: String(msg).slice(0, 200), t: Date.now() }) + '\n');
    } catch {}
  };
  const drain = async () => {
    if (busy) return;
    busy = true;
    try {
      while (dirty.size) {
        const b = dirty.values().next().value;
        dirty.delete(b);
        try {
          const r = await processOne(b);
          stat.buckets++; stat.recs += r.recs; stat.ins += r.ins;
          if (r.skipped) stat.skip++;
          if (r.err) { stat.errs++; log('桶异常', b, r.err); noteFailed(b, r.err); }
          else if (r.ins || r.recs) log(`${b} 记录=${r.recs} 新增=${r.ins} 设备=${r.devIns} ${r.ms}ms`);
        } catch (e) {
          stat.errs++;
          const msg = String((e && e.message) || e);
          log('处理失败', b, msg);
          noteFailed(b, msg);
        }
      }
    } finally {
      busy = false;
      if (!dirty.size && doneOff !== off) { doneOff = off; saveDone(); }   // 全部处理完 → 游标推进
      // spool 维护：全部消费完且超阈值 → 截断（现状 ~30MB/天增长；写入方均 O_APPEND，truncate 安全）
      if (!dirty.size && doneOff === off && off > 33554432) {
        try { fs.writeFileSync(SPOOL, ''); off = doneOff = 0; saveDone(); log('spool 已截断（>32MB 且全部消费）'); } catch {}
      }
    }
  };
  // 启动时重放上次失败桶（先读后清；仍失败的会再次记录）——例：PG 报错修复后重启 → 自动补账
  try {
    const seen = new Set();
    const txt = fs.readFileSync(FAILED_FILE, 'utf8');
    for (const ln of txt.split('\n')) {
      if (!ln.trim()) continue;
      try { const o = JSON.parse(ln); if (o.b && !seen.has(o.b)) { seen.add(o.b); dirty.add(o.b); } } catch {}
    }
    fs.writeFileSync(FAILED_FILE, '');
    if (dirty.size) { log(`重放上次失败桶 ${dirty.size} 个`); drain(); }
  } catch { /* 无失败清单 */ }
  setInterval(() => {
    try {
      const st = fs.statSync(SPOOL);
      if (st.size < off) off = 0;
      if (st.size > off) {
        const len = Math.min(st.size - off, 1048576);
        const fd = fs.openSync(SPOOL, 'r');
        const buf = Buffer.alloc(len);
        const got = fs.readSync(fd, buf, 0, len, off);
        fs.closeSync(fd);
        const txt = buf.toString('utf8', 0, got);
        const nl = txt.lastIndexOf('\n');
        if (nl < 0) return;
        off += Buffer.byteLength(txt.slice(0, nl + 1));
        for (const ln of txt.slice(0, nl).split('\n')) {
          const s = ln.trim(); if (!s) continue;
          let b = s;
          if (s.startsWith('{')) { try { b = JSON.parse(s).bucket || ''; } catch { continue; } }
          if (b && !b.startsWith('_')) dirty.add(b);
        }
        drain();
      }
    } catch { /* spool 未就绪 */ }
  }, 1500);
  setInterval(() => {
    if (stat.buckets) log(`统计：桶=${stat.buckets} 记录=${stat.recs} 新增=${stat.ins} 跳过=${stat.skip} 错误=${stat.errs} 队列=${dirty.size}`);
  }, 60000);
}

if (require.main === module) main().catch(e => { console.error('[ingestd] fatal', e); process.exit(1); });
module.exports = { processOne };
