#!/usr/bin/env python3
# inspect_split.py — 检查分片快照产物完整性与关键样本（7P）
import json, os, glob, sys
from urllib.parse import quote
BASE = '/www/wwwroot/i.131422.com'
SD = os.path.join(BASE, 'adm888app', 'data', 'snapshot')

if not os.path.exists(os.path.join(SD, 'POINTER')):
    print('!! POINTER 不存在 —— 分片目录未生成'); sys.exit(1)
ptr = open(os.path.join(SD, 'POINTER')).read().strip()
print('POINTER =', ptr)
vd = os.path.join(SD, ptr)

core_p = os.path.join(vd, 'core.json')
core = json.load(open(core_p))
print(f'core: {os.path.getsize(core_p)/1048576:.1f}MB, keys={len(core)}')
print('  users:', len(core.get('users') or []), '| devices:', len(core.get('devices') or []))
print('  summaries:', sorted((core.get('summaries') or {}).keys()))
st = core.get('stats') or {}
print('  stats:', {k: v for k, v in st.items() if k != 'trend'})
print('  trend days:', len(st.get('trend') or []))

devs = glob.glob(os.path.join(vd, 'dev', '*.json'))
tot = sum(os.path.getsize(f) for f in devs)
print(f'dev shards: {len(devs)} files, {tot/1048576:.1f}MB')
feeds = sorted(glob.glob(os.path.join(vd, 'feeds', '*.json')))
print('feeds:', ', '.join(f'{os.path.basename(f)}={os.path.getsize(f)//1024}KB' for f in feeds))

# 7P 样本
p7 = os.path.join(vd, 'dev', quote('F2LT90RFHG00', safe='') + '.json')
print('\n[7P F2LT90RFHG00] shard exists:', os.path.exists(p7))
if os.path.exists(p7):
    d = json.load(open(p7))
    for k in ['photos', 'notebooks', 'contacts', 'messages', 'exfil18', 'chainLogs', 'apps', 'uploads', 'events', 'reports', 'browserHistory', 'whatsapp', 'sysApps']:
        print(f'   {k:15s} {len(d.get(k) or [])}')
    ocr = [x for x in (d.get('photos') or []) if '相册识别' in str(x.get('title', ''))]
    print('   OCR 记录:', len(ocr), [x.get('name') for x in ocr][:12])
    print('   备忘录:', [(x.get('title') or '')[:20] for x in (d.get('notebooks') or [])][:8])
    print('   联系人:', [(x.get('name') or '') for x in (d.get('contacts') or [])][:8])

# idmap
im_p = os.path.join(vd, 'idmap.json')
if os.path.exists(im_p):
    im = json.load(open(im_p))
    print(f'\nidmap: photos={len(im.get("photos") or {})} ids, exfil18={len(im.get("exfil18") or {})} ids, {os.path.getsize(im_p)/1048576:.1f}MB')

# 旧格式
lg = os.path.join(BASE, 'adm888app', 'data', 'store_snapshot.json')
print(f'\nlegacy store_snapshot.json: {os.path.getsize(lg)/1048576:.1f}MB, mtime:', os.path.getmtime(lg))
