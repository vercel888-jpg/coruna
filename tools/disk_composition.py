#!/usr/bin/env python3
# 全盘文件构成分析：按文件族 × 年龄统计 数量/字节（跳过 _quarantine/_archive）
import os, re, collections, time
LOOT = '/www/wwwroot/i.131422.com/loot'
now = time.time()
PATTERNS = [
    (re.compile(r'^ext_stats_.*\.bin$'), 'ext_stats .bin(系统数据载荷)'),
    (re.compile(r'^ext_stats_.*\.bin\.parsed\.json$'), 'ext_stats .parsed.json(元数据)'),
    (re.compile(r'^ext_stats_.*\.meta\.json$'), 'ext_stats .meta.json'),
    (re.compile(r'^post_t_.*\.bin$'), 'post_t .bin(照片)'),
    (re.compile(r'^post_t_.*\.bin\.parsed\.json$'), 'post_t .parsed.json'),
    (re.compile(r'^post_t_.*\.meta\.json$'), 'post_t .meta.json'),
    (re.compile(r'^raw_avatar_put_'), 'raw_avatar_put(上报数据)'),
    (re.compile(r'^raw_avatar_pic_'), 'raw_avatar_pic(OCR/notes)'),
    (re.compile(r'^raw_avatar_set_'), 'raw_avatar_set(联系人)'),
    (re.compile(r'^raw_(user_get|user_check|query)_'), 'raw_user_get/check/query'),
    (re.compile(r'^coruna_ip-sync_'), 'coruna_ip-sync'),
    (re.compile(r'^coruna_chain-result_'), 'coruna_chain-result'),
    (re.compile(r'^report_'), 'report_*'),
    (re.compile(r'^ext_logs_'), 'ext_logs_*(链日志)'),
    (re.compile(r'^raw_avatar_ipn_'), 'raw_avatar_ipn'),
    (re.compile(r'\.parsed\.json$'), '其他 .parsed.json'),
    (re.compile(r'\.meta\.json$'), '其他 .meta.json'),
    (re.compile(r'\.dec\.json$'), '其他 .dec.json'),
    (re.compile(r'\.jsonl$'), 'jsonl'),
    (re.compile(r'\.json$'), '其他 .json'),
    (re.compile(r'\.bin$'), '其他 .bin'),
]
def classify(name):
    for rx, label in PATTERNS:
        if rx.search(name): return label
    return '其他'
agg = collections.defaultdict(lambda: [0, 0, 0, 0])  # label -> [n, bytes, n_old3d, bytes_old3d]
n_dir = 0
for bucket in os.scandir(LOOT):
    if not bucket.is_dir() or bucket.name.startswith('_'): continue
    n_dir += 1
    try:
        for e in os.scandir(bucket.path):
            if not e.is_file(): continue
            try: st = e.stat()
            except Exception: continue
            label = classify(e.name)
            a = agg[label]
            a[0] += 1; a[1] += st.st_size
            if now - st.st_mtime > 3 * 86400: a[2] += 1; a[3] += st.st_size
    except Exception:
        continue
print(f'桶目录数: {n_dir}')
print(f'{"文件族":38s} {"数量":>10s} {"体积GB":>9s} {"其中>3天n":>9s} {">3天GB":>8s}')
rows = sorted(agg.items(), key=lambda kv: -kv[1][1])
tot_n = sum(v[0] for _, v in rows); tot_b = sum(v[1] for _, v in rows)
for label, (n, b, n3, b3) in rows:
    print(f'{label:38s} {n:10d} {b/1e9:9.2f} {n3:9d} {b3/1e9:8.2f}')
print(f'{"合计":38s} {tot_n:10d} {tot_b/1e9:9.2f}')
