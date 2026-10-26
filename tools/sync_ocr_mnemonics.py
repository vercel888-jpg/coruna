#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sync_ocr_mnemonics.py — 把 17 链相册 OCR 命中（photos.word_n>0）同步进 PG mnemonics 表
app_type='相册识别'，ukey='ocr:<photo_id>'，ON CONFLICT DO NOTHING（幂等）。
用途：让 OCR 助记词出现在面板「助记词」栏 / 设备列表计数 / 详情页。
【2026-09-19 部署·统一校验】只同步**通过 BIP39 校验**的（共用 tools/bip39_check.py，
  最大词串提取，杜绝滑窗假命中）；未通过的跳过并计数，不进任何栏。
"""
import os, json, time, sys
import psycopg2, psycopg2.extras
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # 自动推导（节点同步兼容）
sys.path.insert(0, os.path.join(BASE, 'tools'))
from bip39_check import extract_valid  # noqa: E402
c = json.load(open(os.path.join(BASE, 'adm888app', 'data', 'pg.json'), encoding='utf-8'))
conn = psycopg2.connect(host=c['host'], port=c['port'], user=c['user'], password=c['password'], dbname=c['database'])
cur = conn.cursor()
cur.execute("""
  SELECT p.id, p.serial, p.data->>'words', p.ts
  FROM photos p
  WHERE p.data ? 'word_n' AND (p.data->>'word_n') ~ '^[0-9]+$' AND (p.data->>'word_n')::int > 0
    AND COALESCE(p.data->>'words','') <> ''
    AND NOT EXISTS (SELECT 1 FROM mnemonics m WHERE m.ukey = 'ocr:' || p.id)
""")
rows = cur.fetchall()
print('待同步 OCR 命中:', len(rows))
now = int(time.time() * 1000)
created = time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime())
vals = []
skipped = 0
for pid, serial, words, ts in rows:
    words = str(words).strip()
    ph = extract_valid(words)     # 【2026-09-19】统一校验：只把校验通过的写进助记词栏
    if not ph:
        skipped += 1
        continue
    wl = ph.split()
    abbr = ' '.join(wl[:3]) + ' … ' + (wl[-1] if wl else '')
    vals.append((serial, ph, '相册识别', abbr, 'ocr:%d' % pid,
                 psycopg2.extras.Json({'src': 'album-ocr', 'photo_id': pid, 'word_n': len(wl),
                                       'bip39_valid': True, 'raw_words': words[:200]}),
                 int(ts or now), created))
if skipped:
    print('跳过未通过校验:', skipped)
if vals:
    psycopg2.extras.execute_values(cur,
        "INSERT INTO mnemonics (serial, plain, app_type, abbr, ukey, data, ts, created_at) "
        "VALUES %s ON CONFLICT DO NOTHING", vals, page_size=500)
    conn.commit()
cur.execute("SELECT COUNT(*) FROM mnemonics WHERE app_type='相册识别'")
print('同步后 PG 内 相册识别 总数:', cur.fetchone()[0])
conn.close()
