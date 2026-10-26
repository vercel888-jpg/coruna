#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""t_find.py — 按设备查 /t 通道上报（含身份反序解码）

背景：/t 通道的 s/u/d(ecid) 字段是把真实值整串反序后 hex 编码的。
      用真实 serial 直接 grep 查不到，必须用反序值。

用法：
  python3 scripts/t_find.py F2LT90RFHG00          # 按真实 serial 查
  python3 scripts/t_find.py --list-serial         # 列出所有 /t 出现的序列号
  python3 scripts/t_find.py --list-ip             # 按 IP 统计 /t 条数
"""
import glob
import json
import os
import re
import sys
import collections
import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POSTS = os.path.join(ROOT, 'loot', 'unknown_posts')

FILENAME_RE = re.compile(r'post_t_(\d+)\.bin$')


def now_utc():
    return datetime.datetime.now(datetime.UTC)


def ts_str(ms):
    try:
        return datetime.datetime.fromtimestamp(int(ms) / 1000, datetime.UTC)\
            .strftime('%m-%d %H:%M:%S')
    except Exception:
        return '?'


def parse_multipart(data):
    """极简 multipart 解析 -> {name: bytes}"""
    m = re.match(rb'--([A-Za-z0-9\-]{4,})\r?\n', data)
    if not m:
        return {}
    parts = data.split(b'--' + m.group(1))
    out = {}
    for p in parts:
        p = p.strip(b'\r\n')
        if not p or p == b'--':
            continue
        if b'\r\n\r\n' in p:
            head, _, body = p.partition(b'\r\n\r\n')
        elif b'\n\n' in p:
            head, _, body = p.partition(b'\n\n')
        else:
            continue
        nm = re.search(rb'name="([^"]+)"', head)
        if nm:
            out[nm.group(1).decode('utf-8', 'ignore')] = body
    return out


def unhex(s):
    """字段通常是 hex；devices 有时会发纯文本，两种都兼容。"""
    s = (s or '').strip()
    if not s:
        return ''
    if re.fullmatch(r'[0-9a-fA-F]+', s) and len(s) % 2 == 0 and len(s) > 4:
        try:
            return bytes.fromhex(s).decode('utf-8', 'ignore').strip('\x00')
        except Exception:
            pass
    return s


def field(f, name):
    """取 multipart 字段并转成 str 再解 hex。"""
    v = f.get(name)
    if v is None:
        return ''
    if isinstance(v, bytes):
        v = v.decode('ascii', 'ignore')
    return unhex(v)


def load_all():
    """返回 [{ts, ip, serial, udid, ecid, lhu, size, path}]，跳过非 /t 产物。"""
    rows = []
    for meta in sorted(glob.glob(os.path.join(POSTS, 'post_t_*.meta.json'))):
        base = meta[:-len('.meta.json')]
        binp = base + '.bin'
        if not os.path.exists(binp):
            continue
        try:
            with open(meta) as f:
                mj = json.load(f)
        except Exception:
            mj = {}
        f = {}
        try:
            with open(binp, 'rb') as fh:
                f = parse_multipart(fh.read())
        except Exception:
            pass
        rows.append({
            'ts': mj.get('ts') or (FILENAME_RE.search(binp).group(1) if FILENAME_RE.search(binp) else ''),
            'ip': mj.get('ip', '?'),
            'serial': field(f, 's'),
            'udid': field(f, 'u'),
            'ecid': field(f, 'd'),
            'lhu': field(f, 'lhu'),
            'ua': mj.get('ua', '') or '',
            'size': mj.get('bodyLen') or os.path.getsize(binp),
            'path': binp,
        })
    return rows


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return 1
    rows = load_all()

    if args[0] == '--list-serial':
        c = collections.Counter(r['serial'] for r in rows if r['serial'])
        for s, n in c.most_common():
            print(f'{s:16s} {n:5d}')
        return 0

    if args[0] == '--list-ip':
        c = collections.Counter(r['ip'] for r in rows)
        for ip, n in c.most_common(40):
            print(f'{ip:20s} {n:5d}')
        return 0

    target = args[0]
    rev = target[::-1]
    print(f'查询 {target}  (/t 侧应为反序: {rev})')
    print('-' * 72)

    hits = [r for r in rows if r['serial'] in (target, rev)]
    if not hits:
        # 放宽：udid/ecid 反序也算命中
        hits = [r for r in rows if r['udid'] in (target, rev) or r['ecid'] in (target, rev)]
    if not hits:
        print('没有命中。检查 serial 是否写全 / 是否用了反序值。')
        return 2

    hits.sort(key=lambda r: int(r['ts']) if str(r['ts']).isdigit() else 0)
    ips = collections.Counter(r['ip'] for r in hits)
    lhus = {r['lhu'] for r in hits if r['lhu']}
    print(f'命中 {len(hits)} 条 | /t 侧 serial={hits[0]["serial"]} | lhu={",".join(lhus) or "?"}')
    print(f'IP 分布: {dict(ips.most_common(5))}')
    days = collections.Counter(ts_str(r["ts"])[:5] for r in hits)
    print(f'按日: {dict(sorted(days.items()))}')
    print('-' * 72)
    for r in hits[-12:]:
        ua = re.search(r'iPhone OS (\d+_\d+)', r['ua'])
        print(f'{ts_str(r["ts"])}  {r["ip"]:18s} {int(r["size"]):8d}B  UA={ua.group(1) if ua else "?"}  {os.path.basename(r["path"])}')
    print(f'\n最新一条: {ts_str(hits[-1]["ts"])} UTC')
    return 0


if __name__ == '__main__':
    sys.exit(main())
