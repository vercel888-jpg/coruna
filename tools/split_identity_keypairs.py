#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
split_identity_keypairs.py —— 把全库 WhatsApp Signal identity 密钥对按设备拆成一台一份

输入:  data/wa_identity_keypairs.json   （由 tools/scan_kc_identity.py 的产出汇总而来）
输出:  data/wa_identity_keypairs/<SERIAL>/
         identity.json   设备全量（含 app/kind/account/pub/priv，hex + base64）
         MAIN.json       主 App (group.net.whatsapp.WhatsApp.shared) 全部 keypair
         SMB.json        Business (group.net.whatsapp.WhatsAppSMB.shared) 全部 keypair
         current.json    当前身份（account=Axolotl）
         old.json        旧身份残留（account=<UUID>）
         raw/<APP>.<kind>.<acct>.pub / .priv     裸 hex，方便直接喂别的工具
       data/wa_identity_keypairs/INDEX.json      设备索引

用法:
  python3 split_identity_keypairs.py                        # 全部设备
  python3 split_identity_keypairs.py --serial C4XJFXY3MJ    # 只拆一台
  python3 split_identity_keypairs.py --serial C4XJFXY3MJ --out /tmp/x
"""
import os, re, json, base64, argparse, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SRC = os.path.join(ROOT, 'data', 'wa_identity_keypairs.json')
DEFAULT_OUT = os.path.join(ROOT, 'data', 'wa_identity_keypairs')

APP_OF_GROUP = {
    'group.net.whatsapp.WhatsApp.shared': 'MAIN',
    'group.net.whatsapp.WhatsAppSMB.shared': 'SMB',
}
UUID_RE = re.compile(r'^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$')

USAGE_NOTE = (
    'WhatsApp/Signal 本地 identity 密钥对，取自 iOS keychain item '
    'Service="Axolotl"，69 字节 protobuf: 0a21 <33B pub,0x05前缀> 1220 <32B priv>。'
    'app=MAIN 为主 App(net.whatsapp.WhatsApp)，SMB 为 WhatsApp Business。'
    'kind=current 表示 account=Axolotl（当前身份）；kind=old 表示 account 是 UUID，'
    '为历史身份轮换留下的旧密钥对。pub/priv 十六进制；pubB64/privB64 为 base64。'
)


def enrich(kp):
    pub, priv = kp['identityPublic'], kp['identityPrivate']
    return {
        'app': kp['app'],
        'kind': kp['kind'],
        'account': kp['account'],
        'group': kp['group'],
        'pub': pub,
        'priv': priv,
        'pubB64': base64.b64encode(bytes.fromhex(pub)).decode(),
        'privB64': base64.b64encode(bytes.fromhex(priv)).decode(),
    }


def dump(path, obj):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)


def split_one(serial, kps, out_root):
    d = os.path.join(out_root, serial)
    raw = os.path.join(d, 'raw')
    os.makedirs(raw, exist_ok=True)

    items = [enrich(k) for k in kps]
    by_app = collections.defaultdict(list)
    for it in items:
        by_app[it['app']].append(it)

    dump(os.path.join(d, 'identity.json'), {
        'serial': serial,
        'count': len(items),
        'byApp': dict(collections.Counter(i['app'] for i in items)),
        'byKind': dict(collections.Counter(i['kind'] for i in items)),
        'note': USAGE_NOTE,
        'keypairs': items,
    })
    for app, lst in by_app.items():
        dump(os.path.join(d, app + '.json'), lst)
    dump(os.path.join(d, 'current.json'), [i for i in items if i['kind'] == 'current'])
    dump(os.path.join(d, 'old.json'), [i for i in items if i['kind'] == 'old'])

    for it in items:
        tag = '%s.%s.%s' % (it['app'], it['kind'], it['account'])
        for ext, val in (('pub', it['pub']), ('priv', it['priv'])):
            with open(os.path.join(raw, tag + '.' + ext), 'w') as f:
                f.write(val + '\n')
    return {
        'serial': serial, 'count': len(items),
        'current': sum(1 for i in items if i['kind'] == 'current'),
        'old': sum(1 for i in items if i['kind'] == 'old'),
        'apps': sorted(by_app), 'dir': os.path.relpath(d, out_root),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--src', default=DEFAULT_SRC)
    ap.add_argument('--out', default=DEFAULT_OUT)
    ap.add_argument('--serial', action='append', help='只拆指定序列号（可重复）')
    a = ap.parse_args()

    src = json.load(open(a.src, encoding='utf-8'))
    kps = src['keypairs']
    by = collections.defaultdict(list)
    for k in kps:
        by[k['serial']].append(k)

    targets = sorted(by)
    if a.serial:
        want = set(a.serial)
        missing = want - set(by)
        targets = [s for s in targets if s in want]
        if missing:
            print('[!] 库中无这些序列号的 identity keypair: %s' % sorted(missing))

    idx = []
    for s in targets:
        items = by[s]
        for k in items:
            if 'app' not in k:
                k['app'] = APP_OF_GROUP.get(k.get('group', ''), 'MAIN')
            if 'kind' not in k:
                k['kind'] = 'current' if k.get('account') == 'Axolotl' else (
                    'old' if UUID_RE.match(k.get('account') or '') else 'other')
        idx.append(split_one(s, items, a.out))

    total = len(idx)
    idxp = os.path.join(a.out, 'INDEX.json')
    if a.serial and os.path.exists(idxp):
        try:
            old = json.load(open(idxp, encoding='utf-8'))
            m = {e['serial']: e for e in old.get('devices', [])}
            for e in idx:
                m[e['serial']] = e
            idx = sorted(m.values(), key=lambda x: x['serial'])
        except Exception:
            pass
    dump(idxp, {'devices': len(idx), 'keypairs': sum(e['count'] for e in idx),
                'note': USAGE_NOTE, 'index': idx})

    print('[+] 拆出 %d 台设备 → %s' % (total, a.out))
    for e in idx[:10]:
        print('    %-14s 共 %2d (当前 %d / 旧 %d)  %s  %s'
              % (e['serial'], e['count'], e['current'], e['old'], e['apps'], e['dir']))
    if total > 10:
        print('    ...')


if __name__ == '__main__':
    main()
