#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
export_wa_signal.py —— 从 loot 的 WhatsApp Axolotl.sqlite / keychain dump 导出 Signal 密钥材料

输入:  <loot_dir>  (目录，或直接给 Axolotl.sqlite 的 ext_stats_*.bin)
输出:  --out <dir>  默认 <loot_dir>/wa_signal_export

产出:
  identity_public.json     本机 Signal identity 公钥（从 SessionStructure.localIdentityPublic 抠，全量会话一致性校验）
  prekeys.json             ZWAPREKEY      一次性预共享私钥 (id / pub / priv)
  signed_prekeys.json      ZWASIGNEDPREKEY 签名预共享私钥 (id / pub / priv / signature / created)
  contact_identities.csv   ZWAAXOLOTLIDENTITY 联系人 identity 公钥
  sessions.jsonl           ZWAAXOLOTLSESSION 会话状态（rootKey / chainKey / ratchet 私钥 / 双方 identity 公钥）
  private_key_hunt.json    全量 32 字节候选值 X25519 反推，找 identity 私钥在哪

用法:
  python3 export_wa_signal.py /www/wwwroot/i.131422.com/loot/191.39.5.158
  python3 export_wa_signal.py <loot_dir> --out /tmp/waexp --no-sessions
"""
import os, sys, json, glob, base64, sqlite3, binascii, argparse, tempfile, re
import collections

# ───────────────────────── protobuf 最小解析 ─────────────────────────
def rd_varint(b, i):
    r = 0; s = 0
    while True:
        x = b[i]; i += 1
        r |= (x & 0x7f) << s; s += 7
        if not x & 0x80:
            return r, i

def pb_fields(b):
    i = 0; out = []
    while i < len(b):
        k, i = rd_varint(b, i)
        fn, wt = k >> 3, k & 7
        if wt == 0:
            v, i = rd_varint(b, i)
        elif wt == 2:
            l, i = rd_varint(b, i); v = b[i:i + l]; i += l
        elif wt == 1:
            v = b[i:i + 8]; i += 8
        elif wt == 5:
            v = b[i:i + 4]; i += 4
        else:
            break
        out.append((fn, wt, v))
    return out

def pb_map(b):
    return {fn: v for fn, wt, v in pb_fields(b) if wt == 2}

def hx(b):
    return binascii.hexlify(b).decode() if b else None

# ───────────────────────── loot 容器解码 ─────────────────────────
def load_bin(path):
    """ext_stats_*.bin 是 JSON 容器；data 字段是 base64 原文。"""
    raw = open(path, 'rb').read()
    if raw.lstrip()[:1] == b'{':
        j = json.loads(raw)
        if isinstance(j.get('data'), str):
            return base64.b64decode(j['data']), j
        return raw, j
    return raw, {}

def find_axolotl(loot_dir):
    """递归找 category=whatsapp 且 path 含 Axolotl.sqlite 的 bin。"""
    hits = []
    for f in glob.glob(os.path.join(loot_dir, '*.bin')):
        pj = f + '.parsed.json'
        if not os.path.exists(pj):
            continue
        try:
            m = json.load(open(pj))
        except Exception:
            continue
        p = str(m.get('path') or '')
        if 'Axolotl.sqlite' in p:
            hits.append((f, m))
    return hits

# ───────────────────────── keychain dump 解析 ─────────────────────────
def parse_keychain(loot_dir):
    out = []
    for f in glob.glob(os.path.join(loot_dir, '*.bin')):
        pj = f + '.parsed.json'
        if not os.path.exists(pj):
            continue
        try:
            m = json.load(open(pj))
        except Exception:
            continue
        if m.get('category') != 'keychain':
            continue
        data, _ = load_bin(f)
        txt = data.decode('utf-8', 'ignore')
        cur = {}
        for line in txt.splitlines():
            g = re.match(r'^(\w+):\s?(.*)$', line)
            if not g:
                continue
            k, v = g.group(1), g.group(2)
            if k == 'UUID':
                if cur:
                    out.append(cur)
                cur = {'UUID': v, '_src': os.path.basename(f)}
            else:
                cur[k] = v
        if cur:
            out.append(cur)
        break   # 路径别名三份内容相同，只取第一份
    return out

def kc_data_bytes(v):
    if not v or v == 'NULL':
        return b''
    if re.fullmatch(r'[0-9a-fA-F]+', v) and len(v) % 2 == 0:
        try:
            return bytes.fromhex(v)
        except Exception:
            pass
    return v.encode('utf-8', 'ignore')

# ───────────────────────── 主流程 ─────────────────────────
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('loot_dir')
    ap.add_argument('--out', default=None)
    ap.add_argument('--no-sessions', action='store_true')
    args = ap.parse_args()

    loot = os.path.abspath(args.loot_dir)
    out = args.out or os.path.join(loot, 'wa_signal_export')
    os.makedirs(out, exist_ok=True)

    axs = find_axolotl(loot)
    if not axs:
        print('[!] 没找到 Axolotl.sqlite'); sys.exit(1)
    print('[*] Axolotl 数据库 %d 个:' % len(axs))
    for f, m in axs:
        print('    %-28s %s' % (os.path.basename(f), m.get('path')))

    prekeys, signed, contacts, sessions, idpub = [], [], [], [], collections.Counter()
    priv_candidates = []

    for f, m in axs:
        data, _ = load_bin(f)
        db = os.path.join(tempfile.gettempdir(), 'ax_' + binascii.hexlify(os.path.basename(f).encode()).decode()[:12] + '.sqlite')
        open(db, 'wb').write(data)
        c = sqlite3.connect(db)
        tag = 'SMB' if 'WhatsAppSMB' in str(m.get('path')) else 'MAIN'

        # 一次性预共享密钥
        for kid, kd in c.execute("select ZKEYID, ZKEYDATA from ZWAPREKEY"):
            if not kd:
                continue
            f1 = pb_map(kd)
            pub, priv = f1.get(2), f1.get(3)
            prekeys.append({'app': tag, 'keyId': kid, 'pub': hx(pub), 'priv': hx(priv)})
            if priv and len(priv) == 32:
                priv_candidates.append(('ZWAPREKEY', tag, kid, priv))

        # 签名预共享密钥
        for pk, kid, cr, kd in c.execute("select Z_PK, ZKEYID, ZCREATIONDATE, ZKEYDATA from ZWASIGNEDPREKEY"):
            if not kd:
                continue
            f1 = pb_map(kd)
            pub, priv, sig = f1.get(2), f1.get(3), f1.get(4)
            signed.append({'app': tag, 'pk': pk, 'keyId': kid, 'created': cr,
                           'pub': hx(pub), 'priv': hx(priv), 'signature': hx(sig)})
            if priv and len(priv) == 32:
                priv_candidates.append(('ZWASIGNEDPREKEY', tag, kid, priv))

        # 联系人 identity 公钥
        for pk, dev, recip, acct, kd in c.execute(
                "select Z_PK, ZDEVICEID, ZRECIPIENTJID, ZACCOUNTJIDSTRING, ZKEYDATA from ZWAAXOLOTLIDENTITY"):
            contacts.append({'app': tag, 'pk': pk, 'deviceId': dev, 'jid': recip,
                             'lid': acct, 'identityKey': hx(kd)})

        # 会话状态
        if not args.no_sessions:
            for pk, recip, dev, sd in c.execute(
                    "select Z_PK, ZRECIPIENTJID, ZDEVICEID, ZSESSIONDATA from ZWAAXOLOTLSESSION where ZSESSIONDATA is not null"):
                try:
                    ss = pb_map(sd).get(1)          # SessionStructure
                    if not ss:
                        continue
                    mm = pb_map(ss)
                    li, ri = mm.get(2), mm.get(3)
                    if li and len(li) == 33:
                        idpub[hx(li)] += 1
                    rec = {
                        'app': tag, 'pk': pk, 'jid': recip, 'deviceId': dev,
                        'sessionVersion': mm.get(1),
                        'localIdentityPublic': hx(li),
                        'remoteIdentityPublic': hx(ri),
                        'rootKey': hx(mm.get(4)),
                        'previousCounter': mm.get(5),
                        'localRegistrationId': mm.get(11),
                        'remoteRegistrationId': mm.get(10),
                        'aliceBaseKey': hx(mm.get(13)),
                    }
                    sc = mm.get(6)
                    if sc:
                        cm = pb_map(sc)
                        rec['senderChain'] = {
                            'ratchetKey': hx(cm.get(1)),
                            'ratchetKeyPrivate': hx(cm.get(2)),
                            'chainKey': (lambda ck: {'index': ck.get(1), 'key': hx(ck.get(2))})(pb_map(cm.get(3))) if cm.get(3) else None,
                            'messageKeys': len([1 for fn, wt, v in pb_fields(sc) if fn == 4]),
                        }
                        if cm.get(2) and len(cm.get(2)) == 32:
                            priv_candidates.append(('SESSION.senderRatchetKeyPrivate', tag, pk, cm.get(2)))
                    rec['receiverChainCount'] = len([1 for fn, wt, v in pb_fields(ss) if fn == 7])
                    sessions.append(rec)
                except Exception:
                    continue

    # keychain 候选
    kc = parse_keychain(loot)
    kc_priv = []
    for i in kc:
        b = kc_data_bytes(i.get('Data'))
        if len(b) == 32:
            kc_priv.append(i)
            priv_candidates.append(('KEYCHAIN', i.get('Group') or '', str(i.get('Account'))[:40], b))

    # ── X25519 反推 identity 私钥 ──
    hunt = {'targetIdentityPublics': [], 'tested': 0, 'match': None,
            'candidatesBySource': {}}
    if idpub:
        # 所有 identity 公钥都作为目标（去 0x05 前缀 → 32 字节 X25519 公钥）
        targets = {bytes.fromhex(k)[1:]: k for k in idpub if k.startswith('05') and len(k) == 66}
        hunt['targetIdentityPublics'] = [{'identityPublic': v, 'x25519': hx(k), 'sessions': idpub[v]}
                                         for k, v in targets.items()]
        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
            from cryptography.hazmat.primitives import serialization
            seen = set()
            for src, tag, ident, pv in priv_candidates:
                if pv in seen:
                    continue
                seen.add(pv)
                hunt['tested'] += 1
                try:
                    pub = X25519PrivateKey.from_private_bytes(pv).public_key()\
                        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                except Exception:
                    continue
                if pub in targets:
                    hunt['match'] = {'source': src, 'app': tag, 'id': str(ident),
                                     'priv': hx(pv), 'identityPublic': targets[pub]}
                    break
            hunt['candidatesBySource'] = dict(collections.Counter(s for s, _, _, _ in priv_candidates))
            hunt['uniqueCandidates'] = len(seen)
        except ImportError:
            hunt['error'] = 'no cryptography lib'

    jdump = lambda n, o: open(os.path.join(out, n), 'w', encoding='utf-8').write(
        json.dumps(o, ensure_ascii=False, indent=1))

    jdump('identity_public.json', {
        'note': '本机 Signal identity 公钥，来自 SessionStructure.localIdentityPublic（33 字节，0x05 前缀）',
        'sources': {k: v for k, v in sorted(idpub.items(), key=lambda x: -x[1])},
        'consistent': len(idpub) == 1,
    })
    jdump('prekeys.json', prekeys)
    jdump('signed_prekeys.json', signed)
    jdump('private_key_hunt.json', hunt)
    with open(os.path.join(out, 'contact_identities.csv'), 'w', encoding='utf-8') as fp:
        fp.write('app,pk,deviceId,jid,lid,identityKey\n')
        for r in contacts:
            fp.write('%s,%s,%s,%s,%s,%s\n' % (r['app'], r['pk'], r['deviceId'], r['jid'], r['lid'], r['identityKey']))
    if not args.no_sessions:
        with open(os.path.join(out, 'sessions.jsonl'), 'w', encoding='utf-8') as fp:
            for r in sessions:
                fp.write(json.dumps(r, ensure_ascii=False) + '\n')

    print()
    print('[+] 输出目录: %s' % out)
    print('    identity_public.json     %d 个不同值 (consistent=%s)' % (len(idpub), len(idpub) == 1))
    for k, v in sorted(idpub.items(), key=lambda x: -x[1])[:5]:
        print('        %s  出现 %d 次' % (k, v))
    print('    prekeys.json             %d 条（含 32 字节私钥）' % len(prekeys))
    print('    signed_prekeys.json      %d 条' % len(signed))
    print('    contact_identities.csv   %d 条（公钥）' % len(contacts))
    if not args.no_sessions:
        print('    sessions.jsonl           %d 条' % len(sessions))
    print('    private_key_hunt.json    identity 私钥反推: tested=%d match=%s'
          % (hunt.get('tested', 0), hunt.get('match')))

if __name__ == '__main__':
    main()
