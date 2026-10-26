#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wa_env_bruteforce.py —— 爆破 WhatsApp keychain 115 字节信封 (01 01 02 + 112B)

密钥候选: 每台设备自己 keychain 里的 32 字节值 + Signal identity(Curve25519) 私钥
布局: 多种 nonce/tag 摆法 + 派生 nonce（全零/sha256(key)）
算法: AES-256-GCM / AES-128-GCM / ChaCha20-Poly1305 / AES-256-CBC(+PKCS7 可打印判据)
判据: AEAD 认证标签通过；或 CBC 解出 PKCS7 合法且明文可打印

用法:
  python3 tools/wa_env_bruteforce.py --stage1          # 小空间快速扫（推荐先跑）
  python3 tools/wa_env_bruteforce.py --stage2          # 全布局全 AAD
  python3 tools/wa_env_bruteforce.py --envelopes <jsonl>   # 枚举所有布局，看结构
"""
import os, re, sys, json, argparse, collections, hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, padding as sympad

ENV_RE = re.compile(r'wa\.(backup|fpm|xplatform)\.e$')


def hkdf1(key, info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b'\x00' * 32, info=info).derive(key)


def cbc_dec(key, iv, ct):
    d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return d.update(ct) + d.finalize()


def printable(b):
    return all(32 <= c < 127 or c in (9, 10, 13) for c in b)


# ── 布局表 ──────────────────────────────────────────────────────────────
def layouts(p):
    """p = 112 字节体；返回 (name, nonce, ct, tag)"""
    return [
        ('n12|ct84|t16', p[0:12], p[12:96], p[96:112]),
        ('n16|ct80|t16', p[0:16], p[16:96], p[96:112]),
        ('n12|t16|ct84', p[0:12], p[28:112], p[12:28]),
        ('n16|t16|ct80', p[0:16], p[32:112], p[16:32]),
        ('ct96|t16', p[0:0], p[0:96], p[96:112]),
        ('ct96|t16|n12', p[100:112], p[0:84], p[84:100]),
        ('n24|ct72|t16', p[0:24], p[24:96], p[96:112]),
        ('n8|ct88|t16', p[0:8], p[8:96], p[96:112]),
    ]


def deriv_nonces(key, blob):
    return [b'\x00' * 12, hashlib.sha256(key).digest()[:12],
            hashlib.sha256(blob).digest()[:12], key[:12], blob[3:15]]


def try_all(key, blob, svc, acct, deep=False):
    """返回命中描述或 None"""
    p = blob[3:]
    hdr = blob[:3]
    svcb, acctb = svc.encode(), acct.encode()
    aad_variants = [b'', hdr, svcb, acctb, svcb + b'|' + acctb]
    if not deep:
        aad_variants = [b'', hdr]
    aesgcm = AESGCM(key)
    a128 = AESGCM(key[:16])
    chacha = ChaCha20Poly1305(key)
    ciphers = [('AES256GCM', aesgcm), ('AES128GCM', a128), ('ChaCha', chacha)]
    for lname, nonce, ct, tag in layouts(p):
        for cname, C in ciphers:
            for aad in aad_variants:
                try:
                    C.decrypt(nonce, ct + tag, aad)
                    return '%s/%s/aad=%s' % (cname, lname, aad.hex() or 'empty')
                except Exception:
                    pass
    # 派生 nonce（nonce 不在体内）
    for dn in deriv_nonces(key, blob):
        for aad in aad_variants:
            for cname, C in (('AES256GCM', aesgcm), ('AES128GCM', a128), ('ChaCha', chacha)):
                try:
                    C.decrypt(dn, p[0:96] + p[96:112], aad)
                    return '%s/derivedNonce:%s/aad=%s' % (cname, dn[:6].hex(), aad.hex() or 'empty')
                except Exception:
                    pass
    # CBC + PKCS7（判据：padding 合法且明文可打印）
    for lname, iv, ct, _tag in layouts(p):
        if len(iv) not in (16,) or len(ct) == 0 or len(ct) % 16:
            continue
        try:
            pt = cbc_dec(key, iv, ct)
            u = sympad.PKCS7(128).unpadder()
            pt = u.update(pt) + u.finalize()
            if pt and printable(pt):
                return 'AES256CBC/%s 明文=%r' % (lname, pt[:80])
        except Exception:
            pass
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--items', default='/tmp/kcscan2/whatsapp_items.jsonl')
    ap.add_argument('--key32', default='/tmp/kcscan2/key32_candidates.jsonl')
    ap.add_argument('--out', default='/tmp/env_hits.json')
    ap.add_argument('--maxkeys', type=int, default=25)
    ap.add_argument('--stage1', action='store_true')
    ap.add_argument('--stage2', action='store_true')
    ap.add_argument('--envelopes', metavar='JSONL',
                    help='枚举指定 jsonl 里的信封，打印每种布局的尝试结果（结构探测）')
    a = ap.parse_args()

    if a.envelopes:
        for line in open(a.envelopes):
            r = json.loads(line)
            if r.get('len') != 115:
                continue
            blob = bytes.fromhex(r['data'])
            print('%s %s %s' % (r['serial'], r['service'], r['account']))
            print('  blob=%s' % blob.hex())
            print('  头=%s  体=%s' % (blob[:3].hex(), blob[3:].hex()))
            print('  按 32|64|16 切: epk=%s ct=%s tag=%s' %
                  (blob[3:35].hex(), blob[35:99].hex(), blob[99:].hex()))
        return

    k32 = collections.defaultdict(list)
    for line in open(a.key32):
        r = json.loads(line)
        if r['len'] == 32:
            k32[r['serial']].append(r)

    def prio(r):
        s = (str(r.get('service')) + ' ' + str(r.get('account'))).lower()
        for w, p in (('cgrek', 0), ('secik', 1), ('static', 2), ('key', 3), ('secret', 4)):
            if w in s:
                return p
        return 9

    ident = collections.defaultdict(list)
    env = collections.defaultdict(list)
    for line in open(a.items):
        r = json.loads(line)
        if r.get('service') == 'Axolotl' and r['len'] == 69:
            ident[r['serial']].append(r['data'][70:134])
        if ENV_RE.match(str(r.get('service') or '')) and r['len'] == 115:
            env[r['serial']].append(r)

    devs = sorted(set(env) & (set(k32) | set(ident)))
    deep = bool(a.stage2)
    print('[*] 设备 %d  信封 %d  deep=%s' % (len(devs), sum(len(env[s]) for s in devs), deep), flush=True)

    hits, tried = [], 0
    keys_cache = {}
    for n, s in enumerate(devs):
        cands = [('identity', h) for h in ident.get(s, [])[:2]]
        for r in sorted(k32.get(s, []), key=prio)[:a.maxkeys]:
            cands.append(('%s|%s' % (r.get('service'), str(r.get('account'))[:20]), r['data']))
        kcache = {}
        for tag0, h in cands:
            try:
                k = bytes.fromhex(h)
            except Exception:
                continue
            if len(k) != 32:
                continue
            kcache[tag0] = [k, hkdf1(k, b'WhatsApp'), hkdf1(k, b'wa')]
        for e in env[s]:
            blob = bytes.fromhex(e['data'])
            svc, acct = str(e['service']), str(e['account'])
            for tag0, ks in kcache.items():
                for ki, key in enumerate(ks):
                    tried += 1
                    hit = try_all(key, blob, svc, acct, deep)
                    if hit:
                        t = tag0 if ki == 0 else tag0 + '|hkdf%d' % ki
                        hits.append({'serial': s, 'service': svc, 'account': acct,
                                     'keySource': t, 'key': key.hex(), 'result': hit})
                        print('  >>> HIT %s %s %s => %s' % (s, svc, t, hit), flush=True)
        if n % 25 == 0:
            print('  ...%d/%d tried=%d hits=%d' % (n, len(devs), tried, len(hits)), flush=True)
    json.dump(hits, open(a.out, 'w'), ensure_ascii=False, indent=1)
    print('[+] 完成: 尝试 %d 次, 命中 %d → %s' % (tried, len(hits), a.out))


if __name__ == '__main__':
    main()
