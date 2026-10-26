#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
18 链钱包数据解密（Bitpie + Trust Wallet）
输入: /tmp/wdec/keychain_dump2.txt + Trust keystore v3 JSON
输出: 两个钱包的助记词候选
"""
import json, re, os, sys, hashlib, itertools

W = '/tmp/wdec'
RESULT = {}

# ─────────────────────────── 1) 解析 keychain dump ───────────────────────────
def parse_keychain(p):
    txt = open(p, encoding='utf-8', errors='replace').read()
    items = []
    for blk in re.split(r'(?=UUID:)', txt):
        if 'Account:' not in blk:
            continue
        svc = re.search(r'Service:\s*(.*)', blk)
        grp = re.search(r'Group:\s*(.*)', blk)
        acc = re.search(r'Account:\s*(.*)', blk)
        dat = re.search(r'Data:\s*(\S+)', blk)
        if not (acc and dat):
            continue
        items.append({
            'service': (svc.group(1).strip() if svc else ''),
            'group': (grp.group(1).strip() if grp else ''),
            'account': acc.group(1).strip(),
            'data': dat.group(1).strip(),
        })
    return items

def hx(s):
    """奇数字符/非法字符容错"""
    s = re.sub(r'[^0-9a-fA-F]', '', s)
    if len(s) % 2:
        s = s[:-1]
    try:
        return bytes.fromhex(s)
    except Exception:
        return b''

def to_ascii(b):
    try:
        return b.decode('utf-8')
    except Exception:
        return b.decode('latin-1')

# ─────────────────────────── 2) BIP39 还原 ───────────────────────────
try:
    from mnemonic import Mnemonic
    M = Mnemonic('english')
    HAVE_BIP39 = True
except Exception as e:
    HAVE_BIP39 = False
    print('!! mnemonic 库不可用:', e)

def entropy_to_words(ent: bytes):
    if not HAVE_BIP39:
        return None
    if len(ent) not in (16, 20, 24, 28, 32):
        return None
    try:
        return M.to_mnemonic(ent)
    except Exception:
        return None

def check_words(p):
    if not HAVE_BIP39:
        return False
    return M.check(p)

# ─────────────────────────── 3) Bitpie ───────────────────────────
def do_bitpie(items):
    print('\n' + '=' * 78)
    print('§ Bitpie (com.bitpie.wallet)')
    print('=' * 78)
    want = ['userHDseed', 'seedPhraseEntropy', 'seedPhraseLanguage',
            'PINCODETYPEKEY', 'PINCODEKEY', 'userXpubExtra']
    got = {}
    for it in items:
        if it['service'] != 'com.bitpie.wallet':
            continue
        if it['account'] in want and it['account'] not in got:
            got[it['account']] = it['data']
    for k in want:
        if k in got:
            raw = hx(got[k])
            asc = to_ascii(raw)
            print('  %-20s len(data)=%-4d len(decoded)=%-3d  ascii=%s' % (
                k, len(got[k]), len(raw), asc[:70]))

    # seedPhraseEntropy → BIP39 熵
    if 'seedPhraseEntropy' in got:
        raw = hx(got['seedPhraseEntropy'])
        asc = to_ascii(raw)
        print('\n  → seedPhraseEntropy 解码: %r (%d 字符)' % (asc, len(asc)))
        for cand, tag in ((hx(asc), 'ASCII 当十六进制'), (raw, '原始字节')):
            w = entropy_to_words(cand)
            if w:
                print('  ✅ [%s] 熵 %d 字节 → 12/24 词:' % (tag, len(cand)))
                print('     %s' % w)
                RESULT['bitpie'] = w
                break
        else:
            print('  ⚠️ 熵长度非 BIP39 标准（%d 字节），无法直接还原' % len(hx(asc)))

    # userHDseed（更长，可能是加密种子）
    if 'userHDseed' in got:
        raw = hx(got['userHDseed'])
        asc = to_ascii(raw)
        print('\n  → userHDseed 解码: %s' % asc[:130])
        print('     字节数: %d（BIP39 24 词熵=32B / 12 词熵=16B）' % len(hx(asc)))
        for cand, tag in ((hx(asc)[:16], '前16B'), (hx(asc)[:32], '前32B')):
            w = entropy_to_words(cand)
            if w:
                print('  ⚠️ [%s] 试出可校验助记词: %s' % (tag, w))

# ─────────────────────────── 4) Trust keystore v3 ───────────────────────────
def keystore_decrypt(crypto, passwd: bytes):
    from Crypto.Cipher import AES
    from Crypto.Hash import keccak
    kdfp = crypto['kdfparams']
    if crypto['kdf'] == 'scrypt':
        dk = hashlib.scrypt(passwd, salt=bytes.fromhex(kdfp['salt']),
                            n=kdfp['n'], r=kdfp['r'], p=kdfp['p'],
                            dklen=kdfp['dklen'], maxmem=512 * 1024 * 1024)
    else:  # pbkdf2
        dk = hashlib.pbkdf2_hmac(kdfp.get('prf', 'hmac-sha256').replace('hmac-', ''),
                                 passwd, bytes.fromhex(kdfp['salt']),
                                 kdfp['c'], kdfp['dklen'])
    mac = keccak.new(digest_bits=256)
    mac.update(dk[16:32] + bytes.fromhex(crypto['ciphertext']))
    if mac.hexdigest().lower() != crypto['mac'].lower():
        return None
    iv = bytes.fromhex(crypto['cipherparams']['iv'])
    ct = bytes.fromhex(crypto['ciphertext'])
    pt = AES.new(dk[:16], AES.MODE_CTR, nonce=b'', initial_value=iv).decrypt(ct)
    return pt

def do_trust(path, hints):
    print('\n' + '=' * 78)
    print('§ Trust Wallet (com.sixdays.trust) — Ethereum keystore v3')
    print('=' * 78)
    d = json.load(open(path, encoding='utf-8'))
    c = d['crypto']
    print('  kdf=%s n=%s r=%s p=%s cipher=%s' % (c['kdf'], c['kdfparams']['n'],
          c['kdfparams']['r'], c['kdfparams']['p'], c['cipher']))
    print('  activeAccounts=%d  type=%s' % (len(d.get('activeAccounts') or []), d.get('type')))

    cands = []
    for h in hints:
        if h is None: continue
        for hh in {h, h.strip(), h.lower(), h.upper()}:
            if hh and hh not in cands:
                cands.append(hh)
    base = ['', '1234', '123456', '000000', '111111', '666666', '888888',
            '112233', '123123', '654321', '0000', '2580', '12345', '1111',
            'password', 'test', 'test123', '12345678', 'abcdef']
    for b in base:
        if b not in cands:
            cands.append(b)

    print('  候选口令 %d 个，开始试解（scrypt n=16384 每个约 1-2 秒）…' % len(cands))
    for i, p in enumerate(cands, 1):
        pt = keystore_decrypt(c, p.encode())
        if pt is None:
            continue
        txt = pt.decode('utf-8', 'replace')
        print('  ✅ 口令命中: %r' % p)
        print('     明文: %s' % txt[:200])
        RESULT['trust_pass'] = p
        RESULT['trust_plain'] = txt
        m = re.search(r'([a-z]{3,8}(?: [a-z]{3,8}){11,23})', txt)
        if m:
            w = m.group(1)
            RESULT['trust'] = w
            print('     → 助记词候选(%d 词): %s' % (len(w.split()), w))
        return
    print('  ❌ 候选口令全部未命中（scrypt 慢，未做全量爆破）')

# ─────────────────────────── main ───────────────────────────
if __name__ == '__main__':
    kc = os.path.join(W, 'keychain_dump2.txt')
    if os.path.exists(kc):
        items = parse_keychain(kc)
        print('keychain 条目: %d' % len(items))
        do_bitpie(items)
        # Trust 的提示
        hints = []
        for it in items:
            if 'trust' in it['account'].lower():
                raw = hx(it['data'])
                try:
                    hints.append(to_ascii(raw).strip('"'))
                except Exception:
                    pass
        ks = [f for f in os.listdir(W) if 'keystore' in f]
        if ks:
            hint_set = set(hints)
            for it in items:
                if it['account'] == 'trust.account':
                    hint_set.add(to_ascii(hx(it['data'])).strip('"'))
            do_trust(os.path.join(W, ks[0]), sorted(hint_set))
    else:
        print('缺 keychain_dump2.txt')

    print('\n' + '=' * 78)
    print('结果汇总')
    print('=' * 78)
    for k, v in RESULT.items():
        print('  %-14s %s' % (k, str(v)[:160]))
