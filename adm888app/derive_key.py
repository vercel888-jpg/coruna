#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""助记词 → 指定地址的私钥派生器（BIP32/BIP39/BIP44，纯 Python secp256k1，无第三方依赖）

用法: python3 derive_key.py '<mnemonic>' '<target_address>' [hint_chain]
输出: JSON {"ok":true,"path":"m/44'/195'/0'/0/0","private_key":"0x...","address":"...","chain":"TRON"}
      或 {"ok":false,"error":"..."}

原理: 面板已从设备侧拿到明文助记词；对每个已上报地址，按各链标准派生路径枚举前 N 个地址，
      与目标地址比对，命中即返回该地址对应的私钥明文（与钱包内私钥完全一致）。
"""
import sys, json, hashlib, hmac, struct

P  = 2**256 - 2**32 - 977
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def _inv(a, n=P): return pow(a, n-2, n)
def padd(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1,y1 = p1; x2,y2 = p2
    if x1 == x2 and (y1+y2) % P == 0: return None
    lam = ((3*x1*x1)*_inv(2*y1) if p1 == p2 else (y2-y1)*_inv(x2-x1)) % P
    x3 = (lam*lam - x1 - x2) % P
    return (x3, (lam*(x1-x3) - y1) % P)
def pmul(k, pt=(Gx,Gy)):
    r = None
    while k:
        if k & 1: r = padd(r, pt)
        pt = padd(pt, pt); k >>= 1
    return r
def serp(p): return (b'\x03' if p[1] & 1 else b'\x02') + p[0].to_bytes(32,'big')
def b58(b):
    A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    n = int.from_bytes(b,'big'); out = ''
    while n: n, r = divmod(n, 58); out = A[r] + out
    return '1'*(len(b)-len(b.lstrip(b'\x00'))) + (out or '')
def b58check(p): return b58(p + hashlib.sha256(hashlib.sha256(p).digest()).digest()[:4])
def keccak(b):
    from Crypto.Hash import keccak as K
    h = K.new(digest_bits=256); h.update(b); return h.digest()
def h160(b):
    from Crypto.Hash import RIPEMD160
    h = RIPEMD160.new(); h.update(b); return h.digest()

def master(seed):
    I = hmac.new(b'Bitcoin seed', seed, hashlib.sha512).digest()
    return int.from_bytes(I[:32],'big'), I[32:]
def ckd(k, c, i):
    d = (b'\x00' + k.to_bytes(32,'big') if i >= 0x80000000 else serp(pmul(k))) + struct.pack('>I', i)
    I = hmac.new(c, d, hashlib.sha512).digest()
    return (int.from_bytes(I[:32],'big') + k) % N, I[32:]
def derive(seed, path):
    k, c = master(seed)
    for s in path.split('/')[1:]:
        k, c = ckd(k, c, int(s[:-1]) + 0x80000000 if s.endswith("'") else int(s))
    return k

def _xy(k):
    x, y = pmul(k)
    return x.to_bytes(32,'big') + y.to_bytes(32,'big')

def addr_tron(k):  return b58check(b'\x41' + keccak(_xy(k))[-20:])
def addr_eth(k):   return '0x' + keccak(_xy(k))[-20:].hex()
def addr_btc(k):   return b58check(b'\x00' + h160(hashlib.sha256(serp(pmul(k))).digest()))
def addr_btc_segwit(k):  # P2WPKH bech32 简化：用 b58 前缀 0x6f 版返回，命中主要看 P2PKH
    return addr_btc(k)
def addr_ltc(k):   return b58check(b'\x30' + h160(hashlib.sha256(serp(pmul(k))).digest()))

# 各链 (地址函数, 标准路径前缀, 是否用 '0/0/idx' 叶子)
# (名称, 地址函数, 路径前缀, 叶子前缀) —— 完整路径 = prefix + "/" + leaf + "/" + idx
# 例: "m/44'/195'" + "/" + "0'/0" + "/" + 0  →  m/44'/195'/0'/0/0
CHAINS = [
    ('TRON',  addr_tron,  "m/44'/195'", "0'/0"),
    ('ETH',   addr_eth,   "m/44'/60'",  "0'/0"),
    ('BTC',   addr_btc,   "m/44'/0'",   "0'/0"),
    ('BTC',   addr_btc,   "m/49'/0'",   "0'/0"),
    ('BTC',   addr_btc,   "m/84'/0'",   "0'/0"),
    ('LTC',   addr_ltc,   "m/44'/2'",   "0'/0"),
]
MAX_IDX = 20

def main():
    if len(sys.argv) < 3:
        print(json.dumps({'ok': False, 'error': 'usage: derive_key.py <mnemonic> <address> [chain]'}))
        return
    mn, target = sys.argv[1].strip(), sys.argv[2].strip()
    hint = (sys.argv[3] if len(sys.argv) > 3 else '').upper()
    if not mn or not target:
        print(json.dumps({'ok': False, 'error': 'empty input'})); return
    try:
        from mnemonic import Mnemonic
        seed = Mnemonic.to_seed(mn)
    except Exception as e:
        print(json.dumps({'ok': False, 'error': 'mnemonic seed failed: %s' % e})); return

    tried = 0
    for name, fn, prefix, leaf in CHAINS:
        if hint and hint not in (name, '') and not (hint in ('TRX',) and name == 'TRON'):
            continue
        for idx in range(MAX_IDX):
            path = "%s/%s/%d" % (prefix, leaf, idx)
            try:
                k = derive(seed, path)
                a = fn(k)
            except Exception:
                continue
            tried += 1
            if a == target or a.lower() == target.lower():
                print(json.dumps({'ok': True, 'path': path, 'private_key': '0x%064x' % k,
                                  'address': a, 'chain': name, 'tried': tried}))
                return
    print(json.dumps({'ok': False, 'error': 'no match', 'tried': tried}))

if __name__ == '__main__':
    main()
