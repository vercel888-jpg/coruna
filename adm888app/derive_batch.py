#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""批量私钥派生：一条助记词 → 枚举各链标准路径 → 与目标地址集合比对 → 输出命中项

用途：面板 lootStore 扫描太慢不能同步派生，改为离线批处理填缓存 data/derived_keys.json
输入(stdin JSON): {"mnemonic":"...", "targets":[{"addr":"TV...","chain":"coin195"}, ...], "maxIdx":5}
输出(stdout JSON): {"ok":true,"hits":[{"addr":"...","path":"...","private_key":"0x...","chain":"TRON"}]}
"""
import sys, json, hashlib, hmac, struct, re

P  = 2**256 - 2**32 - 977
N  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def _inv(a, n=P): return pow(a, n-2, n)
def padd(p1,p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1,y1=p1; x2,y2=p2
    if x1==x2 and (y1+y2)%P==0: return None
    lam = ((3*x1*x1)*_inv(2*y1) if p1==p2 else (y2-y1)*_inv(x2-x1)) % P
    x3=(lam*lam-x1-x2)%P
    return (x3,(lam*(x1-x3)-y1)%P)
def _pmul_py(k, pt=(Gx,Gy)):
    r=None
    while k:
        if k&1: r=padd(r,pt)
        pt=padd(pt,pt); k>>=1
    return r
# 【2026-09-14 提速】点乘改用 eth_keys（底层 C 实现，实测 0.56ms/次 vs 纯 Python ~12ms ≈ 22× 提速；
#   101 个候选地址的派生调用从 19.7s 降至 ~1s）。不可用时自动回退纯实现。本文件调用均为基点乘法。
try:
    from eth_keys import keys as _ethkeys
    def pmul(k, pt=(Gx,Gy)):
        if pt != (Gx,Gy):
            return _pmul_py(k, pt)
        b = _ethkeys.PrivateKey(k.to_bytes(32, 'big')).public_key.to_bytes()
        return (int.from_bytes(b[:32], 'big'), int.from_bytes(b[32:], 'big'))
except Exception:
    def pmul(k, pt=(Gx,Gy)): return _pmul_py(k, pt)
def serp(p): return (b'\x03' if p[1]&1 else b'\x02')+p[0].to_bytes(32,'big')
def b58(b):
    A='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    n=int.from_bytes(b,'big'); out=''
    while n: n,r=divmod(n,58); out=A[r]+out
    return '1'*(len(b)-len(b.lstrip(b'\x00')))+(out or '')
def b58check(p): return b58(p+hashlib.sha256(hashlib.sha256(p).digest()).digest()[:4])
def keccak(b):
    from Crypto.Hash import keccak as K
    h=K.new(digest_bits=256); h.update(b); return h.digest()
def h160(b):
    from Crypto.Hash import RIPEMD160
    h=RIPEMD160.new(); h.update(b); return h.digest()
def master(seed):
    I=hmac.new(b'Bitcoin seed',seed,hashlib.sha512).digest()
    return int.from_bytes(I[:32],'big'), I[32:]
def ckd(k,c,i):
    d=(b'\x00'+k.to_bytes(32,'big') if i>=0x80000000 else serp(pmul(k)))+struct.pack('>I',i)
    I=hmac.new(c,d,hashlib.sha512).digest()
    return (int.from_bytes(I[:32],'big')+k)%N, I[32:]
def derive(seed,path):
    k,c=master(seed)
    for s in path.split('/')[1:]:
        k,c=ckd(k,c,int(s[:-1])+0x80000000 if s.endswith("'") else int(s))
    return k
def _xy(k):
    x,y=pmul(k); return x.to_bytes(32,'big')+y.to_bytes(32,'big')

def a_tron(k): return b58check(b'\x41'+keccak(_xy(k))[-20:])
def a_eth(k):  return '0x'+keccak(_xy(k))[-20:].hex()
def a_btc(k):  return b58check(b'\x00'+h160(hashlib.sha256(serp(pmul(k))).digest()))
def a_ltc(k):  return b58check(b'\x30'+h160(hashlib.sha256(serp(pmul(k))).digest()))
def a_bch(k):  return b58check(b'\x00'+h160(hashlib.sha256(serp(pmul(k))).digest()))
# 【P3b 修复】DOGE/DASH/MONA 此前误用 BTC 版本字节（0x00）→ 生成 1... 而上传的是 D.../X.../M...，永远错配
def a_doge(k): return b58check(b'\x1e'+h160(hashlib.sha256(serp(pmul(k))).digest()))
def a_dash(k): return b58check(b'\x4c'+h160(hashlib.sha256(serp(pmul(k))).digest()))
def a_mona(k): return b58check(b'\x32'+h160(hashlib.sha256(serp(pmul(k))).digest()))

# ── 【2026-09-14 P3】BIP49（P2SH-P2WPKH：3.../M...）与 BIP84（P2WPKH bech32：bc1.../ltc1...）──
#   bech32 为 BIP173 参考实现（纯 Python，无额外依赖）
_B32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
def _b32_polymod(values):
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk
def _b32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
def _b32_create_checksum(hrp, data, spec=1):
    values = _b32_hrp_expand(hrp) + data
    polymod = _b32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ spec
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
def _b32_encode(hrp, data, spec=1):
    combined = data + _b32_create_checksum(hrp, data, spec)
    return hrp + '1' + ''.join([_B32_CHARSET[d] for d in combined])
def _b32_convertbits(data, frombits, tobits, pad=True):
    acc = 0; bits = 0; ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret
def a_p2wpkh(k, hrp):
    """BIP84 原生隔离见证：witness v0 + HASH160(pubkey) → bech32"""
    return _b32_encode(hrp, [0] + _b32_convertbits(h160(hashlib.sha256(serp(pmul(k))).digest()), 8, 5))
def a_p2sh_p2wpkh(k, ver):
    """BIP49 兼容隔离见证：redeemScript=0014||HASH160(pubkey) → P2SH 地址"""
    redeem = b'\x00\x14' + h160(hashlib.sha256(serp(pmul(k))).digest())
    return b58check(bytes([ver]) + h160(hashlib.sha256(redeem).digest()))
def a_btc84(k): return a_p2wpkh(k, 'bc')
def a_btc49(k): return a_p2sh_p2wpkh(k, 0x05)
def a_ltc84(k): return a_p2wpkh(k, 'ltc')
def a_ltc49(k): return a_p2sh_p2wpkh(k, 0x32)
# ── 【P3b】BIP86 Taproot（bc1p：bech32m + x-only 公钥）与 BCH cashaddr（bitcoincash:q...）──
def a_btc86(k):
    # BIP341/86：输出键 = 内部键(even-y) + hashTapTweak(x-only)·G（此前漏了 TapTweak → 地址全错）
    x, y = pmul(k)
    if y % 2 != 0:
        y = P - y
    tag = hashlib.sha256(b'TapTweak').digest()
    t = int.from_bytes(hashlib.sha256(tag + tag + x.to_bytes(32, 'big')).digest(), 'big')
    qx, _qy = padd((x, y), pmul(t))
    return _b32_encode('bc', [1] + _b32_convertbits(qx.to_bytes(32, 'big'), 8, 5), 0x2bc830a3)
def _cash_polymod(values):
    gen = [0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470]
    chk = 1
    for v in values:
        b = chk >> 35
        chk = ((chk & 0x07ffffffff) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1: chk ^= gen[i]
    return chk ^ 1
def a_bch_cashaddr(k):
    h = h160(hashlib.sha256(serp(pmul(k))).digest())
    payload = _b32_convertbits(b'\x00' + h, 8, 5)
    prefix = 'bitcoincash'
    pm = _cash_polymod([ord(x) & 31 for x in prefix] + [0] + payload + [0] * 8)
    chk = [(pm >> 5 * (7 - i)) & 31 for i in range(8)]
    return prefix + ':' + ''.join(_B32_CHARSET[d] for d in payload + chk)

# 每个 coin 的候选 (purpose, 地址函数)；未列出的默认只走 BIP44
VARIANTS = {
    0: [(44, a_btc), (49, a_btc49), (84, a_btc84), (86, a_btc86)],
    2: [(44, a_ltc), (49, a_ltc49), (84, a_ltc84)],
    145: [(44, a_bch), (44, a_bch_cashaddr)],
}
def variants_of(coin, fn):
    return VARIANTS.get(coin, [(44, fn)])

# ── 【P3b】Ed25519 系（SLIP-0010，全硬化路径）：Solana / SUI / Aptos ──
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _Ed25519PK
    def _ed_pub(k):
        return _Ed25519PK.from_private_bytes(k).public_key().public_bytes_raw()
    def _slip10_master(seed):
        I = hmac.new(b'ed25519 seed', seed, hashlib.sha512).digest()
        return I[:32], I[32:]
    def _slip10_ckd(k, c, i):
        I = hmac.new(c, b'\x00' + k + struct.pack('>I', i | 0x80000000), hashlib.sha512).digest()
        return I[:32], I[32:]
    def slip10_path(seed, path):
        k, c = _slip10_master(seed)
        for s in path.split('/'):
            seg = s[:-1] if s.endswith("'") else s
            k, c = _slip10_ckd(k, c, int(seg))
        return k
    def a_sol(k): return b58(_ed_pub(k))
    def a_sui(k): return '0x' + hashlib.blake2b(b'\x00' + _ed_pub(k), digest_size=32).hexdigest()
    def a_apt(k): return '0x' + hashlib.sha3_256(_ed_pub(k) + b'\x00').hexdigest()
except Exception:
    slip10_path = None
    def a_sol(k): return ''
    def a_sui(k): return ''
    def a_apt(k): return ''
# coin → (名称, 地址函数, 候选路径[])（ed25519 全硬化）
ED_COIN = {
    501: ('SOL', a_sol, ["44'/501'/0'/0'", "44'/501'/0'"]),
    784: ('SUI', a_sui, ["44'/784'/0'/0'/0'"]),
    637: ('APT', a_apt, ["44'/637'/0'/0'/0'"]),
}

# ── 【P3b 关键修复】coin 推断：chain 字段常是"钱包应用名"（Bitget/MetaMask/Exodus/imToken…），
#   此前默认按 ETH 试 → 大量 BTC/LTC/TRON 形态地址永远错链。改为 chain 识别 + 地址形态推断双路。──
def infer_coins(addr, chain):
    a = (addr or '').strip()
    al = a.lower()
    coins = set()
    c = str(chain or '').strip()
    cu = c.upper()
    if cu == 'BTC': coins.add(0)
    elif cu in ('ETH', 'ETHEREUM'): coins.add(60)
    elif cu in ('TRON', 'TRX'): coins.add(195)
    elif cu.startswith('COIN') and c[4:].isdigit(): coins.add(int(c[4:]))
    if re.match(r'^bc1[a-z0-9]{11,71}$', al): coins.add(0)
    elif re.match(r'^ltc1[a-z0-9]{11,71}$', al): coins.add(2)
    elif re.match(r'^[13][1-9A-HJ-NP-Za-km-z]{25,34}$', a): coins.update((0, 145))
    elif re.match(r'^[LM][1-9A-HJ-NP-Za-km-z]{25,34}$', a): coins.add(2)
    elif re.match(r'^D[1-9A-HJ-NP-Za-km-z]{33}$', a): coins.add(3)
    elif re.match(r'^X[1-9A-HJ-NP-Za-km-z]{33}$', a): coins.add(5)
    elif re.match(r'^T[1-9A-HJ-NP-Za-km-z]{33}$', a): coins.add(195)
    elif re.match(r'^bitcoincash:', al): coins.add(145)
    elif re.match(r'^0x[0-9a-fA-F]{40}$', al): coins.add(60)
    elif re.match(r'^0x[0-9a-fA-F]{64}$', al): coins.update((784, 637))
    elif re.match(r'^[1-9A-HJ-NP-Za-km-z]{43,44}$', a): coins.add(501)
    if not coins:
        coins.add(60)
    return coins

# SLIP-44 coin_type → (显示名, 地址函数)  —— 仅 secp256k1 链（Solana/Ed25519 不在此列）
COIN = {
    0:   ('BTC', a_btc), 2: ('LTC', a_ltc), 60: ('ETH', a_eth), 145: ('BCH', a_bch),
    118: ('ATOM', a_eth), 195: ('TRON', a_tron), 714: ('BNB', a_eth),
    966: ('MATIC', a_eth), 3: ('DOGE', a_doge), 5: ('DASH', a_dash), 22: ('MONA', a_mona),
    61: ('ETC', a_eth), 137: ('RSK', a_btc), 199: ('BTT', a_tron), 500: ('XLM', a_eth),
}
def coin_of(chain):
    """把面板地址的 chain 字段解析成 coin_type"""
    c = str(chain or '').strip()
    if c.upper() in ('BTC',): return 0
    if c.upper() in ('ETH',): return 60
    if c.upper() in ('TRON','TRX'): return 195
    if c.lower().startswith('coin'):
        try: return int(c[4:])
        except: return None
    return 60  # 未知默认按 ETH 试

def main():
    try:
        req = json.load(sys.stdin)
    except Exception as e:
        print(json.dumps({'ok': False, 'error': 'bad input: %s' % e})); return
    mn = (req.get('mnemonic') or '').strip()
    targets = req.get('targets') or []
    max_idx = int(req.get('maxIdx') or 5)
    if not mn:
        print(json.dumps({'ok': False, 'error': 'missing mnemonic'})); return
    if not targets and not req.get('generate'):
        print(json.dumps({'ok': False, 'error': 'missing mnemonic/targets'})); return
    try:
        from mnemonic import Mnemonic
        seed = Mnemonic.to_seed(mn)
    except Exception as e:
        print(json.dumps({'ok': False, 'error': 'seed failed: %s' % e})); return

    # ── 【2026-09-14 生成模式·热门链】助记词 → 该钱包"应有"的标准地址（供面板展示；与匹配模式互斥）──
    #   热门链口径（用户确认）：BTC(44/49/84/86) · LTC(44/49/84) · DOGE · ETH(EVM) · TRON · SOL
    #   【2026-09-14 按需生成】genCoins 参数：只生成设备实际上报的链（如 [0,60,195]），
    #   不传则维持老口径（全 6 链）。目的：避免为没用到的链生成大量永远匹配不上的地址。
    if req.get('generate'):
        gen_idx = int(req.get('genIdx') or 5)
        gen_coins = req.get('genCoins')   # 可选：coin 白名单（secp256k1 侧）；None=全量
        gens = []
        for coin in (0, 2, 3, 60, 195):    # BTC · LTC · DOGE · ETH(EVM) · TRON（secp256k1）
            if gen_coins is not None and coin not in gen_coins:
                continue
            cname, fn = COIN[coin]
            for purpose, afn in variants_of(coin, fn):
                for idx in range(gen_idx):
                    pth = "m/%d'/%d'/0'/0/%d" % (purpose, coin, idx)
                    try:
                        k = derive(seed, pth); a = afn(k)
                    except Exception:
                        continue
                    if a:
                        gens.append({'addr': a, 'path': pth, 'chain': cname, 'private_key': '0x%064x' % k})
        if slip10_path and (gen_coins is None or 501 in gen_coins):
            for coin in (501,):            # SOL（ed25519）
                cname, afn, paths = ED_COIN[coin]
                for pth2 in paths:
                    try:
                        k2 = slip10_path(seed, pth2); a2 = afn(k2)
                    except Exception:
                        continue
                    if a2:
                        gens.append({'addr': a2, 'path': 'm/' + pth2, 'chain': cname, 'private_key': k2.hex()})
        print(json.dumps({'ok': True, 'generated': gens}))
        return

    # 目标索引：地址 → 候选 coin 集合（【P3b】chain 识别 + 地址形态推断）
    want = {}
    for t in targets:
        ad = (t.get('addr') or '').strip()
        if not ad: continue
        want.setdefault(ad.lower(), set()).update(infer_coins(ad, t.get('chain')))
    hits = []
    seen = set()

    def _try(coin, cname, path, afunc, k_raw=None):
        try:
            k = k_raw if k_raw is not None else derive(seed, path)
            a = afunc(k)
        except Exception:
            return
        if not a:
            return
        key = a.lower()
        if key in want and coin in want[key] and key not in seen:
            seen.add(key)
            pk = k.hex() if isinstance(k, (bytes, bytearray)) else ('0x%064x' % k)
            hits.append({'addr': a, 'path': path, 'private_key': pk, 'chain': cname})

    # ① secp256k1 主表（BTC 44/49/84/86 · LTC 44/49/84 · BCH legacy+cashaddr 多路径）
    for coin, (cname, fn) in COIN.items():
        if not any(coin in v for v in want.values()): continue
        for purpose, afn in variants_of(coin, fn):
            for idx in range(max_idx):
                _try(coin, cname, "m/%d'/%d'/0'/0/%d" % (purpose, coin, idx), afn)
    # ② 未收录 coin_type（多为小众 EVM 链）：目标含 0x 地址时按该 coin 的 BIP44 路径 + ETH 地址函数试
    all_coins = set()
    for v in want.values(): all_coins |= v
    for coin in sorted(all_coins):
        if coin in COIN or coin in ED_COIN or coin <= 0: continue
        if not any(coin in v and re.match(r'^0x[0-9a-fA-F]{40}$', ad) for ad, v in want.items()): continue
        for idx in range(max_idx):
            _try(coin, 'coin%d(EVM)' % coin, "m/44'/%d'/0'/0/%d" % (coin, idx), a_eth)
    # ③ Ed25519 系（SLIP-0010，全硬化）：Solana / SUI / Aptos
    if slip10_path:
        for coin, (cname, afn, paths) in ED_COIN.items():
            if not any(coin in v for v in want.values()): continue
            for pth in paths:
                try: k2 = slip10_path(seed, pth)
                except Exception: continue
                _try(coin, cname, 'm/' + pth, afn, k2)
    print(json.dumps({'ok': True, 'hits': hits, 'checked': len(want)}))

if __name__ == '__main__':
    main()
