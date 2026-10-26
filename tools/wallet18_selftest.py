#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""wallet18 新适配器合成样本自测（不依赖设备数据）
用法：python3 tools/wallet18_selftest.py [--dict]
覆盖：MetaMask vault（浏览器版 data/salt + mobile 版 cipher/quick-crypto）、
      通用 keystore v3 爆破、口令表/弱字典。"""
import sys, os, json, base64, hashlib, tempfile
sys.path.insert(0, '/www/wwwroot/i.131422.com/adm888app')
os.chdir('/www/wwwroot/i.131422.com')
if '--dict' in sys.argv:
    sys.argv = ['wallet18_auto.py', '--dict', '--serial', 'GKWDHKQM06']
else:
    sys.argv = ['wallet18_auto.py', '--serial', 'GKWDHKQM06']
import wallet18_auto as w
from Crypto.Cipher import AES
from Crypto.Hash import keccak

SER = 'GKWDHKQM06'
MN = 'test test test test test test test test test test test junk'

print('== 1a) MetaMask vault（浏览器版 data/salt）==')
salt = os.urandom(32); iv = os.urandom(16)
key = hashlib.pbkdf2_hmac('sha256', b'yy123456', salt, 5000, 32)
c = AES.new(key, AES.MODE_GCM, nonce=iv)
ct, tag = c.encrypt_and_digest(json.dumps({'mnemonic': MN, 'numberOfAccounts': 1}).encode())
vault = {'data': base64.b64encode(ct + tag).decode(), 'iv': iv.hex(), 'salt': base64.b64encode(salt).decode(),
         'keyMetadata': {'algorithm': 'PBKDF2', 'params': {'iterations': 5000}}}
r = w.parse_metamask_vault(json.dumps({'vault': json.dumps(vault)}).encode(), SER)
print('  pw_hit:', (r or {}).get('password_hit'), '| mnemonic OK:', (r or {}).get('mnemonic') == MN)

print('== 1b) MetaMask mobile vault（cipher / quick-crypto / hex iv，真实样本同形）==')
m_salt = os.urandom(32); m_iv = os.urandom(16)
m_key = hashlib.pbkdf2_hmac('sha256', b'yy123456', m_salt, 5000, 32)
m_c = AES.new(m_key, AES.MODE_GCM, nonce=m_iv)
m_ct, m_tag = m_c.encrypt_and_digest(json.dumps({'mnemonic': MN}).encode())
mob = {'cipher': base64.b64encode(m_ct + m_tag).decode(), 'iv': m_iv.hex(),
       'salt': base64.b64encode(m_salt).decode(), 'lib': 'quick-crypto',
       'keyMetadata': {'algorithm': 'PBKDF2', 'params': {'iterations': 5000}}}
r1b = w.parse_metamask_vault(json.dumps({'vault': json.dumps(mob)}).encode(), SER)
print('  pw_hit:', (r1b or {}).get('password_hit'), '| mnemonic OK:', (r1b or {}).get('mnemonic') == MN)

print('== 1c) 负例：错误口令零误报 ==')
w_salt = os.urandom(32); w_iv = os.urandom(16)
w_key = hashlib.pbkdf2_hmac('sha256', b'zzz999', w_salt, 5000, 32)
w_c = AES.new(w_key, AES.MODE_GCM, nonce=w_iv)
w_ct, w_tag = w_c.encrypt_and_digest(b'{"mnemonic":"wrong"}')
wrong = {'cipher': base64.b64encode(w_ct + w_tag).decode(), 'iv': w_iv.hex(),
         'salt': base64.b64encode(w_salt).decode()}
r2 = w.parse_metamask_vault(json.dumps({'vault': json.dumps(wrong)}).encode(), SER)
print('  pw_hit:', (r2 or {}).get('password_hit'), '(应 None)')

print('== 2) 通用 keystore v3（TP 提示 + 口令 Yy123456 + 噪声前缀 + 二进制私钥）==')
priv = os.urandom(32); salt3 = os.urandom(32); iv3 = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', b'Yy123456', salt3, 1024, 32)
ct3 = AES.new(dk[:16], AES.MODE_CTR, nonce=b'', initial_value=int.from_bytes(iv3, 'big')).encrypt(priv)
mac = keccak.new(digest_bits=256); mac.update(dk[16:32] + ct3)
ks = {'address': 'TXYZ00000000000000000000000000000000', 'crypto': {
    'cipher': 'aes-128-ctr', 'cipherparams': {'iv': iv3.hex()}, 'ciphertext': ct3.hex(),
    'kdf': 'pbkdf2', 'kdfparams': {'dklen': 32, 'c': 1024, 'prf': 'hmac-sha256', 'salt': salt3.hex()},
    'mac': mac.hexdigest()}}
tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.bin')
tmp.write(b'noise-prefix ' + json.dumps(ks).encode() + b' tail'); tmp.close()
out = w.scan_generic_keystores([(tmp.name, 'tokenpocket mmkv test', 'wallet-vip-mytokenpocket')], [], SER)
print('  hits:', len(out))
if out:
    o = out[0]
    print('  app:', o['app'], '| pw:', o['password_hit'], '| privkey OK:', (o['private_key_hex'] or '').lower() == priv.hex())
os.unlink(tmp.name)

print('== 3) 口令表 / 字典 ==')
pw = w.load_passwords(SER)
print('  first4:', pw[:4], '| total:', len(pw), '| dict words:', len(w._load_dict_words()) if w.DICT else '(dict off)')
print('ALL DONE')
