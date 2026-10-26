#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""t_decrypt.py — /t 通道 `file` 字段容器解析 + CCCrypt 运行时 key 解密

容器结构（2026-09-11 由 399 个同长度样本逐偏移恒定度分析定案）:

    [0 .. 31]      32B   明文头（同长度类内 100% 恒定）
    [32 .. L-51]   ct    AES-256-ECB/PKCS7 密文（长度 = L-82，恒为 16 的整数倍）
    [L-50 .. L-1]  50B   尾部（含 16B 变化区 + 5B 固定 0c80da0a01 + 4B 变化 + 00 00）

mod-16 验证（全部 8 个长度类零误差）:
    L=59346 → ct=59264=16x3704     L=48034  → ct=47952=16x2997
    L=54178 → ct=54096=16x3381     L=183714 → ct=183632=16x11477
    L=42658 → ct=42576=16x2661     L=114658 → ct=114576=16x7161
    L=32402 → ct=32320=16x2020     L=36690  → ct=36608=16x2288

CCCrypt 实参（设备侧动态捕获）:
    op=0 kCCEncrypt  alg=0 kCCAlgorithmAES  key_len=32 (AES-256)
    options=3 (PKCS7Padding|ECBMode)  iv=NULL
    ★ 注意 dlen 是【明文】长度（加密语义），密文 = ceil16(dlen)

用法:
    t_decrypt.py info  <post_t.bin>                    # 打印容器结构
    t_decrypt.py dec   <post_t.bin> <key_hex>          # 解密（自动试尾部长度）
    t_decrypt.py try   <key_hex>                       # 用该 key 扫全库找命中
    t_decrypt.py keys  <keylist.txt> <post_t.bin>      # 用一批 key 试一个文件
"""
import sys
import os
import re
import glob
import json
import binascii
import collections

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import t_find  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POSTS = os.path.join(ROOT, 'loot', 'unknown_posts')

HDR = 32
# 尾部长度候选：必须满足 (L - HDR - T) % 16 == 0 且 T >= 50（50 之前是恒定区，不可能是密文）
TRAILER_CANDIDATES = [50, 66, 82, 98, 114, 34, 18]

try:
    from Crypto.Cipher import AES
    HAVE_AES = True
except Exception:  # pragma: no cover
    HAVE_AES = False


# ---------------------------------------------------------------- 工具
def get_file_blob(data: bytes) -> bytes:
    """从 post_t .bin（multipart）里取出 file 字段；不是 multipart 就整块当 file。"""
    if data[:2] == b'--':
        f = t_find.parse_multipart(data)
        if 'file' in f:
            return f['file']
    return data


def valid_pkcs7(pt: bytes) -> bool:
    if not pt:
        return False
    n = pt[-1]
    if n < 1 or n > 16 or n > len(pt):
        return False
    return pt[-n:] == bytes([n]) * n


def printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    ok = sum(1 for c in b if 9 <= c <= 13 or 32 <= c <= 126 or c >= 0x80)
    return ok / len(b)


def sniff(pt: bytes) -> str:
    """给明文猜个类型，方便一眼看出解对没解对。"""
    head = pt[:16]
    if head.startswith(b'{') or head.startswith(b'['):
        return 'JSON'
    if head.startswith(b'bplist00'):
        return 'binary plist'
    if head.startswith(b'SQLite format 3'):
        return 'SQLite'
    if head.startswith(b'<?xml'):
        return 'XML/plist'
    if head[:4] == b'\x50\x4b\x03\x04':
        return 'ZIP'
    if head.startswith(b'\x1f\x8b'):
        return 'gzip'
    if head[:3] == b'\xff\xd8\xff':
        return 'JPEG'
    if head.startswith(b'\x89PNG'):
        return 'PNG'
    if re.match(rb'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}', head):
        return 'UUID-ish text'
    r = printable_ratio(pt[:512])
    if r > 0.95:
        return 'text (%.0f%% printable)' % (r * 100)
    if r > 0.6:
        return 'mostly-text (%.0f%%)' % (r * 100)
    return 'binary (%.0f%% printable)' % (r * 100)


def aes_ecb_dec(ct: bytes, key: bytes) -> bytes:
    c = AES.new(key, AES.MODE_ECB)
    return c.decrypt(ct)


def try_decrypt(blob: bytes, key: bytes, verbose=False):
    """返回 [(trailer_len, plaintext, valid_pad, ratio)]，按可信度排序。"""
    out = []
    for T in TRAILER_CANDIDATES:
        ct_len = len(blob) - HDR - T
        if ct_len <= 0 or ct_len % 16:
            continue
        ct = blob[HDR:HDR + ct_len]
        try:
            pt = aes_ecb_dec(ct, key)
        except Exception:
            continue
        good = valid_pkcs7(pt)
        ratio = printable_ratio(pt[:1024])
        out.append((T, pt, good, ratio))
    # 优先：padding 合法；其次可打印率高
    out.sort(key=lambda x: (not x[2], -x[3]))
    return out


# ---------------------------------------------------------------- 子命令
def cmd_info(path):
    data = open(path, 'rb').read()
    blob = get_file_blob(data)
    print(f'输入       : {path}  ({len(data)}B)')
    print(f'file 字段  : {len(blob)}B')
    print(f'32B 头     : {binascii.hexlify(blob[:32]).decode()}')
    print(f'  +00 u32  : 0x%08x     +04 magic: 0x%08x' % (
        int.from_bytes(blob[0:4], 'little'), int.from_bytes(blob[4:8], 'little')))
    print(f'  +08 u32  : 0x%08x     +0c magic: 0x%08x' % (
        int.from_bytes(blob[8:12], 'little'), int.from_bytes(blob[12:16], 'little')))
    print(f'  +10 u32  : 0x%08x     +14 u16  : 0x%04x' % (
        int.from_bytes(blob[16:20], 'little'), int.from_bytes(blob[20:22], 'little')))
    print(f'尾 50B     : {binascii.hexlify(blob[-50:]).decode()}')
    L = len(blob)
    print(f'\n密文候选（L-32-T 且 %16==0）:')
    for T in TRAILER_CANDIDATES:
        cl = L - HDR - T
        if cl > 0 and cl % 16 == 0:
            mark = ' ← 推荐' if T == 50 else ''
            print(f'  trailer={T:3d}  密文={cl:7d}B = 16 x {cl // 16}{mark}')
    ct = L - HDR - 50
    print(f'\n★ 设备侧 CCCrypt 的 dlen 是【明文】长度，本文件预期区间: '
          f'{ct - 16} .. {ct - 1}   (密文 {ct}B = 16 x {ct // 16})')
    return 0


def cmd_dec(path, key_hex):
    key = bytes.fromhex(key_hex)
    if len(key) not in (16, 24, 32):
        print(f'!! key 长度 {len(key)} 非法（应 16/24/32）')
        return 2
    blob = get_file_blob(open(path, 'rb').read())
    res = try_decrypt(blob, key)
    if not res:
        print('!! 没有可用的密文长度')
        return 2
    print(f'key = {key_hex}  ({len(key) * 8}bit)')
    print(f'file = {len(blob)}B   算法 = AES-{len(key) * 8}-ECB/PKCS7\n')
    hit = False
    for T, pt, good, ratio in res:
        flag = '✓ padding 合法' if good else '✗ padding 非法'
        print(f'--- trailer={T:3d}  ct={len(pt)}B  {flag}  可打印率={ratio * 100:.0f}%')
        if good:
            hit = True
            body = pt[:-pt[-1]]
            print(f'    ★ 去 padding 后明文 {len(body)}B  类型: {sniff(body)}')
            print('    前 512B:')
            print('    ' + repr(body[:512]))
            try:
                s = body.decode('utf-8')
                print('    UTF-8 全文:')
                print(s[:3000])
            except Exception:
                print('    (非 UTF-8，十六进制前 256B)')
                print('    ' + binascii.hexlify(body[:256]).decode())
    if not hit:
        print('\n!! 所有候选 trailer 长度都解不出合法 padding —— key 不对，或不是这批数据')
        print('   提示：dlen（明文长度）应满足 ceil16(dlen) == file_len - 82')
        d0 = len(blob) - 82
        print(f'   本文件预期明文长度区间: {d0 - 16} .. {d0 - 1}  (密文 {d0}B)')
    return 0 if hit else 1


def cmd_try(key_hex, limit=0):
    key = bytes.fromhex(key_hex)
    bins = sorted(glob.glob(os.path.join(POSTS, 'post_t_*.bin')))
    print(f'key = {key_hex}')
    print(f'扫描 {len(bins)} 个 post_t ...')
    hits = []
    for i, b in enumerate(bins):
        try:
            blob = get_file_blob(open(b, 'rb').read())
        except Exception:
            continue
        if len(blob) < 100:
            continue
        for T, pt, good, ratio in try_decrypt(blob, key):
            if good:
                hits.append((b, len(blob), T, pt))
                break
        if limit and len(hits) >= limit:
            break
        if i % 500 == 0 and i:
            print(f'  ... {i}/{len(bins)}  命中 {len(hits)}')
    print(f'\n命中 {len(hits)} 个:')
    for b, L, T, pt in hits[:20]:
        body = pt[:-pt[-1]]
        print(f'  {os.path.basename(b)}  file={L}B trailer={T} -> {len(body)}B {sniff(body)}')
        print(f'    {body[:300]!r}')
    return 0 if hits else 1


def cmd_keys(keyfile, path):
    keys = []
    with open(keyfile) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            m = re.search(r'\b([0-9a-fA-F]{32,64})\b', line)
            if m:
                keys.append(m.group(1))
    print(f'载入 {len(keys)} 个 key')
    blob = get_file_blob(open(path, 'rb').read())
    print(f'file = {len(blob)}B')
    for k in keys:
        try:
            res = try_decrypt(blob, bytes.fromhex(k))
        except Exception:
            continue
        for T, pt, good, ratio in res:
            if good:
                body = pt[:-pt[-1]]
                print(f'★ 命中 key={k} trailer={T} -> {len(body)}B {sniff(body)}')
                print(repr(body[:600]))
                return 0
    print('全部不命中')
    return 1


def main():
    if not HAVE_AES:
        print('!! 缺 pycryptodome: pip install pycryptodome')
        return 2
    a = sys.argv[1:]
    if not a:
        print(__doc__)
        return 1
    cmd = a[0]
    if cmd == 'info' and len(a) == 2:
        return cmd_info(a[1])
    if cmd == 'dec' and len(a) == 3:
        return cmd_dec(a[1], a[2])
    if cmd == 'try' and len(a) >= 2:
        return cmd_try(a[1], int(a[2]) if len(a) > 2 else 0)
    if cmd == 'keys' and len(a) == 3:
        return cmd_keys(a[1], a[2])
    print(__doc__)
    return 1


if __name__ == '__main__':
    sys.exit(main())
