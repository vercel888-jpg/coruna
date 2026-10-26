#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scan_keychain_seeds.py —— 通用助记词扫描（不限钱包）
  背景：decrypt_wallet18.py 是"一钱包一解析器"（Bitpie/Trust）——NEAR 钱包明文种
        （Account: nearSeed，Data: URL 编码明文）不在规则内 → 漏采。
  做法：不挑钱包，对 keychain dump 全量条目做通用识别：
    1) 解析 dump（4 行一组：Service/Group/Account/Data；也兼容 svc=..|acct=.. 单行格式）
    2) 每个 Data 值做候选展开：hex→文本、URL 解码（%20 等）
    3) 文本中搜 12/15/18/21/24 个连续 [a-z]{3,8} 词
    4) BIP39 词表 + 校验和双重验证（唯一可靠判据）
    5) 去重汇总输出
  输入：keychain dump 文件（ext_stats_*.bin JSON 容器 / 纯文本 dump），或目录（递归找）
用法: python3 scan_keychain_seeds.py <file|dir> [--json]
"""
import sys, os, re, json, base64, binascii, urllib.parse

try:
    from mnemonic import Mnemonic
    _MN = Mnemonic('english')
    _WL = set(_MN.wordlist)
except Exception:
    _MN = None
    _WL = set()

WORDSEQ_RE = re.compile(r'([a-z]{3,8}(?:\s+[a-z]{3,8}){11,23})')
# 单行兼容格式：svc=... | acct=... | grp=... | data=...
ITEM_RE = re.compile(r'svc\s*=\s*(.*?)\s*\|\s*acct\s*=\s*(.*?)\s*\|\s*grp\s*=\s*(.*?)\s*\|\s*data\s*=\s*(.*)')
# 4 行块格式
RE_SVC = re.compile(r'^Service:\s*(.*)$')
RE_GRP = re.compile(r'^Group:\s*(.*)$')
RE_ACC = re.compile(r'^Account:\s*(.*)$')
RE_DAT = re.compile(r'^Data:\s*(.*)$')


def load_content_text(path):
    """ext_stats_*.bin 是 JSON 容器（data=base64 原文）；纯文本文件原样返回。"""
    try:
        raw = open(path, 'r', encoding='utf-8', errors='ignore').read()
    except Exception:
        return ''
    if raw.lstrip()[:1] == '{':
        try:
            j = json.loads(raw)
            d = j.get('data')
            if isinstance(d, str) and d:
                try:
                    return base64.b64decode(d).decode('utf-8', 'ignore')
                except Exception:
                    return ''
        except Exception:
            pass
    return raw


def parse_items(text):
    """两种格式都吃：4 行块（dump 实际格式）与单行 svc=..|acct=.. 格式。"""
    items = []
    cur = {}
    for line in text.splitlines():
        line = line.rstrip('\r')
        m = RE_SVC.match(line)
        if m:
            if cur.get('account') is not None or cur.get('data'):
                items.append(cur)
            cur = {'service': m.group(1).strip(), 'group': '', 'account': '', 'data': ''}
            continue
        if not cur:
            # 单行兼容格式
            m2 = ITEM_RE.search(line)
            if m2:
                items.append({'service': m2.group(1), 'account': m2.group(2),
                              'group': m2.group(3), 'data': m2.group(4).strip()})
            continue
        m = RE_GRP.match(line)
        if m:
            cur['group'] = m.group(1).strip()
            continue
        m = RE_ACC.match(line)
        if m:
            cur['account'] = m.group(1).strip()
            continue
        m = RE_DAT.match(line)
        if m:
            cur['data'] = m.group(1).strip()
            continue
        # 块结束（UUID: 或空行）→ 结算
        if line.startswith('UUID:') or not line.strip():
            if cur.get('account') is not None or cur.get('data'):
                items.append(cur)
            cur = {}
    if cur.get('account') is not None or cur.get('data'):
        items.append(cur)
    return items


def hx(s):
    s = (s or '').strip()
    try:
        if re.fullmatch(r'[0-9a-fA-F]+', s) and len(s) % 2 == 0:
            return binascii.unhexlify(s)
    except Exception:
        pass
    return b''


def candidates(data):
    """一个 Data 值 → 多个候选文本"""
    out = []
    if not data or data == 'NULL':
        return out
    out.append(data)
    raw = hx(data)
    if raw:
        out.append(raw.decode('utf-8', 'ignore'))
        # 有些值 hex 里再嵌 URL 编码
        try:
            out.append(urllib.parse.unquote(raw.decode('utf-8', 'ignore')))
        except Exception:
            pass
    try:
        out.append(urllib.parse.unquote(data))
    except Exception:
        pass
    return out


def check_phrase(phrase):
    words = phrase.split()
    if len(words) not in (12, 15, 18, 21, 24):
        return False
    if _WL and not all(w in _WL for w in words):
        return False
    if _MN:
        try:
            return bool(_MN.check(phrase))
        except Exception:
            return False
    return bool(_WL)


def scan_file(path):
    text = load_content_text(path)
    items = parse_items(text)
    hits, seen = [], set()
    for it in items:
        for t in candidates(it.get('data', '')):
            for m in WORDSEQ_RE.finditer(t):
                phrase = m.group(1)
                if check_phrase(phrase) and phrase not in seen:
                    seen.add(phrase)
                    hits.append({'phrase': phrase, 'words': len(phrase.split()),
                                 'service': it.get('service', ''), 'account': it.get('account', ''),
                                 'group': it.get('group', ''), 'file': path})
    return hits, len(items)


def main():
    if len(sys.argv) < 2:
        print(__doc__); return 2
    target = sys.argv[1]
    as_json = '--json' in sys.argv
    files = []
    if os.path.isdir(target):
        for root, _d, names in os.walk(target):
            for n in names:
                if 'keychain' in n or n.startswith('ext_stats_'):
                    files.append(os.path.join(root, n))
    else:
        files = [target]

    all_hits, total_items = [], 0
    for f in files:
        hits, n = scan_file(f)
        all_hits += hits
        total_items += n
        if not as_json:
            print('扫描 %s：条目 %d，命中助记词 %d' % (os.path.basename(f), n, len(hits)))

    dedup = {}
    for h in all_hits:
        dedup.setdefault(h['phrase'], h)
    out = list(dedup.values())

    if as_json:
        print(json.dumps({'ok': True, 'files': len(files), 'items': total_items, 'count': len(out), 'seeds': out}, ensure_ascii=False))
    else:
        print('\n' + '=' * 70)
        print('通用扫描：%d 个文件 / %d 条目 → 命中 %d 条助记词（BIP39 校验通过）' % (len(files), total_items, len(out)))
        print('=' * 70)
        for h in out:
            print('\n  [%d 词] %s' % (h['words'], h['phrase']))
            print('    来源: svc=%s | acct=%s | grp=%s' % (h['service'], h['account'], h['group']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
