#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bip39_check.py —— 全站统一的助记词校验/提取模块（2026-09-19 部署）

单一实现来源（所有识别助记词/私钥的脚本共用，杜绝口径不一）：
  · bip39_valid(phrase)      —— 纯 Python BIP39 校验和验证（venv 无 mnemonic 包，自实现；
                                官方向量自测通过：abandon×11+about=True / ×12=False）
  · extract_valid(text)      —— 从自由文本提取校验通过的助记词序列：
                                ① 最大词串（连续 BIP39 单词）优先、精确长度优先
                                ② 兜底窗口扫描每串只取首个命中 → 杜绝"1/16 滑窗假命中"
  · normalize(phrase)        —— 归一化（小写+空白折叠），用于跨来源去重比对
"""
import hashlib
import os
import re


def _load_wordlist():
    """词表加载：随文件附带优先（tools/bip39_wordlist_english.txt），其次常见 venv/系统路径。
    —— 2026-09-19 节点同步修复：迁移机 venv 版本不同（3.10 等），不再依赖固定绝对路径。"""
    import glob as _g
    _here = os.path.dirname(os.path.abspath(__file__))
    cands = [os.path.join(_here, 'bip39_wordlist_english.txt')]
    cands += sorted(_g.glob('/root/venv/lib/python3*/site-packages/bip_utils/bip/bip39/wordlist/english.txt'))
    cands += sorted(_g.glob('/usr/local/lib/python3*/dist-packages/mnemonic/wordlist/english.txt'))
    cands += sorted(_g.glob('/usr/lib/python3*/dist-packages/mnemonic/wordlist/english.txt'))
    for p in cands:
        try:
            if os.path.exists(p):
                ws = [w.strip() for w in open(p) if w.strip()]
                if len(ws) == 2048:
                    return ws
        except Exception:
            continue
    raise RuntimeError('BIP39 wordlist not found（查 bip39_wordlist_english.txt 是否随工具同步）')


WLIST = _load_wordlist()
WIDX = {w: i for i, w in enumerate(WLIST)}
WL = set(WLIST)
_TOK = re.compile(r'[a-zA-Z]{3,8}')


def bip39_valid(phrase):
    """BIP39 校验和验证（12/15/18/21/24 词）。"""
    ws = (phrase or '').split()
    n = len(ws)
    if n not in (12, 15, 18, 21, 24):
        return False
    try:
        idxs = [WIDX[w] for w in ws]
    except KeyError:
        return False
    bits = ''.join(format(i, '011b') for i in idxs)
    ent_len = n * 11 * 32 // 33
    cs_len = n * 11 - ent_len
    ent = int(bits[:ent_len], 2).to_bytes(ent_len // 8, 'big')
    actual = int(bits[ent_len:], 2)
    want = hashlib.sha256(ent).digest()[0] >> (8 - cs_len)
    return actual == want


def normalize(phrase):
    return ' '.join((phrase or '').lower().split())


def _find_in_run(run, deep=False):
    """在一条"连续 BIP39 词串"里找首个有效序列 → (phrase, start, length) 或 None。
    ① 精确长度优先（整串）② 标准窗口（长串头部若干偏移）③ deep：首/尾锚定裁剪
    （防"短语前后混入少量噪声词"的漏扫；锚定式仅 2×长度 个候选，不会像全偏移扫描那样
    在大段英文里刷出 1/16 概率的假命中）。"""
    n = len(run)
    if n < 12:
        return None
    tried = []
    if n in (12, 15, 18, 21, 24):
        tried.append((n, 0))
    for off in range(0, min(3, max(1, n - 11))):
        for L in (24, 21, 18, 15, 12):
            if (L, off) not in tried:
                tried.append((L, off))
    for L, off in tried:
        seg = run[off:off + L]
        if len(seg) == L and bip39_valid(' '.join(seg)):
            return (' '.join(seg), off, L)
    if deep:
        for L in (24, 21, 18, 15, 12):
            for off2, seg in ((0, run[:L]), (max(0, n - L), run[n - L:])):
                if len(seg) == L and bip39_valid(' '.join(seg)):
                    return (' '.join(seg), off2, L)
    return None


def extract_valid(text, deep=False):
    """从自由文本提取全部"校验通过"的助记词（去重保序）。
    【2026-09-19 复审修复】一条词串内**循环提取多个**短语（两句话只隔中文/符号时，
    词元仍连成一条串，旧实现每串只取一处 → 漏掉后面的短语）。deep=True 启用首/尾锚定二遍。"""
    out, seen = [], set()
    run = []

    def flush():
        idx = 0
        while len(run) - idx >= 12:
            hit = _find_in_run(run[idx:], deep=deep)
            if not hit:
                break
            phrase, off, L = hit
            if phrase not in seen:
                seen.add(phrase)
                out.append(phrase)
            idx += off + L
        run.clear()

    for t in _TOK.findall(text or ''):
        w = t.lower()
        if w in WL:
            run.append(w)
        else:
            flush()
    flush()
    return out


def find_hex64(text):
    """64 位十六进制（私钥样式）扫描，去重保序，最多 5 条。"""
    hx = re.findall(r'(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])', text or '')
    return list(dict.fromkeys(hx))[:5]
