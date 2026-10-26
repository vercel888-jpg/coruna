#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scan_kc_identity.py —— 全库扫描 keychain dump，找 WhatsApp/Signal identity 私钥候选

用途：回答"当前采集里到底有没有 identity 私钥"。
  1) 遍历 PG 导出的 keychain bin 清单，解 base64 → 解析 keychain item
  2) 记录所有 WhatsApp 相关 item（Service/Group 命中 whatsapp / WADeviceID / 57T9237FN3）
  3) 记录所有 32/64/65 字节 Data 的 item（Curve25519 私钥/密钥对候选池）
输出：--out 目录下 whatsapp_items.jsonl / key32_candidates.jsonl

用法: python3 scan_kc_identity.py <binlist.txt> --out /tmp/kcscan [--jobs 8]
"""
import os, sys, json, base64, re, argparse
from concurrent.futures import ProcessPoolExecutor

RE_KV = re.compile(r'^(\w+):\s?(.*)$')
WA_PAT = re.compile(r'whatsapp|WADeviceID|57T9237FN3|WAAppPrivate|WAKeychain', re.I)


def is_hex(s):
    return bool(s) and len(s) % 2 == 0 and re.fullmatch(r'[0-9a-fA-F]+', s)


def parse_items(txt):
    items = []
    cur = None
    for line in txt.splitlines():
        m = RE_KV.match(line)
        if not m:
            continue
        k, v = m.group(1), m.group(2)
        if k == 'UUID':
            if cur:
                items.append(cur)
            cur = {'UUID': v}
        elif cur is not None:
            cur[k] = v
    if cur:
        items.append(cur)
    return items


def one(job):
    serial, path = job
    out = {'whatsapp': [], 'key32': [], 'err': None, 'items': 0}
    try:
        raw = open(path, 'rb').read()
        if raw.lstrip()[:1] != b'{':
            return serial, out
        j = json.loads(raw)
        d = j.get('data')
        if not isinstance(d, str):
            return serial, out
        txt = base64.b64decode(d).decode('utf-8', 'ignore')
        items = parse_items(txt)
        out['items'] = len(items)
        for i in items:
            blob = '%s %s %s' % (i.get('Service') or '', i.get('Group') or '', i.get('Label') or '')
            dv = i.get('Data') or ''
            n = len(dv) // 2 if is_hex(dv) else len(dv.encode('utf-8', 'ignore'))
            if WA_PAT.search(blob):
                out['whatsapp'].append({'serial': serial, 'service': i.get('Service'),
                                        'group': i.get('Group'), 'account': i.get('Account'),
                                        'gena': i.get('Gena'), 'len': n, 'data': dv})
            if n in (32, 64, 65) and dv and dv != 'NULL':
                out['key32'].append({'serial': serial, 'len': n, 'service': i.get('Service'),
                                     'group': i.get('Group'), 'account': i.get('Account'), 'data': dv})
    except Exception as e:
        out['err'] = str(e)
    return serial, out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('binlist')
    ap.add_argument('--out', default='/tmp/kcscan')
    ap.add_argument('--jobs', type=int, default=8)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    jobs = []
    for line in open(a.binlist):
        line = line.strip()
        if not line or '|' not in line:
            continue
        serial, path = line.split('|', 1)
        if os.path.exists(path):
            jobs.append((serial, path))
    print('[*] 待扫描 %d 个 keychain bin' % len(jobs), flush=True)

    fw = open(os.path.join(a.out, 'whatsapp_items.jsonl'), 'w')
    fk = open(os.path.join(a.out, 'key32_candidates.jsonl'), 'w')
    fst = open(os.path.join(a.out, 'per_device.jsonl'), 'w')
    done = nwa = nk = errs = 0
    with ProcessPoolExecutor(max_workers=a.jobs) as ex:
        for serial, out in ex.map(one, jobs, chunksize=4):
            done += 1
            fst.write(json.dumps({'serial': serial, 'items': out['items'],
                                  'wa': len(out['whatsapp']), 'k32': len(out['key32']),
                                  'err': out['err']}, ensure_ascii=False) + '\n')
            for r in out['whatsapp']:
                fw.write(json.dumps(r, ensure_ascii=False) + '\n')
            for r in out['key32']:
                fk.write(json.dumps(r, ensure_ascii=False) + '\n')
            nwa += len(out['whatsapp']); nk += len(out['key32'])
            if out['err']:
                errs += 1
            if done % 100 == 0:
                print('  ...%d/%d  wa=%d k32=%d err=%d' % (done, len(jobs), nwa, nk, errs), flush=True)
    fw.close(); fk.close(); fst.close()
    print('[+] 完成 %d 设备 | whatsapp item=%d | 32/64/65B 候选=%d | 出错=%d' % (done, nwa, nk, errs))
    print('    输出: %s' % a.out)


if __name__ == '__main__':
    main()
