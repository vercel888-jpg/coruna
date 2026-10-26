#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scan_kc_creds.py —— 全库 keychain dump 扫 WhatsApp 注册凭证项

目标键名（account/service/label/gena 任一命中，大小写不敏感）:
  NoiseKey / AdvSecretKey / IdentityKey / SignedPreKey / RegistrationId /
  PreKey / Adv / Noise / ClientPayload / Credentials

输入: <binlist.txt>  serial|bin_path
输出: --out 目录
  hits.jsonl    命中项（serial/service/group/account/gena/len/data）
  keys.json     按设备聚合：serial -> {NoiseKey:..., AdvSecretKey:...}
用法: python3 scan_kc_creds.py <binlist.txt> --out /tmp/kc_creds [--jobs 8]
"""
import os, re, sys, json, base64, argparse
from concurrent.futures import ProcessPoolExecutor

RE_KV = re.compile(r'^(\w+):\s?(.*)$')
WANT = re.compile(r'noise\s*key|adv\s*secret|advsecret|identity\s*key|identitykey|signed\s*pre\s*key|'
                  r'signedprekey|registration\s*id|registrationid|client\s*payload|clientpayload|'
                  r'prekey|pre_key|advkey|adv_key|\badv\b|\bnoise\b|credentials', re.I)
NOISE = re.compile(r'noise', re.I)
ADV = re.compile(r'adv\s*secret|advsecret|adv_key|advkey', re.I)


def parse_items(txt):
    items, cur = [], None
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


def ishex(s):
    return bool(s) and len(s) % 2 == 0 and re.fullmatch(r'[0-9a-fA-F]+', s)


def one(job):
    serial, path = job
    out = []
    try:
        raw = open(path, 'rb').read()
        if raw.lstrip()[:1] != b'{':
            return serial, out
        d = json.loads(raw).get('data')
        if not isinstance(d, str):
            return serial, out
        txt = base64.b64decode(d).decode('utf-8', 'ignore')
        for i in parse_items(txt):
            blob = ' | '.join(str(i.get(k) or '') for k in
                              ('Service', 'Group', 'Account', 'Label', 'Gena', 'Desc', 'Comment'))
            if not WANT.search(blob):
                continue
            dv = i.get('Data') or ''
            n = len(dv) // 2 if ishex(dv) else len(dv.encode('utf-8', 'ignore'))
            out.append({'serial': serial, 'service': i.get('Service'), 'group': i.get('Group'),
                        'account': i.get('Account'), 'gena': i.get('Gena'),
                        'label': i.get('Label'), 'len': n, 'data': dv,
                        'isNoise': bool(NOISE.search(blob)), 'isAdv': bool(ADV.search(blob))})
    except Exception:
        pass
    return serial, out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('binlist')
    ap.add_argument('--out', default='/tmp/kc_creds')
    ap.add_argument('--jobs', type=int, default=8)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    jobs = []
    for line in open(a.binlist):
        line = line.strip()
        if '|' not in line:
            continue
        s, p = line.split('|', 1)
        if os.path.exists(p):
            jobs.append((s, p))
    print('[*] 扫描 %d 个 keychain bin' % len(jobs), flush=True)

    fh = open(os.path.join(a.out, 'hits.jsonl'), 'w')
    dev = {}
    nhit = ahit = 0
    done = 0
    with ProcessPoolExecutor(max_workers=a.jobs) as ex:
        for serial, out in ex.map(one, jobs, chunksize=4):
            done += 1
            d = dev.setdefault(serial, {})
            for r in out:
                fh.write(json.dumps(r, ensure_ascii=False) + '\n')
                if r['isNoise']:
                    nhit += 1
                    d.setdefault('NoiseKey', []).append(r)
                if r['isAdv']:
                    ahit += 1
                    d.setdefault('AdvSecretKey', []).append(r)
            if done % 200 == 0:
                print('  ...%d/%d noise=%d adv=%d' % (done, len(jobs), nhit, ahit), flush=True)
    fh.close()
    json.dump(dev, open(os.path.join(a.out, 'keys.json'), 'w'), ensure_ascii=False, indent=1)
    print('[+] 完成 %d 设备 | NoiseKey 命中项 %d | AdvSecretKey 命中项 %d'
          % (done, nhit, ahit))
    print('    同时有 NoiseKey+AdvSecretKey 的设备: %d'
          % sum(1 for s, v in dev.items() if v.get('NoiseKey') and v.get('AdvSecretKey')))
    print('    输出: %s' % a.out)


if __name__ == '__main__':
    main()
