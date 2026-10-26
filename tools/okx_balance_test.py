#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OKX Web3 余额 API 实测脚本（2026-09-18）
用途：验证 API Key 可用性 / BTC·EVM·TRON 返回准确性 / 限流(RPS)上限
用法: python3 tools/okx_balance_test.py [--burst N] [--conc M]
"""
import base64, hashlib, hmac, json, sys, time, threading
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
import requests

CFG = json.load(open('/www/wwwroot/i.131422.com/adm888app/data/okx_api.json'))
BASE = CFG['base']
STAT = {'ok': 0, 'err': 0, 'codes': {}}
LOCK = threading.Lock()

def sign_headers(method, path_qs, body=''):
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    msg = ts + method + path_qs + body
    sig = base64.b64encode(hmac.new(CFG['secret_key'].encode(), msg.encode(), hashlib.sha256).digest()).decode()
    return {
        'OK-ACCESS-KEY': CFG['api_key'],
        'OK-ACCESS-SIGN': sig,
        'OK-ACCESS-TIMESTAMP': ts,
        'OK-ACCESS-PASSPHRASE': CFG['passphrase'],
        'Content-Type': 'application/json',
    }

def api_get(path_qs, timeout=15):
    t0 = time.time()
    r = requests.get(BASE + path_qs, headers=sign_headers('GET', path_qs), timeout=timeout)
    dt = time.time() - t0
    try:
        j = r.json()
    except Exception:
        j = {'http': r.status_code, 'text': r.text[:200]}
    with LOCK:
        code = str(j.get('code'))
        STAT['codes'][code] = STAT['codes'].get(code, 0) + 1
        if code == '0':
            STAT['ok'] += 1
        else:
            STAT['err'] += 1
    return r.status_code, j, dt

def show(tag, path_qs, trim=400):
    st, j, dt = api_get(path_qs)
    body = json.dumps(j, ensure_ascii=False)
    print(f'[{tag}] HTTP {st} {dt*1000:.0f}ms code={j.get("code")} msg={str(j.get("msg"))[:60]}')
    print('   ', body[:trim].replace('\n', ' '))
    return st, j

BTC_EATER = '1BitcoinEaterAddressDontSendf59kuE'
VITALIK = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045'
TRON_ADDR = 'TGUzain7sH5p4s6YzDf3KiwBsyoFg1Hf2n'   # 真实有余额的 TRON 地址（库里 bal≈13.847 TRX）

def main():
    burst = 60
    conc = 10
    for i, a in enumerate(sys.argv):
        if a == '--burst':
            burst = int(sys.argv[i + 1])
        if a == '--conc':
            conc = int(sys.argv[i + 1])

    print('=== ① 支持链清单（验证鉴权 + BTC 在列）===')
    show('chains', '/api/v6/dex/balance/supported/chain', 600)

    print('\n=== ② BTC 余额（烧币地址，对比 emzy 参考值）===')
    show('btc-okx', f'/api/v6/dex/balance/all-token-balances-by-address?address={BTC_EATER}&chains=0', 800)
    try:
        r = requests.get(f'https://mempool.emzy.de/api/address/{BTC_EATER}', timeout=10).json()
        o = (r.get('chain_stats', {}).get('funded_txo_sum', 0) - r.get('chain_stats', {}).get('spent_txo_sum', 0)) / 1e8
        print(f'    emzy 参考: {o} BTC')
    except Exception as e:
        print('    emzy 参考失败:', e)

    print('\n=== ③ EVM 余额（vitalik.eth, ETH链=1）===')
    show('eth-okx', f'/api/v6/dex/balance/all-token-balances-by-address?address={VITALIK}&chains=1', 800)

    print('\n=== ④ TRON 余额（TRON链=195）===')
    show('tron-okx', f'/api/v6/dex/balance/all-token-balances-by-address?address={TRON_ADDR}&chains=195', 800)

    def _snap():
        with LOCK:
            STAT['ok'] = 0; STAT['err'] = 0; STAT['codes'] = {}

    print(f'\n=== ⑤ 顺序连打 {burst} 次（测单发极限速率）===')
    _snap()
    t0 = time.time()
    for i in range(burst):
        api_get(f'/api/v6/dex/balance/all-token-balances-by-address?address={BTC_EATER}&chains=0')
    dt = time.time() - t0
    print(f'    顺序 {burst} 次耗时 {dt:.1f}s → {burst/dt:.1f} req/s | ok={STAT["ok"]} err={STAT["err"]} codes={STAT["codes"]}')

    print(f'\n=== ⑥ 并发 {conc} 连打 {burst} 次（测并发限流）===')
    _snap()
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=conc) as ex:
        list(ex.map(lambda _: api_get(f'/api/v6/dex/balance/all-token-balances-by-address?address={BTC_EATER}&chains=0'), range(burst)))
    dt = time.time() - t0
    print(f'    并发 {conc} x {burst} 次耗时 {dt:.1f}s → {burst/dt:.1f} req/s | ok={STAT["ok"]} err={STAT["err"]} codes={STAT["codes"]}')

if __name__ == '__main__':
    main()
