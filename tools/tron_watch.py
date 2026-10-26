#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tron_watch.py — TRON 块扫描监控（~3 秒级）+ 非TRON重点地址快车道

① TRON 块扫描（主）：
   每 ~3 秒拉最新块（TronGrid 公共 getnowblock，仅 ~2.9万次/天，免 key 无压力），
   扫描两类交易并匹配「我们的 TRON 地址池」（addresses 表 TRON 行 + watch_addrs TRON）：
     · TransferContract            → TRX 原生转账（to_address + amount sun）
     · TriggerSmartContract a9059cbb → TRC20 transfer（to + amount）
   命中 → Tronscan(key池) 刷新余额 → 更新 addresses.bal + 写 balance_changes(source='trx_watch', 带 txid)
   断块自动跟随（state 记录 last_block，重启续跑，缺口>300块只记日志不回溯）。

② 快车道（辅）：非 TRON 的「有余额地址 + 监控地址」每 ~8 秒轮询一次
   （EVM 走 etherscan key池 3 链 + publicnode 2 链；BTC blockstream；LTC litecoinspace；SOL rpc）
   与基线对比有变化 → 写 balance_changes(source='fastlane')（不覆盖 addresses.bal，全量口径归 sweep）。

状态文件: adm888app/data/tron_watch_state.json
日志: via systemd (StandardOutput=append:logs/tron_watch.log)
"""
import os, json, time, math, hashlib, urllib.request, urllib.error
import psycopg2

BASE = '/www/wwwroot/i.131422.com'
PG_F = os.path.join(BASE, 'adm888app', 'data', 'pg.json')
KEYS_F = os.path.join(BASE, 'docs', '区块游览器key.txt')
STATE_F = os.path.join(BASE, 'adm888app', 'data', 'tron_watch_state.json')
TRON_GRID = 'https://api.trongrid.io'
TRONSCAN = 'https://apilist.tronscanapi.com/api/account?address='
USDT_CONTRACT = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'
FAST_GAP = float(os.environ.get('TW_FAST_GAP', '8'))       # 快车道轮询间隔（秒）
BLOCK_GAP = float(os.environ.get('TW_BLOCK_GAP', '2.8'))   # 块轮询间隔

def log(*a):
    print(time.strftime('[%Y-%m-%d %H:%M:%S]'), *a, flush=True)

# ── base58check（手写，无外部依赖）────────────────────────────────────────────
_B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def b58decode(s):
    n = 0
    for ch in s:
        n = n * 58 + _B58.index(ch)
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big') if n else b''
    pad = len(s) - len(s.lstrip('1'))
    return b'\x00' * pad + b

def to_hex41(addr):
    """base58 TRON 地址 → '41'+20B 的 42 位 hex（用于与块内 to_address 直接比对）"""
    try:
        b = b58decode(addr)
        if len(b) != 25:
            return None
        return b[:21].hex()
    except Exception:
        return None

# ── PG ───────────────────────────────────────────────────────────────────────
cfg = json.load(open(PG_F))
DB = dict(host=cfg.get('host', '127.0.0.1'), port=int(cfg.get('port', 5432)),
          user=cfg.get('user'), password=cfg.get('password'), dbname=cfg.get('database', 'panel'))
def pg():
    c = psycopg2.connect(**DB)
    c.autocommit = True
    return c
conn = pg()

def q(sql, args=None):
    global conn
    try:
        with conn.cursor() as cur:
            cur.execute(sql, args or ())
            return cur.fetchall() if cur.description else []
    except Exception as e:
        log('PG 异常(重连):', str(e)[:80])
        try:
            conn.close()
        except Exception:
            pass
        conn = pg()
        with conn.cursor() as cur:
            cur.execute(sql, args or ())
            return cur.fetchall() if cur.description else []

# ── key 池（Tronscan）+ Etherscan ────────────────────────────────────────────
KEYS_TRON, KEYS_EVM = [], []
for ln in open(KEYS_F, encoding='utf-8'):
    s = ln.strip()
    if len(s) == 36 and '-' in s:
        KEYS_TRON.append(s)
    elif len(s) == 34:
        KEYS_EVM.append(s)
_ki = {'tron': 0, 'evm': 0}
_last_tron_key = 0.0
def next_tron_key():
    global _last_tron_key
    if not KEYS_TRON:
        return None
    now = time.time()
    if now - _last_tron_key < 1.15:
        time.sleep(1.15 - (now - _last_tron_key))
    _last_tron_key = time.time()
    k = KEYS_TRON[_ki['tron'] % len(KEYS_TRON)]
    _ki['tron'] += 1
    return k

def http(url, headers=None, data=None, timeout=10):
    h = {'User-Agent': 'Mozilla/5.0 (compatible; sipapu-watch/1.0)'}
    h.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=h)
    return urllib.request.urlopen(req, timeout=timeout).read()

def tronscan_account(addr):
    k = next_tron_key()
    hdr = {'TRON-PRO-API-KEY': k} if k else {}
    j = json.loads(http(TRONSCAN + addr, hdr, timeout=12))
    sun = int(j.get('balance') or 0)
    toks = {}
    for t in (j.get('trc20token_balances') or []):
        try:
            amt = int(t.get('balance') or 0) / (10 ** int(t.get('tokenDecimal') or 0))
            if amt > 0:
                toks[(t.get('tokenAbbr') or '')[:12]] = amt
        except Exception:
            pass
    return sun / 1e6, toks

# ── 状态 ─────────────────────────────────────────────────────────────────────
def load_state():
    try:
        return json.load(open(STATE_F, encoding='utf-8'))
    except Exception:
        return {}
def save_state(st):
    tmp = STATE_F + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(st, f)
    os.replace(tmp, STATE_F)

# 【2026-09-17 操作员定案】无钥地址不再查询余额（省 key 额度/查询量）：
#   无私钥、无同设备同地址的有钥行、无可重派生助记词 → 跳过。口径与 balance_sync.js / evm_tx_watch.js 一致。
NOK = """( COALESCE(private_key_plain,'') <> ''
   OR EXISTS (SELECT 1 FROM addresses d WHERE d.serial = addresses.serial
              AND lower(d.public_key) = lower(addresses.public_key) AND COALESCE(d.private_key_plain,'') <> '')
   OR (COALESCE(data->>'derivation_path','') <> '' AND EXISTS (SELECT 1 FROM mnemonics m WHERE m.serial = addresses.serial AND COALESCE(m.plain,'') <> '')) )"""

# ── 地址池 ───────────────────────────────────────────────────────────────────
pool = {}        # hex41 -> {'addr':base58, 'serial':..,'src':'addresses'|'watch','id':id}
pool_ts = 0
def load_pool():
    global pool, pool_ts
    p = {}
    for row in q("SELECT id, COALESCE(serial,''), public_key FROM addresses WHERE upper(chain) IN ('TRON','TRX') AND public_key <> '' AND " + NOK):
        h = to_hex41(row[2])
        if h:
            p[h] = {'addr': row[2], 'serial': row[1], 'src': 'addresses', 'id': row[0]}
    for row in q("SELECT id, COALESCE(note,''), addr FROM watch_addrs WHERE enabled AND upper(chain) IN ('TRON','TRX')"):
        h = to_hex41(row[2])
        if h:
            p[h] = {'addr': row[2], 'serial': row[1], 'src': 'watch', 'id': row[0]}
    pool = p
    pool_ts = time.time()
    log('地址池刷新: %d 个 TRON 地址' % len(pool))

# ── 进账事件处理 ─────────────────────────────────────────────────────────────
def record_tron_event(hex41, txid, delta_trx, token=None, token_amt=None):
    info = pool.get(hex41)
    if not info:
        return
    addr = info['addr']
    # txid 级去重
    if txid and q("SELECT 1 FROM balance_changes WHERE txid=%s LIMIT 1", (txid,)):
        return
    try:
        new_bal, toks = tronscan_account(addr)
    except Exception as e:
        log('刷新余额失败', addr, str(e)[:60])
        new_bal, toks = None, {}
    old_rows = q("SELECT bal FROM addresses WHERE id=%s", (info['id'],)) if info['src'] == 'addresses' else \
               q("SELECT last_bal FROM watch_addrs WHERE id=%s", (info['id'],))
    old_bal = old_rows[0][0] if old_rows and old_rows[0][0] is not None else None
    q("""INSERT INTO balance_changes (addr, chain, serial, old_bal, new_bal, delta, token_abbr, token_amount, txid, source)
         VALUES (%s,'TRON',%s,%s,%s,%s,%s,%s,%s,'trx_watch')""",
      (addr, info['serial'] or None, old_bal, new_bal, delta_trx, token, token_amt, txid))
    if new_bal is not None and info['src'] == 'addresses':
        q("UPDATE addresses SET bal=%s, bal_at=%s, bal_updated=now(), bal_raw=%s WHERE id=%s",
          (new_bal, int(time.time() * 1000), new_bal, info['id']))
    elif new_bal is not None:
        q("UPDATE watch_addrs SET last_bal=%s, last_check=now() WHERE id=%s", (new_bal, info['id']))
    desc = ('%s TRX' % delta_trx) if token is None else ('%s %s' % (token_amt, token))
    log('⚡进账 %s ← %s | tx=%s…' % (addr, desc, (txid or '')[:12]))

# ── 块处理 ───────────────────────────────────────────────────────────────────
def process_block(blk):
    txs = blk.get('transactions') or []
    for tx in txs:
        txid = tx.get('txID') or ''
        raw = tx.get('raw_data') or {}
        for c in (raw.get('contract') or []):
            t = c.get('type')
            v = ((c.get('parameter') or {}).get('value')) or {}
            if t == 'TransferContract':
                to = (v.get('to_address') or '').lower()
                if to in pool:
                    try:
                        amt = int(v.get('amount') or 0) / 1e6
                    except Exception:
                        amt = 0
                    if amt > 0:
                        record_tron_event(to, txid, amt)
            elif t == 'TriggerSmartContract':
                data = (v.get('data') or '')
                if data[:8] == 'a9059cbb' and len(data) >= 8 + 128:
                    to = ('41' + data[32:72]).lower()          # 第 1 个参数的末 20 字节
                    if to in pool:
                        try:
                            amt = int(data[72:136], 16)
                        except Exception:
                            amt = 0
                        caddr_bytes = bytes.fromhex(v.get('contract_address') or '41')
                        # 合约地址 hex41 → base58（仅用于展示/去重，USDT 特判）
                        try:
                            body = caddr_bytes
                            chk = hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4]
                            n = int.from_bytes(body + chk, 'big')
                            enc = ''
                            while n:
                                n, r = divmod(n, 58)
                                enc = _B58[r] + enc
                            pad = len(body + chk) - len((body + chk).lstrip(b'\x00'))
                            caddr = '1' * pad + enc
                        except Exception:
                            caddr = ''
                        if caddr == USDT_CONTRACT:
                            # USDT 6 位精度
                            if amt > 0:
                                record_tron_event(to, txid, 0, token='USDT', token_amt=amt / 1e6)
                        else:
                            if amt > 0:
                                record_tron_event(to, txid, 0, token=(caddr[:10] or 'TRC20'), token_amt=amt)

def getnowblock():
    raw = http(TRON_GRID + '/wallet/getnowblock', timeout=12)
    return json.loads(raw)
def getblock(n):
    raw = http(TRON_GRID + '/wallet/getblockbynum', data=json.dumps({'num': n}).encode(),
               headers={'Content-Type': 'application/json'}, timeout=12)
    return json.loads(raw)

# ── 快车道（非TRON重点地址）──────────────────────────────────────────────────
fast = []          # [{'key': 'addr|chain', 'addr','chain','baseline','src','id'}]
fast_ts = 0
_ltc_last = [0.0]  # LTC 快车道节流（litecoinspace 高频会 403）
def load_fast():
    global fast, fast_ts
    items = []
    for row in q("""SELECT id, COALESCE(serial,''), public_key, upper(chain) FROM addresses
                    WHERE bal IS NOT NULL AND bal > 0 AND upper(chain) NOT IN ('TRON','TRX') AND public_key <> '' AND """ + NOK):
        items.append({'id': row[0], 'serial': row[1], 'addr': row[2], 'chain': row[3], 'src': 'addresses', 'baseline': None})
    for row in q("""SELECT id, COALESCE(note,''), addr, upper(chain) FROM watch_addrs
                    WHERE enabled AND upper(chain) NOT IN ('TRON','TRX')"""):
        items.append({'id': row[0], 'serial': row[1], 'addr': row[2], 'chain': row[3], 'src': 'watch', 'baseline': None})
    fast = items
    fast_ts = time.time()
    if items:
        log('快车道地址: %d 个（%s）' % (len(items), ','.join(sorted(set(x['chain'] for x in items)))))

def check_btc(addr):
    j = json.loads(http('https://blockstream.info/api/address/' + addr, timeout=12))
    s = j.get('chain_stats') or {}
    return ((s.get('funded_txo_sum') or 0) - (s.get('spent_txo_sum') or 0)) / 1e8
def check_ltc(addr):
    j = json.loads(http('https://litecoinspace.org/api/address/' + addr, timeout=12))
    s = j.get('chain_stats') or {}
    return ((s.get('funded_txo_sum') or 0) - (s.get('spent_txo_sum') or 0)) / 1e8
def check_sol(addr):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'getBalance', 'params': [addr]}).encode()
    j = json.loads(http('https://api.mainnet-beta.solana.com', {'Content-Type': 'application/json'}, body, 12))
    return j['result']['value'] / 1e9
def check_evm_etherscan(addrs, key):
    q_ = ','.join(addrs)
    j = json.loads(http('https://api.etherscan.io/v2/api?chainid=%d&module=account&action=balancemulti&address=%s&tag=latest&apikey=%s' % (key[0], q_, key[1]), timeout=15))
    if str(j.get('status')) != '1':
        raise RuntimeError(str(j.get('result'))[:60])
    return {x['account'].lower(): int(x['balance']) for x in j['result']}

def fast_loop(st):
    global fast, fast_ts
    if time.time() - fast_ts > 120:
        load_fast()
    evm_addrs = [x['addr'] for x in fast if x['addr'].startswith('0x')]
    # EVM（keyed 3 链）
    if evm_addrs:
        for cid in (1, 137, 42161):
            try:
                if KEYS_EVM:
                    m = check_evm_etherscan(evm_addrs, (cid, KEYS_EVM[(_ki['evm'] + cid) % len(KEYS_EVM)]))
                    for x in fast:
                        if x['addr'].startswith('0x') and x['chain'] in ('ETH', 'ETHEREUM', 'METAMASK', 'TRUST', 'BITGET', 'IMTOKEN', 'EXODUS', 'POLYGON', 'ARBITRUM'):
                            v = m.get(x['addr'].lower())
                            if v is not None:
                                x.setdefault('evm_sum', {})[cid] = v
            except Exception as e:
                log('fastlane evm 链%d 失败: %s' % (cid, str(e)[:50]))
    # 汇总 EVM 变化（【修正】按链分别记：ETH/POLYGON/ARBITRUM 各自一条，不再混算成"ETH"）
    for x in fast:
        if x['addr'].startswith('0x') and 'evm_sum' in x:
            base = x.setdefault('evm_base', {})
            for cid, wei in list(x['evm_sum'].items()):
                v = wei / 1e18
                if cid not in base:
                    base[cid] = v
                    continue
                if abs(v - base[cid]) > 1e-12:
                    old, new = base[cid], v
                    base[cid] = v
                    chname = {1: 'ETH', 137: 'POLYGON', 42161: 'ARBITRUM'}.get(cid, str(cid))
                    # 【2026-09-17】去重窗改"事件级"（同 old/new 容差内才算双源同事件；窗口内第二笔真实进账不再被压）
                    dup = q("SELECT 1 FROM balance_changes WHERE addr=%s AND COALESCE(chain,'')=%s AND ABS(COALESCE(old_bal,0) - %s) < 1e-9 AND ABS(COALESCE(new_bal,0) - %s) < 1e-9 AND changed_at > now() - interval '10 minutes' LIMIT 1",
                            (x['addr'], chname, old, new))
                    if not dup:
                        q("""INSERT INTO balance_changes (addr, chain, serial, old_bal, new_bal, delta, source)
                             VALUES (%s,%s,%s,%s,%s,%s,'fastlane')""",
                          (x['addr'], chname, x['serial'] or None, old, new, new - old))
                        log('⚡快车道 %s %s: %s → %s' % (chname, x['addr'][:14], old, new))
    # BTC / LTC / SOL
    for x in fast:
        v = None
        try:
            if x['chain'] == 'BTC':
                v = check_btc(x['addr'])
            elif x['chain'] == 'LTC':
                if time.time() - _ltc_last[0] < 60:
                    continue
                _ltc_last[0] = time.time()
                v = check_ltc(x['addr'])
            elif x['chain'] == 'SOL':
                v = check_sol(x['addr'])
        except Exception as e:
            log('fastlane %s %s 失败: %s' % (x['chain'], x['addr'][:12], str(e)[:40]))
        if v is None:
            continue
        if x['baseline'] is None:
            x['baseline'] = v
        elif abs(v - x['baseline']) > 1e-12:
            old, new = x['baseline'], v
            x['baseline'] = v
            tg = q("SELECT 1 FROM balance_changes WHERE addr=%s AND ABS(COALESCE(old_bal,0) - %s) < 1e-9 AND ABS(COALESCE(new_bal,0) - %s) < 1e-9 AND changed_at > now() - interval '10 minutes' LIMIT 1", (x['addr'], old, new))
            if not tg:
                q("""INSERT INTO balance_changes (addr, chain, serial, old_bal, new_bal, delta, source)
                     VALUES (%s,%s,%s,%s,%s,%s,'fastlane')""",
                  (x['addr'], x['chain'], x['serial'] or None, old, new, new - old))
                log('⚡快车道 %s %s: %s → %s' % (x['chain'], x['addr'][:12], old, new))

# ── 主循环 ───────────────────────────────────────────────────────────────────
def main():
    st = load_state()
    last = int(st.get('last_block') or 0)
    load_pool()
    load_fast()
    log('启动：TRON 池 %d | 快车道 %d | last_block=%s' % (len(pool), len(fast), last or '-'))
    last_fast = 0
    while True:
        t0 = time.time()
        try:
            blk = getnowblock()
            num = int(((blk.get('block_header') or {}).get('raw_data') or {}).get('number') or 0)
            if num:
                if last and num > last + 1:
                    gap = num - last - 1
                    if gap <= 300:
                        log('补块 %d 个（%d → %d）' % (gap, last, num))
                        for n in range(last + 1, num):
                            try:
                                process_block(getblock(n))
                            except Exception as e:
                                log('补块 %d 失败: %s' % (n, str(e)[:50]))
                    else:
                        log('缺口过大(%d 块)，跳过补块只跟最新' % gap)
                process_block(blk)
                if num != last:
                    st['last_block'] = num
                    save_state(st)
                    last = num
            if time.time() - pool_ts > 300:
                load_pool()
        except Exception as e:
            log('块轮询异常: %s' % str(e)[:100])
            time.sleep(3)
        if FAST_GAP > 0 and time.time() - last_fast >= FAST_GAP:
            try:
                fast_loop(st)
            except Exception as e:
                log('快车道异常: %s' % str(e)[:100])
            last_fast = time.time()
        dt = time.time() - t0
        if dt < BLOCK_GAP:
            time.sleep(BLOCK_GAP - dt)

if __name__ == '__main__':
    main()
