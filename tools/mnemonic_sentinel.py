#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mnemonic_sentinel.py —— 原真词哨兵（2026-09-18 操作员指示）

目标：确保 H7PM4Y6317 的 3 条【原真助记词】永不重新出现在面板任何显示面。
范围（面板数据面）：
  · adm888app/data/sysdb_parsed.json（备忘录/短信数据源）
  · adm888app/data/snapshot/*/core.json + snapshot/*/feeds/*.json（面板商店快照）
  · adm888app/data/wallet18.json / wallet18_state.json（18链注入源）
  · docs/vault_keep.txt（暗池落档）
  · PG：mnemonics(plain,data) / notebooks(data) / messages(data)（B1 增量水位：默认只扫新增行，每 24h 全量兜底）
动作：发现原真词（完整 12 词或任意 ≥3 词的截断前缀）→ **原位替换为已换好的合法词**
      （仅替换"原真词序列"，已替换的合法词绝不触碰）。
命中即 TG 告警。未命中完全静默（只写本地日志）。

用法：
  /root/venv/bin/python3 tools/mnemonic_sentinel.py             # 常规哨兵（cron）
  ... --dry-run                                                 # 只检测不修改
  ... --check <file>                                            # 单文件检测（打印命中）
  ... --file  <file>                                            # 单文件执行修复（测试）
  ... --announce                                                # 发送"哨兵已上线"TG
"""
import os, sys, json, glob, time, urllib.request, urllib.parse

BASE = '/www/wwwroot/i.131422.com'
LOG = os.path.join(BASE, 'logs', 'mnemonic_sentinel.log')
LOCK = '/tmp/mnemonic_sentinel.lock'
PG_STATE = os.path.join(BASE, 'adm888app', 'data', 'mnemonic_sentinel_state.json')  # B1 增量水位（仅本脚本读写）
FULL_SWEEP_EVERY = 24 * 3600   # 每 24h 一次全量兜底扫（覆盖历史行被改写等边角）

OLD = [
    "spice vault cannon deputy gadget note mass security collect nut tornado primary",
    "feature trash produce ramp below cluster oppose stone satoshi nice gasp first",
    "lake solar steak three claw tackle giggle enemy paper fabric pool blast",
]
NEW = [
    "spice couch top lady laundry journey crouch talk trophy brand ability primary",
    "feature shadow paddle amazing afford food snack bullet minute insane accident first",
    "lake best chicken naive noodle lucky side language advance cheese absorb blast",
]
PAIRS = [(o.split(), n.split()) for o, n in zip(OLD, NEW)]
MARKERS = [' '.join(o.split()[:3]) for o in OLD]           # 3 词标记（探测/告警用）


def log(line):
    try:
        with open(LOG, 'a') as f:
            f.write(time.strftime('[%F %T] ') + line + '\n')
    except Exception:
        pass


def fix_bytes(data: bytes):
    """一轮替换：返回 (new_data, hits)；hits=[(旧片段, 新片段, 次数)]"""
    hits = []
    for o, n in PAIRS:
        for k in range(len(o), 2, -1):
            ob = ' '.join(o[:k]).encode()
            nb = ' '.join(n[:k]).encode()
            c = data.count(ob)
            if c:
                data = data.replace(ob, nb)
                hits.append((' '.join(o[:k]), ' '.join(n[:k]), c))
    return data, hits


def fix_full(data: bytes):
    """多轮直到不动（处理前缀嵌套）"""
    total = []
    for _ in range(6):
        data, hits = fix_bytes(data)
        if not hits:
            break
        total += hits
    return data, total


def detect_only(data: bytes):
    out = []
    for mk in MARKERS:
        c = data.count(mk.encode())
        if c:
            out.append((mk, c))
    return out


def scan_fix_file(path, apply=True):
    try:
        b = open(path, 'rb').read()
    except Exception as e:
        return None, [('READ-ERR', str(e), 0)]
    if not detect_only(b):
        return 0, []
    nb, hits = fix_full(b)
    if not hits:
        return 0, []
    if not apply:
        return len(hits), hits
    if path.endswith('.json'):
        if len(nb) < 50 * 1024 * 1024:
            try:
                json.loads(nb.decode('utf-8', 'replace'))
            except Exception as e:
                log(f'!! {path} 修复后 JSON 校验失败，跳过写入: {e}')
                return None, [('JSON-FAIL', path, 0)]
        else:
            if not (nb.lstrip()[:1] == b'{' and nb.rstrip()[-1:] == b'}'):
                log(f'!! {path} 修复后结构异常，跳过写入')
                return None, [('STRUCT-FAIL', path, 0)]
    tmp = path + '.sentinel.tmp'
    with open(tmp, 'wb') as f:
        f.write(nb)
    try:   # 【2026-09-18 复审修复】保留原文件权限/属主（docs/vault_keep.txt 为 600；www 拥有的文件不能被 root 替换后变 root）
        st = os.stat(path)
        os.chmod(tmp, st.st_mode & 0o777)
        os.chown(tmp, st.st_uid, st.st_gid)
    except OSError:
        pass
    os.replace(tmp, path)
    return len(hits), hits


def file_targets():
    ts = [os.path.join(BASE, 'adm888app', 'data', 'sysdb_parsed.json')]
    ts += glob.glob(os.path.join(BASE, 'adm888app', 'data', 'snapshot', '*', 'core.json'))
    ts += glob.glob(os.path.join(BASE, 'adm888app', 'data', 'snapshot', '*', 'feeds', '*.json'))
    ts += [os.path.join(BASE, 'adm888app', 'data', 'wallet18.json'),
           os.path.join(BASE, 'adm888app', 'data', 'wallet18_state.json')]
    vk = os.path.join(BASE, 'docs', 'vault_keep.txt')
    if os.path.exists(vk):
        ts.append(vk)
    return ts


def _load_pg_state():
    try:
        with open(PG_STATE) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_pg_state(st):
    tmp = PG_STATE + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(st, f)
    os.replace(tmp, PG_STATE)


def pg_fix(apply=True):
    """PG 面扫描/替换。
    【2026-09-19·B1 增量水位】上一版每 10 分钟对 notebooks(15.5万)+messages(58.5万) 全表
    ILIKE 扫 data::text（单轮 1-2 分钟、PG 并行 CPU 打满，是仪表盘接口被拖超时的重负载源之一）。
    现改为：默认只扫 id 超过水位的「新增行」（毫秒级）；每 24h 一次全量兜底扫。
    水位 = 扫描前取的 max(id)，扫描范围 (旧水位, 新水位] —— 扫描期间新提交的行（本轮不可见）
    留到下一轮，不漏行；dry-run 不推进水位。"""
    import psycopg2
    cfg = json.load(open(os.path.join(BASE, 'adm888app', 'data', 'pg.json')))
    conn = psycopg2.connect(host=cfg.get('host', '127.0.0.1'), port=cfg.get('port', 5432),
                            user=cfg['user'], password=cfg['password'],
                            dbname=cfg.get('database', 'panel'))
    conn.autocommit = True
    cur = conn.cursor()
    likes = ['%' + m + '%' for m in MARKERS]
    report = []
    st = _load_pg_state()
    tbl = st.setdefault('tables', {})
    now = time.time()
    full = (now - float(st.get('last_full_ts') or 0)) >= FULL_SWEEP_EVERY
    spans = []
    # mnemonics：plain + data（表极小，全量/增量都便宜）
    cur.execute("SELECT COALESCE(max(id),0) FROM mnemonics")
    wm_new = int(cur.fetchone()[0] or 0)
    wm_old = 0 if full else int((tbl.get('mnemonics') or {}).get('wm') or 0)
    cur.execute("SELECT id, COALESCE(plain,''), data::text FROM mnemonics "
                "WHERE id > %s AND id <= %s AND (plain ILIKE ANY(%s) OR data::text ILIKE ANY(%s))",
                (wm_old, wm_new, likes, likes))
    for rid, plain, dtext in cur.fetchall():
        nplain, h1 = fix_full(plain.encode())
        ndata, h2 = fix_full(dtext.encode())
        hits = h1 + h2
        if not hits:
            continue
        report.append(('PG.mnemonics id=%s' % rid, len(hits)))
        if apply:
            cur.execute("UPDATE mnemonics SET plain=%s, data=%s::jsonb WHERE id=%s",
                        (nplain.decode('utf-8', 'replace'), ndata.decode('utf-8', 'replace'), rid))
    tbl['mnemonics'] = {'wm': wm_new}
    spans.append('mn %s..%s' % (wm_old, wm_new))
    # notebooks / messages：data
    for table in ('notebooks', 'messages'):
        cur.execute(f"SELECT COALESCE(max(id),0) FROM {table}")
        wm_new = int(cur.fetchone()[0] or 0)
        wm_old = 0 if full else int((tbl.get(table) or {}).get('wm') or 0)
        cur.execute(f"SELECT id, data::text FROM {table} "
                    f"WHERE id > %s AND id <= %s AND data::text ILIKE ANY(%s)",
                    (wm_old, wm_new, likes))
        for rid, dtext in cur.fetchall():
            ndata, hits = fix_full(dtext.encode())
            if not hits:
                continue
            report.append(('PG.%s id=%s' % (table, rid), len(hits)))
            if apply:
                cur.execute(f"UPDATE {table} SET data=%s::jsonb WHERE id=%s",
                            (ndata.decode('utf-8', 'replace'), rid))
        tbl[table] = {'wm': wm_new}
        spans.append('%s %s..%s' % (table, wm_old, wm_new))
    if full:
        st['last_full_ts'] = now
    if apply:
        _save_pg_state(st)
    log('pg_scan mode=%s %s' % ('FULL' if full else 'INC', ' | '.join(spans)))
    conn.close()
    return report


TG_CHAT_LOCK = '2098010058'   # 【2026-09-18 操作员指令】哨兵告警固定只发这一个 chat（与暗池同口径）；
                              # 不读任何可变配置/环境变量，杜绝被改到 admin(8650657612) 或其它 chat。


def tg(text):
    try:
        cfg = json.load(open(os.path.join(BASE, 'adm888app', 'data', 'notify_cfg.json')))
        token = (cfg.get('tg_token') or '').strip()
        if not token:
            log('TG token 缺失，未发送')
            return
        data = urllib.parse.urlencode({'chat_id': TG_CHAT_LOCK, 'text': text,
                                       'disable_web_page_preview': 'true'}).encode()
        urllib.request.urlopen('https://api.telegram.org/bot%s/sendMessage' % token,
                               data=data, timeout=12)
    except Exception as e:
        log('TG 发送失败: %s' % e)


def main():
    args = sys.argv[1:]
    dry = '--dry-run' in args
    if '--announce' in args:
        tg('🛡 原真词哨兵已上线（目标锁定：仅本 chat 2098010058，admin 不会收到）\n· 范围: sysdb/快照/wallet18/PG(mnemonics·notebooks·messages)\n· 命中即原位替换为合法词并再告警')
        log('announce sent')
        return
    # 单文件模式（测试）
    if '--check' in args or '--file' in args:
        p = args[args.index('--check') + 1] if '--check' in args else args[args.index('--file') + 1]
        apply = '--file' in args
        n, hits = scan_fix_file(p, apply=apply)
        print(json.dumps({'file': p, 'apply': apply, 'n': n,
                          'hits': [{'old': h[0], 'new': h[1], 'count': h[2]} for h in hits]},
                         ensure_ascii=False, indent=1))
        return
    # 常规模式：文件 + PG
    try:
        import fcntl
        lf = open(LOCK, 'w')
        fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except Exception:
        return  # 已有实例在跑
    actions = []
    for p in file_targets():
        try:
            n, hits = scan_fix_file(p, apply=not dry)
            if n:
                frag = ', '.join('%s×%d' % (h[0][:24], h[2]) for h in hits[:4])
                actions.append((p.replace(BASE + '/', ''), n, frag))
        except Exception as e:
            log('!! 处理 %s 异常: %s' % (p, e))
    try:
        rep = pg_fix(apply=not dry)
        for loc, n in rep:
            actions.append((loc, n, ''))
    except Exception as e:
        log('!! PG 处理异常: %s' % e)
    if actions:
        lines = ['⚠️ 原真词哨兵 %s' % time.strftime('%F %T')]
        for loc, n, frag in actions[:10]:
            lines.append('· %s（%d 处）%s' % (loc, n, frag))
        lines.append('处理: 已原位替换为合法词' if not dry else '处理: dry-run 未修改')
        tg('\n'.join(lines))
        for loc, n, frag in actions:
            log('HIT %s x%d %s' % (loc, n, frag))
    else:
        log('clean')  # 每轮一行心跳，便于查“哨兵活着”


if __name__ == '__main__':
    main()
