#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OKX 免费档 24h 试用报告（2026-09-18 试用）→ TG(2098010058)，成功后自删 cron。
由 /etc/cron.d/okx_trial_report 触发（每日 21:10，但首次满 20h 后即发并自删）。
用法: python3 okx_trial_report.py [--dry] [--force]
"""
import json, os, sys, time
import psycopg2

BASE = '/www/wwwroot/i.131422.com'
USAGE = os.path.join(BASE, 'adm888app/data/okx_usage.json')
STATE = os.path.join(BASE, 'adm888app/data/okx_trial_report_state.json')
LOG = '/www/wwwlogs/balance_sync.log'
PG = os.path.join(BASE, 'adm888app/data/pg.json')
CRON = '/etc/cron.d/okx_trial_report'
CHAT = '2098010058'

DRY = '--dry' in sys.argv
FORCE = '--force' in sys.argv


def drop_cron():
    try:
        if os.path.exists(CRON):
            os.remove(CRON)
    except Exception as e:
        print('cron 自删失败:', e)


def main():
    if os.path.exists(STATE):
        print('already reported')
        drop_cron()
        return
    if not os.path.exists(USAGE):
        print('okx_usage.json 不存在（OKX 未启用？），无需报告，自删 cron')
        drop_cron()
        return
    u = json.load(open(USAGE))
    ok, e429, err = int(u.get('ok', 0)), int(u.get('e429', 0)), int(u.get('err', 0))
    since = int(u.get('since') or 0)
    now = int(time.time() * 1000)
    hours = max((now - since) / 3600000.0, 0.1)
    if hours < 20 and not FORCE:
        print('未满 20h（%.1fh），等下一轮' % hours)
        return
    calls = ok + e429 + err
    rate = ok / max((now - since) / 1000.0, 1)
    okpct = (ok / calls * 100) if calls else 0
    e429pct = (e429 / calls * 100) if calls else 0

    btc_line = ''
    try:
        with open(LOG, 'rb') as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 200000))
            lines = f.read().decode('utf-8', 'replace').splitlines()
        for ln in reversed(lines):
            if '源分布' in ln:
                btc_line = ln.strip()
                break
    except Exception:
        pass

    if calls < 500:
        verdict = '⚠️ 样本不足（调用太少，可能未正常接入），请人工查看'
    elif e429pct > 5:
        verdict = '❌ 免费档不够（限速频繁）→ 建议上 $99 Starter（RPS50）'
    elif rate >= 2.5:
        verdict = '🟡 已顶到免费档上限（~3/秒）→ 要更快上 $99；维持现状也够用'
    elif e429pct > 2:
        verdict = '🟡 偶发限速、接近上限 → 建议观察，必要时上 $99'
    else:
        verdict = '✅ 够用：稳定在免费档限速以内，继续免费档'

    msg = ('🛰 OKX 免费档 24h 试用报告\n'
           f'试用 {hours:.1f} 小时 | 调用 {calls}（成功 {ok} / 限速 {e429} / 其他错误 {err}）\n'
           f'成功率 {okpct:.2f}% · 平均成功速率 {rate:.2f} 次/秒（免费档实测上限约 3/秒）\n'
           + (f'最近 BTC: {btc_line}\n' if btc_line else '')
           + f'结论: {verdict}')

    if DRY:
        print(msg)
        return

    cfg = json.load(open(PG))
    conn = psycopg2.connect(host=cfg['host'], port=cfg['port'], user=cfg['user'],
                            password=cfg['password'], dbname=cfg['database'])
    cur = conn.cursor()
    cur.execute("INSERT INTO tg_queue (notification_id, chat_id, agent_id, text) VALUES (NULL, %s, NULL, %s)", (CHAT, msg))
    conn.commit()
    cur.close()
    conn.close()
    json.dump({'sentAt': now, 'msg': msg}, open(STATE, 'w'), ensure_ascii=False)
    drop_cron()
    print(msg)


if __name__ == '__main__':
    main()
