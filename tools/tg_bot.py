#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tg_bot.py — Telegram 机器人自动应答（systemd 常驻，长轮询 ~25s）

用途：代理/用户 在 Telegram 给机器人发 /start（或任意消息）→ 机器人自动回复：
        你的 Telegram ID:
        <数字>
        请复制此 ID 到实时通知栏完成绑定。
    来访账号同时记入 adm888app/data/tg_bot_seen.jsonl（调试/审计，可清理）。
"""
import os, json, time, urllib.request, urllib.error

BASE = '/www/wwwroot/i.131422.com'
CFG_F = os.path.join(BASE, 'adm888app', 'data', 'notify_cfg.json')
STATE_F = os.path.join(BASE, 'adm888app', 'data', 'tg_bot_offset.json')
SEEN_F = os.path.join(BASE, 'adm888app', 'data', 'tg_bot_seen.jsonl')

def log(*a):
    print(time.strftime('[%Y-%m-%d %H:%M:%S]'), *a, flush=True)

def load_json(f, d):
    try:
        return json.load(open(f, encoding='utf-8'))
    except Exception:
        return d

def api(token, method, params=None):
    url = 'https://api.telegram.org/bot%s/%s' % (token, method)
    data = json.dumps(params).encode() if params else None
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
    return json.loads(urllib.request.urlopen(req, timeout=40).read())

def main():
    log('tg_bot 启动（长轮询）')
    while True:
        try:
            cfg = load_json(CFG_F, {})
            token = cfg.get('tg_token')
            if not token:
                log('未配置 tg_token，15s 后重试')
                time.sleep(15)
                continue
            off = int(load_json(STATE_F, {}).get('offset', 0) or 0)
            resp = api(token, 'getUpdates', {'offset': off, 'timeout': 25, 'allowed_updates': ['message']})
            for u in resp.get('result', []):
                off = u['update_id'] + 1
                msg = u.get('message') or {}
                chat = msg.get('chat') or {}
                cid = chat.get('id')
                if cid is None:
                    continue
                try:
                    with open(SEEN_F, 'a', encoding='utf-8') as f:
                        f.write(json.dumps({
                            'ts': int(time.time()), 'chat_id': cid,
                            'username': chat.get('username') or '',
                            'name': ((chat.get('first_name') or '') + (chat.get('last_name') or '')),
                            'text': (msg.get('text') or '')[:60],
                        }, ensure_ascii=False) + '\n')
                except Exception:
                    pass
                text = '你的 Telegram ID:\n%d\n\n请复制此 ID 到实时通知栏完成绑定。' % cid
                try:
                    api(token, 'sendMessage', {'chat_id': cid, 'text': text})
                    log('已回复 chat_id=%s（%s）' % (cid, msg.get('text') or ''))
                except Exception as e:
                    log('回复失败:', str(e)[:90])
            with open(STATE_F + '.tmp', 'w') as f:
                json.dump({'offset': off}, f)
            os.replace(STATE_F + '.tmp', STATE_F)
        except urllib.error.HTTPError as e:
            log('getUpdates HTTP', e.code, str(e.read()[:120]))
            time.sleep(5)
        except Exception as e:
            log('轮询异常:', str(e)[:120])
            time.sleep(5)

if __name__ == '__main__':
    main()
