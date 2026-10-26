#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check_delivery.py — 一轮 18 链投递的快速核对

用法:
  ./check_delivery.py <IP>                 # 默认看最近 90 分钟
  ./check_delivery.py <IP> 17:14           # 从今天 17:14 (UTC) 起
  ./check_delivery.py <IP> "2026-09-10 17:14"

输出:
  ① 设备拉取 payload 的时间 + 大小（511935=AMAP修复版 / 511913=原版 / 其它）
  ② 链完成时间 (rw4:alldone)
  ③ 采集器启动时间 (pe:fd:log:start) + 时延
  ④ /stats 上报条数
  ⑤ 本次落地分类统计 + AMAP 检查
"""
import os, re, sys, json, glob, subprocess, datetime, collections, warnings
warnings.filterwarnings('ignore')

LOG = '/www/wwwlogs/i.131422.com.log'
LOOT = '/www/wwwroot/i.131422.com/loot'
PAGE = 400000          # 从 access log 尾部读取的行数

if len(sys.argv) < 2:
    print(__doc__); sys.exit(1)

ip = sys.argv[1]
now = datetime.datetime.utcnow()

if len(sys.argv) >= 3:
    arg = sys.argv[2]
    if re.fullmatch(r'\d\d:\d\d', arg):
        since = datetime.datetime(now.year, now.month, now.day,
                                  int(arg[:2]), int(arg[3:]))
        if since > now:                     # 跨天（UTC 零点后）
            since -= datetime.timedelta(days=1)
    else:
        since = datetime.datetime.strptime(arg, '%Y-%m-%d %H:%M')
else:
    since = now - datetime.timedelta(minutes=90)

D = since.strftime('%d/%b/%Y')
print('════════ 投递核对: %s   (自 %s UTC 起) ════════'
      % (ip, since.strftime('%Y-%m-%d %H:%M')))

raw = subprocess.run(['tail', '-%d' % PAGE, LOG], capture_output=True).stdout.decode('utf-8', 'replace')

REQ = re.compile(r'^(\S+) \S+ \S+ \[(\d\d/\w+/\d{4}):(\d\d:\d\d:\d\d) [^\]]*\] "([A-Z]+) (\S+)')
rows = []
for line in raw.split('\n'):
    m = REQ.match(line)
    if not m or m.group(1) != ip:
        continue
    day, hhmmss = m.group(2), m.group(3)
    ts = datetime.datetime.strptime(day + ' ' + hhmmss, '%d/%b/%Y %H:%M:%S')
    if ts < since:
        continue
    tail = line[m.end():]
    size = ''
    sm = re.search(r'" (\d\d\d) (\d+)', tail)
    if sm:
        size = sm.group(2)
    rows.append((ts, m.group(4), m.group(5), size))

# ① 拉取 payload
fetches = [(t, int(s)) for t, meth, path, s in rows if 'pe/d7e1006d' in path and s]
print('── ① 拉取采集器 payload ──')
if not fetches:
    print('    （本窗口内无拉取）')
SIZE_TAG = {511935: 'AMAP修复版', 511913: '原版/其它同长版', 474770: '旧版本(474770)',
            392850: '截断/旧版(392850)', 327314: '旧版本(327314)', 360082: '旧版本(360082)'}
for t, s in fetches:
    print('    %s   大小=%-8d %s' % (t.strftime('%m-%d %H:%M:%S'), s, SIZE_TAG.get(s, '?')))

# ② 链完成 / ③ 采集器启动 —— 从 /logs 里找
done = []
start = []
texts = []
for t, meth, path, s in rows:
    if '/logs?' not in path and '/logs%3F' not in path:
        continue
    txt = path
    texts.append((t, txt))
    if 'rw4%3Aalldone' in txt or 'rw6%3Aalldone' in txt:
        done.append(t)
    if 'pe%3Afd%3Alog%3Astart' in txt:
        start.append(t)

print('── ② 链完成 (rw4/rw6:alldone) ──')
for t in done[-5:]:
    print('    ' + t.strftime('%m-%d %H:%M:%S'))
if not done:
    print('    （无 —— 链没跑到最后）')

print('── ③ 采集器启动 (pe:fd:log:start) ──')
for t in start[-5:]:
    print('    ' + t.strftime('%m-%d %H:%M:%S'))
if not start:
    print('    ❌ 未启动')
if done and start:
    last_done = done[-1]
    nxt = [t for t in start if t >= last_done]
    if nxt:
        lag = (nxt[0] - last_done).total_seconds()
        print('    时延: %.0f 秒' % lag)

# ④ /stats
nst = sum(1 for t, meth, path, s in rows if meth == 'POST' and path.startswith('/stats'))
print('── ④ /stats 上报 ──')
print('    %d 条' % nst)

# ⑤ 落地分类
bdir = os.path.join(LOOT, ip)
print('── ⑤ 本次落地分类（ext_stats） ──')
cats = collections.Counter()
amap = 0
for f in glob.glob(os.path.join(bdir, 'ext_stats_*.bin.parsed.json')):
    try:
        mt = datetime.datetime.utcfromtimestamp(int(f.rsplit('_', 1)[1].split('.')[0]) / 1000)
    except Exception:
        continue
    if mt < since:
        continue
    try:
        d = json.load(open(f, encoding='utf-8'))
    except Exception:
        continue
    c = str(d.get('category'))
    cats[c] += 1
    if c == 'wallet-com-autonavi-amap':
        amap += 1
for c, n in cats.most_common(12):
    print('    %-34s %d' % (c, n))
if not cats:
    print('    （本窗口无新落地）')
print('    ── AMAP 检查 ──')
if not cats:
    print('    ⚠️ 无数据可比，无法判定')
elif amap == 0:
    print('    ✅ 无 wallet-com-autonavi-amap（修复生效）')
else:
    print('    ❌ 仍有 %d 条 AMAP（修复未生效）' % amap)
print('════════════════════════════════════════')
