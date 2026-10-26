#!/bin/bash
# 16.1 重投盯梢（临时）：抓 plugin_* 事件 + daily/corefiles 请求
L=/www/wwwroot/i.131422.com/loot
LOG=/www/wwwlogs/i.131422.com.log
SEEN=/tmp/hg_retest_seen.txt
HIT=/tmp/hg_retest_found
REQ=/tmp/hg_retest_req.txt
: > "$SEEN"; rm -f "$HIT"; : > "$REQ"
END=$(( $(date +%s) + 1800 ))
echo "[$(date -u +%T)] watcher start (30min cap)"

while [ "$(date +%s)" -lt "$END" ]; do
  SINCE="$(date -u -d '-90 seconds' '+%Y-%m-%d %H:%M:%S')"
  find "$L" -name '*.json' ! -name '*.meta.json' -newermt "$SINCE" 2>/dev/null > /tmp/hg_retest_files.txt
  while IFS= read -r f; do
    grep -q 'plugin_batch_done\|plugin_download_ok\|plugin_download_failed\|plugin_verify_failed\|config_download_failed\|corepayload_update' "$f" 2>/dev/null || continue
    grep -qF "$f" "$SEEN" 2>/dev/null && continue
    echo "$f" >> "$SEEN"
    python3 - "$f" <<'PY'
import json, sys, datetime
f = sys.argv[1]
try:
    d = json.load(open(f))
except Exception:
    sys.exit()
print('[%s] %-24s dev=%-12s os=%-7s total=%-3s entries=%-3s ok=%-3s sb=%-3s bundle=%-28s reason=%s' % (
    datetime.datetime.utcnow().strftime('%H:%M:%S'), d.get('et'), str(d.get('device')),
    str(d.get('pv')), str(d.get('total')), str(d.get('entries')), str(d.get('ok')),
    str(d.get('springboard')), str(d.get('bundleId'))[:28], d.get('reason')))
PY
    case "$(python3 -c "import json,sys;print(json.load(open('$f')).get('et',''))" 2>/dev/null)" in
      plugin_batch_done|plugin_download_ok|plugin_download_failed|plugin_verify_failed) echo hit >> "$HIT" ;;
    esac
  done < /tmp/hg_retest_files.txt

  grep -a "sync/daily.html\|corefiles/variants" "$LOG" 2>/dev/null | tail -400 \
    | grep -av "^127.0.0.1" | tail -8 > "$REQ"

  if [ -s "$HIT" ]; then echo "[$(date -u +%T)] 命中 plugin_* 事件，退出"; break; fi
  sleep 20
done

echo "=== watcher 结束 $(date -u +%T) ==="
echo "--- 期间新事件 ($(wc -l < "$SEEN") 条) ---"
while IFS= read -r f; do basename "$f"; done < "$SEEN"
echo "--- 最新 daily/corefiles 外部请求 ---"
cat "$REQ" 2>/dev/null
echo "--- post_t 最新 5 ---"
ls -t "$L"/unknown_posts/post_t_*.bin 2>/dev/null | head -5 | while read -r x; do echo "$(basename "$x")"; done
