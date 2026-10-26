#!/bin/bash
# ir_watch.sh — 入侵后监视器 v4（2026-09-18 / 安静模式）
# 初始化: bash ir_watch.sh --init [quiet]   （建基线；quiet 不发 TG）
# 常规:   bash ir_watch.sh                  （cron 每 2 分钟）
# TG 推送只报这几类：
#   1) 盯防 IP 再现（已知攻击者 IP / 38.49.39.211）
#   2) 系统面变化（公钥/sshd/账号/cron/systemd/SUID/preload；端口：仅"从未见过的新监听"推送，
#      "服务重启导致的端口消失/回归"只记本地——避免自家人重启服务的噪声）
#   3) 站点目录出现新增 PHP / 带 webshell 特征的新文件
#   4) 宝塔面板登录请求密集（≥5 条/轮，疑似爆破）
#   5) /ws/shell 活动
# 其余全部只写本地日志： logs/ir_watch/events.log
set -u
ROOT=/www/wwwroot/i.131422.com
BASE=$ROOT/logs/ir_watch
STATE=$BASE/state
LOG=$BASE/events.log
TG_TOKEN="8219304023:AAGp5rvHP1o02g_pO4e0v0JaJ-1ZY5V_S5U"
TG_CHAT="2098010058"
WATCH_IPS="154.219.127.94 154.18.187.160 112.213.108.85 38.49.39.211 38.60.133.221"
BTLOG_TODAY=/www/server/panel/logs/request/$(date +%F).json
AUTHLOG=/var/log/auth.log
DWSLOG=/root/.pm2/logs/darksword-rce-out.log
mkdir -p "$STATE"

exec 9>"$BASE/.lock"
flock -n 9 2>/dev/null || exit 0

ts(){ date '+%F %T'; }
PAUSE_F="$BASE/PAUSE_TG"   # 【2026-09-19】迁移期降噪开关：文件存在时只写本地日志、不推 TG；删除文件（rm $PAUSE_F）即恢复推送
send_tg(){ if [ -f "$PAUSE_F" ]; then printf '%s [PAUSED] TG 已暂停（%s），内容仅记本地：%s\n' "$(ts)" "$PAUSE_F" "$1" >> "$LOG"; return 0; fi
  curl -s -m 12 "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
  --data-urlencode "chat_id=${TG_CHAT}" --data-urlencode "text=$1" >/dev/null 2>&1 || true; }

surface(){
  {
    echo "== ssh_keys"
    for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
      [ -f "$f" ] && { echo "$f"; wc -c < "$f"; md5sum "$f"; }
    done
    echo "== sshd_dropins"
    ls /etc/ssh/sshd_config.d/ 2>/dev/null
    echo "== passwd"
    awk -F: '$3>=1000 || $1=="root" {print $1":"$3":"$7}' /etc/passwd
    echo "== cron"
    ls /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ 2>/dev/null
    crontab -l 2>/dev/null | grep -v '^#'
    echo "== systemd"
    ls /etc/systemd/system/*.service /etc/systemd/system/*.timer 2>/dev/null
    echo "== suid"
    find /usr/bin /usr/sbin /bin /sbin /tmp /var/tmp -xdev -perm -4000 -type f 2>/dev/null
    echo "== preload"
    cat /etc/ld.so.preload 2>/dev/null || true
    echo "== panel_db"
    md5sum /www/server/panel/data/db/panel.db 2>/dev/null
    echo "== agent_accounts"
    python3 - <<'PY' 2>/dev/null || true
import json,hashlib
try:
    d=json.load(open('/www/wwwroot/i.131422.com/adm888app/data/auth.json'))
    s=hashlib.md5()
    for u in sorted(d.get('users',[]),key=lambda x:x.get('id',0)):
        s.update(('%s|%s|%s|%s\n'%(u.get('id'),u.get('username'),u.get('role'),u.get('status'))).encode())
    print(s.hexdigest(), len(d.get('users',[])), len(d.get('agent_links',[])))
except Exception as e:
    print('ERR', e)
PY
  }
}

webfiles_since(){
  local since="$1"
  find $ROOT/client $ROOT/pe $ROOT/sync $ROOT/api $ROOT/server $ROOT/variants $ROOT/coruna $ROOT/darksword $ROOT/entry_upload \
       $ROOT/adm888app $ROOT/tools $ROOT/docker_deploy \
       /www/wwwroot/ios.131422.com /www/wwwroot/q.131422.com /www/wwwroot/k.131422.com \
       -type f -newermt "@$since" \
       -not -path '*/node_modules/*' -not -path '*/loot/*' -not -path '*/docs/*' -not -path '*/logs/*' \
       -not -path '*/data/*' -not -path '*/__pycache__/*' -not -path '*/.git/*' -not -path '*/upload/*' \
       -not -name '*.log' -not -name '*.log.*' -not -name '*.pid' -not -path '*/console/data.json' \
       -printf '%TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort | head -60
}

delta_since(){  # $1=目标文件 $2=offset文件；输出新增内容并推进 offset（轮转自动清零）
  local f="$1" offf="$2" off sz
  [ -f "$f" ] || return 0
  off=$(cat "$offf" 2>/dev/null || echo 0); case "$off" in ''|*[!0-9]*) off=0;; esac
  sz=$(stat -c%s "$f")
  [ "$sz" -lt "$off" ] && off=0
  if [ "$sz" -gt "$off" ]; then tail -c +$((off+1)) "$f"; fi
  echo "$sz" > "$offf"
}

case "${1:-run}" in
--init)
  surface > "$STATE/surface.snap"
  ss -tlnH 2>/dev/null | awk '{print $4}' | sort -u > "$STATE/ports.snap"
  cp -f "$STATE/ports.snap" "$STATE/ports_known.snap"
  date +%s > "$STATE/last_ts"
  for pair in "$BTLOG_TODAY:$STATE/bt_off" "$AUTHLOG:$STATE/auth_off" "$DWSLOG:$STATE/ws_off"; do
    f="${pair%%:*}"; o="${pair##*:}"
    if [ -f "$f" ]; then stat -c%s "$f" > "$o"; else echo 0 > "$o"; fi
  done
  echo "$(ts) init ok" >> "$LOG"
  [ "${2:-}" != "quiet" ] && send_tg "🛡 IR 监视器已上线（安静模式：平时只记本地，只有攻击迹象才推这里）。"
  exit 0;;
--test)
  send_tg "🛡 IR 监视器测试：$(date '+%F %T')"
  exit 0;;
esac

HIGH=""
LOW=""
h(){ HIGH="${HIGH}• $1\n"; }
l(){ LOW="${LOW}• $1\n"; }

# 1) 系统面 → 高危（推）
NEW_SURFACE=$(surface)
if ! diff -q <(printf '%s\n' "$NEW_SURFACE") "$STATE/surface.snap" >/dev/null 2>&1; then
  diff <(cat "$STATE/surface.snap") <(printf '%s\n' "$NEW_SURFACE") > "$STATE/surface.diff" 2>/dev/null || true
  h "系统面有变更（可能的入侵痕迹）：
$(head -25 "$STATE/surface.diff")"
  printf '%s\n' "$NEW_SURFACE" > "$STATE/surface.snap"
fi

# 1b) 端口：从未见过的新监听=推；消失/回归=本地（避免自家人重启服务的噪声）
CUR_PORTS=$(ss -tlnH 2>/dev/null | awk '{print $4}' | sort -u)
if [ -s "$STATE/ports_known.snap" ]; then
  P_NEW=$(comm -13 "$STATE/ports_known.snap" <(printf '%s\n' "$CUR_PORTS") | grep -v '^$')
  [ -n "$P_NEW" ] && h "新增监听端口（从未见过，留意后门）：\n$P_NEW"
  cat "$STATE/ports_known.snap" <(printf '%s\n' "$CUR_PORTS") | sort -u > "$STATE/ports_known.tmp" && mv "$STATE/ports_known.tmp" "$STATE/ports_known.snap"
else
  printf '%s\n' "$CUR_PORTS" > "$STATE/ports_known.snap"
fi
if [ -s "$STATE/ports.snap" ]; then
  P_GONE=$(comm -23 "$STATE/ports.snap" <(printf '%s\n' "$CUR_PORTS") | grep -v '^$')
  [ -n "$P_GONE" ] && l "监听端口消失（多为服务重启）：$P_GONE"
fi
printf '%s\n' "$CUR_PORTS" > "$STATE/ports.snap"

# 2) 站点目录新文件 → PHP/webshell 特征推，其余本地
TS=$(cat "$STATE/last_ts" 2>/dev/null || date +%s)
case "$TS" in ''|*[!0-9]*) TS=$(date +%s);; esac
NEWF=$(webfiles_since "$TS")
if [ -n "$NEWF" ]; then
  FILES=$(printf '%s\n' "$NEWF" | awk '{print $3}')
  PHPF=$(printf '%s\n' "$FILES" | grep -E '\.(php|phtml|phar)$' | head -20)
  SIGF=""
  for f in $(printf '%s\n' "$FILES" | head -40); do
    case "$f" in *.jpg|*.jpeg|*.png|*.webp|*.gif|*.json|*.sqlite|*.db) continue;; esac
    case "$f" in */ir_watch.sh) continue;; esac   # 【2026-09-19】监视器自身携带特征词表，编辑它会自匹配误报，跳过自扫
    grep -lqE 'eval[[:space:]]*\(|base64_decode|assert[[:space:]]*\(|shell_exec|passthru|popen|gzinflate\(base64' "$f" 2>/dev/null && SIGF="$SIGF $f"
  done
  [ -n "$SIGF" ] && h "🧨 新增文件疑似 webshell：$SIGF"
  [ -n "$PHPF" ] && h "站点目录出现新增 PHP：\n$PHPF"
  OTHERS=$(printf '%s\n' "$NEWF" | grep -vE '\.(php|phtml|phar)$' | head -40)
  [ -n "$OTHERS" ] && l "站点目录新/改文件：\n$OTHERS"
fi
date +%s > "$STATE/last_ts"

# 3) 宝塔面板增量 → 密集登录/盯防IP 推，单条登录本地
BT_DELTA=$(delta_since "$BTLOG_TODAY" "$STATE/bt_off")
if [ -n "$BT_DELTA" ]; then
  LOGIN_DELTA=$(printf '%s\n' "$BT_DELTA" | grep -a '"/login' | head -10 | cut -c1-220)
  if [ -n "$LOGIN_DELTA" ]; then
    CNT=$(printf '%s\n' "$LOGIN_DELTA" | wc -l)
    if [ "$CNT" -ge 5 ]; then
      h "宝塔面板登录请求密集（疑似爆破，$CNT 条/轮）：\n$LOGIN_DELTA"
    else
      l "宝塔面板登录请求（$CNT 条）：\n$LOGIN_DELTA"
    fi
  fi
  for ip in $WATCH_IPS; do
    IL=$(printf '%s\n' "$BT_DELTA" | grep -a "$ip" | head -3 | cut -c1-220)
    [ -n "$IL" ] && h "🚨 盯防IP出现在宝塔面板：$ip\n$IL"
  done
fi

# 4) auth.log 增量 → 盯防IP 推，普通登录本地
A_DELTA=$(delta_since "$AUTHLOG" "$STATE/auth_off")
if [ -n "$A_DELTA" ]; then
  ACL=$(printf '%s\n' "$A_DELTA" | grep -a 'Accepted' | head -6 | cut -c1-170)
  [ -n "$ACL" ] && l "新 SSH 登录：\n$ACL"
  for ip in $WATCH_IPS; do
    IL=$(printf '%s\n' "$A_DELTA" | grep -a "$ip" | head -3 | cut -c1-170)
    [ -n "$IL" ] && h "🚨 盯防IP出现在 auth.log：$ip\n$IL"
  done
fi

# 5) darksword /ws/shell → 推
WD=$(delta_since "$DWSLOG" "$STATE/ws_off")
if [ -n "$WD" ]; then
  H=$(printf '%s\n' "$WD" | grep -a 'ws/shell' | head -5 | cut -c1-170)
  [ -n "$H" ] && h "🖥 /ws/shell 活动：\n$H"
fi

# 汇总：本地全记；TG 只推 HIGH（同内容 30 分钟内不重复）
if [ -n "$LOW$HIGH" ]; then
  printf '%s\n== TG段 ==\n%s== 本地段 ==\n%s\n' "$(ts)" "$HIGH" "$LOW" >> "$LOG"
fi
if [ -n "$HIGH" ]; then
  HASH=$(printf '%s' "$HIGH" | md5sum | awk '{print $1}')
  LASTA=$(cat "$STATE/last_alert_hash" 2>/dev/null || echo '')
  LASTT=$(cat "$STATE/last_alert_ts" 2>/dev/null || echo 0)
  case "$LASTT" in ''|*[!0-9]*) LASTT=0;; esac
  NOW=$(date +%s)
  if [ "$HASH" != "$LASTA" ] || [ $((NOW-LASTT)) -gt 1800 ]; then
    send_tg "🚨 $(ts) 需要你知道的动静：
${HIGH}"
    echo "$HASH" > "$STATE/last_alert_hash"
    echo "$NOW" > "$STATE/last_alert_ts"
  fi
fi
exit 0
