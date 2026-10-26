#!/bin/bash
# prune_ext_logs.sh — ext_logs 清理（cron 每天 03:35）
# 背景：admin_server 的 /logs 端点（18 链设备调试日志）每次上报写一个独立 txt（~97 字节），
#   投递放量后达到 ~20 万个/天 —— 文件数灾难（readdir/scan 拖垮面板）。
# 策略：3 天前的打包成 tar.gz 归档（省 inode、可查），最近 3 天保留原文件。
# 注：日志摘要亦记录在 /www/wwwlogs/i.131422.com.deliveries.log（JSONL，含 ip/uuid/ua/前200字符）。
set -u
LOOT=/www/wwwroot/i.131422.com/loot
AR=/www/loot_logs_archive
mkdir -p "$AR"
OUT="$AR/ext_logs_$(date +%Y%m%d).tar.gz"
n=1
while [ -e "$OUT" ]; do OUT="$AR/ext_logs_$(date +%Y%m%d)_$n.tar.gz"; n=$((n+1)); done   # 同日重跑不覆盖已有归档
COUNT=$(find "$LOOT"/*/ -maxdepth 1 -name 'ext_logs_*.txt' ! -newermt '3 days ago' 2>/dev/null | wc -l)
if [ "$COUNT" -gt 0 ]; then
  find "$LOOT"/*/ -maxdepth 1 -name 'ext_logs_*.txt' ! -newermt '3 days ago' -print0 2>/dev/null \
    | tar -czf "$OUT" --null -T - --remove-files 2>/dev/null
  echo "$(date -u +%FT%TZ) archived $COUNT files -> $OUT ($(du -h "$OUT" 2>/dev/null | cut -f1))"
else
  echo "$(date -u +%FT%TZ) nothing to prune"
fi
