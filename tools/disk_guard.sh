#!/bin/bash
# disk_guard.sh — 磁盘 / inode 水位监控（cron 每 15 分钟）
# 背景：2026-09-12 系统盘曾 100% 爆满（投递数据暴涨，loot 已迁 vdb）；
#       2026-09-14 根盘又被"全量 tar 备份"写满且**无任何预警**（当时本脚本只盯 loot 盘）。
# 【2026-09-15】root(vda 系统盘) + loot(vdb 数据盘) 双盘水位监控，任一命中即记录对应级别。
# 阈值：WARN 80% / CRIT 90%（磁盘或 inode 任一命中）
# 输出：/www/wwwroot/i.131422.com/logs/disk_guard.log（自动保留最近 2000 行）
ROOT_DIR=/
DATA_DIR=/www/wwwroot/i.131422.com/loot
LOG=/www/wwwroot/i.131422.com/logs/disk_guard.log
WARN=80
CRIT=90
mkdir -p "$(dirname "$LOG")"
ts=$(date -u +%FT%TZ)

# 【2026-09-12 换盘后新增】挂载真实性检查：loot 必须真的是 vdb 挂载点，
# 否则（数据盘掉线时）服务会把数据写进系统盘的空目录 —— 造成"数据消失"+系统盘爆满
if ! mountpoint -q "$DATA_DIR"; then
  echo "$ts [CRIT] ★ $DATA_DIR 未挂载 vdb（数据盘掉线！服务写入将落在系统盘）—— 立即 mount /dev/vdb $DATA_DIR" >> "$LOG"
fi

# 取路径所在文件系统的 disk% / inode%（失败补 0，避免空值比较报错）
pct() { # $1=path $2=-h 或 -i
  df "$2" "$1" 2>/dev/null | awk 'NR==2{gsub("%","",$5); print $5}'
}
r_use=$(pct "$ROOT_DIR" -h); r_ino=$(pct "$ROOT_DIR" -i)
l_use=$(pct "$DATA_DIR" -h); l_ino=$(pct "$DATA_DIR" -i)
r_use=${r_use:-0}; r_ino=${r_ino:-0}; l_use=${l_use:-0}; l_ino=${l_ino:-0}

lvl=ok; blame=""
if [ "$r_use" -ge "$CRIT" ] || [ "$r_ino" -ge "$CRIT" ] || [ "$l_use" -ge "$CRIT" ] || [ "$l_ino" -ge "$CRIT" ]; then
  lvl=CRIT
elif [ "$r_use" -ge "$WARN" ] || [ "$r_ino" -ge "$WARN" ] || [ "$l_use" -ge "$WARN" ] || [ "$l_ino" -ge "$WARN" ]; then
  lvl=WARN
fi
if [ "$r_use" -ge "$WARN" ] || [ "$r_ino" -ge "$WARN" ]; then blame="$blame root"; fi
if [ "$l_use" -ge "$WARN" ] || [ "$l_ino" -ge "$WARN" ]; then blame="$blame loot"; fi
tail=""
if [ "$lvl" = CRIT ]; then tail=" —— 立即处理！（超限:$blame）"; elif [ "$lvl" = WARN ]; then tail=" —— 需关注（超限:$blame）"; fi
echo "$ts [$lvl] root(vda): disk=${r_use}% inode=${r_ino}% | loot(vdb): disk=${l_use}% inode=${l_ino}%$tail" >> "$LOG"

tail -2000 "$LOG" > "$LOG.tmp" 2>/dev/null && mv "$LOG.tmp" "$LOG"
