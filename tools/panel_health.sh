#!/bin/bash
# panel_health.sh — 面板健康监控（cron 每分钟）
# 记录：面板响应时间（本机 + 域名）、面板进程 CPU/内存、快照体积/mtime、负载；
#   慢（首页 >3s）或快照异常时抓现场写入日志。
# 【2026-09-12 分片升级】新增 v2 分片指标：core（常驻小快照）体积/age + POINTER；旧单文件保留监控（过渡期双写）。
# 日志：logs/panel_health.log（保留最近 3000 行）
LOG=/www/wwwroot/i.131422.com/logs/panel_health.log
SNAP=/www/wwwroot/i.131422.com/adm888app/data/store_snapshot.json
SDIR=/www/wwwroot/i.131422.com/adm888app/data/snapshot
POINTER=$SDIR/POINTER
mkdir -p "$(dirname "$LOG")"
TS=$(date -u +%FT%TZ)

# 1) 本机响应（面板事件循环）
R1=$(curl -s -o /dev/null -w '%{http_code}:%{time_total}' -m 120 http://127.0.0.1:8020/ 2>/dev/null || echo "TO:120")
# 2) 域名响应（含 nginx 链路）
R2=$(curl -s -o /dev/null -w '%{http_code}:%{time_total}' -m 120 http://wpsdz.com/adm888panel/ 2>/dev/null || echo "TO:120")
# 3) 面板容器（新机 Docker 架构：面板跑在 i131422-panel 容器内，宿主 ps 看不到）
if [ "$(docker inspect -f '{{.State.Running}}' i131422-panel 2>/dev/null)" = "true" ]; then
  P=$(docker stats --no-stream --format '{{.CPUPerc}} {{.MemUsage}}' i131422-panel 2>/dev/null | awk '{printf "%s/%s", $1, $2}')
else
  P="DOWN!"
fi
# 4a) 分片 v2：core 体积 / POINTER 年龄
CORE=-1; COREAGE=-1
if [ -f "$POINTER" ]; then
  VER=$(tr -d '\n' < "$POINTER" 2>/dev/null)
  CORE=$(( $(stat -c %s "$SDIR/$VER/core.json" 2>/dev/null || echo 0) / 1048576 ))
  COREAGE=$(( $(date +%s) - $(stat -c %Y "$POINTER" 2>/dev/null || echo 0) ))
fi
# 4b) 旧单文件（过渡期）
if [ -f "$SNAP" ]; then
  SZ=$(stat -c %s "$SNAP"); MT=$(stat -c %Y "$SNAP")
  SNAPMB=$(( SZ / 1048576 ))
  SNAPAGE=$(( $(date +%s) - MT ))
else
  SNAPMB=0; SNAPAGE=-1
fi
LOAD=$(cut -d' ' -f1-3 /proc/loadavg)

T1=${R1##*:}; T2=${R2##*:}
FLAGS=""
awk -v t="$T1" 'BEGIN{exit !(t>3)}' && FLAGS="$FLAGS SLOW-home=${T1}s"
awk -v t="$T2" 'BEGIN{exit !(t>3)}' && FLAGS="$FLAGS SLOW-http=${T2}s"
[ "$SNAPMB" -gt 450 ] && FLAGS="$FLAGS SNAP-BIG=${SNAPMB}MB"
[ "$SNAPAGE" -gt 1200 ] && [ "$SNAPMB" -gt 0 ] && [ "$CORE" -lt 0 ] && FLAGS="$FLAGS SNAP-STALE=${SNAPAGE}s"
[ "$CORE" -gt 60 ] && FLAGS="$FLAGS CORE-BIG=${CORE}MB"
# 【2026-09-13 复审】CORE-STALE 阈值与读端 SNAPSHOT_MAX_MS 对齐（45→180 分钟）：构建周期在全量重建
#   轮可达 80-90 分钟，2700s 会持续误报；180min 后若仍无新快照 → 构建连续失败，值得告警。
[ "$COREAGE" -gt 10800 ] && FLAGS="$FLAGS CORE-STALE=${COREAGE}s"
# 【2026-09-13 复审】构建健康检查（补 OOM 崩溃无人知的缺口）：
#   ①最后 60 行出现 FATAL/heap out of memory → 提示；②最后 60 行无任何完成行 → 多轮未成功构建，告警。
BLOG=/www/wwwroot/i.131422.com/logs/store_snapshot.log
if [ -f "$BLOG" ]; then
  BTAIL=$(tail -60 "$BLOG" 2>/dev/null)
  echo "$BTAIL" | grep -q "FATAL ERROR\|heap out of memory" && FLAGS="$FLAGS BUILD-OOM"
  echo "$BTAIL" | grep -q "legacy disabled\|^\[snapshot\] [0-9]*ms" || FLAGS="$FLAGS BUILD-NO-DONE"
fi
[ "$P" = "DOWN!" ] && FLAGS="$FLAGS PANEL-DOWN"

LINE="$TS home=$R1 http=$R2 panel=$P snap=${SNAPMB}MB/age=${SNAPAGE}s core=${CORE}MB/age=${COREAGE}s load=$LOAD"
if [ -n "$FLAGS" ]; then
  echo "$LINE [WARN$FLAGS]" >> "$LOG"
  # 慢/异常时抓现场（一次性快照，供事后分析）
  {
    echo "$TS --- 现场: top8 ---"
    top -bn1 2>/dev/null | head -14 | tail -8
    echo "$TS --- 现场: nginx 错误尾 3 ---"
    grep -a "upstream\|504\|timed out" /opt/i131422/wwwlogs/i.131422.com.error.log 2>/dev/null | tail -3 | cut -c1-200
  } >> "$LOG" 2>/dev/null
else
  echo "$LINE [ok]" >> "$LOG"
fi

# 保留最近 3000 行
tail -3000 "$LOG" > "$LOG.tmp" 2>/dev/null && mv "$LOG.tmp" "$LOG"
