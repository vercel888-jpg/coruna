#!/bin/bash
# fc_quickflush.sh — 手动触发设备数据回填（测试用：真机投递后执行 → 面板秒级可见）
# 用法: bash /www/wwwroot/i.131422.com/tools/fc_quickflush.sh
cd /www/wwwroot/i.131422.com || exit 1
echo "=== $(date '+%F %T') 触发回填（pg_backfill + pg_sync_globals）==="
docker exec -w /www/wwwroot/i.131422.com i131422-panel node tools/pg_backfill.js 2>&1 | tail -2
docker exec -w /www/wwwroot/i.131422.com i131422-panel node tools/pg_sync_globals.js 2>&1 | tail -3
echo "--- 最近 15 分钟入库的设备 ---"
docker exec i131422-panel sh -c 'cat /www/wwwroot/i.131422.com/adm888app/data/pg.json 2>/dev/null' >/dev/null 2>&1
su - postgres -c "psql -d panel -t -c \"SELECT serial || ' | iOS ' || coalesce(ios_version,'?') || ' | ' || to_char(to_timestamp(first_seen/1000),'HH24:MI:SS') FROM devices WHERE first_seen > (extract(epoch from now())*1000 - 900000) ORDER BY first_seen DESC LIMIT 6;\"" 2>/dev/null || echo "(PG 查询需在宿主机 postgres 用户下运行)"
echo "=== 完成：回上面看有没有新设备 ==="
