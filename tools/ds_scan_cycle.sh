#!/bin/bash
# ds_scan_cycle.sh — DS 扫描流水线（增量档·高清）: 余额检查 → 扫描 → 未过项复扫 → 面板同步
# cron: 4,14,24,34,44,54 * * * *  /bin/bash /www/wwwroot/i.131422.com/tools/ds_scan_cycle.sh >> /www/wwwroot/i.131422.com/logs/ds_cycle.log 2>&1
# 资源约束（增量档）: 并发30 + 4核(20-23) + nice15 + io低优 → 负载占用控制在 30-50%
# 数据纪律: 只扫未扫过的图（ai_scan_log 主键锁死，永不重扫）
# 余额保护: 低于 5 元自动跳过扫描/复扫（只跑免费的面板同步），避免余额耗尽后刷出大量 error 记录
cd /www/wwwroot/i.131422.com || exit 1
exec 9>/tmp/ds_cycle.lock
flock -n 9 || exit 0

BAL_CENTS=$(/root/venv/bin/python3 - <<'PY' 2>/dev/null
import re, json, urllib.request
try:
    key = ''
    try:   # 【2026-09-15】优先专用 key 文件（与扫描器同口径），缺失回退 kimi-code 配置
        key = open('/www/wwwroot/i.131422.com/adm888app/data/ds_api_key.txt', encoding='utf-8').read().strip()
    except Exception:
        key = ''
    cfg = open('/root/.kimi-code/config.toml', encoding='utf-8').read()
    blk = re.search(r'\[providers\.deepseek\]([^\[]*)', cfg, re.S).group(1)
    if not key:
        key = re.search(r'api_key\s*=\s*"([^"]+)"', blk).group(1)
    base = re.search(r'base_url\s*=\s*"([^"]+)"', blk).group(1).rstrip('/')
    req = urllib.request.Request(base + '/user/balance', headers={'Authorization': 'Bearer ' + key})
    j = json.loads(urllib.request.urlopen(req, timeout=15).read())
    b = j['balance_infos'][0]['total_balance']
    print(int(float(b) * 100))
except Exception:
    print(999999)   # 查询失败不阻塞（宁可跑）
PY
)
if [ "${BAL_CENTS:-0}" -ge 500 ]; then
    nice -n 15 ionice -c2 -n7 taskset -c 20-23 /root/venv/bin/python3 tools/ds_mnemonic_scan.py --concurrency 30 >> logs/ds_mnemonic_scan.log 2>&1
    nice -n 15 /root/venv/bin/python3 tools/ds_rescan_failed.py >> logs/ds_rescan.log 2>&1
else
    echo "[$(date -u +%FT%TZ)] 余额低于 5 元（${BAL_CENTS} 分），跳过扫描/复扫；请充值后自动恢复" >> logs/ds_cycle.log
fi
/root/venv/bin/python3 tools/ds_sync_panel.py >> logs/ds_sync.log 2>&1
