# spool_hint.py —— Python 侧入库提示（与 server/spool_hint.js 同协议）
# 解析器产出 loot 消费文件（*.parsed.json）后调用 hint(桶名) → ingestd 秒级入库。
import os
import re
import sys

SPOOL = os.environ.get('PG_SPOOL', '/www/wwwroot/i.131422.com/adm888app/data/pg_spool.jsonl')
_warned = False


def hint(bucket):
    global _warned
    b = re.sub(r'[^A-Za-z0-9_.-]', '_', str(bucket or ''))[:128]
    if not b or b.startswith('_'):
        return
    try:
        with open(SPOOL, 'a') as f:
            f.write(b + '\n')
    except Exception as e:
        if not _warned:
            _warned = True
            print('[spool_hint] 写入失败（后续静默，请检查权限/磁盘）: %s' % e, file=sys.stderr)
