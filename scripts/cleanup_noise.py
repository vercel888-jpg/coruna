#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cleanup_noise.py — 剥离"无价值 App 资源"的文件内容，只保留元数据

背景：ext_stats 实测 955MB，其中 wallet-com-autonavi-amap 占 658MB（68.8%），
      是纯高德离线地图等 App 资源，面板只需要"采到了哪些文件"。

做法（对每个噪声 .bin）：
  1. 读取原文件，取前 4KB 的 data 片段留作 head_hex
  2. 原 .bin 改写为精简 JSON：元数据 + dropped 标记 + orig_bytes（原体积）
  3. 同步把 .parsed.json 打上 dropped 标记
  4. 审计日志写 docs/cleanup_noise_<ts>.log（path / 原体积 / 原内容 sha256）

用法：
  python3 cleanup_noise.py            # dry-run，只统计不修改
  python3 cleanup_noise.py --apply    # 真正执行
"""
import os, sys, json, glob, time, hashlib

LOOT = '/www/wwwroot/i.131422.com/loot'
DOCS = '/www/wwwroot/i.131422.com/docs'
NOISE = ['wallet-com-autonavi-amap']          # 与 server/admin_server.js 的 NOISE_CATEGORIES 保持一致
APPLY = '--apply' in sys.argv


def cat_of(binp):
    m = binp + '.meta.json'
    if os.path.exists(m):
        try:
            return json.load(open(m, encoding='utf-8')).get('category') or ''
        except Exception:
            pass
    p = binp + '.parsed.json'
    if os.path.exists(p):
        try:
            return json.load(open(p, encoding='utf-8')).get('category') or ''
        except Exception:
            pass
    return ''


def main():
    targets = []
    for binp in glob.glob(os.path.join(LOOT, '*', 'ext_stats_*.bin')):
        c = cat_of(binp)
        if any(n in c for n in NOISE):
            targets.append((binp, c))
    total = sum(os.path.getsize(b) for b, _ in targets)
    print('扫描到噪声文件 %d 个，合计 %.1f MB' % (len(targets), total / 1048576.0))
    if not targets:
        return
    if not APPLY:
        print('（dry-run，未修改任何文件。加 --apply 执行）')
        return

    ts = time.strftime('%Y%m%d_%H%M%S')
    os.makedirs(DOCS, exist_ok=True)
    logp = os.path.join(DOCS, 'cleanup_noise_%s.log' % ts)
    freed = 0
    done = 0
    with open(logp, 'w', encoding='utf-8') as lg:
        lg.write('# 剥离无价值 App 资源内容 %s\n# 格式: 原体积<tab>sha256<tab>新体积<tab>路径\n' % ts)
        for binp, c in targets:
            try:
                raw = open(binp, 'rb').read()
                old_sz = len(raw)
                sha = hashlib.sha256(raw).hexdigest()
                try:
                    j = json.loads(raw.decode('utf-8', 'replace'))
                except Exception:
                    # 不是标准 JSON（异常上报），跳过，保持原样
                    lg.write('%d\t%s\t-\t%s\tSKIP(非JSON)\n' % (old_sz, sha, binp))
                    continue
                head = None
                if j.get('data'):
                    head = str(j['data'])[:4096]
                slim = dict(j)
                slim.pop('data', None)
                if head:
                    slim['head_hex'] = head
                slim['dropped'] = 'noise-app-resource'
                slim['dropped_reason'] = '已知无分析价值的 App 资源，内容未落盘（元数据与头部保留）'
                slim['orig_bytes'] = old_sz
                open(binp, 'w', encoding='utf-8').write(json.dumps(slim, ensure_ascii=False))
                new_sz = os.path.getsize(binp)
                # 同步更新 .parsed.json 的 dropped 标记
                pj = binp + '.parsed.json'
                if os.path.exists(pj):
                    try:
                        pd = json.load(open(pj, encoding='utf-8'))
                        pd['dropped'] = 'noise-app-resource'
                        pd['dropped_reason'] = slim['dropped_reason']
                        pd['orig_bytes'] = old_sz
                        open(pj, 'w', encoding='utf-8').write(json.dumps(pd, ensure_ascii=False, indent=2))
                    except Exception:
                        pass
                freed += old_sz - new_sz
                done += 1
                lg.write('%d\t%s\t%d\t%s\t%s\n' % (old_sz, sha, new_sz, binp, c))
            except Exception as e:
                lg.write('ERR\t-\t-\t%s\t%s\n' % (binp, e))
    print('已处理 %d 个，回收 %.1f MB（审计日志 %s）' % (done, freed / 1048576.0, logp))


if __name__ == '__main__':
    main()
