#!/usr/bin/env node
// decrypt_v6_backlog.js — v6 上报通道「积压补解」（decrypt_v6_watch.js 的回填版）
//   与 watcher 同一算法：key = sha256(FIX16 + 13位ms时间戳)，AES-256-ECB/PKCS7，
//   明文 = 13位时间戳前缀 + JSON。watcher 只看最近 10 分钟，本脚本把历史积压全部补上。
// 用法: node decrypt_v6_backlog.js [并发数] [--limit N]
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const LOOT_DIR = '/www/wwwroot/i.131422.com/loot';
const FIX16 = Buffer.from('37404c62226057355f3767584e3b3638', 'hex');
const WINDOW_MS = 30000;

function decrypt(ct, ts) {
    const key = crypto.createHash('sha256').update(Buffer.concat([FIX16, Buffer.from(String(ts))])).digest();
    try {
        const d = crypto.createDecipheriv('aes-256-ecb', key, null);
        d.setAutoPadding(true);
        const pt = Buffer.concat([d.update(ct), d.final()]).toString('utf8');
        if (/^\d{13}\{/.test(pt)) return pt;
    } catch (e) { }
    return null;
}

function processFile(binPath) {
    const base = path.basename(binPath);
    const m = base.match(/_(\d{13})\.bin$/);
    if (!m) return { st: 'skip' };
    const ts0 = parseInt(m[1], 10);
    let raw;
    try { raw = fs.readFileSync(binPath, 'utf8').trim(); } catch (e) { return { st: 'readerr' }; }
    let ct; try { ct = Buffer.from(raw, 'base64'); } catch (e) { return { st: 'b64err' }; }
    if (ct.length % 16 !== 0 || ct.length === 0) return { st: 'skip' };
    let pt = null;
    // 【2026-09-12 性能】从 0 向两侧扩散（同 watch：原线性扫描平均 3 万次尝试/文件 → 单轮分钟级）
    for (let i = 0; i <= WINDOW_MS && !pt; i++) {
        pt = decrypt(ct, ts0 + i);
        if (!pt && i > 0) pt = decrypt(ct, ts0 - i);
    }
    if (!pt) return { st: 'miss' };
    const body = pt.slice(13);
    let obj; try { obj = JSON.parse(body); } catch (e) { obj = body; }
    try { fs.writeFileSync(binPath.replace(/\.bin$/, '.json'), JSON.stringify(obj, null, 2)); }
    catch (e) { return { st: 'werr' }; }
    return { st: 'ok', et: (obj && obj.et) ? obj.et : '?', ts: pt.slice(0, 13) };
}

const args = process.argv.slice(2);
const procs = parseInt(args[0], 10) || 6;
const limIdx = args.indexOf('--limit');
const LIMIT = limIdx >= 0 ? parseInt(args[limIdx + 1], 10) : 0;

const jobs = [];
for (const entry of fs.readdirSync(LOOT_DIR)) {
    const dp = path.join(LOOT_DIR, entry);
    let st; try { st = fs.statSync(dp); } catch (e) { continue; }
    if (!st.isDirectory()) continue;
    let files; try { files = fs.readdirSync(dp); } catch (e) { continue; }
    for (const f of files) {
        if (!/^raw_.*_\d{13}\.bin$/.test(f)) continue;
        if (fs.existsSync(path.join(dp, f.replace(/\.bin$/, '.json')))) continue;
        jobs.push(path.join(dp, f));
    }
}
const todo = LIMIT ? jobs.slice(0, LIMIT) : jobs;
console.log('积压待解: '+jobs.length+(LIMIT?('（本次限 '+todo.length+'）'):'')+' 并发 '+procs);
const t0 = Date.now();
const stat = {}; const etc = {};
let idx = 0;
function worker() {
    return new Promise(resolve => {
        (function next() {
            if (!todo.length) return resolve();
            const f = todo.shift();
            const r = processFile(f);
            stat[r.st] = (stat[r.st] || 0) + 1;
            if (r.st === 'ok') etc[r.et] = (etc[r.et] || 0) + 1;
            if (++idx % 100 === 0) console.log('  ['+idx+'/'+todo0.length+'] '+((Date.now()-t0)/1000).toFixed(0)+'s '+JSON.stringify(stat));
            setImmediate(next);
        })();
    });
}
const todo0 = todo.slice();
Promise.all(Array.from({ length: procs }, worker)).then(() => {
    console.log('\n完成 '+((Date.now()-t0)/1000).toFixed(0)+'s  '+JSON.stringify(stat));
    const top = Object.entries(etc).sort((a, b) => b[1] - a[1]).slice(0, 20);
    console.log('et 分布 Top20:', JSON.stringify(top));
});
