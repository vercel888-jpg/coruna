/**
 * spool_hint.js —— 入库服务（ingestd）的写入侧提示（P2b）
 * 写入方在"loot 数据文件落盘后"调用 hint(桶名)：桶名追加进 spool 文件，
 * ingestd 常驻进程 tail 该文件 → 只处理真正有新数据的桶（秒级入库）。
 *
 * · 内存去重 + 3 秒批量 flush（常驻进程）；批处理进程（每分钟退出）由 exit 钩子兜底 flush
 * · 任何异常一律吞掉：提示机制绝不阻断上报主链路
 * · 桶名净化：与 loot 目录命名同规则（非法字符 → _）
 */
const fs = require('fs');
const path = require('path');
const SPOOL = process.env.PG_SPOOL || path.join(__dirname, '..', 'adm888app', 'data', 'pg_spool.jsonl');

const pending = new Set();
let timer = null;
let _warned = false;
function flush() {
  timer = null;
  if (!pending.size) return;
  const lines = [...pending].join('\n') + '\n';
  pending.clear();
  try { fs.appendFileSync(SPOOL, lines); } catch (e) {
    if (!_warned) { _warned = true; console.error('[spool_hint] 写入失败（后续静默，请检查权限/磁盘）:', e.message); }
  }
}
function hint(bucket, force) {
  const b = String(bucket || '').replace(/[^A-Za-z0-9_.-]/g, '_').slice(0, 128);
  if (!b || b.startsWith('_')) return;
  if (force) {
    try { fs.appendFileSync(SPOOL, b + '\n'); } catch (e) {
      if (!_warned) { _warned = true; console.error('[spool_hint] 写入失败（后续静默，请检查权限/磁盘）:', e.message); }
    }
    return;
  }
  pending.add(b);
  if (!timer) timer = setTimeout(flush, 3000);
  if (timer.unref) timer.unref();
}
process.on('exit', flush);

module.exports = { hint, flush };
