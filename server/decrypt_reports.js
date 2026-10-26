#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const LOOT_DIR = path.join(__dirname, '../loot/59.51.174.97');
const KEY_PREFIX = 'Ek8pl31K2yeHgQwy';

// 单文件解密（供 admin_server.js 调用，传入 binPath 和可选的 x_ts）
function decryptSingle(binPath, xTsHint) {
  const base64Text = fs.readFileSync(binPath, 'utf8').trim();
  const cipherBuf = Buffer.from(base64Text, 'base64');
  
  if (cipherBuf.length % 16 !== 0) {
    return { success: false, error: `密文长度 ${cipherBuf.length} 不是 16 倍数` };
  }

  let x_ts_list = [];
  if (xTsHint) {
    x_ts_list.push(String(xTsHint));
  } else {
    // 基准：从文件名提取 13 位毫秒时间戳（不能用 stat.mtimeMs，文件系统时间不可靠）
    const m = path.basename(binPath).match(/_(\d{13})\.bin$/);
    const fileTs = m ? parseInt(m[1], 10) : Math.floor(Date.now());
    // 窗口 ±15 秒，步长 1ms（真实 x_ts 与文件名时间戳偏差 500~1100ms）
    for (let offset = -15000; offset <= 15000; offset += 1) {
      x_ts_list.push(String(fileTs + offset));
    }
  }

  for (const x_ts of x_ts_list) {
    try {
      const key = crypto.createHash('sha256').update(KEY_PREFIX + x_ts).digest();
      const decipher = crypto.createDecipheriv('aes-256-ecb', key, null);
      decipher.setAutoPadding(true);
      
      const plain = Buffer.concat([decipher.update(cipherBuf), decipher.final()]).toString('utf8');
      const match = plain.match(/^(\d+)(\{.*\})/s);
      if (!match) continue;
      
      const jsonText = match[2];
      const obj = JSON.parse(jsonText);
      
      return { success: true, data: obj, x_ts };
    } catch (e) {
      continue;
    }
  }
  
  return { success: false, error: '枚举全部失败' };
}

// 导出供 admin_server.js 使用
module.exports = { decryptReport: decryptSingle };

// 主逻辑：独立运行时批量解密
if (require.main === module) {
  const files = fs.readdirSync(LOOT_DIR).filter(f => f.startsWith('report_') && f.endsWith('.bin'));
  console.log(`找到 ${files.length} 个 report_*.bin 文件\n`);

  files.forEach(fname => {
    const binPath = path.join(LOOT_DIR, fname);
    const decPath = binPath.replace('.bin', '.dec.json');
    if (fs.existsSync(decPath)) {
      console.log(`[SKIP] ${fname} (已解密)`);
      return;
    }
    
    const result = decryptSingle(binPath);
    if (result.success) {
      fs.writeFileSync(decPath, JSON.stringify(result.data, null, 2), 'utf8');
      require('./spool_hint').hint(path.basename(path.dirname(binPath)));   // 【P2b】解密产物落地 → 提示 ingestd
      const preview = JSON.stringify(result.data).slice(0, 100);
      console.log(`[OK] ${fname} (x_ts=${result.x_ts}, 明文前100字符: ${preview})`);
    } else {
      console.log(`[FAIL] ${fname} (${result.error})`);
    }
  });

  console.log('\n解密完成。');
}
