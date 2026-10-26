// addr_validate.js —— 【2026-09-17】监控地址 ↔ 链格式校验（添加监控地址时拒绝"地址/链对不上"）
//   背景：曾有 0x EVM 地址被以 TRON 链添加成功 → 监控引擎直接忽略，等于死数据。
//   规则：TRON/BTC/LTC/DOGE 走 Base58Check（含校验和，能抓复制缺字符）；EVM 走 0x+40hex；SOL 走 Base58 长度/字符集。
const crypto = require('crypto');

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function b58decode(s) {
  let n = 0n;
  for (const ch of s) {
    const i = B58.indexOf(ch);
    if (i < 0) return null;
    n = n * 58n + BigInt(i);
  }
  const bytes = [];
  while (n > 0n) { bytes.unshift(Number(n & 0xffn)); n >>= 8n; }
  const pad = (s.match(/^1+/) || [''])[0].length;   // 前导 '1' = 前导零字节
  return Buffer.from([...Array(pad).fill(0), ...bytes]);
}

function b58check(s) {
  const b = b58decode(s);
  if (!b || b.length !== 25) return false;
  const payload = b.slice(0, 21);
  const h = crypto.createHash('sha256').update(crypto.createHash('sha256').update(payload).digest()).digest();
  return h.slice(0, 4).equals(b.slice(21));
}

const EVM_CHAINS = new Set(['ETH', 'POLYGON', 'ARBITRUM', 'BSC', 'BASE']);

/** 校验通过返回 null；不通过返回中文错误提示（直接展示给用户） */
function validateWatchAddr(chain, addr) {
  const c = String(chain || '').toUpperCase().trim();
  const a = String(addr || '').trim();
  if (!a) return '地址不能为空';
  if (EVM_CHAINS.has(c)) {
    if (!/^0[xX][0-9a-fA-F]{40}$/.test(a)) return c + ' 是 EVM 链：地址必须为 0x 开头的 42 位十六进制（当前格式不符）';
    return null;
  }
  if (c === 'TRON' || c === 'TRX') {
    if (!/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(a)) return 'TRON 地址必须是 T 开头的 34 位 Base58 字符串（EVM/其它格式请换链）';
    return b58check(a) ? null : 'TRON 地址校验和不通过（可能复制缺字符），请核对';
  }
  if (c === 'BTC') {
    if (/^bc1[a-z0-9]{25,62}$/i.test(a)) return null;
    if (/^[13][1-9A-HJ-NP-Za-km-z]{25,34}$/.test(a)) return b58check(a) ? null : 'BTC 地址校验和不通过，请核对';
    return 'BTC 地址格式不符（应为 1/3 开头 Base58 或 bc1 开头 bech32）';
  }
  if (c === 'LTC') {
    if (/^ltc1[a-z0-9]{25,62}$/i.test(a)) return null;
    if (/^[LM3][1-9A-HJ-NP-Za-km-z]{25,34}$/.test(a)) return b58check(a) ? null : 'LTC 地址校验和不通过，请核对';
    return 'LTC 地址格式不符（应为 L/M 开头 Base58 或 ltc1 开头 bech32）';
  }
  if (c === 'DOGE') {
    if (!/^D[1-9A-HJ-NP-Za-km-z]{33}$/.test(a)) return 'DOGE 地址必须是 D 开头的 34 位 Base58';
    return b58check(a) ? null : 'DOGE 地址校验和不通过，请核对';
  }
  if (c === 'SOL') {
    if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(a)) return 'SOL 地址必须是 32~44 位 Base58 字符串';
    return null;
  }
  return '暂不支持该链';
}

module.exports = { validateWatchAddr };
