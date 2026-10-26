// captcha.js — SVG 图形验证码（2026-09-20 上线：对抗面板登录接口的外部爆破）
//   设计：6 位字符（去 I/O/0/1 易混淆，32 字符集 ≈ 10.7 亿组合）；SVG 扭曲渲染 + 干扰线 + 噪点；
//   一次性（无论对错都销毁）；5 分钟过期；内存存储（无外部依赖）；同 IP 生成限速在 server.js 路由层。
'use strict';
const crypto = require('crypto');

const TTL_MS = 5 * 60 * 1000;                       // 验证码有效期 5 分钟
const MAX_ENTRIES = 5000;                            // 内存上限（超限清最旧一半，防堆积）
const CHARSET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';  // 32 字符：去 I/O（易混）与 0/1（易混）
const store = new Map();                             // id -> { code, exp }

function _gc() {
  const now = Date.now();
  for (const [k, v] of store) { if (v.exp <= now) store.delete(k); }
  if (store.size > MAX_ENTRIES) {
    const keys = [...store.keys()].slice(0, Math.floor(store.size / 2));
    for (const k of keys) store.delete(k);
  }
}

function _rand(min, max) { return min + Math.random() * (max - min); }

function _makeSvg(code) {
  const W = 200, H = 64;
  let s = `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">`;
  s += `<rect width="${W}" height="${H}" fill="#F5F7FA"/>`;
  // 噪点
  for (let i = 0; i < 42; i++) {
    s += `<circle cx="${_rand(0, W).toFixed(1)}" cy="${_rand(0, H).toFixed(1)}" r="${_rand(0.5, 1.5).toFixed(1)}" fill="rgba(60,70,90,${_rand(0.08, 0.32).toFixed(2)})"/>`;
  }
  // 干扰曲线（在字符下层与上层各几条）
  for (let i = 0; i < 4; i++) {
    const x1 = _rand(0, W * 0.3), y1 = _rand(0, H), x2 = _rand(W * 0.6, W), y2 = _rand(0, H);
    const mx = _rand(0, W), my = _rand(0, H);
    s += `<path d="M${x1.toFixed(1)} ${y1.toFixed(1)} Q${mx.toFixed(1)} ${my.toFixed(1)} ${x2.toFixed(1)} ${y2.toFixed(1)}" stroke="rgba(70,90,130,${_rand(0.22, 0.45).toFixed(2)})" stroke-width="${_rand(1, 1.8).toFixed(1)}" fill="none"/>`;
  }
  // 字符：逐字随机旋转/位移/字号/颜色
  const n = code.length;
  const step = (W - 30) / n;
  const colors = ['#1F2937', '#27324A', '#0F2A43', '#33261c', '#1e3a2f'];
  for (let i = 0; i < n; i++) {
    const ch = code[i];
    const x = 16 + i * step + _rand(-2.5, 2.5);
    const y = H / 2 + _rand(-5, 5);
    const rot = _rand(-26, 26);
    const fs = _rand(26, 33);
    const c = colors[Math.floor(_rand(0, colors.length))];
    s += `<text x="${x.toFixed(1)}" y="${y.toFixed(1)}" font-family="Menlo,Consolas,monospace" font-size="${fs.toFixed(1)}" font-weight="700" fill="${c}" transform="rotate(${rot.toFixed(1)} ${x.toFixed(1)} ${y.toFixed(1)})">${ch}</text>`;
  }
  // 顶部再压一条干扰线，增加切分难度
  {
    const x1 = _rand(0, W * 0.25), y1 = _rand(0, H), x2 = _rand(W * 0.75, W), y2 = _rand(0, H);
    const mx = _rand(0, W), my = _rand(0, H);
    s += `<path d="M${x1.toFixed(1)} ${y1.toFixed(1)} Q${mx.toFixed(1)} ${my.toFixed(1)} ${x2.toFixed(1)} ${y2.toFixed(1)}" stroke="rgba(120,60,80,${_rand(0.2, 0.38).toFixed(2)})" stroke-width="${_rand(1, 1.6).toFixed(1)}" fill="none"/>`;
  }
  s += '</svg>';
  return s;
}

function create() {
  _gc();
  const code = Array.from({ length: 6 }, () => CHARSET[Math.floor(Math.random() * CHARSET.length)]).join('');
  const id = crypto.randomBytes(16).toString('hex');
  store.set(id, { code, exp: Date.now() + TTL_MS });
  return { id, svg: _makeSvg(code) };
}

// 校验：一次性（无论对错都销毁）、大小写不敏感、过期检查
function verify(id, input) {
  if (!id || typeof id !== 'string') return { ok: false, msg: '验证码错误或已过期，请刷新后重试' };
  const rec = store.get(id);
  if (!rec) return { ok: false, msg: '验证码错误或已过期，请刷新后重试' };
  store.delete(id);                                   // 一次性：先删再判（防重放/防爆破）
  if (rec.exp <= Date.now()) return { ok: false, msg: '验证码已过期，请刷新后重试' };
  const got = String(input == null ? '' : input).trim().toUpperCase();
  if (got !== rec.code) return { ok: false, msg: '验证码错误，请重试' };
  return { ok: true };
}

module.exports = { create, verify };
