#!/usr/bin/env node
/**
 * crypto_helper.js — 服务端加密解密辅助模块
 * 
 * 用于解密客户端发送的加密 payload (AES-GCM)
 */

'use strict';

const crypto = require('crypto');

/**
 * 从共享密钥派生 AES 密钥
 * @param {string} sharedSecret - 共享密钥
 * @returns {Buffer} 派生的 32 字节密钥
 */
function deriveKey(sharedSecret) {
  if (!sharedSecret) throw new Error('Shared secret required');
  
  // PBKDF2 派生（与客户端参数一致）
  return crypto.pbkdf2Sync(
    sharedSecret,
    'DarkSword-Salt-v1',
    10000,
    32,
    'sha256'
  );
}

/**
 * 解密 AES-GCM 加密的 payload
 * @param {object} encryptedData - { encrypted: true, iv: base64, data: base64 }
 * @param {string} sharedSecret - 共享密钥
 * @returns {object} 解密后的 JSON 对象
 */
function decryptPayload(encryptedData, sharedSecret) {
  // 如果未加密，直接解析
  if (!encryptedData.encrypted) {
    return JSON.parse(encryptedData.data);
  }

  try {
    const key = deriveKey(sharedSecret);
    const iv = Buffer.from(encryptedData.iv, 'base64');
    const encryptedBuffer = Buffer.from(encryptedData.data, 'base64');

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    
    // 提取认证标签（最后 16 字节）
    const authTag = encryptedBuffer.slice(-16);
    const ciphertext = encryptedBuffer.slice(0, -16);
    
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(ciphertext);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return JSON.parse(decrypted.toString('utf8'));
  } catch (e) {
    // 解密失败，尝试当作明文
    try {
      return JSON.parse(encryptedData.data);
    } catch {
      throw new Error('Decryption failed: ' + e.message);
    }
  }
}

/**
 * 加密响应数据（用于返回给客户端）
 * @param {object} payload - 要加密的 JSON 对象
 * @param {string} sharedSecret - 共享密钥
 * @returns {object} { encrypted: true, iv: base64, data: base64 }
 */
function encryptPayload(payload, sharedSecret) {
  if (!sharedSecret) {
    return { encrypted: false, data: JSON.stringify(payload) };
  }

  try {
    const key = deriveKey(sharedSecret);
    const iv = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

    let encrypted = cipher.update(JSON.stringify(payload), 'utf8');
    encrypted = Buffer.concat([encrypted, cipher.final()]);

    const authTag = cipher.getAuthTag();
    const combined = Buffer.concat([encrypted, authTag]);

    return {
      encrypted: true,
      iv: iv.toString('base64'),
      data: combined.toString('base64')
    };
  } catch (e) {
    // 加密失败，降级为明文
    return { encrypted: false, data: JSON.stringify(payload) };
  }
}

module.exports = {
  deriveKey,
  decryptPayload,
  encryptPayload
};