#!/usr/bin/env node
/**
 * security_utils.js — 安全工具函数库
 * 
 * 用于统一处理安全相关的验证和转义操作
 */

'use strict';

const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

// ── 路径安全验证 ──────────────────────────────────────────────────────────────

/**
 * 安全的路径解析，防止路径遍历攻击
 * @param {string} baseDir - 基础目录（必须是绝对路径）
 * @param {string} userPath - 用户提供的路径
 * @returns {string|null} - 安全的绝对路径，或 null（如果不安全）
 */
function safeResolvePath(baseDir, userPath) {
  try {
    // 规范化基础目录
    const normalizedBase = path.normalize(path.resolve(baseDir));
    
    // 解析用户路径
    const resolved = path.resolve(normalizedBase, userPath);
    const normalized = path.normalize(resolved);
    
    // 检查是否在基础目录内（必须严格匹配或在子目录）
    if (normalized !== normalizedBase && 
        !normalized.startsWith(normalizedBase + path.sep)) {
      return null;
    }
    
    // 如果路径已存在，检查是否为符号链接（防止符号链接逃逸）
    if (fs.existsSync(normalized)) {
      const stat = fs.lstatSync(normalized);
      if (stat.isSymbolicLink()) {
        return null;
      }
    }
    
    return normalized;
  } catch (e) {
    return null;
  }
}

/**
 * 验证路径是否在允许的白名单内
 * @param {string} requestedPath - 请求的路径
 * @param {Array<string>} allowedPaths - 允许的路径列表
 * @returns {boolean}
 */
function isPathAllowed(requestedPath, allowedPaths) {
  try {
    const normalized = path.normalize(path.resolve(requestedPath));
    
    return allowedPaths.some(allowed => {
      const normalizedAllowed = path.normalize(path.resolve(allowed));
      return normalized === normalizedAllowed || 
             normalized.startsWith(normalizedAllowed + path.sep);
    });
  } catch (e) {
    return false;
  }
}

// ── 输入验证和清理 ────────────────────────────────────────────────────────────

/**
 * 清理日志输入，防止日志注入
 * @param {*} input - 任意输入
 * @returns {string} - 清理后的字符串
 */
function sanitizeLogInput(input) {
  if (input === null || input === undefined) return '';
  
  const str = String(input);
  return str
    .replace(/\r\n/g, ' ')
    .replace(/[\r\n]/g, ' ')
    .replace(/\x00/g, '')
    .replace(/\x1b\[[0-9;]*m/g, '') // 移除 ANSI 颜色码
    .slice(0, 2000); // 限制长度
}

/**
 * 验证设备 ID 格式
 * @param {string} deviceId - 设备 ID
 * @returns {boolean}
 */
function isValidDeviceId(deviceId) {
  if (typeof deviceId !== 'string') return false;
  // 只允许字母、数字、下划线、连字符
  return /^[a-zA-Z0-9_-]{1,64}$/.test(deviceId);
}

/**
 * 验证文件名安全性
 * @param {string} filename - 文件名
 * @returns {boolean}
 */
function isValidFilename(filename) {
  if (typeof filename !== 'string' || filename.length === 0) return false;
  if (filename.length > 255) return false;
  
  // 禁止路径分隔符和特殊字符
  if (/[\/\\:*?"<>|]/.test(filename)) return false;
  
  // 禁止以点开头（隐藏文件）或以点/空格结尾
  if (/^\./.test(filename) || /[\.\s]$/.test(filename)) return false;
  
  return true;
}

// ── 密码学安全函数 ────────────────────────────────────────────────────────────

/**
 * 恒定时间字符串比较，防止时序攻击
 * @param {string} a - 字符串 A
 * @param {string} b - 字符串 B
 * @returns {boolean}
 */
function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }
  
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  
  // 如果长度不同，仍执行比较避免泄露长度信息
  if (bufA.length !== bufB.length) {
    const hashA = crypto.createHash('sha256').update(bufA).digest();
    const hashB = crypto.createHash('sha256').update(bufB).digest();
    return crypto.timingSafeEqual(hashA, hashB);
  }
  
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * 生成加密安全的随机令牌
 * @param {number} length - 字节长度（默认 32）
 * @returns {string} - 十六进制字符串
 */
function generateSecureToken(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

/**
 * 派生设备特定密钥（防止密钥硬编码）
 * @param {string} deviceId - 设备 ID
 * @param {string} masterSecret - 主密钥
 * @returns {string} - 派生的设备密钥
 */
function deriveDeviceKey(deviceId, masterSecret) {
  return crypto
    .createHmac('sha256', masterSecret)
    .update(deviceId)
    .digest('hex');
}

// ── 速率限制 ──────────────────────────────────────────────────────────────────

class RateLimiter {
  constructor() {
    this.records = new Map(); // key -> [timestamps]
    this.cleanupInterval = null;
    
    // 每小时清理过期记录
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, 60 * 60 * 1000);
  }
  
  /**
   * 检查是否超出速率限制
   * @param {string} key - 限制键（如 IP 地址）
   * @param {number} maxRequests - 最大请求数
   * @param {number} windowMs - 时间窗口（毫秒）
   * @returns {boolean} - true 表示允许，false 表示超限
   */
  check(key, maxRequests, windowMs) {
    const now = Date.now();
    
    if (!this.records.has(key)) {
      this.records.set(key, []);
    }
    
    const timestamps = this.records.get(key);
    
    // 清理过期时间戳
    while (timestamps.length > 0 && timestamps[0] < now - windowMs) {
      timestamps.shift();
    }
    
    if (timestamps.length >= maxRequests) {
      return false;
    }
    
    timestamps.push(now);
    return true;
  }
  
  /**
   * 清除指定 key 的所有记录（如登录成功后清零）
   * @param {string} key - 限制键（如 IP 地址）
   */
  reset(key) {
    this.records.delete(key);
  }
  
  /**
   * 查询指定 key 剩余可尝试次数
   * @param {string} key - 限制键（如 IP 地址）
   * @param {number} maxRequests - 最大请求数
   * @param {number} windowMs - 时间窗口（毫秒）
   * @returns {number} - 剩余次数（可能为 0 或负数）
   */
  remaining(key, maxRequests, windowMs) {
    const now = Date.now();
    const timestamps = this.records.get(key) || [];
    while (timestamps.length > 0 && timestamps[0] < now - windowMs) {
      timestamps.shift();
    }
    return maxRequests - timestamps.length;
  }
  
  /**
   * 清理所有过期记录
   */
  cleanup() {
    const now = Date.now();
    const maxAge = 24 * 60 * 60 * 1000; // 24小时
    
    for (const [key, timestamps] of this.records.entries()) {
      // 清理超过24小时没活动的记录
      if (timestamps.length === 0 || timestamps[timestamps.length - 1] < now - maxAge) {
        this.records.delete(key);
      }
    }
  }
  
  /**
   * 销毁速率限制器
   */
  destroy() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.records.clear();
  }
}

// ── 连接数限制 ────────────────────────────────────────────────────────────────

class ConnectionLimiter {
  constructor(maxPerIP = 10) {
    this.maxPerIP = maxPerIP;
    this.connections = new Map(); // IP -> count
  }
  
  /**
   * 尝试获取连接槽位
   * @param {string} ip - IP 地址
   * @returns {boolean} - true 表示允许，false 表示超限
   */
  acquire(ip) {
    const count = this.connections.get(ip) || 0;
    
    if (count >= this.maxPerIP) {
      return false;
    }
    
    this.connections.set(ip, count + 1);
    return true;
  }
  
  /**
   * 释放连接槽位
   * @param {string} ip - IP 地址
   */
  release(ip) {
    const count = this.connections.get(ip) || 0;
    
    if (count <= 1) {
      this.connections.delete(ip);
    } else {
      this.connections.set(ip, count - 1);
    }
  }
  
  /**
   * 获取当前连接数
   * @param {string} ip - IP 地址
   * @returns {number}
   */
  getCount(ip) {
    return this.connections.get(ip) || 0;
  }
}

// ── 导出 ──────────────────────────────────────────────────────────────────────

module.exports = {
  // 路径安全
  safeResolvePath,
  isPathAllowed,
  
  // 输入验证
  sanitizeLogInput,
  isValidDeviceId,
  isValidFilename,
  
  // 密码学
  timingSafeEqual,
  generateSecureToken,
  deriveDeviceKey,
  
  // 速率和连接限制
  RateLimiter,
  ConnectionLimiter,
};