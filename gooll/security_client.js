/**
 * security_client.js — 客户端安全工具函数
 * 
 * 用于客户端的输入验证和命令转义
 */

(function() {
  'use strict';

  /**
   * 转义 shell 命令参数（用于单引号包裹的参数）
   * @param {string} arg - 命令参数
   * @returns {string} - 转义后的参数
   */
  function escapeShellArg(arg) {
    if (typeof arg !== 'string') {
      arg = String(arg);
    }
    // 将单引号替换为 '\''（结束引号、转义单引号、开始新引号）
    return arg.replace(/'/g, "'\\''");
  }

  /**
   * 转义 shell 命令中的特殊字符（用于双引号包裹或无引号的参数）
   * @param {string} arg - 命令参数
   * @returns {string} - 转义后的参数
   */
  function escapeShellSpecialChars(arg) {
    if (typeof arg !== 'string') {
      arg = String(arg);
    }
    // 转义所有 shell 特殊字符
    return arg.replace(/(["\\\$`!])/g, '\\$1');
  }

  /**
   * 验证路径是否安全（防止路径遍历）
   * @param {string} path - 路径
   * @returns {boolean}
   */
  function isPathSafe(path) {
    if (typeof path !== 'string' || path.length === 0) {
      return false;
    }
    
    // 禁止包含路径遍历序列
    if (path.includes('..') || path.includes('//')) {
      return false;
    }
    
    // 禁止包含 null 字节
    if (path.includes('\0')) {
      return false;
    }
    
    return true;
  }

  /**
   * 构建安全的 sqlite3 命令（使用参数化查询模拟）
   * @param {string} dbPath - 数据库路径
   * @param {string} query - SQL 查询
   * @returns {string|null} - 安全的命令字符串，或 null（如果不安全）
   */
  function buildSafeSqliteCommand(dbPath, query) {
    // 验证路径安全性
    if (!isPathSafe(dbPath)) {
      return null;
    }
    
    // 确保 SQL 查询是只读的（只允许 SELECT）
    const trimmedQuery = query.trim().toUpperCase();
    if (!trimmedQuery.startsWith('SELECT')) {
      return null;
    }
    
    // 禁止危险的 SQL 语句
    const dangerousPatterns = [
      /ATTACH/i,
      /PRAGMA/i,
      /CREATE/i,
      /DROP/i,
      /DELETE/i,
      /UPDATE/i,
      /INSERT/i,
      /ALTER/i,
    ];
    
    for (const pattern of dangerousPatterns) {
      if (pattern.test(query)) {
        return null;
      }
    }
    
    // 转义路径和查询
    const escapedPath = escapeShellArg(dbPath);
    const escapedQuery = escapeShellArg(query);
    
    return `sqlite3 '${escapedPath}' '${escapedQuery}' 2>/dev/null`;
  }

  /**
   * 构建安全的 plutil 命令
   * @param {string} plistPath - plist 文件路径
   * @returns {string|null} - 安全的命令字符串，或 null（如果不安全）
   */
  function buildSafePlutilCommand(plistPath) {
    if (!isPathSafe(plistPath)) {
      return null;
    }
    
    const escapedPath = escapeShellArg(plistPath);
    return `plutil -convert json -o - '${escapedPath}' 2>/dev/null`;
  }

  /**
   * 清理日志输出（防止日志注入）
   * @param {string} message - 日志消息
   * @returns {string}
   */
  function sanitizeLogMessage(message) {
    if (typeof message !== 'string') {
      message = String(message);
    }
    
    return message
      .replace(/\r\n/g, ' ')
      .replace(/[\r\n]/g, ' ')
      .replace(/\x00/g, '')
      .slice(0, 2000);
  }

  /**
   * 验证文件名安全性
   * @param {string} filename - 文件名
   * @returns {boolean}
   */
  function isFilenameSafe(filename) {
    if (typeof filename !== 'string' || filename.length === 0) {
      return false;
    }
    
    // 禁止路径分隔符
    if (filename.includes('/') || filename.includes('\\')) {
      return false;
    }
    
    // 禁止特殊字符
    if (/[<>:"|?*\0]/.test(filename)) {
      return false;
    }
    
    // 禁止以点开头或结尾
    if (filename.startsWith('.') || filename.endsWith('.')) {
      return false;
    }
    
    return true;
  }

  // 导出到全局
  if (typeof globalThis !== 'undefined') {
    globalThis.securityClient = {
      escapeShellArg,
      escapeShellSpecialChars,
      isPathSafe,
      buildSafeSqliteCommand,
      buildSafePlutilCommand,
      sanitizeLogMessage,
      isFilenameSafe,
    };
  }

  if (typeof print === 'function') {
    print('[Security Client] Security utilities loaded');
  }

})();