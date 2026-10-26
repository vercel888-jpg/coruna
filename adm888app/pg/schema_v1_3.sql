-- ============================================================
-- Schema v1.3（P4.1-3 多出口 IP 匹配）——2026-09-14
-- 应用：runuser -u postgres -- psql -d panel -f adm888app/pg/schema_v1_3.sql
-- 来源：lootStore 的 store.deviceIps（serial → 该设备出现过的所有出口 IP）
--   经 tools/pg_sync_globals.js 的 syncDeviceIps 从最新快照 core.json 定期镜像。
-- 用途：可见性匹配从"单 IP"升级为"设备任一出口 IP 命中代理 IP 集"（修复 IP 漂移导致的漏可见）。
-- ============================================================
SET ROLE panel;

CREATE TABLE IF NOT EXISTS device_ip_map (
  serial text NOT NULL,
  ip inet NOT NULL,
  PRIMARY KEY (serial, ip)
);
CREATE INDEX IF NOT EXISTS device_ip_map_ip_idx ON device_ip_map (ip);
CREATE INDEX IF NOT EXISTS device_ip_map_serial_idx ON device_ip_map (serial);
