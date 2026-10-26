-- ============================================================
-- Schema v1.1（P4 面板读层）——代理数据镜像表（2026-09-13）
-- 应用：runuser -u postgres -- psql -d panel -f adm888app/pg/schema_v1_1.sql
-- 来源与语义：
--   agents.role/status    ← auth.json users（面板过滤/递归依赖）
--   agent_device          ← auth.json device_agents（serial → agent_id，2863 行）
--   agent_ip_map          ← data/ip_agents.json（ip → agent_id，6.9 万行）
--   devices.owner_agent_id 由 tools/pg_sync_agents.js 物化
-- ============================================================
SET ROLE panel;

ALTER TABLE agents ADD COLUMN IF NOT EXISTS role text;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS status text;

CREATE TABLE IF NOT EXISTS agent_device (
  serial text PRIMARY KEY,
  agent_id bigint NOT NULL,
  updated_at timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS agent_device_agent_idx ON agent_device (agent_id);

CREATE TABLE IF NOT EXISTS agent_ip_map (
  ip inet PRIMARY KEY,
  agent_id bigint NOT NULL,
  updated_at timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS agent_ip_map_agent_idx ON agent_ip_map (agent_id);
