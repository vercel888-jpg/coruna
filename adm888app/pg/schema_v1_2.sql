-- ============================================================
-- Schema v1.2（P4 面板读层·设备元数据）——2026-09-13
-- 应用：runuser -u postgres -- psql -d panel -f adm888app/pg/schema_v1_2.sql
-- 背景：钱包识别/计数/file_count/upload_status/is_wallet_user 是 lootStore.scan() 全局阶段的合成产物，
--       桶级入库（ingestd/backfill）不产出；由 tools/pg_sync_globals.js 从最新快照 core.json 定期同步。
-- ============================================================
SET ROLE panel;

ALTER TABLE devices ADD COLUMN IF NOT EXISTS exfil18_count int DEFAULT 0;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS file_count int DEFAULT 0;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS upload_status text;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS is_wallet_user boolean DEFAULT false;
