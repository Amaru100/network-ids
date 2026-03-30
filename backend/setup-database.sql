-- ================================================================
-- NIDS Database Setup - Run this in Supabase SQL Editor
-- Dashboard > SQL Editor > New Query > Paste this > Run
-- ================================================================

-- Create alerts table for storing detected intrusions
CREATE TABLE IF NOT EXISTS alerts (
  id BIGSERIAL PRIMARY KEY,
  category TEXT NOT NULL,
  attack_type TEXT NOT NULL,
  confidence DECIMAL(5,2) NOT NULL,
  severity TEXT NOT NULL,
  src_ip TEXT NOT NULL,
  dst_ip TEXT NOT NULL,
  dst_port INTEGER NOT NULL DEFAULT 0,
  src_port INTEGER DEFAULT 0,
  protocol TEXT DEFAULT 'tcp',
  agent_name TEXT,
  timestamp TIMESTAMPTZ DEFAULT NOW(),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create traffic_stats table for tracking overall statistics
CREATE TABLE IF NOT EXISTS traffic_stats (
  id BIGSERIAL PRIMARY KEY,
  total_packets BIGINT DEFAULT 0,
  normal_count BIGINT DEFAULT 0,
  attack_count BIGINT DEFAULT 0,
  dos_count BIGINT DEFAULT 0,
  probe_count BIGINT DEFAULT 0,
  r2l_count BIGINT DEFAULT 0,
  u2r_count BIGINT DEFAULT 0,
  last_updated TIMESTAMPTZ DEFAULT NOW()
);

-- Insert initial stats row
INSERT INTO traffic_stats (total_packets, normal_count, attack_count)
VALUES (0, 0, 0);

-- Create agents table for tracking registered NIDS agents
CREATE TABLE IF NOT EXISTS agents (
  id BIGSERIAL PRIMARY KEY,
  agent_name TEXT NOT NULL UNIQUE,
  hostname TEXT,
  ip_address TEXT,
  os_info TEXT,
  last_heartbeat TIMESTAMPTZ DEFAULT NOW(),
  registered_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes for faster queries
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_category ON alerts(category);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_agent ON alerts(agent_name);
CREATE INDEX IF NOT EXISTS idx_agents_heartbeat ON agents(last_heartbeat DESC);

-- Enable Row Level Security (RLS) and allow public access
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE traffic_stats ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow public read alerts" ON alerts FOR SELECT USING (true);
CREATE POLICY "Allow public insert alerts" ON alerts FOR INSERT WITH CHECK (true);
CREATE POLICY "Allow public delete alerts" ON alerts FOR DELETE USING (true);
CREATE POLICY "Allow public read stats" ON traffic_stats FOR SELECT USING (true);
CREATE POLICY "Allow public update stats" ON traffic_stats FOR UPDATE USING (true);
CREATE POLICY "Allow public read agents" ON agents FOR SELECT USING (true);
CREATE POLICY "Allow public insert agents" ON agents FOR INSERT WITH CHECK (true);
CREATE POLICY "Allow public update agents" ON agents FOR UPDATE USING (true);

-- Enable Realtime for live dashboard updates
ALTER PUBLICATION supabase_realtime ADD TABLE alerts;
ALTER PUBLICATION supabase_realtime ADD TABLE agents;
