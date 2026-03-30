-- ================================================================
-- NIDS Beta Migration - Run this in Supabase SQL Editor
-- This adds the agents table and agent_name column to existing DB
-- ================================================================

-- Add agent_name column to existing alerts table
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS agent_name TEXT;

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

-- Add new indexes
CREATE INDEX IF NOT EXISTS idx_alerts_agent ON alerts(agent_name);
CREATE INDEX IF NOT EXISTS idx_agents_heartbeat ON agents(last_heartbeat DESC);

-- RLS for agents table
ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow public read agents" ON agents FOR SELECT USING (true);
CREATE POLICY "Allow public insert agents" ON agents FOR INSERT WITH CHECK (true);
CREATE POLICY "Allow public update agents" ON agents FOR UPDATE USING (true);

-- Add DELETE policy for alerts (needed for Clear All Alerts feature)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies WHERE tablename = 'alerts' AND policyname = 'Allow public delete alerts'
  ) THEN
    CREATE POLICY "Allow public delete alerts" ON alerts FOR DELETE USING (true);
  END IF;
END $$;

-- Enable Realtime on agents table
ALTER PUBLICATION supabase_realtime ADD TABLE agents;
