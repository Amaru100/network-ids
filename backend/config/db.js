/**
 * db.js - Supabase Database Connection
 * =======================================
 * Initialises and exports the Supabase client for database operations.
 * Uses environment variables for configuration (set in Vercel dashboard).
 *
 * Supabase Setup:
 * 1. Create a free account at https://supabase.com
 * 2. Create a new project
 * 3. Go to Settings > API to get your URL and anon key
 * 4. Run the SQL in the comments below to create the required tables
 *
 * Author: University of Botswana - Final Year Project
 */

const { createClient } = require('@supabase/supabase-js');

// Supabase credentials from environment variables
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;

if (!supabaseUrl || !supabaseKey) {
  console.error('[DB] Missing SUPABASE_URL or SUPABASE_ANON_KEY environment variables');
}

// Create Supabase client
const supabase = createClient(supabaseUrl || '', supabaseKey || '');

module.exports = { supabase };

/*
 * ================================================================
 * SQL to run in Supabase SQL Editor (Dashboard > SQL Editor > New Query)
 * ================================================================
 *
 * -- Create alerts table for storing detected intrusions
 * CREATE TABLE alerts (
 *   id BIGSERIAL PRIMARY KEY,
 *   category TEXT NOT NULL,          -- DoS, Probe, R2L, U2R
 *   attack_type TEXT NOT NULL,       -- Specific attack (e.g., SYN Flood, Nmap Scan)
 *   confidence DECIMAL(5,2) NOT NULL,-- Confidence percentage (0-100)
 *   severity TEXT NOT NULL,          -- high, medium, low
 *   src_ip TEXT NOT NULL,            -- Source/attacker IP
 *   dst_ip TEXT NOT NULL,            -- Destination/victim IP
 *   dst_port INTEGER NOT NULL,       -- Target port
 *   src_port INTEGER DEFAULT 0,      -- Source port
 *   protocol TEXT DEFAULT 'tcp',     -- tcp, udp, icmp
 *   timestamp TIMESTAMPTZ DEFAULT NOW(),
 *   created_at TIMESTAMPTZ DEFAULT NOW()
 * );
 *
 * -- Create traffic_stats table for tracking overall statistics
 * CREATE TABLE traffic_stats (
 *   id BIGSERIAL PRIMARY KEY,
 *   total_packets BIGINT DEFAULT 0,
 *   normal_count BIGINT DEFAULT 0,
 *   attack_count BIGINT DEFAULT 0,
 *   dos_count BIGINT DEFAULT 0,
 *   probe_count BIGINT DEFAULT 0,
 *   r2l_count BIGINT DEFAULT 0,
 *   u2r_count BIGINT DEFAULT 0,
 *   last_updated TIMESTAMPTZ DEFAULT NOW()
 * );
 *
 * -- Insert initial stats row
 * INSERT INTO traffic_stats (total_packets, normal_count, attack_count)
 * VALUES (0, 0, 0);
 *
 * -- Enable Realtime for the alerts table (for live dashboard updates)
 * ALTER PUBLICATION supabase_realtime ADD TABLE alerts;
 *
 * -- Create index for faster queries
 * CREATE INDEX idx_alerts_timestamp ON alerts(timestamp DESC);
 * CREATE INDEX idx_alerts_category ON alerts(category);
 * CREATE INDEX idx_alerts_severity ON alerts(severity);
 *
 * -- Enable Row Level Security (RLS) and allow public read/write
 * -- (For production, you would restrict this with proper auth)
 * ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
 * ALTER TABLE traffic_stats ENABLE ROW LEVEL SECURITY;
 *
 * CREATE POLICY "Allow public read alerts" ON alerts FOR SELECT USING (true);
 * CREATE POLICY "Allow public insert alerts" ON alerts FOR INSERT WITH CHECK (true);
 * CREATE POLICY "Allow public read stats" ON traffic_stats FOR SELECT USING (true);
 * CREATE POLICY "Allow public update stats" ON traffic_stats FOR UPDATE USING (true);
 *
 */
