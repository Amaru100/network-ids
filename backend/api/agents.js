/**
 * agents.js - Agents API Endpoint (Vercel Serverless Function)
 * =============================================================
 * POST   /api/agents - Register agent / send heartbeat
 * GET    /api/agents - List all agents with online/offline status
 *
 * Author: University of Botswana - Final Year Project
 */

const { supabase } = require('../config/db');

const HEARTBEAT_TIMEOUT_MS = 60000; // 60 seconds — agent is offline if no heartbeat

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  try {
    if (req.method === 'POST') {
      return await handlePost(req, res);
    } else if (req.method === 'GET') {
      return await handleGet(req, res);
    } else {
      return res.status(405).json({ error: 'Method not allowed' });
    }
  } catch (error) {
    console.error('[Agents API] Error:', error.message);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

/**
 * POST /api/agents - Register a new agent or update heartbeat
 */
async function handlePost(req, res) {
  const { agent_name, hostname, ip_address, os_info } = req.body;

  if (!agent_name) {
    return res.status(400).json({ error: 'Missing required field: agent_name' });
  }

  // Check if agent already exists
  const { data: existing } = await supabase
    .from('agents')
    .select('id')
    .eq('agent_name', agent_name)
    .limit(1)
    .single();

  if (existing) {
    // Update heartbeat for existing agent
    const { data, error } = await supabase
      .from('agents')
      .update({
        hostname: hostname || undefined,
        ip_address: ip_address || undefined,
        os_info: os_info || undefined,
        last_heartbeat: new Date().toISOString(),
      })
      .eq('id', existing.id)
      .select();

    if (error) {
      console.error('[Agents API] Heartbeat update error:', error.message);
      return res.status(500).json({ error: 'Failed to update heartbeat' });
    }

    console.log(`[Agents API] Heartbeat: ${agent_name} (${ip_address})`);
    return res.status(200).json({ message: 'Heartbeat updated', agent: data[0] });
  }

  // Register new agent
  const { data, error } = await supabase
    .from('agents')
    .insert([{
      agent_name,
      hostname: hostname || agent_name,
      ip_address: ip_address || 'unknown',
      os_info: os_info || 'unknown',
      last_heartbeat: new Date().toISOString(),
      registered_at: new Date().toISOString(),
    }])
    .select();

  if (error) {
    console.error('[Agents API] Registration error:', error.message);
    return res.status(500).json({ error: 'Failed to register agent' });
  }

  console.log(`[Agents API] New agent registered: ${agent_name} (${ip_address})`);
  return res.status(201).json({ message: 'Agent registered', agent: data[0] });
}

/**
 * GET /api/agents - List all agents with computed status
 */
async function handleGet(req, res) {
  const { data, error } = await supabase
    .from('agents')
    .select('*')
    .order('last_heartbeat', { ascending: false });

  if (error) {
    console.error('[Agents API] Query error:', error.message);
    return res.status(500).json({ error: 'Failed to retrieve agents' });
  }

  const now = Date.now();
  const agents = (data || []).map((agent) => ({
    ...agent,
    status: (now - new Date(agent.last_heartbeat).getTime()) < HEARTBEAT_TIMEOUT_MS
      ? 'online'
      : 'offline',
  }));

  return res.status(200).json({
    agents,
    total: agents.length,
    online: agents.filter((a) => a.status === 'online').length,
  });
}
