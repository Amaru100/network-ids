/**
 * stats.js - Traffic Statistics API Endpoint (Vercel Serverless Function)
 * ========================================================================
 * GET  /api/stats - Retrieve current traffic statistics
 * PUT  /api/stats - Update traffic statistics (from capture system)
 *
 * Author: University of Botswana - Final Year Project
 */

const { supabase } = require('../config/db');

module.exports = async function handler(req, res) {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  try {
    if (req.method === 'GET') {
      return await handleGet(req, res);
    } else if (req.method === 'PUT') {
      return await handlePut(req, res);
    } else {
      return res.status(405).json({ error: 'Method not allowed' });
    }
  } catch (error) {
    console.error('[Stats API] Error:', error.message);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

/**
 * GET /api/stats - Retrieve current traffic statistics
 */
async function handleGet(req, res) {
  const { data, error } = await supabase
    .from('traffic_stats')
    .select('*')
    .limit(1)
    .single();

  if (error) {
    console.error('[Stats API] Supabase query error:', error.message);
    return res.status(500).json({ error: 'Failed to retrieve stats' });
  }

  // Also get recent alert counts by category (last 24 hours)
  const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

  const { data: recentAlerts, error: recentError } = await supabase
    .from('alerts')
    .select('category')
    .gte('timestamp', oneDayAgo);

  let recentBreakdown = { DoS: 0, Probe: 0, R2L: 0, U2R: 0 };
  if (!recentError && recentAlerts) {
    recentAlerts.forEach((alert) => {
      if (recentBreakdown[alert.category] !== undefined) {
        recentBreakdown[alert.category]++;
      }
    });
  }

  return res.status(200).json({
    stats: data,
    recent_24h: {
      total: recentAlerts ? recentAlerts.length : 0,
      breakdown: recentBreakdown,
    },
  });
}

/**
 * PUT /api/stats - Update traffic statistics
 * Used by the capture system to report packet counts
 */
async function handlePut(req, res) {
  const { total_packets, normal_count } = req.body;

  if (total_packets === undefined) {
    return res.status(400).json({ error: 'Missing total_packets field' });
  }

  // Get existing stats row
  const { data: existing } = await supabase
    .from('traffic_stats')
    .select('id')
    .limit(1)
    .single();

  if (!existing) {
    return res.status(500).json({ error: 'Stats row not found' });
  }

  const updates = {
    total_packets,
    last_updated: new Date().toISOString(),
  };

  if (normal_count !== undefined) {
    updates.normal_count = normal_count;
  }

  const { data, error } = await supabase
    .from('traffic_stats')
    .update(updates)
    .eq('id', existing.id)
    .select();

  if (error) {
    console.error('[Stats API] Supabase update error:', error.message);
    return res.status(500).json({ error: 'Failed to update stats' });
  }

  return res.status(200).json({ message: 'Stats updated', stats: data[0] });
}
