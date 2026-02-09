/**
 * alerts.js - Alerts API Endpoint (Vercel Serverless Function)
 * =============================================================
 * POST /api/alerts - Receive a new alert from the capture system
 * GET  /api/alerts - Retrieve alerts for the dashboard
 *
 * Author: University of Botswana - Final Year Project
 */

const { supabase } = require('../config/db');
const { sendAlertEmail } = require('../services/emailService');

module.exports = async function handler(req, res) {
  // Handle CORS preflight
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
    console.error('[Alerts API] Error:', error.message);
    return res.status(500).json({ error: 'Internal server error' });
  }
};

/**
 * POST /api/alerts - Receive and store a new alert
 */
async function handlePost(req, res) {
  const {
    category,
    attack_type,
    confidence,
    severity,
    src_ip,
    dst_ip,
    dst_port,
    src_port,
    protocol,
    timestamp,
  } = req.body;

  // Validate required fields
  if (!category || !attack_type || confidence === undefined || !severity || !src_ip || !dst_ip) {
    return res.status(400).json({
      error: 'Missing required fields',
      required: ['category', 'attack_type', 'confidence', 'severity', 'src_ip', 'dst_ip'],
    });
  }

  // Insert alert into Supabase
  const { data, error } = await supabase
    .from('alerts')
    .insert([
      {
        category,
        attack_type,
        confidence,
        severity,
        src_ip,
        dst_ip,
        dst_port: dst_port || 0,
        src_port: src_port || 0,
        protocol: protocol || 'tcp',
        timestamp: timestamp || new Date().toISOString(),
      },
    ])
    .select();

  if (error) {
    console.error('[Alerts API] Supabase insert error:', error.message);
    return res.status(500).json({ error: 'Failed to store alert' });
  }

  // Update traffic stats
  await updateStats(category);

  // Send email for high-confidence alerts
  if (confidence > 80) {
    await sendAlertEmail({
      category,
      attack_type,
      confidence,
      severity,
      src_ip,
      dst_ip,
      dst_port: dst_port || 0,
      protocol: protocol || 'tcp',
      timestamp: timestamp || new Date().toISOString(),
    });
  }

  console.log(`[Alerts API] Alert stored: ${category} - ${attack_type} (${confidence}%)`);
  return res.status(201).json({ message: 'Alert stored', alert: data[0] });
}

/**
 * GET /api/alerts - Retrieve alerts with optional filters
 * Query params: limit, offset, category, severity, src_ip, dst_ip
 */
async function handleGet(req, res) {
  const {
    limit = 50,
    offset = 0,
    category,
    severity,
    src_ip,
    dst_ip,
  } = req.query;

  let query = supabase
    .from('alerts')
    .select('*', { count: 'exact' })
    .order('timestamp', { ascending: false })
    .range(Number(offset), Number(offset) + Number(limit) - 1);

  // Apply filters
  if (category) query = query.eq('category', category);
  if (severity) query = query.eq('severity', severity);
  if (src_ip) query = query.eq('src_ip', src_ip);
  if (dst_ip) query = query.eq('dst_ip', dst_ip);

  const { data, count, error } = await query;

  if (error) {
    console.error('[Alerts API] Supabase query error:', error.message);
    return res.status(500).json({ error: 'Failed to retrieve alerts' });
  }

  return res.status(200).json({
    alerts: data,
    total: count,
    limit: Number(limit),
    offset: Number(offset),
  });
}

/**
 * Update traffic_stats counters after a new alert
 */
async function updateStats(category) {
  try {
    // Get current stats
    const { data: stats } = await supabase
      .from('traffic_stats')
      .select('*')
      .limit(1)
      .single();

    if (!stats) return;

    // Build update object
    const updates = {
      attack_count: (stats.attack_count || 0) + 1,
      last_updated: new Date().toISOString(),
    };

    // Increment the specific category counter
    const categoryMap = {
      DoS: 'dos_count',
      Probe: 'probe_count',
      R2L: 'r2l_count',
      U2R: 'u2r_count',
    };

    const counterField = categoryMap[category];
    if (counterField) {
      updates[counterField] = (stats[counterField] || 0) + 1;
    }

    await supabase
      .from('traffic_stats')
      .update(updates)
      .eq('id', stats.id);
  } catch (err) {
    console.error('[Alerts API] Failed to update stats:', err.message);
  }
}
