/**
 * health.js - Health Check Endpoint (Vercel Serverless Function)
 * ===============================================================
 * GET /api/health - Check if the API and database are operational
 *
 * Author: University of Botswana - Final Year Project
 */

const { supabase } = require('../config/db');

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  try {
    // Test Supabase connection
    const { error } = await supabase
      .from('traffic_stats')
      .select('id')
      .limit(1);

    if (error) {
      return res.status(503).json({
        status: 'unhealthy',
        database: 'disconnected',
        error: error.message,
      });
    }

    return res.status(200).json({
      status: 'healthy',
      database: 'connected',
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    return res.status(503).json({
      status: 'unhealthy',
      error: error.message,
    });
  }
};
