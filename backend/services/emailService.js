/**
 * emailService.js - Email Notification Service
 * ===============================================
 * Sends email alerts to the administrator when high-confidence
 * attacks are detected (confidence > 80%).
 *
 * Uses Nodemailer with Outlook/Gmail SMTP.
 *
 * Setup:
 * Set EMAIL_USER, EMAIL_PASS, and optionally EMAIL_TO in Vercel env vars.
 * EMAIL_PROVIDER can be 'outlook' or 'gmail' (default: outlook).
 *
 * Author: University of Botswana - Final Year Project
 */

const nodemailer = require('nodemailer');

// Create transporter based on configured provider
const provider = (process.env.EMAIL_PROVIDER || 'outlook').toLowerCase();

const transportConfig = provider === 'gmail'
  ? { service: 'gmail', auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS } }
  : { host: 'smtp.office365.com', port: 587, secure: false, auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }, tls: { ciphers: 'SSLv3' } };

const transporter = nodemailer.createTransport(transportConfig);

/**
 * Send an attack alert email to the administrator.
 *
 * @param {Object} alert - The alert data
 * @param {string} alert.category - Attack category (DoS, Probe, R2L, U2R)
 * @param {string} alert.attack_type - Specific attack type
 * @param {number} alert.confidence - Confidence percentage
 * @param {string} alert.src_ip - Source/attacker IP
 * @param {string} alert.dst_ip - Destination/victim IP
 * @param {number} alert.dst_port - Target port
 * @param {string} alert.severity - Severity level
 * @param {string} alert.timestamp - Detection timestamp
 * @returns {Promise<boolean>} True if email sent successfully
 */
async function sendAlertEmail(alert) {
  // Only send emails for alerts above 65% confidence
  if (alert.confidence <= 65) {
    return false;
  }

  // Check if email is configured
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.warn('[Email] Email not configured - skipping notification');
    return false;
  }

  const recipientEmail = process.env.EMAIL_TO || process.env.EMAIL_USER;

  // Severity colour for the email
  const severityColor = alert.severity === 'high' ? '#FF0000' : '#FF9800';

  const mailOptions = {
    from: `"NIDS Alert System" <${process.env.EMAIL_USER}>`,
    to: recipientEmail,
    subject: `[NIDS ALERT] ${alert.category} Attack on ${alert.agent_name || 'Unknown'} - ${alert.confidence}% Confidence`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background-color: ${severityColor}; color: white; padding: 20px; text-align: center;">
          <h1 style="margin: 0;">INTRUSION DETECTED</h1>
          <p style="margin: 5px 0 0 0; font-size: 18px;">${alert.category} Attack on ${alert.agent_name || 'Unknown Agent'}</p>
        </div>

        <div style="padding: 20px; border: 1px solid #ddd;">
          <table style="width: 100%; border-collapse: collapse;">
            <tr>
              <td style="padding: 10px; border-bottom: 1px solid #eee; font-weight: bold;">Agent (Machine)</td>
              <td style="padding: 10px; border-bottom: 1px solid #eee; font-weight: bold; color: #0366d6;">${alert.agent_name || 'Unknown'}</td>
            </tr>
            <tr>
              <td style="padding: 10px; border-bottom: 1px solid #eee; font-weight: bold;">Attack Category</td>
              <td style="padding: 10px; border-bottom: 1px solid #eee; color: ${severityColor}; font-weight: bold;">${alert.category}</td>
            </tr>
            <tr>
              <td style="padding: 10px; border-bottom: 1px solid #eee; font-weight: bold;">Attack Type</td>
              <td style="padding: 10px; border-bottom: 1px solid #eee;">${alert.attack_type}</td>
            </tr>
            <tr>
              <td style="padding: 10px; border-bottom: 1px solid #eee; font-weight: bold;">Confidence</td>
              <td style="padding: 10px; border-bottom: 1px solid #eee; font-size: 18px; font-weight: bold;">${alert.confidence}%</td>
            </tr>
            <tr>
              <td style="padding: 10px; border-bottom: 1px solid #eee; font-weight: bold;">Severity</td>
              <td style="padding: 10px; border-bottom: 1px solid #eee; text-transform: uppercase;">${alert.severity}</td>
            </tr>
            <tr>
              <td style="padding: 10px; border-bottom: 1px solid #eee; font-weight: bold;">Source IP (Attacker)</td>
              <td style="padding: 10px; border-bottom: 1px solid #eee; font-family: monospace;">${alert.src_ip}</td>
            </tr>
            <tr>
              <td style="padding: 10px; border-bottom: 1px solid #eee; font-weight: bold;">Destination IP (Victim)</td>
              <td style="padding: 10px; border-bottom: 1px solid #eee; font-family: monospace;">${alert.dst_ip}</td>
            </tr>
            <tr>
              <td style="padding: 10px; border-bottom: 1px solid #eee; font-weight: bold;">Target Port</td>
              <td style="padding: 10px; border-bottom: 1px solid #eee; font-family: monospace;">${alert.dst_port}</td>
            </tr>
            <tr>
              <td style="padding: 10px; border-bottom: 1px solid #eee; font-weight: bold;">Protocol</td>
              <td style="padding: 10px; border-bottom: 1px solid #eee;">${alert.protocol || 'tcp'}</td>
            </tr>
            <tr>
              <td style="padding: 10px; font-weight: bold;">Detected At</td>
              <td style="padding: 10px;">${alert.timestamp || new Date().toISOString()}</td>
            </tr>
          </table>
        </div>

        <div style="background-color: #f5f5f5; padding: 15px; text-align: center; font-size: 12px; color: #666;">
          <p>This is an automated alert from the Network Intrusion Detection System (NIDS).</p>
          <p>University of Botswana - Final Year Project</p>
        </div>
      </div>
    `,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`[Email] Alert email sent for ${alert.category} attack (${alert.confidence}%)`);
    return true;
  } catch (error) {
    console.error('[Email] Failed to send alert email:', error.message);
    return false;
  }
}

module.exports = { sendAlertEmail };
