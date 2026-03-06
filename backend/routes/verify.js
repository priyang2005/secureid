/**
 * routes/verify.js
 * QR code verification endpoint — used by the scanner device.
 *
 * POST /api/verify/scan
 *   Body: { qrData: "<encrypted-payload>", scannerId?: "scanner-01" }
 *   Returns: { result: "ALLOW" | "DENY", reason?: string, user?: {...} }
 */

const express  = require('express');
const router   = express.Router();

const supabase              = require('../supabaseClient');
const { verifyPayload, hashTokenForLog } = require('../services/tokenService');
const { decryptPayload }    = require('../services/encryptionService');

// ─── POST /api/verify/scan ────────────────────────────────────────────────────
router.post('/scan', async (req, res) => {
  const scannerId = req.body.scannerId || 'unknown';
  let userId = null;

  try {
    const { qrData } = req.body;

    // ── Input validation ──────────────────────────────────────────────────────
    if (!qrData || typeof qrData !== 'string') {
      return res.status(400).json({ result: 'DENY', reason: 'No QR data provided' });
    }

    // ── Step 1: Decrypt QR payload ────────────────────────────────────────────
    let payload;
    try {
      payload = decryptPayload(qrData);
    } catch (decryptErr) {
      console.warn('[Verify] Decryption failed:', decryptErr.message);
      await logAccess(null, null, 'DENY', 'Invalid or tampered QR code', scannerId);
      return res.json({ result: 'DENY', reason: 'Invalid QR code' });
    }

    userId = payload.uid;

    // ── Step 2: Fetch user + secret key from database ─────────────────────────
    const { data: user, error: userErr } = await supabase
      .from('users')
      .select('id, name, role, department, secret_key')
      .eq('id', userId)
      .single();

    if (userErr || !user) {
      await logAccess(userId, payload.sig, 'DENY', 'User not found', scannerId);
      return res.json({ result: 'DENY', reason: 'Unrecognized user' });
    }

    // ── Step 3: Verify HMAC signature and timestamp ───────────────────────────
    const verification = verifyPayload(payload, user.secret_key);
    if (!verification.valid) {
      await logAccess(userId, payload.sig, 'DENY', verification.reason, scannerId);
      console.log(`[Verify] DENY  ${user.name} (${user.role}) — ${verification.reason}`);
      return res.json({ result: 'DENY', reason: verification.reason });
    }

    // ── Step 4: Replay attack protection ─────────────────────────────────────
    // Check if this exact token (sig + interval) has been used before
    const tokenHash = hashTokenForLog(payload.sig, payload.t);
    const { data: existingLog } = await supabase
      .from('access_logs')
      .select('id')
      .eq('token_hash', tokenHash)
      .eq('result', 'allow')
      .single();

    if (existingLog) {
      await logAccess(userId, tokenHash, 'DENY', 'Replay attack detected', scannerId);
      console.warn(`[Verify] REPLAY ATTACK by ${user.name} at ${new Date().toISOString()}`);
      return res.json({ result: 'DENY', reason: 'Token already used (replay attack)' });
    }

    // ── Step 5: All checks passed — ALLOW ────────────────────────────────────
    await logAccess(userId, tokenHash, 'ALLOW', null, scannerId);
    console.log(`[Verify] ALLOW ${user.name} (${user.role}) at ${new Date().toISOString()}`);

    return res.json({
      result: 'ALLOW',
      user: {
        name:       user.name,
        role:       user.role,
        department: user.department
      }
    });

  } catch (err) {
    console.error('[Verify] Unexpected error:', err.message);
    // Log the failure attempt
    await logAccess(userId, null, 'DENY', 'Server error during verification', scannerId);
    return res.status(500).json({ result: 'DENY', reason: 'Verification failed (server error)' });
  }
});

// ─── GET /api/verify/logs ─────────────────────────────────────────────────────
/**
 * Return recent access logs (for admin/scanner display).
 * In production, protect this with admin authentication.
 */
router.get('/logs', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);

    const { data: logs, error } = await supabase
      .from('access_logs')
      .select(`
        id,
        user_id,
        result,
        reason,
        scanner_id,
        timestamp,
        users ( name, role )
      `)
      .order('timestamp', { ascending: false })
      .limit(limit);

    if (error) throw error;

    return res.json({ logs: logs || [] });
  } catch (err) {
    console.error('[Verify] Logs error:', err.message);
    return res.status(500).json({ error: 'Failed to fetch logs' });
  }
});

// ─── Helper: Write to access_logs ────────────────────────────────────────────
async function logAccess(userId, tokenHash, result, reason, scannerId) {
  try {
    await supabase.from('access_logs').insert({
      user_id:    userId,
      token_hash: tokenHash,
      result:     result.toLowerCase(),
      reason:     reason,
      scanner_id: scannerId,
      timestamp:  new Date().toISOString()
    });
  } catch (err) {
    // Don't fail the main flow if logging fails
    console.error('[Verify] Failed to log access:', err.message);
  }
}

module.exports = router;
