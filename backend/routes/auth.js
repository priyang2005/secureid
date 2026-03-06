/**
 * routes/auth.js
 * Authentication endpoints.
 *
 * POST /api/auth/login      → Validate credentials, return JWT session token
 * GET  /api/auth/qr-token   → Generate a time-based QR payload for the logged-in user
 * POST /api/auth/logout     → Invalidate session (client-side for JWT)
 */

const express  = require('express');
const bcrypt   = require('bcrypt');
const jwt      = require('jsonwebtoken');
const router   = express.Router();

const supabase              = require('../supabaseClient');
const { buildQRPayload, secondsUntilNextInterval } = require('../services/tokenService');
const { encryptPayload }    = require('../services/encryptionService');

require('dotenv').config();

const JWT_SECRET  = process.env.JWT_SECRET || 'change-this-in-production';
const JWT_EXPIRES = '8h'; // Session expires after 8 hours

// ─── Middleware: Verify JWT ───────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // "Bearer <token>"

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { id, email, role, name }
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid or expired session' });
  }
}

// ─── POST /api/auth/login ─────────────────────────────────────────────────────
/**
 * Authenticate a user with email + password.
 * Returns a JWT session token and basic user info.
 */
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // ── Input validation ──────────────────────────────────────────────────────
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    if (typeof email !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ error: 'Invalid input types' });
    }

    // ── Look up user in Supabase ──────────────────────────────────────────────
    const { data: user, error } = await supabase
      .from('users')
      .select('id, name, email, password_hash, role, department, secret_key')
      .eq('email', email.toLowerCase().trim())
      .single();

    if (error || !user) {
      // Return same error for wrong email or wrong password (prevent enumeration)
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // ── Verify password ───────────────────────────────────────────────────────
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // ── Issue JWT session token ───────────────────────────────────────────────
    const sessionPayload = {
      id:   user.id,
      email: user.email,
      name:  user.name,
      role:  user.role
    };
    const sessionToken = jwt.sign(sessionPayload, JWT_SECRET, { expiresIn: JWT_EXPIRES });

    console.log(`[Auth] Login: ${user.email} (${user.role}) at ${new Date().toISOString()}`);

    return res.json({
      token: sessionToken,
      user: {
        id:         user.id,
        name:       user.name,
        email:      user.email,
        role:       user.role,
        department: user.department
      }
    });

  } catch (err) {
    console.error('[Auth] Login error:', err.message);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// ─── GET /api/auth/qr-token ───────────────────────────────────────────────────
/**
 * Generate a fresh QR payload for the authenticated user.
 * Called by the dashboard every 30 seconds to refresh the QR code.
 *
 * Returns:
 * {
 *   qrData:          string  ← encrypted, URL-safe payload to embed in QR
 *   secondsRemaining: number ← seconds until this token expires
 * }
 */
router.get('/qr-token', requireAuth, async (req, res) => {
  try {
    // ── Fetch user's secret key from DB ───────────────────────────────────────
    const { data: user, error } = await supabase
      .from('users')
      .select('id, secret_key')
      .eq('id', req.user.id)
      .single();

    if (error || !user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // ── Build and encrypt QR payload ─────────────────────────────────────────
    const rawPayload      = buildQRPayload(user.id, user.secret_key);
    const encryptedQRData = encryptPayload(rawPayload);

    return res.json({
      qrData:           encryptedQRData,
      secondsRemaining: secondsUntilNextInterval()
    });

  } catch (err) {
    console.error('[Auth] QR token error:', err.message);
    return res.status(500).json({ error: 'Failed to generate QR token' });
  }
});

// ─── GET /api/auth/me ─────────────────────────────────────────────────────────
/**
 * Return current user info from JWT (no DB call needed).
 * Used by the frontend to restore session after page reload.
 */
router.get('/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// Export requireAuth so other routes can use it
router.requireAuth = requireAuth;

module.exports = router;
