/**
 * tokenService.js
 * Handles time-based HMAC token generation and verification.
 *
 * Security model:
 *   - Each user has a unique secret_key stored in the database.
 *   - A token = HMAC-SHA256( secret_key, userId + ":" + timeInterval )
 *   - timeInterval = Math.floor(Date.now() / 1000 / 30)  → changes every 30 seconds
 *   - Verification allows ±1 interval tolerance for clock drift.
 *   - Tokens are one-time-use (tracked in access_logs to prevent replay attacks).
 */

const crypto = require('crypto');

const TOKEN_INTERVAL_SECONDS = 30; // QR refreshes every 30 seconds

/**
 * Get the current time interval index.
 * Increments every TOKEN_INTERVAL_SECONDS.
 * @returns {number}
 */
function getCurrentInterval() {
  return Math.floor(Date.now() / 1000 / TOKEN_INTERVAL_SECONDS);
}

/**
 * Generate an HMAC-SHA256 token for a given user and time interval.
 * @param {string} userId - The user's UUID
 * @param {string} secretKey - The user's unique secret (hex string)
 * @param {number} interval - Time interval index
 * @returns {string} Hex-encoded HMAC digest
 */
function generateHMAC(userId, secretKey, interval) {
  const message = `${userId}:${interval}`;
  return crypto
    .createHmac('sha256', Buffer.from(secretKey, 'hex'))
    .update(message)
    .digest('hex');
}

/**
 * Build a complete QR payload object for the current time window.
 * The payload is JSON-stringified and encoded into the QR code.
 *
 * Payload structure:
 * {
 *   uid: "user-uuid",
 *   t:   1234567,       ← current interval
 *   sig: "abcdef..."    ← HMAC signature
 * }
 *
 * @param {string} userId
 * @param {string} secretKey
 * @returns {{ uid: string, t: number, sig: string }}
 */
function buildQRPayload(userId, secretKey) {
  const interval = getCurrentInterval();
  const sig = generateHMAC(userId, secretKey, interval);
  return { uid: userId, t: interval, sig };
}

/**
 * Verify a QR payload received from the scanner.
 * Checks:
 *   1. Payload has required fields
 *   2. Signature is valid for current interval ±1 (clock drift tolerance)
 *   3. Token has not been used before (replay protection — caller must check DB)
 *
 * @param {{ uid: string, t: number, sig: string }} payload - Parsed QR payload
 * @param {string} secretKey - Secret key from database for the claimed user
 * @returns {{ valid: boolean, reason?: string }}
 */
function verifyPayload(payload, secretKey) {
  // ── 1. Validate payload structure ─────────────────────────────────────────
  if (!payload || typeof payload !== 'object') {
    return { valid: false, reason: 'Invalid payload format' };
  }
  const { uid, t, sig } = payload;
  if (!uid || typeof t !== 'number' || !sig) {
    return { valid: false, reason: 'Missing required payload fields' };
  }

  // ── 2. Check timestamp is within ±1 interval of current time ──────────────
  const now = getCurrentInterval();
  const intervalDrift = Math.abs(now - t);
  if (intervalDrift > 1) {
    return {
      valid: false,
      reason: `Token expired (interval drift: ${intervalDrift})`
    };
  }

  // ── 3. Verify HMAC signature against the claimed interval ─────────────────
  const expectedSig = generateHMAC(uid, secretKey, t);

  // Use timingSafeEqual to prevent timing attacks
  const sigBuffer      = Buffer.from(sig,         'hex');
  const expectedBuffer = Buffer.from(expectedSig, 'hex');

  if (
    sigBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(sigBuffer, expectedBuffer)
  ) {
    return { valid: false, reason: 'Invalid signature' };
  }

  return { valid: true };
}

/**
 * Create a SHA-256 hash of a token (used as the key for replay detection in DB).
 * We store the hash rather than the raw token to avoid leaking it.
 * @param {string} sig - The HMAC signature string
 * @param {number} t   - The interval
 * @returns {string} Hex-encoded SHA-256 hash
 */
function hashTokenForLog(sig, t) {
  return crypto
    .createHash('sha256')
    .update(`${sig}:${t}`)
    .digest('hex');
}

/**
 * Returns how many seconds remain in the current interval.
 * Used by the frontend countdown timer.
 * @returns {number} Seconds until next token refresh (0–29)
 */
function secondsUntilNextInterval() {
  return TOKEN_INTERVAL_SECONDS - (Math.floor(Date.now() / 1000) % TOKEN_INTERVAL_SECONDS);
}

module.exports = {
  buildQRPayload,
  verifyPayload,
  hashTokenForLog,
  secondsUntilNextInterval,
  getCurrentInterval,
  TOKEN_INTERVAL_SECONDS
};
