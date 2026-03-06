/**
 * encryptionService.js
 * Optional AES-256-GCM encryption layer for QR payload.
 *
 * While the HMAC alone prevents forgery, encrypting the payload
 * hides the user ID and interval from a casual observer scanning the QR code.
 *
 * Encryption key: derived from ENCRYPTION_SECRET in .env
 * Algorithm: AES-256-GCM (authenticated encryption — prevents tampering)
 */

const crypto = require('crypto');
require('dotenv').config();

const ALGORITHM    = 'aes-256-gcm';
const IV_LENGTH    = 12;   // 96-bit IV recommended for GCM
const TAG_LENGTH   = 16;   // Authentication tag length in bytes
const KEY_LENGTH   = 32;   // 256-bit key

/**
 * Derive a 256-bit encryption key from the ENCRYPTION_SECRET env variable.
 * Uses PBKDF2 with a fixed salt (the app name) — suitable for this use case
 * since the key is not user-specific.
 * @returns {Buffer}
 */
function getDerivedKey() {
  const secret = process.env.ENCRYPTION_SECRET || 'secure-id-default-secret-change-me';
  return crypto.pbkdf2Sync(secret, 'secure-id-app-salt', 100000, KEY_LENGTH, 'sha256');
}

/**
 * Encrypt a JSON payload using AES-256-GCM.
 * Returns a Base64-encoded string: iv + authTag + ciphertext
 *
 * @param {object} payload - Object to encrypt
 * @returns {string} Base64-encoded encrypted data
 */
function encryptPayload(payload) {
  const key        = getDerivedKey();
  const iv         = crypto.randomBytes(IV_LENGTH);
  const cipher     = crypto.createCipheriv(ALGORITHM, key, iv);
  const plaintext  = JSON.stringify(payload);

  const encrypted  = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final()
  ]);
  const authTag    = cipher.getAuthTag();

  // Pack: iv (12) + authTag (16) + ciphertext (variable)
  const combined = Buffer.concat([iv, authTag, encrypted]);
  return combined.toString('base64url'); // URL-safe Base64 (safe for QR codes)
}

/**
 * Decrypt a Base64-encoded AES-256-GCM payload.
 *
 * @param {string} encryptedBase64 - Output from encryptPayload()
 * @returns {object} Decrypted and parsed JSON object
 * @throws {Error} If decryption fails (tampered data, wrong key, etc.)
 */
function decryptPayload(encryptedBase64) {
  const key       = getDerivedKey();
  const combined  = Buffer.from(encryptedBase64, 'base64url');

  // Unpack: iv (12) + authTag (16) + ciphertext (rest)
  const iv         = combined.subarray(0, IV_LENGTH);
  const authTag    = combined.subarray(IV_LENGTH, IV_LENGTH + TAG_LENGTH);
  const ciphertext = combined.subarray(IV_LENGTH + TAG_LENGTH);

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final()
  ]);

  return JSON.parse(decrypted.toString('utf8'));
}

module.exports = { encryptPayload, decryptPayload };
