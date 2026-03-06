/**
 * app.js
 * Secure ID — Frontend API Client
 *
 * Provides the global `SecureID` object with methods for:
 *   - login / logout
 *   - session management (JWT stored in localStorage)
 *   - fetching QR tokens from the backend
 */

const SecureID = (() => {
  // ── Configuration ──────────────────────────────────────────────────────────
  // ── RENDER DEPLOYMENT ───────────────────────────────────────────────────────
  // After deploying to Render, paste your backend URL below, e.g.:
  //   const API_BASE = 'https://secure-id-backend.onrender.com';
  // If frontend is served by the SAME Render service, leave this as-is:
  const API_BASE = window.SECURE_ID_API_URL || window.location.origin;

  const STORAGE_TOKEN = 'secure_id_token';
  const STORAGE_USER  = 'secure_id_user';

  // ── Helpers ────────────────────────────────────────────────────────────────

  /**
   * Make an authenticated API request.
   * Automatically attaches the stored JWT as a Bearer token.
   * @param {string} path - API path (e.g. '/api/auth/qr-token')
   * @param {object} [options] - fetch options override
   * @returns {Promise<object>} Parsed JSON response
   */
  async function apiFetch(path, options = {}) {
    const token = localStorage.getItem(STORAGE_TOKEN);

    const defaultHeaders = {
      'Content-Type': 'application/json'
    };
    if (token) {
      defaultHeaders['Authorization'] = `Bearer ${token}`;
    }

    const response = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers: {
        ...defaultHeaders,
        ...(options.headers || {})
      }
    });

    const data = await response.json();

    // If server returns 401/403, session is expired — redirect to login
    if (response.status === 401 || response.status === 403) {
      logout();
      window.location.href = '/login.html';
      return;
    }

    return data;
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  /**
   * Log in with email + password.
   * On success, stores JWT and user info in localStorage.
   *
   * @param {string} email
   * @param {string} password
   * @returns {Promise<{ success: boolean, error?: string }>}
   */
  async function login(email, password) {
    try {
      const data = await apiFetch('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password })
      });

      if (data.token && data.user) {
        localStorage.setItem(STORAGE_TOKEN, data.token);
        localStorage.setItem(STORAGE_USER, JSON.stringify(data.user));
        return { success: true, user: data.user };
      }

      return { success: false, error: data.error || 'Login failed' };
    } catch (err) {
      console.error('[SecureID] Login error:', err);
      throw err; // Let the UI handle network errors
    }
  }

  /**
   * Log out — clear all stored session data.
   */
  function logout() {
    localStorage.removeItem(STORAGE_TOKEN);
    localStorage.removeItem(STORAGE_USER);
  }

  /**
   * Get the current session (JWT + user info).
   * Returns null if not logged in.
   * @returns {{ token: string, user: object } | null}
   */
  function getSession() {
    const token    = localStorage.getItem(STORAGE_TOKEN);
    const userJSON = localStorage.getItem(STORAGE_USER);
    if (!token || !userJSON) return null;

    try {
      const user = JSON.parse(userJSON);
      return { token, user };
    } catch {
      return null;
    }
  }

  /**
   * Fetch a fresh QR token payload from the backend.
   * The backend generates a time-based HMAC token and encrypts it.
   *
   * @returns {Promise<{ qrData: string, secondsRemaining: number }>}
   */
  async function getQRToken() {
    const data = await apiFetch('/api/auth/qr-token');
    if (!data || !data.qrData) {
      throw new Error('Failed to get QR token from server');
    }
    return data;
  }

  /**
   * Verify a QR code payload (used by the scanner interface).
   * Sends the encrypted QR data to the backend for validation.
   *
   * @param {string} qrData - Raw string scanned from the QR code
   * @param {string} [scannerId] - Identifier for this scanner device
   * @returns {Promise<{ result: 'ALLOW' | 'DENY', reason?: string, user?: object }>}
   */
  async function verifyQR(qrData, scannerId = 'web-scanner') {
    const data = await apiFetch('/api/verify/scan', {
      method: 'POST',
      body: JSON.stringify({ qrData, scannerId })
    });
    return data;
  }

  /**
   * Fetch recent access logs (for admin/scanner display).
   * @param {number} [limit=10]
   * @returns {Promise<{ logs: Array }>}
   */
  async function getAccessLogs(limit = 10) {
    return await apiFetch(`/api/verify/logs?limit=${limit}`);
  }

  // Expose public interface
  return { login, logout, getSession, getQRToken, verifyQR, getAccessLogs };
})();
