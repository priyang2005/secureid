/**
 * scanner.js
 * Secure ID — Scanner Interface Logic
 *
 * Responsibilities:
 *   1. Access device camera via getUserMedia
 *   2. Continuously scan video frames for QR codes using jsQR
 *   3. Send decoded QR data to backend /api/verify/scan
 *   4. Display ACCESS GRANTED (green) or ACCESS DENIED (red)
 *   5. Log every scan attempt with timestamp and result
 *
 * Anti-spam:
 *   - After a successful scan, the scanner pauses for 3 seconds
 *     before accepting the next QR code.
 *   - The same QR data cannot be re-submitted within 5 seconds
 *     (client-side debounce; server has its own replay protection).
 */

// ── Configuration ─────────────────────────────────────────────────────────────
const API_BASE   = window.location.origin;  // Same origin as backend
const SCANNER_ID = 'scanner-' + Math.random().toString(36).slice(2, 8).toUpperCase();
const COOLDOWN_MS      = 3000;   // Lock scanner for 3s after each scan
const DEBOUNCE_MS      = 5000;   // Ignore the same QR data within 5s
const FLASH_DURATION   = 2500;   // How long the result flash stays on screen (ms)
const RESULT_HOLD_MS   = 3000;   // How long the result card stays populated

// ── State ─────────────────────────────────────────────────────────────────────
let videoStream    = null;
let scanCanvas     = null;
let scanCtx        = null;
let isScanning     = false;       // Is the scan loop running?
let isCooldown     = false;       // Is the scanner in cooldown after a scan?
let lastScannedData = null;       // Last QR string (for client-side debounce)
let lastScannedTime = 0;          // Timestamp of last scan
let accessLog      = [];          // In-memory log (shown in side panel)

// ── Init ──────────────────────────────────────────────────────────────────────
document.getElementById('scannerIdDisplay').textContent = 'DEVICE: ' + SCANNER_ID;

// ── Camera Setup ──────────────────────────────────────────────────────────────

/**
 * Request camera access and start the scan loop.
 * Called when the user clicks "Start Camera".
 */
async function startScanner() {
  try {
    document.getElementById('topbarStatus').textContent = 'Requesting camera...';

    // Prefer rear camera on mobile devices
    videoStream = await navigator.mediaDevices.getUserMedia({
      video: {
        facingMode: { ideal: 'environment' },
        width:      { ideal: 1280 },
        height:     { ideal: 720 }
      }
    });

    const video = document.getElementById('preview');
    video.srcObject = videoStream;
    await video.play();

    // Show video feed, hide permission screen
    document.getElementById('permissionScreen').style.display = 'none';
    document.getElementById('video-container').style.display  = 'block';

    // Create offscreen canvas for frame analysis
    scanCanvas = document.createElement('canvas');
    scanCtx    = scanCanvas.getContext('2d');

    isScanning = true;
    document.getElementById('topbarStatus').textContent = 'Scanning...';

    // Start the decode loop
    requestAnimationFrame(scanLoop);

  } catch (err) {
    console.error('[Scanner] Camera error:', err);
    document.getElementById('topbarStatus').textContent = 'Camera error';

    const screen = document.getElementById('permissionScreen');
    screen.querySelector('p').textContent =
      'Camera access denied or unavailable. Please grant permission and refresh.';
    screen.querySelector('h2').textContent = '⚠️ Camera Error';
  }
}

// ── Scan Loop ─────────────────────────────────────────────────────────────────

/**
 * Continuously capture video frames and try to decode a QR code.
 * Uses requestAnimationFrame for smooth, efficient looping.
 */
function scanLoop() {
  if (!isScanning) return;

  const video = document.getElementById('preview');

  // Only process when video has data
  if (video.readyState === video.HAVE_ENOUGH_DATA) {
    scanCanvas.width  = video.videoWidth;
    scanCanvas.height = video.videoHeight;
    scanCtx.drawImage(video, 0, 0, scanCanvas.width, scanCanvas.height);

    const imageData = scanCtx.getImageData(0, 0, scanCanvas.width, scanCanvas.height);

    // jsQR: decode QR from pixel data
    const qrCode = jsQR(imageData.data, imageData.width, imageData.height, {
      inversionAttempts: 'dontInvert'
    });

    if (qrCode && qrCode.data && !isCooldown) {
      handleQRDetected(qrCode.data);
    }
  }

  requestAnimationFrame(scanLoop);
}

// ── QR Handling ───────────────────────────────────────────────────────────────

/**
 * Called when a QR code is decoded from the camera.
 * Implements client-side debounce, then sends to backend.
 * @param {string} qrData - Raw decoded QR string
 */
async function handleQRDetected(qrData) {
  const now = Date.now();

  // Client-side debounce: ignore same QR within DEBOUNCE_MS
  if (qrData === lastScannedData && now - lastScannedTime < DEBOUNCE_MS) {
    return;
  }

  // Enter cooldown to prevent double-scanning
  isCooldown = true;
  lastScannedData = qrData;
  lastScannedTime = now;

  document.getElementById('topbarStatus').textContent = 'Verifying...';

  try {
    const result = await verifyWithServer(qrData);
    displayResult(result);
    addToLog(result);
  } catch (err) {
    console.error('[Scanner] Verification error:', err);
    displayResult({ result: 'DENY', reason: 'Network error — could not reach server' });
    addToLog({ result: 'DENY', reason: 'Network error' });
  }

  // Release cooldown after COOLDOWN_MS
  setTimeout(() => {
    isCooldown = false;
    document.getElementById('topbarStatus').textContent = 'Scanning...';
  }, COOLDOWN_MS);
}

// ── Backend Verification ──────────────────────────────────────────────────────

/**
 * Send QR data to backend for verification.
 * @param {string} qrData
 * @returns {Promise<{ result: 'ALLOW'|'DENY', reason?: string, user?: object }>}
 */
async function verifyWithServer(qrData) {
  const response = await fetch(`${API_BASE}/api/verify/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      qrData:    qrData,
      scannerId: SCANNER_ID
    })
  });

  if (!response.ok) {
    throw new Error(`Server returned ${response.status}`);
  }

  return await response.json();
}

// ── Result Display ────────────────────────────────────────────────────────────

/**
 * Show the result flash overlay and update the side panel result card.
 * @param {{ result: 'ALLOW'|'DENY', reason?: string, user?: object }} data
 */
function displayResult(data) {
  const isAllow = data.result === 'ALLOW';
  const flash   = document.getElementById('resultFlash');
  const card    = document.getElementById('resultCard');

  // ── Full-screen flash ─────────────────────────────────────────────────────
  document.getElementById('flashIcon').textContent = isAllow ? '✅' : '❌';
  document.getElementById('flashWord').textContent = isAllow ? 'ACCESS GRANTED' : 'ACCESS DENIED';
  document.getElementById('flashUser').textContent = data.user?.name || '';
  document.getElementById('flashSub').textContent  =
    isAllow
      ? `${data.user?.role || ''} · ${data.user?.department || ''}`
      : (data.reason || 'Unauthorized');

  flash.className = `result-flash show ${isAllow ? 'allow' : 'deny'}`;

  // Hide flash after duration
  setTimeout(() => {
    flash.classList.remove('show');
  }, FLASH_DURATION);

  // ── Side panel result card ────────────────────────────────────────────────
  card.className = `result-card ${isAllow ? 'allow' : 'deny'}`;
  card.innerHTML = `
    <div class="rc-status">
      ${isAllow ? '✅' : '❌'}
      ${isAllow ? 'ACCESS GRANTED' : 'ACCESS DENIED'}
    </div>
    ${data.user ? `<div class="rc-name">${escapeHtml(data.user.name)}</div>` : ''}
    <div class="rc-detail">${escapeHtml(data.user?.role || data.reason || '')}</div>
  `;

  // Reset card after hold duration
  setTimeout(() => {
    card.className = 'result-card';
    card.innerHTML = '<div class="idle-text">Waiting for scan...</div>';
  }, RESULT_HOLD_MS);
}

// ── Access Log ────────────────────────────────────────────────────────────────

/**
 * Add an entry to the in-memory access log and re-render the list.
 */
function addToLog(data) {
  const isAllow = data.result === 'ALLOW';
  const entry = {
    result:    isAllow ? 'allow' : 'deny',
    icon:      isAllow ? '✅' : '❌',
    name:      data.user?.name || 'Unknown',
    timestamp: new Date(),
    reason:    data.reason || ''
  };

  // Add to front of log
  accessLog.unshift(entry);
  if (accessLog.length > 50) accessLog.pop(); // Keep max 50 entries

  renderLog();
}

/**
 * Re-render the access log list in the side panel.
 */
function renderLog() {
  const list = document.getElementById('logList');
  list.innerHTML = '';

  if (accessLog.length === 0) {
    list.innerHTML = '<div class="log-empty">No scans yet</div>';
    return;
  }

  for (const entry of accessLog) {
    const time = entry.timestamp.toLocaleTimeString('en-US', {
      hour: '2-digit', minute: '2-digit', second: '2-digit'
    });
    const item = document.createElement('div');
    item.className = `log-item ${entry.result}`;
    item.innerHTML = `
      <span class="log-icon">${entry.icon}</span>
      <span class="log-name">${escapeHtml(entry.name)}</span>
      <span class="log-result">${entry.result.toUpperCase()}</span>
      <span class="log-time">${time}</span>
    `;
    list.appendChild(item);
  }
}

// ── Utility ───────────────────────────────────────────────────────────────────
function escapeHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
