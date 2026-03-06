/**
 * server.js
 * Secure ID — Main Express Server
 *
 * Endpoints:
 *   /api/auth/*    → Login, QR token generation, session management
 *   /api/verify/*  → QR code scanner verification
 *   /api/health    → Server health check
 *
 * Static files:
 *   /              → frontend/
 *   /scanner       → scanner/  (in production: private network only)
 */

require('dotenv').config();

const express    = require('express');
const cors       = require('cors');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const path       = require('path');

const authRoutes   = require('./routes/auth');
const verifyRoutes = require('./routes/verify');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── Security Middleware ─────────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));

app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (mobile apps, curl, Postman)
    if (!origin) return callback(null, true);
    // Allow all render.app domains + any configured origins
    const allowed = process.env.ALLOWED_ORIGINS
      ? process.env.ALLOWED_ORIGINS.split(',')
      : [];
    if (
      allowed.includes(origin) ||
      origin.endsWith('.onrender.com') ||
      origin.includes('localhost')
    ) {
      return callback(null, true);
    }
    return callback(null, true); // Open CORS for now — restrict in production
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// ─── Rate Limiting ────────────────────────────────────────────────────────────
app.use('/api/', rateLimit({
  windowMs: 60 * 1000, max: 100, standardHeaders: true,
  message: { error: 'Too many requests — please slow down.' }
}));
app.use('/api/auth/login', rateLimit({
  windowMs: 15 * 60 * 1000, max: 10,
  message: { error: 'Too many login attempts. Try again in 15 minutes.' }
}));
app.use('/api/verify/scan', rateLimit({
  windowMs: 60 * 1000, max: 30,
  message: { result: 'DENY', reason: 'Too many scan attempts.' }
}));

// ─── Body Parser ─────────────────────────────────────────────────────────────
app.use(express.json({ limit: '10kb' }));

// ─── Static Files ─────────────────────────────────────────────────────────── 
app.use(express.static(path.join(__dirname, '../frontend')));
app.use('/scanner', express.static(path.join(__dirname, '../scanner')));

// ─── API Routes ──────────────────────────────────────────────────────────────
app.use('/api/auth',   authRoutes);
app.use('/api/verify', verifyRoutes);

// ─── Health Check ────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString(), version: '1.0.0' });
});

// ─── Fallback → Frontend ─────────────────────────────────────────────────────
app.get('*', (req, res) => {
  if (req.path.startsWith('/api') || req.path.startsWith('/scanner')) {
    return res.status(404).json({ error: 'Not found' });
  }
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

// ─── Global Error Handler ────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error(`[ERROR] ${new Date().toISOString()} — ${err.message}`);
  res.status(err.status || 500).json({
    error: process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message
  });
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log('\n╔════════════════════════════════════════╗');
  console.log('║       🔐  Secure ID Server             ║');
  console.log('╠════════════════════════════════════════╣');
  console.log(`║  Frontend : http://localhost:${PORT}        ║`);
  console.log(`║  Scanner  : http://localhost:${PORT}/scanner ║`);
  console.log(`║  API      : http://localhost:${PORT}/api     ║`);
  console.log('╚════════════════════════════════════════╝\n');
});

module.exports = app;
