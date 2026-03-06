# Secure ID — System Architecture

## Overview

Secure ID replaces traditional campus ID cards with a **dynamic QR authentication system** that is resistant to cloning, screenshot sharing, and replay attacks.

---

## Security Model

### Why Traditional QR Codes Fail

| Problem | Traditional QR | Secure ID |
|---|---|---|
| Cloning | Trivial | Impossible (token expires in 30s) |
| Screenshot sharing | Works | Denied (already expired or used) |
| Real-time validation | None | Server-side every scan |
| Replay attacks | Unprotected | Blocked by token hash log |

### Token Generation

```
interval = floor(unix_timestamp / 30)      // Changes every 30 seconds
message  = userId + ":" + interval
token    = HMAC-SHA256(secret_key, message) // Hex string
payload  = { uid, t: interval, sig: token }
qrData   = AES-256-GCM-Encrypt(payload)    // URL-safe Base64
```

Each user has a unique `secret_key` stored in the database. This key never leaves the backend.

### Verification Flow

```
Scanner scans QR
     │
     ▼
Decrypt AES payload  ──── fail ──► DENY (tampered QR)
     │
     ▼
Fetch user secret_key from DB  ──── not found ──► DENY
     │
     ▼
Verify HMAC(secret_key, uid:interval)  ──── mismatch ──► DENY
     │
     ▼
Check timestamp: |now_interval - t| ≤ 1  ──── too old ──► DENY
     │
     ▼
Check token_hash in access_logs  ──── already used ──► DENY (replay)
     │
     ▼
Log token_hash as used
     │
     ▼
ALLOW ✅
```

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         FRONTEND                                 │
│                                                                  │
│   login.html         dashboard.html           index.html        │
│      │                    │                                      │
│      │   POST /api/auth/login                                   │
│      ├──────────────────────────────────────► backend           │
│      │   ◄── JWT session token                                  │
│      │                                                          │
│      │   GET /api/auth/qr-token (with JWT)                      │
│      │──────────────────────────────────────► backend           │
│      │   ◄── encrypted QR payload                              │
│      │                                                          │
│      │   [QRCode library renders payload as QR image]           │
│      │   [Timer counts down 30s, then re-fetches]               │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                         SCANNER                                  │
│                                                                  │
│   scanner.html + scanner.js                                      │
│      │                                                          │
│      │   [Camera → jsQR → decoded QR string]                    │
│      │                                                          │
│      │   POST /api/verify/scan                                  │
│      ├──────────────────────────────────────► backend           │
│      │   ◄── { result: "ALLOW" | "DENY" }                      │
│      │                                                          │
│      │   [Green/Red full-screen flash]                          │
│      │   [Access log entry added]                               │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                         BACKEND                                  │
│                                                                  │
│   server.js (Express)                                           │
│      │                                                          │
│      ├── routes/auth.js                                         │
│      │      POST /login     → bcrypt verify → JWT              │
│      │      GET  /qr-token  → HMAC token → AES encrypt         │
│      │      GET  /me        → JWT decode                       │
│      │                                                          │
│      ├── routes/verify.js                                       │
│      │      POST /scan      → decrypt → verify HMAC            │
│      │                         → check replay → log            │
│      │      GET  /logs      → recent access logs               │
│      │                                                          │
│      ├── services/tokenService.js                               │
│      │      buildQRPayload()    HMAC generation                 │
│      │      verifyPayload()     HMAC + timestamp verification   │
│      │      hashTokenForLog()   SHA-256 for replay log key     │
│      │                                                          │
│      └── services/encryptionService.js                         │
│             encryptPayload()    AES-256-GCM encrypt            │
│             decryptPayload()    AES-256-GCM decrypt            │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    SUPABASE (Database)                           │
│                                                                  │
│   users table                                                    │
│     id, name, email, password_hash, role, secret_key            │
│                                                                  │
│   access_logs table                                              │
│     user_id, token_hash, result, reason, scanner_id, timestamp  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Data Flow — QR Refresh Cycle

1. User logs in → receives JWT (valid 8 hours)
2. Dashboard loads → immediately fetches first QR token
3. Every second: countdown timer decrements
4. When `seconds_in_current_30s_cycle == 30` (i.e. a new interval started):
   - Frontend calls `GET /api/auth/qr-token`
   - Backend generates new HMAC for the new interval
   - QR code image is updated
5. Scanner can scan within the same interval (±1 for drift)

---

## Security Features Summary

| Feature | Implementation |
|---|---|
| Time-based tokens | `Math.floor(Date.now() / 1000 / 30)` interval index |
| HMAC signing | `crypto.createHmac('sha256', secretKey).update(uid:interval)` |
| Payload encryption | AES-256-GCM with random IV per token |
| Token expiry | Server rejects tokens with interval drift > 1 |
| Replay protection | `token_hash` stored in `access_logs`; duplicate = DENY |
| Brute force protection | Rate limiting: 10 login attempts / 15 min / IP |
| Timing attack prevention | `crypto.timingSafeEqual()` for HMAC comparison |
| Key isolation | User secret keys never leave the backend |
| Frontend key safety | Anon key used in frontend; service role key backend only |
