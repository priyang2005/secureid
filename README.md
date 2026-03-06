# 🔐 Secure ID

> Dynamic QR-based campus authentication system. No cloning. No screenshots. No replay attacks.

## Problem

Traditional campus ID cards have critical security flaws:
- QR codes can be **screenshot and shared**
- Physical cards can be **cloned**
- No **real-time validation**
- No protection against **replay attacks**

## Solution

Secure ID generates a **time-based encrypted QR code** that:
- Refreshes every **30 seconds**
- Is signed with **HMAC-SHA256** (unique per user)
- Is encrypted with **AES-256-GCM**
- Is verified **server-side in real time**
- Tracks used tokens to **block replay attacks**

---

## Quick Start

### Prerequisites
- Node.js 18+
- A [Supabase](https://supabase.com) project (free tier works)

### 1. Clone the repo
```bash
git clone https://github.com/yourusername/Secure-ID.git
cd Secure-ID
```

### 2. Set up the database

1. Open your Supabase project → **SQL Editor** → **New Query**
2. Paste and run the contents of `docs/schema.sql`
3. This creates the `users` and `access_logs` tables with RLS policies

### 3. Configure environment

```bash
cd backend
cp ../.env.example .env
```

Edit `.env` and fill in:

```env
SUPABASE_URL=https://htwmwvsiyjjhgjpdqoes.supabase.co
SUPABASE_ANON_KEY=your_anon_key         # Settings → API → anon key
SUPABASE_SERVICE_ROLE_KEY=your_service_key  # Settings → API → service_role key
JWT_SECRET=some_long_random_string
ENCRYPTION_SECRET=another_long_random_string
```

### 4. Create demo users

Run the seed script to create demo accounts:

```bash
cd backend
npm install
node scripts/seed.js
```

Or manually insert users into Supabase with the `users` table form.

**Demo credentials:**
| Email | Password | Role |
|---|---|---|
| student@secureid.edu | student123 | Student |
| teacher@secureid.edu | teacher123 | Teacher |
| admin@secureid.edu   | admin123   | Admin |

### 5. Start the server

```bash
cd backend
npm start
```

Server starts at `http://localhost:3000`

### 6. Open the app

| Interface | URL |
|---|---|
| 🎓 User Dashboard | http://localhost:3000 |
| 📷 Scanner Device | http://localhost:3000/scanner |

---

## Project Structure

```
Secure-ID/
├── .env.example              ← Environment variable template
├── .gitignore
├── README.md
│
├── backend/
│   ├── server.js             ← Express app, routing, middleware
│   ├── supabaseClient.js     ← Supabase client (service role)
│   ├── package.json
│   │
│   ├── routes/
│   │   ├── auth.js           ← POST /login, GET /qr-token, GET /me
│   │   └── verify.js         ← POST /scan, GET /logs
│   │
│   └── services/
│       ├── tokenService.js   ← HMAC token generation + verification
│       └── encryptionService.js  ← AES-256-GCM encrypt/decrypt
│
├── frontend/
│   ├── index.html            ← Landing page
│   ├── login.html            ← Login form
│   ├── dashboard.html        ← QR display + countdown timer
│   ├── style.css             ← Global styles
│   └── app.js                ← Frontend API client (SecureID object)
│
├── scanner/
│   ├── scanner.html          ← Scanner UI
│   ├── scanner.js            ← Camera + jsQR + verify logic
│   └── scanner.css           ← Scanner styles
│
└── docs/
    ├── schema.sql            ← Supabase table definitions
    └── architecture.md       ← System architecture + diagrams
```

---

## Security Architecture

### Token Generation
```
interval = floor(unix_timestamp / 30)
payload  = { uid, t: interval, sig: HMAC-SHA256(secretKey, uid:interval) }
qrData   = AES-256-GCM-Encrypt(payload)  →  shown as QR code
```

### Verification (Server-side)
1. **Decrypt** AES payload (tampered = DENY)
2. **Fetch** user's `secret_key` from database
3. **Verify** HMAC signature (mismatch = DENY)
4. **Check** timestamp: `|now_interval - t| ≤ 1` (expired = DENY)
5. **Check** `token_hash` in `access_logs` (already used = DENY)
6. **Log** token hash and return **ALLOW** ✅

### Security Features
| Feature | Implementation |
|---|---|
| Time-based tokens | 30-second interval index |
| Cryptographic signing | HMAC-SHA256 per user |
| Payload encryption | AES-256-GCM |
| Replay prevention | SHA-256 token hash in DB |
| Timing attack safety | `crypto.timingSafeEqual()` |
| Brute force protection | Rate limiting (10 logins/15min) |
| Key isolation | Secret keys never leave backend |

---

## API Reference

### Auth

```
POST /api/auth/login
Body: { email, password }
Response: { token, user: { id, name, email, role, department } }

GET /api/auth/qr-token   [Authorization: Bearer <token>]
Response: { qrData, secondsRemaining }

GET /api/auth/me         [Authorization: Bearer <token>]
Response: { user }
```

### Verify

```
POST /api/verify/scan
Body: { qrData, scannerId? }
Response: { result: "ALLOW"|"DENY", reason?, user? }

GET /api/verify/logs?limit=20
Response: { logs: [...] }
```

---

## Production Notes

- Move scanner interface to a **private network** — it should only be accessible by security personnel
- Add `HTTPS` — required for camera access on mobile browsers
- Set `NODE_ENV=production` — enables stricter error handling
- Use a **reverse proxy** (nginx/Caddy) in front of the Node server
- Rotate `JWT_SECRET` and `ENCRYPTION_SECRET` periodically

---

## License

MIT
