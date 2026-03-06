-- ══════════════════════════════════════════════════════════════════════════
-- Secure ID — Supabase Database Schema
-- Run this SQL in your Supabase project: SQL Editor → New Query → Run
-- ══════════════════════════════════════════════════════════════════════════

-- ── Enable UUID generation ────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── Users Table ───────────────────────────────────────────────────────────
-- Stores campus members (students, teachers, admins).
-- Each user has a unique HMAC secret_key for token generation.

CREATE TABLE IF NOT EXISTS users (
  id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  name          TEXT        NOT NULL,
  email         TEXT        UNIQUE NOT NULL,
  password_hash TEXT        NOT NULL,                    -- bcrypt hash
  role          TEXT        NOT NULL DEFAULT 'student'
                            CHECK (role IN ('student', 'teacher', 'admin')),
  department    TEXT,
  secret_key    TEXT        NOT NULL,                    -- HMAC secret (hex, 64 chars)
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for fast login lookups
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- ── Access Logs Table ──────────────────────────────────────────────────────
-- Records every QR scan attempt.
-- token_hash is used for replay attack prevention.

CREATE TABLE IF NOT EXISTS access_logs (
  id          BIGSERIAL   PRIMARY KEY,
  user_id     UUID        REFERENCES users(id) ON DELETE SET NULL,
  token_hash  TEXT,                                      -- SHA-256 hash of (sig:interval)
  result      TEXT        NOT NULL
              CHECK (result IN ('allow', 'deny')),
  reason      TEXT,                                      -- Reason for denial
  scanner_id  TEXT        DEFAULT 'unknown',             -- Which scanner device
  timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for fast replay detection and log queries
CREATE INDEX IF NOT EXISTS idx_logs_token_hash ON access_logs(token_hash);
CREATE INDEX IF NOT EXISTS idx_logs_user_id    ON access_logs(user_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_timestamp  ON access_logs(timestamp DESC);

-- ── Row Level Security ─────────────────────────────────────────────────────
-- The backend uses the service role key which bypasses RLS.
-- These policies protect the anon key from direct access.

ALTER TABLE users       ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_logs ENABLE ROW LEVEL SECURITY;

-- Block all direct access from anonymous/frontend clients
-- (All access goes through the backend API with the service role key)
CREATE POLICY "No direct anon access to users"
  ON users FOR ALL TO anon USING (false);

CREATE POLICY "No direct anon access to logs"
  ON access_logs FOR ALL TO anon USING (false);

-- ── Demo Users (optional) ──────────────────────────────────────────────────
-- Uncomment to seed demo users directly in Supabase.
-- Passwords are bcrypt hashes of: student123, teacher123, admin123
-- Generate fresh hashes with: node -e "const b=require('bcrypt'); b.hash('student123',10).then(console.log)"

/*
INSERT INTO users (name, email, password_hash, role, department, secret_key) VALUES
(
  'Alex Johnson',
  'student@secureid.edu',
  '$2b$10$REPLACE_WITH_REAL_BCRYPT_HASH',
  'student',
  'Computer Science',
  encode(gen_random_bytes(32), 'hex')
),
(
  'Dr. Sarah Chen',
  'teacher@secureid.edu',
  '$2b$10$REPLACE_WITH_REAL_BCRYPT_HASH',
  'teacher',
  'Engineering',
  encode(gen_random_bytes(32), 'hex')
),
(
  'Marcus Williams',
  'admin@secureid.edu',
  '$2b$10$REPLACE_WITH_REAL_BCRYPT_HASH',
  'admin',
  'Administration',
  encode(gen_random_bytes(32), 'hex')
);
*/
