/**
 * supabaseClient.js
 * Initializes the Supabase client using the SERVICE ROLE KEY.
 * This file is for backend use ONLY — never expose the service role key to the frontend.
 */

const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  throw new Error(
    '[Supabase] Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in environment variables.\n' +
    'Copy .env.example to .env and fill in your credentials.'
  );
}

// Use service role key on the backend — bypasses Row Level Security (RLS)
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: {
    autoRefreshToken: false,
    persistSession: false
  }
});

module.exports = supabase;
