/**
 * scripts/seed.js
 * Run this ONCE to create demo users in your Supabase database.
 *
 * Usage:
 *   cd backend
 *   node scripts/seed.js
 *
 * Make sure your .env file is configured first!
 */

require('dotenv').config({ path: require('path').join(__dirname, '../.env') });

const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const DEMO_USERS = [
  {
    name:       'Alex Johnson',
    email:      'student@secureid.edu',
    password:   'student123',
    role:       'student',
    department: 'Computer Science'
  },
  {
    name:       'Dr. Sarah Chen',
    email:      'teacher@secureid.edu',
    password:   'teacher123',
    role:       'teacher',
    department: 'Engineering'
  },
  {
    name:       'Marcus Williams',
    email:      'admin@secureid.edu',
    password:   'admin123',
    role:       'admin',
    department: 'Administration'
  }
];

async function seed() {
  console.log('\n🌱 Seeding Secure ID demo users...\n');

  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
    console.error('❌ Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in .env');
    process.exit(1);
  }

  for (const user of DEMO_USERS) {
    // Check if user already exists
    const { data: existing } = await supabase
      .from('users')
      .select('id')
      .eq('email', user.email)
      .single();

    if (existing) {
      console.log(`⏭  Skipping ${user.email} (already exists)`);
      continue;
    }

    // Hash password
    const password_hash = await bcrypt.hash(user.password, 10);

    // Generate unique HMAC secret key for this user
    const secret_key = crypto.randomBytes(32).toString('hex');

    // Insert into Supabase
    const { error } = await supabase.from('users').insert({
      name:          user.name,
      email:         user.email,
      password_hash,
      role:          user.role,
      department:    user.department,
      secret_key
    });

    if (error) {
      console.error(`❌ Failed to create ${user.email}:`, error.message);
    } else {
      console.log(`✅ Created ${user.role}: ${user.email} / ${user.password}`);
    }
  }

  console.log('\n✨ Seeding complete!\n');
  console.log('Demo accounts:');
  console.log('  📧 student@secureid.edu  /  student123');
  console.log('  📧 teacher@secureid.edu  /  teacher123');
  console.log('  📧 admin@secureid.edu    /  admin123\n');
}

seed().catch(console.error);
