require('dotenv').config();
const { Pool } = require('pg');

// Grab connection string from database (Port: 5432 direct / 6543 pooler)
const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
  console.error("CRITICAL CONFIG ERROR: DATABASE_URL variable is missing in .env! Database connectivity will crash.");
}

const pool = new Pool({
  connectionString: connectionString,
  // Database connections over SSL are mandatory natively
  ssl: { rejectUnauthorized: false },
  max: 10,                  // Optimal concurrent pool limits for hosting targets
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Set search_path to piggybag schema on every new pool connection
pool.on('connect', (client) => {
  client.query('SET search_path TO piggybag');
});

// Seed defaults cleanly inside database
async function seedDefaultCategories() {
  const client = await pool.connect();
  try {
    // Explicitly set schema for this client session (avoids race with on('connect'))
    await client.query('SET search_path TO piggybag');
    const checkCategories = await client.query('SELECT id FROM categories WHERE is_default = true LIMIT 1');
    if (checkCategories.rows.length === 0) {
      console.log("Seeding base global default categories into database...");
      const defaultCategories = [
        ['Food',     'expense', 'restaurant',    '#EAF2F8', true, 1],
        ['Travel',   'expense', 'flight',         '#FDEDEC', true, 2],
        ['Salary',   'income',  'payments',        '#B9FBC0', true, 3],
        ['Shopping', 'expense', 'checkroom',       '#FFC6FF', true, 4],
        ['Bills',    'expense', 'receipt_long',    '#FFDFBA', true, 5]
      ];
      for (const cat of defaultCategories) {
        await client.query(
          'INSERT INTO categories (name, type, icon, color, is_default, order_index) VALUES ($1, $2, $3, $4, $5, $6)',
          cat
        );
      }
    }
  } catch (err) {
    console.error("Error patching category records seed metadata:", err);
  } finally {
    client.release();
  }
}

// Migration helper: Ensure 'journals' table has 'type' column (income/expense)
async function ensureTypeColumn() {
  const client = await pool.connect();
  try {
    // Explicitly set schema for this client session
    await client.query('SET search_path TO piggybag');
    const res = await client.query(`
      SELECT column_name
      FROM information_schema.columns
      WHERE table_name = 'journals' AND column_name = 'type'
    `);
    if (res.rows.length === 0) {
      console.log("Migration: Adding 'type' column to 'journals' table...");
      await client.query("ALTER TABLE journals ADD COLUMN type VARCHAR(20) DEFAULT 'expense'");
      console.log("Migration: 'type' column added successfully.");
    }
  } catch (err) {
    // If table doesn't exist yet, it's fine, it will be handled when sync is called
    if (err.code !== '42P01') {
      console.error("Migration error (ensureTypeColumn):", err);
    }
  } finally {
    client.release();
  }
}

// Migration helper: Ensure group splits columns exist
async function ensureGroupSplitColumns() {
  const client = await pool.connect();
  try {
    await client.query('SET search_path TO piggybag');
    
    // Add group_pin to expense_groups
    await client.query(`ALTER TABLE expense_groups ADD COLUMN IF NOT EXISTS group_pin VARCHAR(50)`);
    
    // Add display_name to expense_group_members
    await client.query(`ALTER TABLE expense_group_members ADD COLUMN IF NOT EXISTS display_name VARCHAR(255)`);
    
    // Add split_type, participants_included, shares to expenses
    await client.query(`ALTER TABLE expenses ADD COLUMN IF NOT EXISTS split_type VARCHAR(50) DEFAULT 'Equal'`);
    await client.query(`ALTER TABLE expenses ADD COLUMN IF NOT EXISTS participants_included TEXT`);
    await client.query(`ALTER TABLE expenses ADD COLUMN IF NOT EXISTS shares TEXT`);
    
    // Add status, from_user_name, to_user_name to settlements
    await client.query(`ALTER TABLE settlements ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'Pending'`);
    await client.query(`ALTER TABLE settlements ADD COLUMN IF NOT EXISTS from_user_name VARCHAR(255)`);
    await client.query(`ALTER TABLE settlements ADD COLUMN IF NOT EXISTS to_user_name VARCHAR(255)`);
    
    console.log("Migration: Group split columns verified/added successfully.");
  } catch (err) {
    console.error("Migration error (ensureGroupSplitColumns):", err);
  } finally {
    client.release();
  }
}

module.exports = {
  pool,
  seedDefaultCategories,
  ensureTypeColumn,
  ensureGroupSplitColumns
};