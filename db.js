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

module.exports = {
  pool,
  seedDefaultCategories
};