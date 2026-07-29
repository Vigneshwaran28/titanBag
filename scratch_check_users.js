const { pool, seedDefaultCategories } = require('./db');
const bcrypt = require('bcryptjs');

function getPartnerShareCode(userId) {
  if (!userId) return '';
  const cleanUuid = userId.replace(/-/g, '').toUpperCase();
  const p1 = cleanUuid.substring(0, 4);
  const p2 = cleanUuid.substring(4, 8);
  const p3 = cleanUuid.substring(8, 12);
  const p4 = cleanUuid.substring(12, 16);
  return `PB-${p1}-${p2}-${p3}-${p4}`;
}

async function testRegistrationAndDb() {
  const client = await pool.connect();
  try {
    await client.query('SET search_path TO piggybag');
    console.log("Connected to PostgreSQL database successfully.");

    // Test insertion
    const testUsername = `testuser_${Date.now()}`;
    const testEmail = `test_${Date.now()}@example.com`;
    const passwordHash = await bcrypt.hash("password123", 10);
    const timestamp = new Date();

    const result = await client.query(
      `INSERT INTO users (username, email, display_name, password_hash, created_at, updated_at, last_login)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING user_id, username, email, display_name, created_at, updated_at`,
      [testUsername, testEmail, 'Test User', passwordHash, timestamp, timestamp, timestamp]
    );

    console.log("=== SUCCESSFULLY INSERTED USER ROW ===");
    console.log(result.rows[0]);
    console.log("Generated Partner Share Code:", getPartnerShareCode(result.rows[0].user_id));

    const checkAll = await client.query('SELECT user_id, username, email, display_name FROM users ORDER BY created_at DESC');
    console.log("\n=== CURRENT ALL USERS IN DATABASE ===");
    console.log(checkAll.rows);

  } catch (err) {
    console.error("Database Test Error:", err);
  } finally {
    client.release();
    await pool.end();
  }
}

testRegistrationAndDb();
