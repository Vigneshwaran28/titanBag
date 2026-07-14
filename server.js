require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { pool, initializeDatabase } = require('./db');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  throw new Error("JWT_SECRET environment variable is not defined.");
}

app.use(cors());
app.use(express.json());

// Helper: Generate invitation share code
function generatePartnerCode() {
  const uuid = crypto.randomUUID();
  const hash = crypto.createHash('sha256').update(uuid).digest('hex').toUpperCase();
  const p1 = hash.substring(0, 4);
  const p2 = hash.substring(4, 8);
  const p3 = hash.substring(8, 12);
  const p4 = hash.substring(12, 16);
  return `EXP-${p1}-${p2}-${p3}-${p4}`;
}

// Authentication Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: "Access token required" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid or expired token" });
    }
    req.user = user;
    next();
  });
}

// Endpoint: POST /register
app.post('/register', async (req, res) => {
  const { username, email, password, display_name } = req.body;

  if (!username || !email || !password || !display_name) {
    return res.status(400).json({ message: "All fields are required" });
  }

  if (password.length < 8) {
    return res.status(400).json({ message: "Password must be at least 8 characters long" });
  }

  try {
    // Check if user already exists
    const duplicateCheck = await pool.query(
      "SELECT id FROM users WHERE username = $1 OR email = $2",
      [username.trim().toLowerCase(), email.trim().toLowerCase()]
    );

    if (duplicateCheck.rows.length > 0) {
      return res.status(400).json({ message: "Username or Email already registered" });
    }

    const userId = crypto.randomUUID();
    const passwordHash = await bcrypt.hash(password, 10);
    const partnerShareCode = generatePartnerCode();
    const timestamp = new Date();

    const result = await pool.query(
      `INSERT INTO users (id, username, email, display_name, password_hash, partner_share_code, created_at, updated_at, last_login)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id, username, email, display_name, partner_share_code, created_at, updated_at`,
      [userId, username.trim().toLowerCase(), email.trim().toLowerCase(), display_name.trim(), passwordHash, partnerShareCode, timestamp, timestamp, timestamp]
    );

    const newUser = result.rows[0];
    const token = jwt.sign({ id: newUser.id, username: newUser.username }, JWT_SECRET, { expiresIn: '30d' });

    res.status(201).json({
      token,
      user: {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email,
        display_name: newUser.display_name,
        partner_share_code: newUser.partner_share_code,
        created_at: newUser.created_at,
        updated_at: newUser.updated_at
      }
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error during registration" });
  }
});

// Endpoint: POST /login
app.post('/login', async (req, res) => {
  const { identifier, password } = req.body;

  if (!identifier || !password) {
    return res.status(400).json({ message: "Identifier and password required" });
  }

  try {
    const userResult = await pool.query(
      "SELECT * FROM users WHERE username = $1 OR email = $2",
      [identifier.trim().toLowerCase(), identifier.trim().toLowerCase()]
    );

    if (userResult.rows.length === 0) {
      return res.status(400).json({ message: "Invalid username/email or password" });
    }

    const user = userResult.rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password_hash);

    if (!isPasswordValid) {
      return res.status(400).json({ message: "Invalid username/email or password" });
    }

    // Update last login
    const timestamp = new Date();
    await pool.query("UPDATE users SET last_login = $1 WHERE id = $2", [timestamp, user.id]);

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });

    res.status(200).json({
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        display_name: user.display_name,
        partner_share_code: user.partner_share_code,
        created_at: user.created_at,
        updated_at: user.updated_at,
        last_login: timestamp
      }
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error during login" });
  }
});

// Endpoint: GET /profile
app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const userResult = await pool.query("SELECT id, username, email, display_name, partner_share_code, created_at, updated_at, last_login FROM users WHERE id = $1", [req.user.id]);

    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const user = userResult.rows[0];

    // Check for active partner
    const partnerResult = await pool.query(
      `SELECT p.*, 
              u.display_name as partner_display_name, 
              u.username as partner_username
       FROM partners p
       JOIN users u ON (u.id = p.user_one_id OR u.id = p.user_two_id) AND u.id != $1
       WHERE (p.user_one_id = $1 OR p.user_two_id = $1) AND p.status = 'active'
       LIMIT 1`,
      [req.user.id]
    );

    const partner = partnerResult.rows.length > 0 ? partnerResult.rows[0] : null;

    res.status(200).json({
      user,
      partner
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error fetching profile" });
  }
});

// Endpoint: POST /partner/connect
app.post('/partner/connect', authenticateToken, async (req, res) => {
  const { partner_code } = req.body;

  if (!partner_code) {
    return res.status(400).json({ message: "Partner share code required" });
  }

  try {
    // 1. Find user by share code
    const targetResult = await pool.query("SELECT id, display_name FROM users WHERE partner_share_code = $1", [partner_code.trim()]);
    if (targetResult.rows.length === 0) {
      return res.status(404).json({ message: "Invalid share code. Partner not found." });
    }

    const partnerUser = targetResult.rows[0];

    if (partnerUser.id === req.user.id) {
      return res.status(400).json({ message: "You cannot connect with your own share code" });
    }

    // 2. Check if already connected
    const activeLink = await pool.query(
      "SELECT id FROM partners WHERE (user_one_id = $1 OR user_two_id = $1) AND status = 'active'",
      [req.user.id]
    );

    if (activeLink.rows.length > 0) {
      return res.status(400).json({ message: "You are already connected to a partner. Disconnect first." });
    }

    const partnerActiveLink = await pool.query(
      "SELECT id FROM partners WHERE (user_one_id = $1 OR user_two_id = $1) AND status = 'active'",
      [partnerUser.id]
    );

    if (partnerActiveLink.rows.length > 0) {
      return res.status(400).json({ message: "The partner is already linked with someone else." });
    }

    // 3. Create active link
    const partnerId = crypto.randomUUID();
    const timestamp = new Date();

    await pool.query(
      "INSERT INTO partners (id, user_one_id, user_two_id, connected_at, status) VALUES ($1, $2, $3, $4, 'active')",
      [partnerId, req.user.id, partnerUser.id, timestamp]
    );

    res.status(200).json({ success: true, message: `Connected successfully with ${partnerUser.display_name}!` });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error linking partner" });
  }
});

// Endpoint: DELETE /partner/disconnect
app.delete('/partner/disconnect', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      "UPDATE partners SET status = 'disconnected' WHERE (user_one_id = $1 OR user_two_id = $1) AND status = 'active'",
      [req.user.id]
    );

    if (result.rowCount === 0) {
      return res.status(400).json({ message: "No active partner connection found" });
    }

    res.status(200).json({ success: true, message: "Partner disconnected successfully. Data is no longer shared." });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error disconnecting partner" });
  }
});

// Endpoint: POST /sync
app.post('/sync', authenticateToken, async (req, res) => {
  const { journals } = req.body;

  if (!Array.isArray(journals)) {
    return res.status(400).json({ message: "Journals array expected" });
  }

  const client = await pool.connect();
  const syncedIds = [];

  try {
    await client.query('BEGIN');

    // 1. Process local updates from client
    for (const jr of journals) {
      // Fetch existing record on server
      const existingRes = await client.query("SELECT updated_at, deleted FROM journals WHERE id = $1", [jr.id]);

      if (existingRes.rows.length === 0) {
        // Insert new journal if not marked deleted on client
        if (!jr.deleted) {
          await client.query(
            `INSERT INTO journals (id, owner_id, title, amount, category, notes, payment_method, date, created_at, updated_at, deleted)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
            [jr.id, req.user.id, jr.title, jr.amount, jr.category, jr.notes, jr.payment_method, jr.date, jr.created_at, jr.updated_at, jr.deleted]
          );
        }
        syncedIds.push(jr.id);
      } else {
        const existing = existingRes.rows[0];

        // Conflict resolution: newer updatedAt wins
        const incomingTime = new Date(jr.updated_at).getTime();
        const existingTime = new Date(existing.updated_at).getTime();

        if (incomingTime >= existingTime) {
          // Client is newer or equal, update server
          await client.query(
            `UPDATE journals 
             SET title = $1, amount = $2, category = $3, notes = $4, payment_method = $5, date = $6, updated_at = $7, deleted = $8
             WHERE id = $9`,
            [jr.title, jr.amount, jr.category, jr.notes, jr.payment_method, jr.date, jr.updated_at, jr.deleted, jr.id]
          );
          syncedIds.push(jr.id);
        } else {
          // Server is newer. Client will be updated in step 2.
          syncedIds.push(jr.id);
        }
      }
    }

    await client.query('COMMIT');

    // 2. Fetch all active journals (User's own journals + Partner's journals)
    // Find partner first
    const partnerRes = await client.query(
      `SELECT user_one_id, user_two_id FROM partners 
       WHERE (user_one_id = $1 OR user_two_id = $1) AND status = 'active' LIMIT 1`,
      [req.user.id]
    );

    let partnerId = null;
    if (partnerRes.rows.length > 0) {
      const p = partnerRes.rows[0];
      partnerId = p.user_one_id === req.user.id ? p.user_two_id : p.user_one_id;
    }

    const idsToFetch = [req.user.id];
    if (partnerId) {
      idsToFetch.push(partnerId);
    }

    const journalsResult = await client.query(
      `SELECT id, owner_id, title, amount, category, notes, payment_method, date, created_at, updated_at, deleted 
       FROM journals 
       WHERE owner_id = ANY($1::uuid[])`,
      [idsToFetch]
    );

    const remoteJournals = journalsResult.rows.map(row => ({
      id: row.id,
      owner_id: row.owner_id,
      title: row.title,
      amount: parseFloat(row.amount),
      category: row.category,
      notes: row.notes || "",
      payment_method: row.payment_method || "",
      date: row.date.toISOString(),
      created_at: row.created_at.toISOString(),
      updated_at: row.updated_at.toISOString(),
      deleted: row.deleted
    }));

    res.status(200).json({
      synced_ids: syncedIds,
      remote_journals: remoteJournals
    });

  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ message: "Server error during synchronization" });
  } finally {
    client.release();
  }
});

// App initialization
initializeDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`TitanBag Sync server is running on port ${PORT}`);
    });
  })
  .catch(err => {
    console.error("Failed to start server due to database initialization error:", err);
    process.exit(1);
  });

app.get("/", (req, res) => {
  res.json({
    status: "OK",
    message: "Expenso Backend is running"
  });
});