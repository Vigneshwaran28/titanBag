require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const os = require('os');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { OAuth2Client } = require('google-auth-library');
const { Resend } = require('resend');
const { pool, initializeDatabase } = require('./db');

const resend = new Resend('re_ejSGebMb_9NWuzS6BuCpXtDBkNtqWhVdx');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

if (!JWT_SECRET) {
  console.warn("WARNING: JWT_SECRET environment variable is not defined. Using insecure fallback secret.");
}

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// Helper: Get Client IP
function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
}

// Endpoint: POST /login/google
app.post('/login/google', async (req, res) => {
  const { id_token, device_model, device_manufacturer } = req.body;

  if (!id_token) {
    return res.status(400).json({ message: "Google ID token required" });
  }

  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: id_token,
      audience: GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const email = payload.email;
    const name = payload.name;
    const googleId = payload.sub;
    const ipAddress = getClientIp(req);
    // Simple location placeholder (would usually need a GeoIP service)
    const location = req.headers['x-vercel-ip-city'] || req.headers['cf-ipcity'] || 'Unknown';

    // Check if user exists by email
    let userResult = await pool.query("SELECT * FROM users WHERE email = $1", [email.toLowerCase()]);
    let user;

    if (userResult.rows.length === 0) {
      // Auto-register new Google user
      const userId = crypto.randomUUID();
      const username = `google_${googleId.substring(0, 8)}`;
      const partnerShareCode = generatePartnerCode();
      const timestamp = new Date();

      const insertResult = await pool.query(
        `INSERT INTO users (id, username, email, display_name, password_hash, partner_share_code, ip_address, location, device_model, device_manufacturer, created_at, updated_at, last_login)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING id, username, email, display_name, partner_share_code, created_at, updated_at`,
        [userId, username, email.toLowerCase(), name, 'GOOGLE_AUTH_EXTERNAL', partnerShareCode, ipAddress, location, device_model, device_manufacturer, timestamp, timestamp, timestamp]
      );
      user = insertResult.rows[0];
    } else {
      user = userResult.rows[0];
      // Update last login and device info
      const timestamp = new Date();
      await pool.query(
        "UPDATE users SET last_login = $1, ip_address = $2, location = $3, device_model = $4, device_manufacturer = $5 WHERE id = $6",
        [timestamp, ipAddress, location, device_model, device_manufacturer, user.id]
      );
    }

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET || 'fallback', { expiresIn: '30d' });

    res.status(200).json({
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        display_name: user.display_name,
        partner_share_code: user.partner_share_code,
        created_at: user.created_at,
        updated_at: user.updated_at
      }
    });

  } catch (err) {
    console.error("Google Login Error:", err);
    res.status(401).json({ message: "Invalid Google ID token" });
  }
});

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

// Admin Authentication Middleware (God User)
function authenticateGodToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: "Admin access token required" });
  }

  jwt.verify(token, JWT_SECRET || 'fallback', (err, decoded) => {
    if (err || decoded.role !== 'god') {
      return res.status(403).json({ message: "Forbidden: Admin access only" });
    }
    req.godUser = decoded;
    next();
  });
}

// Endpoint: POST /register
app.post('/register', async (req, res) => {
  const { username, email, password, display_name, device_model, device_manufacturer } = req.body;

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
    const ipAddress = getClientIp(req);
    const location = req.headers['x-vercel-ip-city'] || req.headers['cf-ipcity'] || 'Unknown';

    const result = await pool.query(
      `INSERT INTO users (id, username, email, display_name, password_hash, partner_share_code, ip_address, location, device_model, device_manufacturer, created_at, updated_at, last_login)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING id, username, email, display_name, partner_share_code, created_at, updated_at`,
      [userId, username.trim().toLowerCase(), email.trim().toLowerCase(), display_name.trim(), passwordHash, partnerShareCode, ipAddress, location, device_model, device_manufacturer, timestamp, timestamp, timestamp]
    );

    const newUser = result.rows[0];
    const token = jwt.sign({ id: newUser.id, username: newUser.username }, JWT_SECRET || 'fallback', { expiresIn: '30d' });

    // HTML Welcome Page Layout
    const welcomeHtml = `
      <div style="background-color: #07090e; color: #f3f4f6; font-family: 'Inter', Helvetica, Arial, sans-serif; padding: 40px 20px; text-align: center; border-radius: 12px; max-width: 600px; margin: 0 auto; border: 1px solid #1e2633;">
        <div style="background: linear-gradient(135deg, #6366f1, #8b5cf6); width: 50px; height: 50px; border-radius: 12px; display: inline-flex; align-items: center; justify-content: center; margin-bottom: 20px; box-shadow: 0 4px 12px rgba(99, 102, 241, 0.3); margin: 0 auto;">
          <span style="font-size: 24px; color: white; font-weight: bold; line-height: 50px; display: block; text-align: center; width: 100%;">T</span>
        </div>
        <h1 style="font-size: 26px; font-weight: 800; margin-bottom: 10px; color: #a5b4fc;">Welcome to TitanBag!</h1>
        <p style="color: #9ca3af; font-size: 15px; line-height: 1.6; margin-bottom: 30px;">
          Hi ${newUser.display_name}, your offline-first personal wallet synchronization portal is ready. Easily manage and sync your expense journals securely.
        </p>
        <div style="background-color: #0f131a; border: 1px solid #1e2633; border-radius: 10px; padding: 20px; margin-bottom: 30px; text-align: left;">
          <h3 style="color: #f3f4f6; margin-top: 0; font-size: 14px; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid #1e2633; padding-bottom: 10px; margin-bottom: 15px;">Your Connection Details</h3>
          <div style="margin-bottom: 10px; font-size: 14px;">
            <span style="color: #9ca3af;">Username:</span>
            <strong style="color: #f3f4f6; float: right;">@${newUser.username}</strong>
          </div>
          <div style="font-size: 14px;">
            <span style="color: #9ca3af;">Invitation Share Code:</span>
            <strong style="color: #818cf8; font-family: monospace; float: right;">${newUser.partner_share_code}</strong>
          </div>
          <div style="clear: both;"></div>
        </div>
        <div style="background-color: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.3); color: #fb7185; padding: 15px 20px; border-radius: 10px; font-size: 13px; text-align: left; line-height: 1.5; margin-bottom: 30px;">
          <strong style="display: block; margin-bottom: 5px;">⚠️ SECURITY WARNING</strong>
          Connecting with a partner using your invitation code allows them to view, edit, and automatically synchronize your personal expense journals. Only share this code with trusted partners.
        </div>
        <div style="margin-top: 30px; border-top: 1px solid #1e2633; padding-top: 20px; color: #6b7280; font-size: 12px;">
          TitanBag Secure Cloud Systems. Powered by Node.js & Neon Serverless PostgreSQL.
        </div>
      </div>
    `;

    // Asynchronously send onboarding welcome email via Resend (non-blocking)
    resend.emails.send({
      from: 'onboarding@resend.dev',
      to: newUser.email,
      subject: 'Welcome to TitanBag! 🎒',
      html: welcomeHtml
    }).then(emailRes => {
      console.log('Welcome email dispatched successfully:', emailRes);
    }).catch(emailErr => {
      console.error('Welcome email dispatch failed:', emailErr);
    });

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
  const { identifier, password, device_model, device_manufacturer } = req.body;

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

    // Update last login and device info
    const timestamp = new Date();
    const ipAddress = getClientIp(req);
    const location = req.headers['x-vercel-ip-city'] || req.headers['cf-ipcity'] || 'Unknown';

    await pool.query(
      "UPDATE users SET last_login = $1, ip_address = $2, location = $3, device_model = $4, device_manufacturer = $5 WHERE id = $6",
      [timestamp, ipAddress, location, device_model, device_manufacturer, user.id]
    );

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET || 'fallback', { expiresIn: '30d' });

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

// Endpoint: POST /api/auth/forgot-password
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ message: "Email is required" });
  }

  try {
    const userResult = await pool.query("SELECT id, display_name FROM users WHERE email = $1", [email.trim().toLowerCase()]);
    if (userResult.rows.length === 0) {
      // For security, do not leak whether email exists. Send success.
      return res.status(200).json({ message: "If that email exists, we have sent a link to reset your password." });
    }

    const user = userResult.rows[0];
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    await pool.query(
      'INSERT INTO password_resets (user_id, token, expires_at) VALUES ($1, $2, $3)',
      [user.id, token, expiresAt]
    );

    const protocol = req.headers['x-forwarded-proto'] || req.protocol;
    const host = req.get('host');
    const resetLink = `${protocol}://${host}/reset-password?token=${token}`;

    const resetHtml = `
      <div style="background-color: #07090e; color: #f3f4f6; font-family: 'Inter', Helvetica, Arial, sans-serif; padding: 40px 20px; text-align: center; border-radius: 12px; max-width: 600px; margin: 0 auto; border: 1px solid #1e2633;">
        <h2 style="font-size: 22px; font-weight: 700; color: #a5b4fc; margin-bottom: 15px;">Reset Your Password</h2>
        <p style="color: #9ca3af; font-size: 15px; line-height: 1.6; margin-bottom: 25px;">
          Hi ${user.display_name}, you requested a password reset for your TitanBag account. Click the button below to update your password. This link is active for <strong>10 minutes</strong> and will expire immediately after use.
        </p>
        <div style="margin: 25px 0;">
          <a href="${resetLink}" style="background: linear-gradient(135deg, #6366f1, #8b5cf6); color: white; text-decoration: none; padding: 12px 24px; border-radius: 8px; font-weight: 600; display: inline-block; box-shadow: 0 4px 12px rgba(99, 102, 241, 0.25);">Reset Password</a>
        </div>
        <p style="color: #6b7280; font-size: 12px; margin-top: 20px;">
          If you did not request this, you can safely ignore this email. Your password will remain unchanged.
        </p>
      </div>
    `;

    // Asynchronously send reset email
    resend.emails.send({
      from: 'onboarding@resend.dev',
      to: email.trim().toLowerCase(),
      subject: 'Reset your TitanBag Password 🔒',
      html: resetHtml
    }).then(emailRes => {
      console.log('Reset email dispatched successfully:', emailRes);
    }).catch(emailErr => {
      console.error('Reset email dispatch failed:', emailErr);
    });

    res.status(200).json({ message: "If that email exists, we have sent a link to reset your password." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error during password reset request" });
  }
});

// Endpoint: POST /api/auth/reset-password
app.post('/api/auth/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) {
    return res.status(400).json({ message: "Token and password are required" });
  }

  if (password.length < 8) {
    return res.status(400).json({ message: "Password must be at least 8 characters long" });
  }

  try {
    // Look up token
    const resetResult = await pool.query(
      'SELECT * FROM password_resets WHERE token = $1 AND expires_at > NOW() AND used = false',
      [token]
    );

    if (resetResult.rows.length === 0) {
      return res.status(400).json({ message: "Invalid or expired password reset link" });
    }

    const resetRequest = resetResult.rows[0];
    const passwordHash = await bcrypt.hash(password, 10);

    // Update password
    await pool.query('UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2', [passwordHash, resetRequest.user_id]);
    
    // Mark token as used
    await pool.query('UPDATE password_resets SET used = true WHERE id = $3', [resetRequest.id]);

    res.status(200).json({ message: "Password reset successfully. You can now log in." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error resetting password" });
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
if (process.env.DATABASE_URL) {
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
} else {
  console.warn("WARNING: DATABASE_URL not defined. Running in Demo/Development mode (no DB connections).");
  app.listen(PORT, () => {
    console.log(`TitanBag Sync server is running on port ${PORT} (Demo Mode)`);
  });
}

app.get("/api/info", (req, res) => {
  res.json({
    status: "OK",
    uptime: Math.floor(process.uptime()),
    node_version: process.version,
    platform: `${os.platform()} (${os.arch()})`,
    memory: {
      free: `${Math.floor(os.freemem() / 1024 / 1024)} MB`,
      total: `${Math.floor(os.totalmem() / 1024 / 1024)} MB`
    },
    database: process.env.DATABASE_URL ? "Connected (Neon)" : "Demo Mode (Disconnected)"
  });
});

app.post('/api/god/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: "Username and password required" });
  }
  try {
    if (!process.env.DATABASE_URL) {
      // Demo mode fallback authentication
      if (username === 'admin' && password === '00000000-0000-0000-0000-000000000000') {
        const token = jwt.sign({ id: 'demo-admin-id', username: 'admin', role: 'god' }, JWT_SECRET || 'fallback', { expiresIn: '1d' });
        return res.json({ token });
      } else {
        return res.status(401).json({ message: "Invalid admin credentials (Demo Mode: use admin/00000000-0000-0000-0000-000000000000)" });
      }
    }

    const result = await pool.query('SELECT * FROM "godUser" WHERE "super_user" = $1', [username.trim()]);
    if (result.rows.length === 0) {
      return res.status(401).json({ message: "Invalid admin credentials" });
    }
    const god = result.rows[0];
    
    // UUID comparison as string equality (direct text auth check)
    const passwordMatch = password.trim().toLowerCase() === String(god.authenticate).toLowerCase();
    if (!passwordMatch) {
      return res.status(401).json({ message: "Invalid admin credentials" });
    }

    const token = jwt.sign({ id: god.id, username: god.super_user, role: 'god' }, JWT_SECRET || 'fallback', { expiresIn: '1d' });
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error during admin authentication" });
  }
});

app.get('/api/god/users', authenticateGodToken, async (req, res) => {
  try {
    if (!process.env.DATABASE_URL) {
      // Return mock users in demo mode
      return res.json({
        users: [
          { username: "john_doe", device_model: "iPhone 15 Pro", device_manufacturer: "Apple", updated_at: new Date().toISOString() },
          { username: "alice_w", device_model: "Galaxy S24 Ultra", device_manufacturer: "Samsung", updated_at: new Date().toISOString() },
          { username: "bob_smith", device_model: "Pixel 8 Pro", device_manufacturer: "Google", updated_at: new Date().toISOString() }
        ]
      });
    }

    const result = await pool.query(
      "SELECT username, device_model, device_manufacturer, updated_at FROM users ORDER BY updated_at DESC"
    );
    res.json({ users: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error retrieving user records" });
  }
});

app.get("*", (req, res) => {
  if (req.accepts('html')) {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  } else {
    res.json({
      status: "OK",
      message: "TitanBag Backend is running"
    });
  }
});