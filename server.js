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
const { pool, seedDefaultCategories, ensureTypeColumn, ensureGroupSplitColumns } = require('./db');

const resend = new Resend(process.env.RESEND_MAIL || 're_placeholder_local_testing');


const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const RESEND_MAIL = process.env.RESEND_MAIL;

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

// Helper to record registered device in device_register table
async function registerDevice(userId, req) {
  try {
    const { device_id, device_model, device_manufacturer, os_version, app_version } = req.body;
    if (device_id) {
      const deviceName = device_manufacturer ? `${device_manufacturer} ${device_model}` : (device_model || 'Unknown Device');
      await pool.query(
        `INSERT INTO device_register (user_id, device_id, device_name, manufacturer, model, os_version, app_version, last_active)
         VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
         ON CONFLICT (user_id, device_id) DO UPDATE SET
           last_active  = NOW(),
           os_version   = COALESCE($6, device_register.os_version),
           app_version  = COALESCE($7, device_register.app_version)`,
        [userId, device_id, deviceName, device_manufacturer || 'Unknown', device_model || 'Unknown', os_version || null, app_version || null]
      );
      console.log(`Device registered/updated: ${deviceName} (ID: ${device_id}) for User: ${userId}`);
    }
  } catch (err) {
    console.error("Device registration error:", err);
  }
}

// Endpoint: POST /login/google
app.post('/login/google', async (req, res) => {
  const { id_token, display_name, profile_photo, device_model, device_manufacturer, device_id } = req.body;

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
    const location = req.headers['x-vercel-ip-city'] || req.headers['cf-ipcity'] || 'Unknown';

    // Check if user exists by email
    let userResult = await pool.query("SELECT * FROM users WHERE email = $1", [email.toLowerCase()]);
    let user;

    if (userResult.rows.length === 0) {
      // Auto-register new Google user
      const username = `google_${googleId.substring(0, 8)}`;
      const timestamp = new Date();

      const insertResult = await pool.query(
        `INSERT INTO users (username, email, display_name, password_hash, profile_photo, created_at, updated_at, last_login)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING user_id, username, email, display_name, profile_photo, created_at, updated_at`,
        [username, email.toLowerCase(), display_name || name, 'GOOGLE_AUTH_EXTERNAL', profile_photo || payload.picture, timestamp, timestamp, timestamp]
      );
      user = insertResult.rows[0];
    } else {
      user = userResult.rows[0];
      // Update last login
      const timestamp = new Date();
      const updatedResult = await pool.query(
        `UPDATE users 
         SET last_login = $1, profile_photo = COALESCE($2, profile_photo), updated_at = $3 
         WHERE user_id = $4 
         RETURNING user_id, username, email, display_name, profile_photo, created_at, updated_at`,
        [timestamp, profile_photo || payload.picture, timestamp, user.user_id]
      );
      user = updatedResult.rows[0];
    }

    // Call device registration helper
    await registerDevice(user.user_id, req);

    const token = jwt.sign({ id: user.user_id, username: user.username }, JWT_SECRET || 'fallback', { expiresIn: '30d' });

    res.status(200).json({
      token,
      is_new: userResult.rows.length === 0,
      user: {
        id: user.user_id,
        username: user.username,
        email: user.email,
        display_name: user.display_name,
        profile_photo: user.profile_photo,
        partner_share_code: getPartnerShareCode(user.user_id),
        created_at: user.created_at,
        updated_at: user.updated_at
      }
    });

  } catch (err) {
    console.error("Google Login Error:", err);
    res.status(401).json({ message: "Invalid Google ID token" });
  }
});

// Helper: Get invitation share code deterministically from user_id to match Android segmented input format
function getPartnerShareCode(userId) {
  if (!userId) return '';
  const cleanUuid = userId.replace(/-/g, '').toUpperCase();
  const p1 = cleanUuid.substring(0, 4);
  const p2 = cleanUuid.substring(4, 8);
  const p3 = cleanUuid.substring(8, 12);
  const p4 = cleanUuid.substring(12, 16);
  return `PB-${p1}-${p2}-${p3}-${p4}`;
}


// Authentication Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: "Access token required" });
  }

  jwt.verify(token, JWT_SECRET || 'fallback', (err, user) => {
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
      "SELECT user_id FROM users WHERE username = $1 OR email = $2",
      [username.trim().toLowerCase(), email.trim().toLowerCase()]
    );

    if (duplicateCheck.rows.length > 0) {
      const existingUser = duplicateCheck.rows[0];
      const timestamp = new Date();
      const updatedResult = await pool.query(
        `UPDATE users 
         SET display_name = COALESCE(NULLIF($1, ''), display_name), last_login = $2, updated_at = $3 
         WHERE user_id = $4 
         RETURNING user_id, username, email, display_name, profile_photo, created_at, updated_at, last_login`,
        [display_name.trim(), timestamp, timestamp, existingUser.user_id]
      );
      const user = updatedResult.rows[0];
      await registerDevice(user.user_id, req);
      const token = jwt.sign({ id: user.user_id, username: user.username }, JWT_SECRET || 'fallback', { expiresIn: '30d' });

      return res.status(200).json({
        token,
        user: {
          id: user.user_id,
          username: user.username,
          email: user.email,
          display_name: user.display_name,
          partner_share_code: getPartnerShareCode(user.user_id),
          created_at: user.created_at,
          updated_at: user.updated_at,
          last_login: user.last_login
        }
      });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const timestamp = new Date();

    const result = await pool.query(
      `INSERT INTO users (username, email, display_name, password_hash, created_at, updated_at, last_login)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING user_id, username, email, display_name, created_at, updated_at, last_login`,
      [username.trim().toLowerCase(), email.trim().toLowerCase(), display_name.trim(), passwordHash, timestamp, timestamp, timestamp]
    );

    const newUser = result.rows[0];

    // Register device
    await registerDevice(newUser.user_id, req);

    const token = jwt.sign({ id: newUser.user_id, username: newUser.username }, JWT_SECRET || 'fallback', { expiresIn: '30d' });

    // Asynchronously send onboarding welcome email via Resend (non-blocking)
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
          <h3 style="color: #f3f4f6; margin-top: 0; font-size: 14px; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid #1e2633; padding-bottom: 10px; margin-bottom: 15px;">Your Account</h3>
          <div style="margin-bottom: 10px; font-size: 14px;">
            <span style="color: #9ca3af;">Username:</span>
            <strong style="color: #f3f4f6; float: right;">@${newUser.username}</strong>
          </div>
          <div style="clear: both;"></div>
        </div>
        <div style="margin-top: 30px; border-top: 1px solid #1e2633; padding-top: 20px; color: #6b7280; font-size: 12px;">
          TitanBag Secure Cloud Systems. Powered by Node.js &amp; PostgreSQL.
        </div>
      </div>
    `;

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
        id: newUser.user_id,
        username: newUser.username,
        email: newUser.email,
        display_name: newUser.display_name,
        partner_share_code: getPartnerShareCode(newUser.user_id),
        created_at: newUser.created_at,
        updated_at: newUser.updated_at,
        last_login: newUser.last_login
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

    // Update last login timestamp
    const timestamp = new Date();
    await pool.query(
      "UPDATE users SET last_login = $1, updated_at = $2 WHERE user_id = $3",
      [timestamp, timestamp, user.user_id]
    );

    // Call device registration helper
    await registerDevice(user.user_id, req);

    const token = jwt.sign({ id: user.user_id, username: user.username }, JWT_SECRET || 'fallback', { expiresIn: '30d' });

    res.status(200).json({
      token,
      user: {
        id: user.user_id,
        username: user.username,
        email: user.email,
        display_name: user.display_name,
        profile_photo: user.profile_photo,
        partner_share_code: getPartnerShareCode(user.user_id),
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
    const userResult = await pool.query("SELECT user_id, display_name FROM users WHERE email = $1", [email.trim().toLowerCase()]);
    if (userResult.rows.length === 0) {
      // For security, do not leak whether email exists. Send success.
      return res.status(200).json({ message: "If that email exists, we have sent a link to reset your password." });
    }

    const user = userResult.rows[0];
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    await pool.query(
      'INSERT INTO password_resets (user_id, token, expires_at) VALUES ($1, $2, $3)',
      [user.user_id, token, expiresAt]
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
    await pool.query('UPDATE users SET password_hash = $1, updated_at = NOW() WHERE user_id = $2', [passwordHash, resetRequest.user_id]);

    // Mark token as used
    await pool.query('UPDATE password_resets SET used = true WHERE id = $1', [resetRequest.id]);

    res.status(200).json({ message: "Password reset successfully. You can now log in." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error resetting password" });
  }
});

// Endpoint: POST /api/auth/set-password
app.post('/api/auth/set-password', authenticateToken, async (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 8) {
    return res.status(400).json({ message: "Password must be at least 8 characters long." });
  }
  try {
    const passwordHash = await bcrypt.hash(password, 10);
    await pool.query('UPDATE users SET password_hash = $1, updated_at = NOW() WHERE user_id = $2', [passwordHash, req.user.id]);
    res.status(200).json({ success: true, message: "Password configured successfully." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error configuring password." });
  }
});

// Endpoint: GET /profile
app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const userResult = await pool.query(
      "SELECT user_id, username, email, display_name, profile_photo, created_at, updated_at, last_login FROM users WHERE user_id = $1",
      [req.user.id]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const dbUser = userResult.rows[0];
    const user = {
      id: dbUser.user_id,
      username: dbUser.username,
      email: dbUser.email,
      display_name: dbUser.display_name,
      profile_photo: dbUser.profile_photo,
      partner_share_code: getPartnerShareCode(dbUser.user_id),
      created_at: dbUser.created_at,
      updated_at: dbUser.updated_at,
      last_login: dbUser.last_login
    };

    // Check for active partner
    const partnerResult = await pool.query(
      `SELECT p.*,
              u.display_name as partner_display_name,
              u.username as partner_username
       FROM partners p
       JOIN users u ON (u.user_id = p.user_one_id OR u.user_id = p.user_two_id) AND u.user_id != $1
       WHERE (p.user_one_id = $1 OR p.user_two_id = $1) AND p.status = 'active'
       LIMIT 1`,
      [req.user.id]
    );

    const partner = partnerResult.rows.length > 0 ? partnerResult.rows[0] : null;

    res.status(200).json({ user, partner });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error fetching profile" });
  }
});

// Endpoint: POST /partner/connect
// Accepts partner_code or partner_share_code (username OR deterministically derived EXP share code)
app.post('/partner/connect', authenticateToken, async (req, res) => {
  const partner_code = req.body.partner_code || req.body.partner_share_code;

  if (!partner_code) {
    return res.status(400).json({ message: "Partner username or code required" });
  }

  try {
    // 1. Find target user by username or derived share code prefix
    let targetResult;
    let cleanCode = partner_code.trim().toUpperCase();
    if (cleanCode.startsWith('EXP') || cleanCode.startsWith('PB')) {
      const hexPrefix = cleanCode.replace(/^(EXP|PB)-?/i, '').replace(/-/g, '').toLowerCase() + '%';
      targetResult = await pool.query(
        "SELECT user_id, display_name FROM users WHERE REPLACE(user_id::text, '-', '') LIKE $1 OR username = $2",
        [hexPrefix, partner_code.trim().toLowerCase()]
      );
    } else {
      targetResult = await pool.query(
        "SELECT user_id, display_name FROM users WHERE username = $1 OR REPLACE(user_id::text, '-', '') LIKE $2",
        [partner_code.trim().toLowerCase(), cleanCode.replace(/-/g, '').toLowerCase() + '%']
      );
    }

    if (targetResult.rows.length === 0) {
      return res.status(404).json({ message: "Partner not found. Check the username/code and try again." });
    }

    const partnerUser = targetResult.rows[0];

    if (partnerUser.user_id === req.user.id) {
      return res.status(400).json({ message: "You cannot connect with yourself" });
    }

    // 2. Check if requester is already connected
    const activeLink = await pool.query(
      "SELECT id FROM partners WHERE (user_one_id = $1 OR user_two_id = $1) AND status = 'active'",
      [req.user.id]
    );
    if (activeLink.rows.length > 0) {
      return res.status(400).json({ message: "You are already connected to a partner. Disconnect first." });
    }

    // 3. Check if target partner is already connected
    const partnerActiveLink = await pool.query(
      "SELECT id FROM partners WHERE (user_one_id = $1 OR user_two_id = $1) AND status = 'active'",
      [partnerUser.user_id]
    );
    if (partnerActiveLink.rows.length > 0) {
      return res.status(400).json({ message: "That user is already linked with someone else." });
    }

    // 4. Create active link
    await pool.query(
      "INSERT INTO partners (user_one_id, user_two_id, connected_at, status) VALUES ($1, $2, NOW(), 'active')",
      [req.user.id, partnerUser.user_id]
    );

    const requesterName = req.user.displayName || req.user.username || "Someone";
    await sendNotification(partnerUser.user_id, "Partner Connected", `${requesterName} has connected with you as a partner!`, "partner_sharing");

    res.status(200).json({ success: true, message: `Connected successfully with ${partnerUser.display_name}!` });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error linking partner" });
  }
});

// Endpoint: DELETE & POST /partner/disconnect (supports both Android & Web client HTTP methods)
const handleDisconnect = async (req, res) => {
  try {
    const partnerRes = await pool.query(
      `SELECT user_one_id, user_two_id FROM partners
       WHERE (user_one_id = $1 OR user_two_id = $1) AND status = 'active' LIMIT 1`,
      [req.user.id]
    );

    const result = await pool.query(
      "UPDATE partners SET status = 'disconnected' WHERE (user_one_id = $1 OR user_two_id = $1) AND status = 'active'",
      [req.user.id]
    );

    if (result.rowCount === 0) {
      return res.status(400).json({ message: "No active partner connection found" });
    }

    if (partnerRes.rows.length > 0) {
      const p = partnerRes.rows[0];
      const partnerId = p.user_one_id === req.user.id ? p.user_two_id : p.user_one_id;
      const requesterName = req.user.displayName || req.user.username || "Someone";
      await sendNotification(partnerId, "Partner Disconnected", `${requesterName} disconnected the partner link.`, "partner_sharing");
    }

    res.status(200).json({ success: true, message: "Partner disconnected successfully. Data is no longer shared." });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error disconnecting partner" });
  }
};
app.delete('/partner/disconnect', authenticateToken, handleDisconnect);
app.post('/partner/disconnect', authenticateToken, handleDisconnect);


// Endpoint: POST /api/partner/block
app.post('/api/partner/block', authenticateToken, async (req, res) => {
  try {
    await pool.query(
      "UPDATE partners SET status = 'blocked' WHERE (user_one_id = $1 OR user_two_id = $1) AND status = 'active'",
      [req.user.id]
    );
    res.json({ success: true, message: "Partner blocked" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error blocking partner" });
  }
});
// Endpoint: GET /partner/status
// Returns the active partner info for the logged-in user
app.get('/partner/status', authenticateToken, async (req, res) => {
  try {
    const partnerResult = await pool.query(
      `SELECT p.id, p.user_one_id, p.user_two_id, p.status, p.connected_at,
              u.display_name as partner_display_name,
              u.username as partner_username,
              u.user_id as partner_user_id
       FROM partners p
       JOIN users u ON (u.user_id = p.user_one_id OR u.user_id = p.user_two_id) AND u.user_id != $1
       WHERE (p.user_one_id = $1 OR p.user_two_id = $1) AND p.status = 'active'
       LIMIT 1`,
      [req.user.id]
    );

    if (partnerResult.rows.length === 0) {
      return res.status(200).json({ connected: false, partner: null });
    }

    const p = partnerResult.rows[0];
    res.status(200).json({
      connected: true,
      partner: {
        id: p.partner_user_id,
        display_name: p.partner_display_name,
        username: p.partner_username,
        connected_at: p.connected_at,
        partner_share_code: getPartnerShareCode(p.partner_user_id)
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error fetching partner status' });
  }
});

// Endpoint: GET /partner/transactions
// Returns the partner's journal transactions securely (only if active partner link exists)
app.get('/partner/transactions', authenticateToken, async (req, res) => {
  try {
    // Security: Verify active partner connection first
    const partnerRes = await pool.query(
      `SELECT user_one_id, user_two_id FROM partners
       WHERE (user_one_id = $1 OR user_two_id = $1) AND status = 'active' LIMIT 1`,
      [req.user.id]
    );

    if (partnerRes.rows.length === 0) {
      return res.status(403).json({ message: 'No active partner connection found. Connect with a partner first.' });
    }

    const p = partnerRes.rows[0];
    const partnerId = p.user_one_id === req.user.id ? p.user_two_id : p.user_one_id;

    // Optional date range filters from query params (e.g. ?from=2024-01-01&to=2024-12-31)
    const { from, to, type, limit = 100 } = req.query;

    let whereClause = 'WHERE j.owner_id = $1';
    const params = [partnerId];
    let paramIdx = 2;

    if (from) {
      whereClause += ` AND j.date >= $${paramIdx++}`;
      params.push(from);
    }
    if (to) {
      whereClause += ` AND j.date <= $${paramIdx++}`;
      params.push(to);
    }
    if (type && (type === 'income' || type === 'expense')) {
      whereClause += ` AND j.type = $${paramIdx++}`;
      params.push(type);
    }
    whereClause += ` AND j.deleted = false`;

    const safeLimit = Math.min(parseInt(limit) || 100, 500);

    const txResult = await pool.query(
      `SELECT j.id, j.owner_id, j.title, j.amount, j.category,
              j.notes, j.payment_method, j.date, j.created_at, j.updated_at,
              j.type, j.deleted,
              u.display_name as owner_display_name
       FROM journals j
       JOIN users u ON j.owner_id = u.user_id
       ${whereClause}
       ORDER BY j.date DESC
       LIMIT ${safeLimit}`,
      params
    );

    const transactions = txResult.rows.map(row => ({
      id: row.id,
      owner_id: row.owner_id,
      owner_name: row.owner_display_name,
      title: row.title,
      amount: parseFloat(row.amount),
      category: row.category || 'General',
      notes: row.notes || '',
      payment_method: row.payment_method || '',
      type: row.type || 'expense',
      date: row.date instanceof Date ? row.date.toISOString() : row.date,
      created_at: row.created_at instanceof Date ? row.created_at.toISOString() : row.created_at,
      updated_at: row.updated_at instanceof Date ? row.updated_at.toISOString() : row.updated_at
    }));

    const totalIncome = transactions.filter(t => t.type === 'income').reduce((s, t) => s + t.amount, 0);
    const totalExpense = transactions.filter(t => t.type === 'expense').reduce((s, t) => s + t.amount, 0);

    res.status(200).json({
      partner_id: partnerId,
      transaction_count: transactions.length,
      total_income: totalIncome,
      total_expense: totalExpense,
      net_balance: totalIncome - totalExpense,
      transactions
    });

  } catch (err) {
    console.error('Error fetching partner transactions:', err);
    res.status(500).json({ message: 'Error fetching partner transactions' });
  }
});



// Create Shared Journal
app.post('/api/journals', authenticateToken, async (req, res) => {
  const { title, description, start_date, end_date, currency } = req.body;
  if (!title) return res.status(400).json({ message: "Title is required" });

  try {
    const joinToken = crypto.randomBytes(16).toString('hex');
    const result = await pool.query(
      `INSERT INTO shared_journals (creator_id, title, description, start_date, end_date, currency, join_token)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [req.user.id, title, description, start_date, end_date, currency || '₹', joinToken]
    );

    const journal = result.rows[0];

    // Add creator as member
    await pool.query(
      `INSERT INTO journal_members (journal_id, user_id, role) VALUES ($1, $2, 'creator')`,
      [journal.id, req.user.id]
    );

    res.status(201).json(journal);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error creating shared journal" });
  }
});

// Join Shared Journal
app.post('/api/journals/join', authenticateToken, async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ message: "Join token required" });

  try {
    const journalRes = await pool.query("SELECT id FROM shared_journals WHERE join_token = $1", [token]);
    if (journalRes.rows.length === 0) return res.status(404).json({ message: "Invalid join token" });

    const journalId = journalRes.rows[0].id;

    // Check if already a member
    const memberCheck = await pool.query(
      "SELECT user_id FROM journal_members WHERE journal_id = $1 AND user_id = $2",
      [journalId, req.user.id]
    );
    if (memberCheck.rows.length > 0) return res.status(400).json({ message: "Already a member of this journal" });

    await pool.query(
      "INSERT INTO journal_members (journal_id, user_id) VALUES ($1, $2)",
      [journalId, req.user.id]
    );

    res.json({ success: true, journal_id: journalId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error joining journal" });
  }
});

// List My Shared Journals
app.get('/api/journals', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT DISTINCT j.*, m.role,
       (SELECT count(*) FROM journal_members WHERE journal_id = j.id) as member_count
       FROM shared_journals j
       JOIN journal_members m ON j.id = m.journal_id
       WHERE m.user_id = $1`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error fetching journals" });
  }
});

// Get Journal Details & Transactions
app.get('/api/journals/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    // Verify membership
    const memberCheck = await pool.query(
      "SELECT role FROM journal_members WHERE journal_id = $1 AND user_id = $2",
      [id, req.user.id]
    );
    if (memberCheck.rows.length === 0) return res.status(403).json({ message: "Access denied" });

    const journalRes = await pool.query("SELECT * FROM shared_journals WHERE id = $1", [id]);
    const membersRes = await pool.query(
      `SELECT u.id, u.username, u.display_name, m.role
       FROM users u JOIN journal_members m ON u.id = m.user_id
       WHERE m.journal_id = $1`, [id]
    );
    const txRes = await pool.query(
      `SELECT t.*, u.display_name as paid_by_name
       FROM journal_transactions t
       JOIN users u ON t.paid_by = u.id
       WHERE t.journal_id = $1 ORDER BY t.date DESC`, [id]
    );

    res.json({
      journal: journalRes.rows[0],
      members: membersRes.rows,
      transactions: txRes.rows
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error fetching journal details" });
  }
});

// Add Transaction to Shared Journal
app.post('/api/journals/:id/transactions', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { amount, category, description, date, type, notes } = req.body;

  try {
    // Verify membership
    const memberCheck = await pool.query(
      "SELECT role FROM journal_members WHERE journal_id = $1 AND user_id = $2",
      [id, req.user.id]
    );
    if (memberCheck.rows.length === 0) return res.status(403).json({ message: "Access denied" });

    const result = await pool.query(
      `INSERT INTO journal_transactions (journal_id, paid_by, amount, category, description, date, type, notes)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [id, req.user.id, amount, category, description, date, type || 'expense', notes]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error adding transaction" });
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
            `INSERT INTO journals (id, owner_id, title, amount, category, notes, payment_method, date, created_at, updated_at, type, deleted)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
            [jr.id, req.user.id, jr.title, jr.amount, jr.category, jr.notes, jr.payment_method, jr.date, jr.created_at, jr.updated_at, jr.type || 'expense', jr.deleted]
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
             SET title = $1, amount = $2, category = $3, notes = $4, payment_method = $5, date = $6, updated_at = $7, type = $8, deleted = $9
             WHERE id = $10`,
            [jr.title, jr.amount, jr.category, jr.notes, jr.payment_method, jr.date, jr.updated_at, jr.type || 'expense', jr.deleted, jr.id]
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
      `SELECT id, owner_id, title, amount, category, notes, payment_method, date, created_at, updated_at, type, deleted
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
      type: row.type || 'expense',
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

// ─────────────────────────────────────────────────────────────────────────────
// ACCOUNTS — user wallet/bank accounts
// ─────────────────────────────────────────────────────────────────────────────

// GET /api/accounts — list all accounts for the logged-in user
app.get('/api/accounts', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM accounts WHERE user_id = $1 ORDER BY id ASC',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error fetching accounts' });
  }
});

// POST /api/accounts — create a new account
app.post('/api/accounts', authenticateToken, async (req, res) => {
  const { name, type, opening_balance, current_balance, icon, color } = req.body;
  if (!name || !type) return res.status(400).json({ message: 'name and type are required' });
  try {
    const result = await pool.query(
      `INSERT INTO accounts (user_id, name, type, opening_balance, current_balance, icon, color)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [req.user.id, name, type, opening_balance || 0, current_balance || 0, icon || null, color || null]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error creating account' });
  }
});

// PUT /api/accounts/:id — update an account
app.put('/api/accounts/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { name, type, opening_balance, current_balance, icon, color } = req.body;
  try {
    const result = await pool.query(
      `UPDATE accounts
       SET name = COALESCE($1, name), type = COALESCE($2, type),
           opening_balance = COALESCE($3, opening_balance), current_balance = COALESCE($4, current_balance),
           icon = COALESCE($5, icon), color = COALESCE($6, color)
       WHERE id = $7 AND user_id = $8 RETURNING *`,
      [name, type, opening_balance, current_balance, icon, color, id, req.user.id]
    );
    if (result.rowCount === 0) return res.status(404).json({ message: 'Account not found' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error updating account' });
  }
});

// DELETE /api/accounts/:id — delete an account
app.delete('/api/accounts/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      'DELETE FROM accounts WHERE id = $1 AND user_id = $2',
      [id, req.user.id]
    );
    if (result.rowCount === 0) return res.status(404).json({ message: 'Account not found' });
    res.json({ success: true, message: 'Account deleted' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error deleting account' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// BUDGETS — monthly/custom budgets per user
// ─────────────────────────────────────────────────────────────────────────────

// GET /api/budgets — list all budgets for the logged-in user
app.get('/api/budgets', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM budgets WHERE user_id = $1 ORDER BY year DESC, month DESC',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error fetching budgets' });
  }
});

// POST /api/budgets — create a new budget
app.post('/api/budgets', authenticateToken, async (req, res) => {
  const { category_id, budget_amount, month, year, budget_type, start_date, end_date, budget_name } = req.body;
  if (!budget_amount || !month || !year) {
    return res.status(400).json({ message: 'budget_amount, month, and year are required' });
  }
  try {
    const result = await pool.query(
      `INSERT INTO budgets (user_id, category_id, budget_amount, month, year, budget_type, start_date, end_date, budget_name)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [req.user.id, category_id || null, budget_amount, month, year, budget_type || 'MONTHLY', start_date || null, end_date || null, budget_name || null]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error creating budget' });
  }
});

// PUT /api/budgets/:id — update a budget
app.put('/api/budgets/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { category_id, budget_amount, month, year, budget_type, start_date, end_date, budget_name } = req.body;
  try {
    const result = await pool.query(
      `UPDATE budgets
       SET category_id = COALESCE($1, category_id), budget_amount = COALESCE($2, budget_amount),
           month = COALESCE($3, month), year = COALESCE($4, year),
           budget_type = COALESCE($5, budget_type), start_date = COALESCE($6, start_date),
           end_date = COALESCE($7, end_date), budget_name = COALESCE($8, budget_name)
       WHERE id = $9 AND user_id = $10 RETURNING *`,
      [category_id, budget_amount, month, year, budget_type, start_date, end_date, budget_name, id, req.user.id]
    );
    if (result.rowCount === 0) return res.status(404).json({ message: 'Budget not found' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error updating budget' });
  }
});

// DELETE /api/budgets/:id — delete a budget
app.delete('/api/budgets/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      'DELETE FROM budgets WHERE id = $1 AND user_id = $2',
      [id, req.user.id]
    );
    if (result.rowCount === 0) return res.status(404).json({ message: 'Budget not found' });
    res.json({ success: true, message: 'Budget deleted' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error deleting budget' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// SAVINGS GOALS — per-user savings targets
// ─────────────────────────────────────────────────────────────────────────────

// GET /api/savings-goals — list all savings goals for the logged-in user
app.get('/api/savings-goals', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM savings_goals WHERE user_id = $1 ORDER BY id ASC',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error fetching savings goals' });
  }
});

// POST /api/savings-goals — create a new savings goal
app.post('/api/savings-goals', authenticateToken, async (req, res) => {
  const { title, target_amount, current_amount, target_date, status, icon, color } = req.body;
  if (!title || !target_amount) return res.status(400).json({ message: 'title and target_amount are required' });
  try {
    const result = await pool.query(
      `INSERT INTO savings_goals (user_id, title, target_amount, current_amount, target_date, status, icon, color)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [req.user.id, title, target_amount, current_amount || 0, target_date || null, status || 'active', icon || null, color || null]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error creating savings goal' });
  }
});

// PUT /api/savings-goals/:id — update a savings goal
app.put('/api/savings-goals/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { title, target_amount, current_amount, target_date, status, icon, color } = req.body;
  try {
    const result = await pool.query(
      `UPDATE savings_goals
       SET title = COALESCE($1, title), target_amount = COALESCE($2, target_amount),
           current_amount = COALESCE($3, current_amount), target_date = COALESCE($4, target_date),
           status = COALESCE($5, status), icon = COALESCE($6, icon), color = COALESCE($7, color)
       WHERE id = $8 AND user_id = $9 RETURNING *`,
      [title, target_amount, current_amount, target_date, status, icon, color, id, req.user.id]
    );
    if (result.rowCount === 0) return res.status(404).json({ message: 'Savings goal not found' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error updating savings goal' });
  }
});

// DELETE /api/savings-goals/:id — delete a savings goal
app.delete('/api/savings-goals/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      'DELETE FROM savings_goals WHERE id = $1 AND user_id = $2',
      [id, req.user.id]
    );
    if (result.rowCount === 0) return res.status(404).json({ message: 'Savings goal not found' });
    res.json({ success: true, message: 'Savings goal deleted' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error deleting savings goal' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// RECURRING TRANSACTIONS — per-user recurring expense/income rules
// ─────────────────────────────────────────────────────────────────────────────

// GET /api/recurring-transactions — list all recurring transactions for the logged-in user
app.get('/api/recurring-transactions', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM recurring_transactions WHERE user_id = $1 ORDER BY id ASC',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error fetching recurring transactions' });
  }
});

// POST /api/recurring-transactions — create a recurring transaction rule
app.post('/api/recurring-transactions', authenticateToken, async (req, res) => {
  const { amount, type, category_id, account_id, note, frequency, next_execution_date, enabled } = req.body;
  if (!amount || !type || !frequency) {
    return res.status(400).json({ message: 'amount, type, and frequency are required' });
  }
  try {
    const result = await pool.query(
      `INSERT INTO recurring_transactions (user_id, amount, type, category_id, account_id, note, frequency, next_execution_date, enabled)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [req.user.id, amount, type, category_id || null, account_id || null, note || null, frequency, next_execution_date || null, enabled !== undefined ? enabled : true]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error creating recurring transaction' });
  }
});

// PUT /api/recurring-transactions/:id — update a recurring transaction rule
app.put('/api/recurring-transactions/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { amount, type, category_id, account_id, note, frequency, next_execution_date, enabled } = req.body;
  try {
    const result = await pool.query(
      `UPDATE recurring_transactions
       SET amount = COALESCE($1, amount), type = COALESCE($2, type),
           category_id = COALESCE($3, category_id), account_id = COALESCE($4, account_id),
           note = COALESCE($5, note), frequency = COALESCE($6, frequency),
           next_execution_date = COALESCE($7, next_execution_date),
           enabled = COALESCE($8, enabled)
       WHERE id = $9 AND user_id = $10 RETURNING *`,
      [amount, type, category_id, account_id, note, frequency, next_execution_date, enabled, id, req.user.id]
    );
    if (result.rowCount === 0) return res.status(404).json({ message: 'Recurring transaction not found' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error updating recurring transaction' });
  }
});

// DELETE /api/recurring-transactions/:id — delete a recurring transaction rule
app.delete('/api/recurring-transactions/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      'DELETE FROM recurring_transactions WHERE id = $1 AND user_id = $2',
      [id, req.user.id]
    );
    if (result.rowCount === 0) return res.status(404).json({ message: 'Recurring transaction not found' });
    res.json({ success: true, message: 'Recurring transaction deleted' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error deleting recurring transaction' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// SETTINGS — one row per user; upsert on POST
// ─────────────────────────────────────────────────────────────────────────────

// GET /api/settings — get settings for the logged-in user
app.get('/api/settings', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM settings WHERE user_id = $1',
      [req.user.id]
    );
    if (result.rows.length === 0) {
      // Return defaults if not yet saved
      return res.json({
        user_id: req.user.id,
        theme_mode: 'system',
        currency: '₹',
        pin_enabled: false,
        biometric_enabled: false,
        notifications_enabled: true,
        debt_list_enabled: true,
        color_palette: 'Default',
        custom_color: null,
        custom_icon_color: null,
        custom_bg_color: null
      });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error fetching settings' });
  }
});

// POST /api/settings — upsert (create or update) settings for the logged-in user
app.post('/api/settings', authenticateToken, async (req, res) => {
  const {
    theme_mode, currency, pin_enabled, biometric_enabled,
    notifications_enabled, debt_list_enabled, color_palette,
    custom_color, custom_icon_color, custom_bg_color
  } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO settings (user_id, theme_mode, currency, pin_enabled, biometric_enabled, notifications_enabled, debt_list_enabled, color_palette, custom_color, custom_icon_color, custom_bg_color)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       ON CONFLICT (user_id) DO UPDATE SET
         theme_mode            = COALESCE(EXCLUDED.theme_mode, settings.theme_mode),
         currency              = COALESCE(EXCLUDED.currency, settings.currency),
         pin_enabled           = COALESCE(EXCLUDED.pin_enabled, settings.pin_enabled),
         biometric_enabled     = COALESCE(EXCLUDED.biometric_enabled, settings.biometric_enabled),
         notifications_enabled = COALESCE(EXCLUDED.notifications_enabled, settings.notifications_enabled),
         debt_list_enabled     = COALESCE(EXCLUDED.debt_list_enabled, settings.debt_list_enabled),
         color_palette         = COALESCE(EXCLUDED.color_palette, settings.color_palette),
         custom_color          = COALESCE(EXCLUDED.custom_color, settings.custom_color),
         custom_icon_color     = COALESCE(EXCLUDED.custom_icon_color, settings.custom_icon_color),
         custom_bg_color       = COALESCE(EXCLUDED.custom_bg_color, settings.custom_bg_color)
       RETURNING *`,
      [
        req.user.id,
        theme_mode || 'system',
        currency || '₹',
        pin_enabled !== undefined ? pin_enabled : false,
        biometric_enabled !== undefined ? biometric_enabled : false,
        notifications_enabled !== undefined ? notifications_enabled : true,
        debt_list_enabled !== undefined ? debt_list_enabled : true,
        color_palette || 'Default',
        custom_color || null,
        custom_icon_color || null,
        custom_bg_color || null
      ]
    );
    res.status(200).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error saving settings' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// DEBT RECORDS — personal debt/credit tracking per user
// ─────────────────────────────────────────────────────────────────────────────

// GET /api/debts — list all debt records for the logged-in user
app.get('/api/debts', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM debt_records WHERE user_id = $1 ORDER BY borrowed_date DESC',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error fetching debt records' });
  }
});

// POST /api/debts — create a new debt record
app.post('/api/debts', authenticateToken, async (req, res) => {
  const { id, person_name, borrowed_date, action, amount, remainder_boolean, date_timestamp, returned_date, status, mode_of_transaction } = req.body;
  if (!person_name || !borrowed_date || !action || !amount) {
    return res.status(400).json({ message: 'person_name, borrowed_date, action, and amount are required' });
  }
  if (!['Debt', 'Credit'].includes(action)) {
    return res.status(400).json({ message: 'action must be "Debt" or "Credit"' });
  }
  try {
    const recordId = id || crypto.randomUUID();
    const result = await pool.query(
      `INSERT INTO debt_records (id, user_id, person_name, borrowed_date, action, amount, remainder_boolean, date_timestamp, returned_date, status, mode_of_transaction)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *`,
      [recordId, req.user.id, person_name, borrowed_date, action, amount, remainder_boolean || false, date_timestamp || null, returned_date || null, status || 'Pending', mode_of_transaction || 'Cash']
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error creating debt record' });
  }
});

// PUT /api/debts/:id — update a debt record (e.g. mark as returned)
app.put('/api/debts/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { person_name, borrowed_date, action, amount, remainder_boolean, date_timestamp, returned_date, status, mode_of_transaction } = req.body;
  try {
    const result = await pool.query(
      `UPDATE debt_records
       SET person_name         = COALESCE($1, person_name),
           borrowed_date       = COALESCE($2, borrowed_date),
           action              = COALESCE($3, action),
           amount              = COALESCE($4, amount),
           remainder_boolean   = COALESCE($5, remainder_boolean),
           date_timestamp      = COALESCE($6, date_timestamp),
           returned_date       = COALESCE($7, returned_date),
           status              = COALESCE($8, status),
           mode_of_transaction = COALESCE($9, mode_of_transaction)
       WHERE id = $10 AND user_id = $11 RETURNING *`,
      [person_name, borrowed_date, action, amount, remainder_boolean, date_timestamp, returned_date, status, mode_of_transaction, id, req.user.id]
    );
    if (result.rowCount === 0) return res.status(404).json({ message: 'Debt record not found' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error updating debt record' });
  }
});

// DELETE /api/debts/:id — delete a debt record
app.delete('/api/debts/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      'DELETE FROM debt_records WHERE id = $1 AND user_id = $2',
      [id, req.user.id]
    );
    if (result.rowCount === 0) return res.status(404).json({ message: 'Debt record not found' });
    res.json({ success: true, message: 'Debt record deleted' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error deleting debt record' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// CATEGORIES — global shared categories (read + create custom)
// ─────────────────────────────────────────────────────────────────────────────

// GET /api/categories — list all categories (default + custom)
app.get('/api/categories', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM categories ORDER BY order_index ASC, id ASC'
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error fetching categories' });
  }
});

// POST /api/categories — create a custom category
app.post('/api/categories', authenticateToken, async (req, res) => {
  const { name, type, icon, color, order_index } = req.body;
  if (!name || !type) return res.status(400).json({ message: 'name and type are required' });
  if (!['income', 'expense'].includes(type)) {
    return res.status(400).json({ message: 'type must be "income" or "expense"' });
  }
  try {
    const result = await pool.query(
      `INSERT INTO categories (name, type, icon, color, is_default, order_index)
       VALUES ($1, $2, $3, $4, false, $5) RETURNING *`,
      [name, type, icon || null, color || null, order_index || 0]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error creating category' });
  }
});

// PUT /api/categories/:id — update a custom (non-default) category
app.put('/api/categories/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { name, type, icon, color, order_index } = req.body;
  try {
    const result = await pool.query(
      `UPDATE categories
       SET name = COALESCE($1, name), type = COALESCE($2, type),
           icon = COALESCE($3, icon), color = COALESCE($4, color),
           order_index = COALESCE($5, order_index)
       WHERE id = $6 AND is_default = false RETURNING *`,
      [name, type, icon, color, order_index, id]
    );
    if (result.rowCount === 0) return res.status(404).json({ message: 'Category not found or is a default category' });
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error updating category' });
  }
});

// DELETE /api/categories/:id — delete a custom (non-default) category
app.delete('/api/categories/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      'DELETE FROM categories WHERE id = $1 AND is_default = false',
      [id]
    );
    if (result.rowCount === 0) return res.status(404).json({ message: 'Category not found or is a default category' });
    res.json({ success: true, message: 'Category deleted' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error deleting category' });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GROUP EXPENSE & MULTI-PARTY SPLIT ENDPOINTS
// ─────────────────────────────────────────────────────────────────────────────

// POST /api/groups — Create a split group or trip
app.post('/api/groups', authenticateToken, async (req, res) => {
  const { id, name, description, start_date, end_date, currency, group_pin } = req.body;
  if (!name) return res.status(400).json({ message: "Group name required" });

  const groupId = id || crypto.randomUUID();
  const pin = group_pin || Math.floor(100000 + Math.random() * 900000).toString();

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SET search_path TO piggybag');
    
    // Create the group
    const groupRes = await client.query(
      `INSERT INTO expense_groups (id, created_by, name, description, start_date, end_date, currency, status, group_pin, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
       ON CONFLICT (id) DO UPDATE SET
         name = EXCLUDED.name,
         description = EXCLUDED.description,
         start_date = EXCLUDED.start_date,
         end_date = EXCLUDED.end_date,
         currency = EXCLUDED.currency,
         updated_at = NOW()
       RETURNING *`,
      [groupId, req.user.id, name, description || null, start_date || null, end_date || null, currency || '₹', 'Running', pin]
    );
    const newGroup = groupRes.rows[0];

    // Fetch user profile display name
    const userRes = await client.query("SELECT display_name FROM users WHERE user_id = $1", [req.user.id]);
    const displayName = userRes.rows[0]?.display_name || "Organizer";

    // Auto-add creator as a member if not already exists
    const memberCheck = await client.query(
      "SELECT id FROM expense_group_members WHERE group_id = $1 AND user_id = $2",
      [groupId, req.user.id]
    );
    if (memberCheck.rows.length === 0) {
      await client.query(
        `INSERT INTO expense_group_members (id, group_id, user_id, role, status, joined_at, display_name)
         VALUES ($1, $2, $3, 'creator', 'active', NOW(), $4)`,
        [crypto.randomUUID(), groupId, req.user.id, displayName]
      );
    }

    await client.query('COMMIT');
    res.status(201).json(newGroup);
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ message: "Error setting up group" });
  } finally {
    client.release();
  }
});

// POST /api/groups/join — Join group by PIN code
app.post('/api/groups/join', authenticateToken, async (req, res) => {
  const { group_pin } = req.body;
  if (!group_pin) return res.status(400).json({ message: "Group PIN required" });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SET search_path TO piggybag');

    // Find group
    const groupRes = await client.query(
      "SELECT * FROM expense_groups WHERE TRIM(group_pin) = TRIM($1) LIMIT 1",
      [group_pin]
    );
    if (groupRes.rows.length === 0) {
      return res.status(404).json({ message: "Group not found with this PIN." });
    }
    const group = groupRes.rows[0];

    // Check if already finalized
    if (group.status === 'Completed' || group.status === 'Finalized' || group.status === 'Archived') {
      return res.status(400).json({ message: "Cannot join: This group is finalized and locked." });
    }

    // Check if user is already a member
    const memberCheck = await client.query(
      "SELECT id FROM expense_group_members WHERE group_id = $1 AND user_id = $2",
      [group.id, req.user.id]
    );
    if (memberCheck.rows.length > 0) {
      await client.query('COMMIT');
      return res.json({ success: true, message: "Already joined", group });
    }

    // Enforce 12-member limit
    const countRes = await client.query(
      "SELECT COUNT(*) as count FROM expense_group_members WHERE group_id = $1",
      [group.id]
    );
    const memberCount = parseInt(countRes.rows[0].count, 10);
    if (memberCount >= 12) {
      return res.status(400).json({ message: "Cannot join: This group is full (maximum 12 members allowed)." });
    }

    // Fetch user details
    const userRes = await client.query("SELECT display_name FROM users WHERE user_id = $1", [req.user.id]);
    const displayName = userRes.rows[0]?.display_name || "Guest";

    // Insert new member
    await client.query(
      `INSERT INTO expense_group_members (id, group_id, user_id, role, status, joined_at, display_name)
       VALUES ($1, $2, $3, 'member', 'active', NOW(), $4)`,
      [crypto.randomUUID(), group.id, req.user.id, displayName]
    );

    // Notify other group members
    const otherMembers = await client.query(
      "SELECT user_id FROM expense_group_members WHERE group_id = $1 AND user_id != $2",
      [group.id, req.user.id]
    );
    for (const member of otherMembers.rows) {
      await sendNotification(
        member.user_id,
        "New Member Joined",
        `${displayName} joined your group "${group.name}".`,
        "group_expense"
      );
    }

    await client.query('COMMIT');
    res.json({ success: true, message: `Joined group split: ${group.name}!`, group });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ message: "Error joining group split" });
  } finally {
    client.release();
  }
});

// GET /api/groups — List all groups user belongs to
app.get('/api/groups', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT DISTINCT g.*,
       (SELECT COUNT(*) FROM expense_group_members WHERE group_id = g.id) as member_count
       FROM expense_groups g
       JOIN expense_group_members m ON g.id = m.group_id
       WHERE m.user_id = $1
       ORDER BY g.created_at DESC`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error fetching group splits" });
  }
});

// GET /api/groups/:id — Get details of a single group split
app.get('/api/groups/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const client = await pool.connect();
  try {
    await client.query('SET search_path TO piggybag');
    // Verify membership
    const memberCheck = await client.query(
      "SELECT id FROM expense_group_members WHERE group_id = $1 AND user_id = $2",
      [id, req.user.id]
    );
    if (memberCheck.rows.length === 0) {
      return res.status(403).json({ message: "Access denied: Not a member of this group." });
    }

    const groupRes = await client.query("SELECT * FROM expense_groups WHERE id = $1", [id]);
    const membersRes = await client.query("SELECT * FROM expense_group_members WHERE group_id = $1 ORDER BY display_name ASC", [id]);
    const expensesRes = await client.query(
      `SELECT e.*, m.display_name as memberName
       FROM expenses e
       LEFT JOIN expense_group_members m ON e.group_id = m.group_id AND e.paid_by = m.user_id
       WHERE e.group_id = $1 ORDER BY e.expense_date DESC`,
      [id]
    );
    const settlementsRes = await client.query("SELECT * FROM settlements WHERE group_id = $1 ORDER BY settlement_date DESC", [id]);

    res.json({
      group: groupRes.rows[0],
      members: membersRes.rows.map(m => ({
        id: m.id,
        groupId: m.group_id,
        userId: m.user_id,
        displayName: m.display_name,
        joinedDate: m.joined_at
      })),
      expenses: expensesRes.rows.map(e => ({
        id: e.id,
        groupId: e.group_id,
        userId: e.paid_by,
        amount: parseFloat(e.amount),
        description: e.title,
        expenseDate: e.expense_date,
        createdAt: e.created_at,
        memberName: e.memberName || "Unknown",
        participantsIncluded: e.participants_included || "",
        splitType: e.split_type || "Equal",
        shares: e.shares || ""
      })),
      settlements: settlementsRes.rows.map(s => ({
        id: s.id,
        groupId: s.group_id,
        fromUserId: s.from_user,
        fromUserName: s.from_user_name,
        toUserId: s.to_user,
        toUserName: s.to_user_name,
        amount: parseFloat(s.amount),
        status: s.status || "Pending"
      }))
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Error fetching group split details" });
  } finally {
    client.release();
  }
});

// POST /api/groups/:id/members — Add custom guest member or sync member
app.post('/api/groups/:id/members', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { id: memberId, userId, displayName, joinedDate } = req.body;

  if (!memberId || !displayName) return res.status(400).json({ message: "Member ID and Display Name required" });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SET search_path TO piggybag');

    // Verify membership
    const memberCheck = await client.query(
      "SELECT id FROM expense_group_members WHERE group_id = $1 AND user_id = $2",
      [id, req.user.id]
    );
    if (memberCheck.rows.length === 0) {
      return res.status(403).json({ message: "Access denied" });
    }

    // Enforce 12-member limit
    const countRes = await client.query(
      "SELECT COUNT(*) as count FROM expense_group_members WHERE group_id = $1",
      [id]
    );
    const memberCount = parseInt(countRes.rows[0].count, 10);
    
    // Check if member already exists
    const existingRes = await client.query(
      "SELECT id FROM expense_group_members WHERE group_id = $1 AND (id = $2 OR (user_id IS NOT NULL AND user_id = $3))",
      [id, memberId, userId || null]
    );

    if (existingRes.rows.length === 0 && memberCount >= 12) {
      return res.status(400).json({ message: "Group is full (maximum 12 members allowed)." });
    }

    const mUserId = userId || crypto.randomUUID();
    const joined = joinedDate || new Date();

    // Satisfy foreign key constraint: auto-create shadow user in users table if not exists
    const userExistRes = await client.query("SELECT user_id FROM users WHERE user_id = $1", [mUserId]);
    if (userExistRes.rows.length === 0) {
      const cleanUsername = `guest_${memberId.substring(0, 8)}_${Date.now().toString().slice(-4)}`;
      await client.query(
        `INSERT INTO users (user_id, username, email, display_name, password_hash, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'GUEST_USER', NOW(), NOW())`,
        [mUserId, cleanUsername, `${mUserId.substring(0, 8)}@guest.local`, displayName]
      );
    }

    await client.query(
      `INSERT INTO expense_group_members (id, group_id, user_id, role, status, joined_at, display_name)
       VALUES ($1, $2, $3, 'guest', 'active', $4, $5)
       ON CONFLICT (id) DO UPDATE SET
         display_name = EXCLUDED.display_name,
         joined_at = EXCLUDED.joined_at`,
      [memberId, id, mUserId, joined, displayName]
    );

    await client.query('COMMIT');
    res.status(201).json({ success: true, message: "Member synced successfully" });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ message: "Error syncing group member" });
  } finally {
    client.release();
  }
});

// POST /api/groups/:id/expenses — Add/Update/Delete group expense
app.post('/api/groups/:id/expenses', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { id: expenseId, amount, description, expenseDate, paidByUserId, splitType, participantsIncluded, shares, deleted } = req.body;

  if (!expenseId) return res.status(400).json({ message: "Expense ID is required" });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SET search_path TO piggybag');

    // Verify membership
    const memberCheck = await client.query(
      "SELECT id FROM expense_group_members WHERE group_id = $1 AND user_id = $2",
      [id, req.user.id]
    );
    if (memberCheck.rows.length === 0) {
      return res.status(403).json({ message: "Access denied" });
    }

    if (deleted) {
      const groupNameRes = await client.query("SELECT name FROM expense_groups WHERE id = $1", [id]);
      const groupName = groupNameRes.rows[0]?.name || "Group";

      await client.query("DELETE FROM expenses WHERE id = $1", [expenseId]);

      // Notify other members
      const otherMembers = await client.query("SELECT user_id FROM expense_group_members WHERE group_id = $1 AND user_id != $2", [id, req.user.id]);
      for (const member of otherMembers.rows) {
        await sendNotification(
          member.user_id,
          "Expense Deleted",
          `${req.user.display_name || req.user.username} deleted an expense in "${groupName}".`,
          "group_expense"
        );
      }

      await client.query('COMMIT');
      return res.json({ success: true, message: "Expense deleted" });
    }

    const payer = paidByUserId || req.user.id;
    const date = expenseDate || new Date();

    const groupNameRes = await client.query("SELECT name FROM expense_groups WHERE id = $1", [id]);
    const groupName = groupNameRes.rows[0]?.name || "Group";

    const existCheck = await client.query("SELECT id FROM expenses WHERE id = $1", [expenseId]);
    const action = existCheck.rows.length > 0 ? "updated" : "added";

    const insertRes = await client.query(
      `INSERT INTO expenses (id, group_id, created_by, paid_by, title, amount, expense_date, split_type, participants_included, shares, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW())
       ON CONFLICT (id) DO UPDATE SET
         paid_by = EXCLUDED.paid_by,
         title = EXCLUDED.title,
         amount = EXCLUDED.amount,
         expense_date = EXCLUDED.expense_date,
         split_type = EXCLUDED.split_type,
         participants_included = EXCLUDED.participants_included,
         shares = EXCLUDED.shares,
         updated_at = NOW()
       RETURNING *`,
      [expenseId, id, req.user.id, payer, description, amount, date, splitType, participantsIncluded, shares]
    );

    // Notify other members
    const otherMembers = await client.query("SELECT user_id FROM expense_group_members WHERE group_id = $1 AND user_id != $2", [id, req.user.id]);
    for (const member of otherMembers.rows) {
      await sendNotification(
        member.user_id,
        "Expense Update",
        `${req.user.display_name || req.user.username} ${action} expense "${description}" for ₹${parseFloat(amount).toFixed(2)} in "${groupName}".`,
        "group_expense"
      );
    }

    await client.query('COMMIT');
    res.status(201).json(insertRes.rows[0]);
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ message: "Error syncing group expense" });
  } finally {
    client.release();
  }
});

// POST /api/groups/:id/finalize — Finalize group report & save settlements
app.post('/api/groups/:id/finalize', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { settlements } = req.body; // Array of Settlement DTOs

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SET search_path TO piggybag');

    // Verify creator status
    const groupRes = await client.query("SELECT created_by FROM expense_groups WHERE id = $1", [id]);
    if (groupRes.rows.length === 0) return res.status(404).json({ message: "Group not found" });
    if (groupRes.rows[0].created_by !== req.user.id) {
      return res.status(403).json({ message: "Only the group creator can finalize the split report." });
    }

    // Update group status
    await client.query("UPDATE expense_groups SET status = 'Completed', updated_at = NOW() WHERE id = $1", [id]);

    // Clear and insert settlements
    await client.query("DELETE FROM settlements WHERE group_id = $1", [id]);

    if (settlements && Array.isArray(settlements)) {
      for (const s of settlements) {
        await client.query(
          `INSERT INTO settlements (id, group_id, from_user, to_user, amount, status, from_user_name, to_user_name, settlement_date, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())`,
          [s.id || crypto.randomUUID(), id, s.fromUserId, s.toUserId, s.amount, s.status || 'Pending', s.fromUserName, s.toUserName]
        );
      }
    }

    // Notify other group members
    const groupName = groupRes.rows[0]?.name || "Group";
    const otherMembers = await client.query("SELECT user_id FROM expense_group_members WHERE group_id = $1 AND user_id != $2", [id, req.user.id]);
    for (const member of otherMembers.rows) {
      await sendNotification(
        member.user_id,
        "Group Finalized",
        `The group "${groupName}" splits have been finalized by the creator. Check your settlements!`,
        "group_expense"
      );
    }

    await client.query('COMMIT');
    res.json({ success: true, message: "Group splits finalized successfully!" });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ message: "Error finalizing group splits" });
  } finally {
    client.release();
  }
});

// POST /api/groups/:id/reopen — Reopen finalized group split
app.post('/api/groups/:id/reopen', authenticateToken, async (req, res) => {
  const { id } = req.params;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SET search_path TO piggybag');

    // Verify creator status
    const groupRes = await client.query("SELECT created_by FROM expense_groups WHERE id = $1", [id]);
    if (groupRes.rows.length === 0) return res.status(404).json({ message: "Group not found" });
    if (groupRes.rows[0].created_by !== req.user.id) {
      return res.status(403).json({ message: "Only the group creator can reopen this group split." });
    }

    // Update group status to Running and delete settlements
    await client.query("UPDATE expense_groups SET status = 'Running', updated_at = NOW() WHERE id = $1", [id]);
    await client.query("DELETE FROM settlements WHERE group_id = $1", [id]);

    // Notify other group members
    const groupName = groupRes.rows[0]?.name || "Group";
    const otherMembers = await client.query("SELECT user_id FROM expense_group_members WHERE group_id = $1 AND user_id != $2", [id, req.user.id]);
    for (const member of otherMembers.rows) {
      await sendNotification(
        member.user_id,
        "Group Reopened",
        `The group "${groupName}" splits have been reopened.`,
        "group_expense"
      );
    }

    await client.query('COMMIT');
    res.json({ success: true, message: "Group reopened successfully!" });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ message: "Error reopening group split" });
  } finally {
    client.release();
  }
});

// PUT /api/groups/:id/settlements/:settlementId — Update settlement payment status
app.put('/api/groups/:id/settlements/:settlementId', authenticateToken, async (req, res) => {
  const { id, settlementId } = req.params;
  const { status } = req.body;

  if (!status) return res.status(400).json({ message: "Status required" });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SET search_path TO piggybag');

    // Verify membership of active user in group
    const memberCheck = await client.query(
      "SELECT id FROM expense_group_members WHERE group_id = $1 AND user_id = $2",
      [id, req.user.id]
    );
    if (memberCheck.rows.length === 0) {
      return res.status(403).json({ message: "Access denied" });
    }

    // Fetch settlement details to notify the partner user of payment updates
    const sDetails = await client.query("SELECT from_user, to_user, amount, from_user_name, to_user_name FROM settlements WHERE id = $1", [settlementId]);

    // Update settlement
    await client.query(
      "UPDATE settlements SET status = $1 WHERE id = $2 AND group_id = $3",
      [status, settlementId, id]
    );

    if (sDetails.rows.length > 0) {
      const s = sDetails.rows[0];
      const notifyUser = req.user.id === s.from_user ? s.to_user : s.from_user;
      const displayAmount = parseFloat(s.amount).toFixed(2);
      
      const groupDetails = await client.query("SELECT name FROM expense_groups WHERE id = $1", [id]);
      const groupName = groupDetails.rows[0]?.name || "Group";
      
      await sendNotification(
        notifyUser,
        "Settlement Paid Update",
        `Settlement of ₹${displayAmount} from ${s.from_user_name} to ${s.to_user_name} has been marked as "${status}" in "${groupName}".`,
        "group_expense"
      );
    }

    await client.query('COMMIT');
    res.json({ success: true, message: `Settlement status updated to ${status}!` });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ message: "Error updating settlement payment status" });
  } finally {
    client.release();
  }
});

// App initialization — bind database connection pool then start server
if (process.env.DATABASE_URL) {
  Promise.all([seedDefaultCategories(), ensureTypeColumn(), ensureGroupSplitColumns()])
    .then(() => {
      app.listen(PORT, () => {
        console.log(`TitanBag Sync server live on port ${PORT}`);
      });
    })
    .catch(err => {
      console.error("Database engine boot failure:", err);
      process.exit(1);
    });
} else {
  console.error("Missing database target configuration.");
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
    database: process.env.DATABASE_URL ? "Connected (PostgreSQL)" : "Demo Mode (Disconnected)"
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

app.post('/api/god/test-email', authenticateGodToken, async (req, res) => {
  const { to, subject, html } = req.body;
  if (!to || !subject || !html) {
    return res.status(400).json({ message: "Recipient (to), subject, and html body are required" });
  }

  try {
    const emailRes = await resend.emails.send({
      from: 'onboarding@resend.dev',
      to: to.trim(),
      subject: subject.trim(),
      html: html
    });

    res.status(200).json({ success: true, data: emailRes });
  } catch (err) {
    console.error("Test email send failed:", err);
    res.status(500).json({ success: false, message: err.message || "Failed to send test email" });
  }
});

// Helper to send a notification (saves in postgres)
async function sendNotification(userId, title, message, destination) {
  try {
    const id = crypto.randomUUID();
    await pool.query(
      `INSERT INTO piggybag.notifications (id, user_id, title, message, destination, read, created_at)
       VALUES ($1, $2, $3, $4, $5, false, NOW())`,
      [id, userId, title, message, destination || null]
    );
    console.log(`Notification inserted for ${userId}: ${title}`);
  } catch (err) {
    console.error("Failed to insert notification:", err);
  }
}

// Endpoint: GET /api/notifications
// Retrieves unread notifications and marks them as read
app.get('/api/notifications', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SET search_path TO piggybag');
    
    const result = await client.query(
      `SELECT id, title, message, destination, created_at 
       FROM notifications 
       WHERE user_id = $1 AND read = false 
       ORDER BY created_at ASC`,
      [req.user.id]
    );
    
    if (result.rows.length > 0) {
      const ids = result.rows.map(r => r.id);
      await client.query(
        `UPDATE notifications SET read = true WHERE id = ANY($1::uuid[])`,
        [ids]
      );
    }
    
    await client.query('COMMIT');
    res.json({ notifications: result.rows });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error("Error retrieving notifications:", err);
    res.status(500).json({ message: "Error retrieving notifications" });
  } finally {
    client.release();
  }
});

// Endpoint: POST /api/security/recovery/request
// Initiate recovery from connected partner
app.post('/api/security/recovery/request', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('SET search_path TO piggybag');
    
    // Find connected partner
    const partnerRes = await client.query(
      `SELECT user_one_id, user_two_id FROM partners
       WHERE (user_one_id = $1 OR user_two_id = $1) AND status = 'active' LIMIT 1`,
      [req.user.id]
    );
    
    if (partnerRes.rows.length === 0) {
      return res.status(400).json({ message: "Recovery is only available if a partner account is connected." });
    }
    
    const p = partnerRes.rows[0];
    const partnerId = p.user_one_id === req.user.id ? p.user_two_id : p.user_one_id;
    
    // Generate secure random 6 digit code
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const codeHash = crypto.createHash('sha256').update(code).digest('hex');
    
    // Delete older requests
    await client.query(
      "DELETE FROM password_recoveries WHERE request_user_id = $1",
      [req.user.id]
    );
    
    const requestId = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes from now
    
    await client.query(
      `INSERT INTO password_recoveries (id, request_user_id, partner_id, code_hash, expires_at, used, status, created_at)
       VALUES ($1, $2, $3, $4, $5, false, 'Pending', NOW())`,
      [requestId, req.user.id, partnerId, codeHash, expiresAt]
    );
    
    // Fetch requester display name
    const userRes = await client.query("SELECT display_name FROM users WHERE user_id = $1", [req.user.id]);
    const requesterName = userRes.rows[0]?.display_name || "Your partner";
    
    // Send transient notification to partner containing the code (Method 1) and request (Method 2)
    await sendNotification(
      partnerId,
      "App Lock Recovery Request",
      `${requesterName} has requested App Lock recovery. Code: ${code}`,
      "partner_sharing"
    );
    
    res.json({ success: true, message: "Recovery request generated successfully. Ask your partner for code." });
  } catch (err) {
    console.error("Error generating recovery request:", err);
    res.status(500).json({ message: "Server error generating recovery request" });
  } finally {
    client.release();
  }
});

// Endpoint: GET /api/security/recovery/status
// Poll request status (Method 2: partner approval check)
app.get('/api/security/recovery/status', authenticateToken, async (req, res) => {
  try {
    const resu = await pool.query(
      `SELECT status FROM piggybag.password_recoveries 
       WHERE request_user_id = $1 AND used = false AND expires_at > NOW() 
       ORDER BY created_at DESC LIMIT 1`,
      [req.user.id]
    );
    const approved = resu.rows.length > 0 && resu.rows[0].status === 'Approved';
    res.json({ approved });
  } catch (err) {
    console.error("Error checking recovery status:", err);
    res.status(500).json({ message: "Error checking recovery status" });
  }
});

// Endpoint: POST /api/security/recovery/verify-code
// Verify the entered 6-digit code (Method 1)
app.post('/api/security/recovery/verify-code', authenticateToken, async (req, res) => {
  const { code } = req.body;
  if (!code) {
    return res.status(400).json({ message: "Recovery code is required" });
  }
  
  const client = await pool.connect();
  try {
    await client.query('SET search_path TO piggybag');
    
    const requestRes = await client.query(
      `SELECT id, code_hash FROM password_recoveries 
       WHERE request_user_id = $1 AND used = false AND expires_at > NOW() 
       ORDER BY created_at DESC LIMIT 1`,
      [req.user.id]
    );
    
    if (requestRes.rows.length === 0) {
      return res.status(400).json({ message: "No active recovery request found or code expired." });
    }
    
    const request = requestRes.rows[0];
    const inputHash = crypto.createHash('sha256').update(code.trim()).digest('hex');
    
    if (inputHash !== request.code_hash) {
      return res.status(400).json({ message: "Incorrect verification code." });
    }
    
    // Mark as approved & verified
    await client.query(
      "UPDATE password_recoveries SET status = 'Approved' WHERE id = $1",
      [request.id]
    );
    
    res.json({ success: true, message: "Code verified successfully." });
  } catch (err) {
    console.error("Error verifying recovery code:", err);
    res.status(500).json({ message: "Server error verifying code" });
  } finally {
    client.release();
  }
});

// Endpoint: POST /api/security/recovery/approve
// Partner approves the recovery request (Method 2)
app.post('/api/security/recovery/approve', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('SET search_path TO piggybag');
    
    // Find active pending request where req.user.id is the partner
    const pendingRequest = await client.query(
      `SELECT id, request_user_id FROM password_recoveries 
       WHERE partner_id = $1 AND status = 'Pending' AND expires_at > NOW() 
       ORDER BY created_at DESC LIMIT 1`,
      [req.user.id]
    );
    
    if (pendingRequest.rows.length === 0) {
      return res.status(404).json({ message: "No pending recovery requests found." });
    }
    
    const request = pendingRequest.rows[0];
    await client.query(
      "UPDATE password_recoveries SET status = 'Approved' WHERE id = $1",
      [request.id]
    );
    
    // Notify requesting user
    await sendNotification(
      request.request_user_id,
      "Recovery Request Approved",
      "Your partner approved your App Lock reset request. You may now create a new lock credential.",
      "partner_sharing"
    );
    
    res.json({ success: true, message: "Recovery request approved successfully." });
  } catch (err) {
    console.error("Error approving recovery request:", err);
    res.status(500).json({ message: "Server error approving request" });
  } finally {
    client.release();
  }
});

// Endpoint: POST /api/security/recovery/reset-lock
// Reset and consume the request
app.post('/api/security/recovery/reset-lock', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE piggybag.password_recoveries 
       SET used = true 
       WHERE request_user_id = $1 AND status = 'Approved' AND used = false AND expires_at > NOW()`,
      [req.user.id]
    );
    if (result.rowCount === 0) {
      return res.status(400).json({ message: "No approved and active reset request found." });
    }
    res.json({ success: true, message: "Reset permission consumed." });
  } catch (err) {
    console.error("Error resetting lock:", err);
    res.status(500).json({ message: "Error resetting lock" });
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