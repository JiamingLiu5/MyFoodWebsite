require('dotenv').config();
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { S3Client, PutObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');
let nodemailer = null;
try {
  nodemailer = require('nodemailer');
} catch (err) {
  // Optional dependency: registration email verification stays disabled until installed.
}

const app = express();
app.disable('x-powered-by');
const PORT = process.env.PORT || 3000;
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data.db');
const BODY_LIMIT = process.env.BODY_LIMIT || '256kb';
const DAILY_UPLOAD_LIMIT = Math.max(1, Number.parseInt(process.env.DAILY_UPLOAD_LIMIT || '1000', 10));
const DAILY_REGISTRATION_LIMIT = Math.max(1, Number.parseInt(process.env.DAILY_REGISTRATION_LIMIT || '200', 10));
const MAX_IMAGES_PER_POST = Math.max(1, Number.parseInt(process.env.MAX_IMAGES_PER_POST || '10', 10));
const MAX_UPLOAD_FILE_SIZE_MB = Math.max(1, Number.parseInt(process.env.MAX_UPLOAD_FILE_SIZE_MB || '10', 10));
const MAX_UPLOAD_FILE_SIZE_BYTES = MAX_UPLOAD_FILE_SIZE_MB * 1024 * 1024;
const AUTH_RATE_LIMIT_WINDOW_MINUTES = Math.max(1, Number.parseInt(process.env.AUTH_RATE_LIMIT_WINDOW_MINUTES || '15', 10));
const AUTH_RATE_LIMIT_MAX_ATTEMPTS = Math.max(1, Number.parseInt(process.env.AUTH_RATE_LIMIT_MAX_ATTEMPTS || '25', 10));
const AUTH_RATE_LIMIT_WINDOW_MS = AUTH_RATE_LIMIT_WINDOW_MINUTES * 60 * 1000;
const TRUST_PROXY = process.env.TRUST_PROXY === 'true';
const SESSION_COOKIE_SECURE = process.env.SESSION_COOKIE_SECURE === 'true';
const SESSION_COOKIE_SAME_SITE = process.env.SESSION_COOKIE_SAME_SITE || 'lax';
const REGISTRATION_CODE_TTL_MINUTES = Math.max(
  1,
  Number.parseInt(process.env.REGISTRATION_CODE_TTL_MINUTES || '10', 10)
);
const REGISTRATION_CODE_TTL_MS = REGISTRATION_CODE_TTL_MINUTES * 60 * 1000;
const SMTP_HOST = (process.env.SMTP_HOST || '').trim();
const SMTP_PORT = Math.max(1, Number.parseInt(process.env.SMTP_PORT || '587', 10));
const SMTP_SECURE = process.env.SMTP_SECURE === 'true';
const SMTP_USER = (process.env.SMTP_USER || '').trim();
const SMTP_PASS = process.env.SMTP_PASS || '';
const SMTP_FROM = (process.env.SMTP_FROM || '').trim();
const EMAIL_VERIFICATION_ENABLED = Boolean(nodemailer && SMTP_HOST && SMTP_FROM);
const hasR2UploadConfig = Boolean(
  process.env.R2_ENDPOINT &&
  process.env.R2_BUCKET &&
  process.env.R2_ACCESS_KEY_ID &&
  process.env.R2_SECRET_ACCESS_KEY
);

fs.mkdirSync(UPLOADS_DIR, { recursive: true });
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

if (TRUST_PROXY) {
  app.set('trust proxy', 1);
}

// Configure storage: we'll upload to Cloudflare R2 using S3-compatible API.
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    files: MAX_IMAGES_PER_POST,
    fileSize: MAX_UPLOAD_FILE_SIZE_BYTES
  }
});

// Setup view engine and static
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use('/static', express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOADS_DIR));
app.use(express.urlencoded({ extended: true, limit: BODY_LIMIT }));

// Sessions (simple memory store for dev)
app.use(session({
  secret: process.env.SESSION_SECRET || 'devsecret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: SESSION_COOKIE_SECURE,
    sameSite: SESSION_COOKIE_SAME_SITE,
    httpOnly: true
  }
}));

// Basic HTTP security headers.
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  if (req.secure || SESSION_COOKIE_SECURE) {
    res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
  }
  next();
});

function ensureSessionCsrfToken(req) {
  if (!req.session) return '';
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  return req.session.csrfToken;
}

function verifyCsrfToken(req, res, next) {
  const expected = req.session ? req.session.csrfToken : '';
  const provided = String(
    (req.body && req.body._csrf) ||
    req.get('x-csrf-token') ||
    ''
  );

  if (!expected || !provided || provided !== expected) {
    return res.status(403).send('Invalid CSRF token');
  }
  return next();
}

// Expose CSRF token to all templates.
app.use((req, res, next) => {
  res.locals.csrfToken = ensureSessionCsrfToken(req);
  next();
});

const authRateLimitBuckets = new Map();

function makeAuthRateLimiter(scope) {
  return (req, res, next) => {
    const now = Date.now();
    if (authRateLimitBuckets.size > 5000) {
      for (const [bucketKey, bucketValue] of authRateLimitBuckets.entries()) {
        if (bucketValue.resetAt <= now) authRateLimitBuckets.delete(bucketKey);
      }
    }
    const ip = req.ip || req.socket?.remoteAddress || 'unknown';
    const key = `${scope}:${ip}`;
    const current = authRateLimitBuckets.get(key);

    if (!current || current.resetAt <= now) {
      authRateLimitBuckets.set(key, { count: 1, resetAt: now + AUTH_RATE_LIMIT_WINDOW_MS });
      return next();
    }

    if (current.count >= AUTH_RATE_LIMIT_MAX_ATTEMPTS) {
      const retryAfterSeconds = Math.max(1, Math.ceil((current.resetAt - now) / 1000));
      res.setHeader('Retry-After', String(retryAfterSeconds));
      return res.status(429).send('Too many attempts. Please try again later.');
    }

    current.count += 1;
    authRateLimitBuckets.set(key, current);
    return next();
  };
}

// Attach user role/permissions to request for authorization checks
app.use(async (req, res, next) => {
  if (req.session && req.session.userId) {
    // Use session cache if available
    if (req.session.userRole && typeof req.session.userCanPin === 'boolean') {
      req.userRole = req.session.userRole;
      req.userCanPin = req.session.userCanPin;
    } else {
      // Fetch from DB and cache in session
      const user = await dbGetAsync('SELECT role, can_pin FROM users WHERE id = ?', [req.session.userId]);
      req.userRole = user ? user.role : null;
      req.userCanPin = Boolean(user && Number(user.can_pin || 0) === 1);
      if (req.userRole) {
        req.session.userRole = req.userRole;
        req.session.userCanPin = req.userCanPin;
      }
    }
    res.locals.userRole = req.userRole; // Make available to views
    res.locals.userCanPin = req.userCanPin;
  } else {
    req.userRole = null;
    req.userCanPin = false;
    res.locals.userRole = null;
    res.locals.userCanPin = false;
  }
  next();
});

// DB
const db = new sqlite3.Database(DB_PATH);
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT,
    originalname TEXT,
    note TEXT,
    is_pinned INTEGER DEFAULT 0,
    created_at INTEGER
  )`);
  db.all('PRAGMA table_info(entries)', (pragmaErr, cols) => {
    if (pragmaErr) return console.error('PRAGMA entries error:', pragmaErr);
    const hasPinned = Array.isArray(cols) && cols.some((col) => col.name === 'is_pinned');
    if (!hasPinned) {
      db.run('ALTER TABLE entries ADD COLUMN is_pinned INTEGER DEFAULT 0', (alterErr) => {
        if (alterErr) console.error('entries migration error:', alterErr);
      });
    }
    // Migration: Add user_id column to entries table
    const hasUserId = Array.isArray(cols) && cols.some((col) => col.name === 'user_id');
    if (!hasUserId) {
      db.run('ALTER TABLE entries ADD COLUMN user_id INTEGER', (alterErr) => {
        if (alterErr) return console.error('entries user_id migration error:', alterErr);
        console.log('✓ Added user_id column to entries');
        // Set existing entries to first user (id=1)
        db.run('UPDATE entries SET user_id = 1 WHERE user_id IS NULL', (updateErr) => {
          if (updateErr) console.error('entries user_id backfill error:', updateErr);
          else console.log('✓ Backfilled existing entries to user_id = 1');
        });
        // Create index for faster queries
        db.run('CREATE INDEX IF NOT EXISTS idx_entries_user_id ON entries(user_id)');
      });
    }
  });
  db.run(`CREATE TABLE IF NOT EXISTS entry_images (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    originalname TEXT,
    sort_order INTEGER DEFAULT 0
  )`);
  db.run('CREATE INDEX IF NOT EXISTS idx_entry_images_entry_id ON entry_images(entry_id)');
  // Backfill legacy single-image entries into entry_images.
  db.run(`
    INSERT INTO entry_images(entry_id, filename, originalname, sort_order)
    SELECT e.id, e.filename, e.originalname, 0
    FROM entries e
    WHERE e.filename IS NOT NULL
      AND NOT EXISTS (
        SELECT 1 FROM entry_images i WHERE i.entry_id = e.id
      )
  `);
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    password_hash TEXT,
    role TEXT DEFAULT "normal",
    can_pin INTEGER DEFAULT 0,
    email_verified_at INTEGER
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS pending_registrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    verification_code TEXT NOT NULL,
    code_expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  )`);
  db.run('CREATE INDEX IF NOT EXISTS idx_pending_registrations_expires ON pending_registrations(code_expires_at)');
  // Migration: Add role column to users table
  db.all('PRAGMA table_info(users)', (pragmaErr, cols) => {
    if (pragmaErr) return console.error('PRAGMA users error:', pragmaErr);
    const ensureUsersEmailIndex = () => {
      db.run(
        'CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique ON users(email) WHERE email IS NOT NULL',
        (indexErr) => {
          if (indexErr) console.error('users email index migration error:', indexErr);
        }
      );
    };
    const hasRole = Array.isArray(cols) && cols.some((col) => col.name === 'role');
    if (!hasRole) {
      db.run('ALTER TABLE users ADD COLUMN role TEXT DEFAULT "normal"', (alterErr) => {
        if (alterErr) return console.error('users role migration error:', alterErr);
        console.log('✓ Added role column to users');
        // Set first user to admin
        db.run('UPDATE users SET role = "admin" WHERE id = 1', (updateErr) => {
          if (updateErr) console.error('users role update error:', updateErr);
          else console.log('✓ First user set to admin role');
        });
      });
    }
    const hasEmail = Array.isArray(cols) && cols.some((col) => col.name === 'email');
    if (!hasEmail) {
      db.run('ALTER TABLE users ADD COLUMN email TEXT', (alterErr) => {
        if (alterErr) console.error('users email migration error:', alterErr);
        else {
          console.log('✓ Added email column to users');
          ensureUsersEmailIndex();
        }
      });
    } else {
      ensureUsersEmailIndex();
    }
    const hasEmailVerifiedAt = Array.isArray(cols) && cols.some((col) => col.name === 'email_verified_at');
    if (!hasEmailVerifiedAt) {
      db.run('ALTER TABLE users ADD COLUMN email_verified_at INTEGER', (alterErr) => {
        if (alterErr) console.error('users email_verified_at migration error:', alterErr);
        else console.log('✓ Added email_verified_at column to users');
      });
    }
    const hasCanPin = Array.isArray(cols) && cols.some((col) => col.name === 'can_pin');
    if (!hasCanPin) {
      db.run('ALTER TABLE users ADD COLUMN can_pin INTEGER DEFAULT 0', (alterErr) => {
        if (alterErr) return console.error('users can_pin migration error:', alterErr);
        console.log('✓ Added can_pin column to users');
      });
    }
  });
});

// Configure S3 client for R2
const s3 = new S3Client({
  region: process.env.R2_REGION || 'auto',
  endpoint: process.env.R2_ENDPOINT || undefined,
  credentials: process.env.R2_ACCESS_KEY_ID ? {
    accessKeyId: process.env.R2_ACCESS_KEY_ID,
    secretAccessKey: process.env.R2_SECRET_ACCESS_KEY
  } : undefined,
});

function buildFileUrl(key) {
  if (hasR2UploadConfig && process.env.R2_PUBLIC_BASE_URL) {
    return `${process.env.R2_PUBLIC_BASE_URL.replace(/\/$/, '')}/${key}`;
  }
  if (hasR2UploadConfig && process.env.R2_ENDPOINT && process.env.R2_BUCKET) {
    return `${process.env.R2_ENDPOINT.replace(/\/$/, '')}/${process.env.R2_BUCKET}/${key}`;
  }
  return `/uploads/${key}`;
}

function dbGetAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}

function dbAllAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

function dbRunAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function runHandler(err) {
      if (err) return reject(err);
      resolve(this);
    });
  });
}

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function generateVerificationCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function maskEmail(email) {
  const [local, domain] = String(email || '').split('@');
  if (!local || !domain) return email;
  const first = local.slice(0, 1);
  const last = local.length > 1 ? local.slice(-1) : '';
  return `${first}${'*'.repeat(Math.max(1, local.length - 2))}${last}@${domain}`;
}

let emailTransporter = null;

function getEmailTransporter() {
  if (!EMAIL_VERIFICATION_ENABLED) return null;
  if (emailTransporter) return emailTransporter;
  const baseConfig = {
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_SECURE
  };
  if (SMTP_USER && SMTP_PASS) {
    baseConfig.auth = {
      user: SMTP_USER,
      pass: SMTP_PASS
    };
  }
  emailTransporter = nodemailer.createTransport(baseConfig);
  return emailTransporter;
}

async function sendRegistrationVerificationEmail(email, username, code) {
  const transporter = getEmailTransporter();
  if (!transporter) throw new Error('Email verification is not configured');

  await transporter.sendMail({
    from: SMTP_FROM,
    to: email,
    subject: 'Your MyFoodWebsite confirmation code',
    text: [
      `Hi ${username},`,
      '',
      `Your confirmation code is: ${code}`,
      `This code expires in ${REGISTRATION_CODE_TTL_MINUTES} minute(s).`,
      '',
      'If you did not request this, please ignore this email.'
    ].join('\n')
  });
}

const ENTRY_SELECT_WITH_AUTHOR = `
  SELECT e.*, u.username AS author_username
  FROM entries e
  LEFT JOIN users u ON u.id = e.user_id
`;

async function getEntryImagesForEntry(entryId, legacyEntry) {
  const rows = await dbAllAsync(
    'SELECT id, entry_id, filename, originalname, sort_order FROM entry_images WHERE entry_id = ? ORDER BY sort_order, id',
    [entryId]
  );
  if (rows.length > 0) return rows;
  if (legacyEntry && legacyEntry.filename) {
    await dbRunAsync(
      'INSERT INTO entry_images(entry_id, filename, originalname, sort_order) VALUES (?,?,?,?)',
      [entryId, legacyEntry.filename, legacyEntry.originalname || null, 0]
    );
    return dbAllAsync(
      'SELECT id, entry_id, filename, originalname, sort_order FROM entry_images WHERE entry_id = ? ORDER BY sort_order, id',
      [entryId]
    );
  }
  return [];
}

async function getEntryImagesMap(entryIds, entriesById) {
  const map = {};
  if (!entryIds.length) return map;

  const placeholders = entryIds.map(() => '?').join(',');
  const rows = await dbAllAsync(
    `SELECT id, entry_id, filename, originalname, sort_order
     FROM entry_images
     WHERE entry_id IN (${placeholders})
     ORDER BY entry_id, sort_order, id`,
    entryIds
  );

  for (const row of rows) {
    if (!map[row.entry_id]) map[row.entry_id] = [];
    map[row.entry_id].push(row);
  }

  for (const entryId of entryIds) {
    if (!map[entryId] || map[entryId].length === 0) {
      const legacy = entriesById[entryId];
      if (legacy && legacy.filename) {
        map[entryId] = [{
          id: null,
          entry_id: entryId,
          filename: legacy.filename,
          originalname: legacy.originalname || null,
          sort_order: 0
        }];
      } else {
        map[entryId] = [];
      }
    }
  }

  return map;
}

async function deleteStoredFile(filename) {
  if (!filename) return;

  if (hasR2UploadConfig) {
    await s3.send(new DeleteObjectCommand({
      Bucket: process.env.R2_BUCKET,
      Key: filename
    }));
    return;
  }

  const safeFilename = path.basename(filename);
  await fs.promises.unlink(path.join(UPLOADS_DIR, safeFilename));
}

async function storeUploadedFile(file) {
  const safeOriginalName = (file.originalname || 'upload.bin').replace(/[^a-z0-9.\-\_]/gi, '_');
  const key = `${Date.now()}-${safeOriginalName}`;

  if (hasR2UploadConfig) {
    const put = new PutObjectCommand({
      Bucket: process.env.R2_BUCKET,
      Key: key,
      Body: file.buffer,
      ContentType: file.mimetype
    });
    await s3.send(put);
  } else {
    await fs.promises.writeFile(path.join(UPLOADS_DIR, key), file.buffer);
  }

  return { key, originalname: file.originalname || null };
}

function ensureAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  res.redirect('/login');
}

// New ensureAdmin - for admin-only routes
async function ensureAdmin(req, res, next) {
  if (!req.session || !req.session.userId) return res.redirect('/login');
  if (req.userRole !== 'admin') return res.status(403).send('Admin access required');
  return next();
}

function canPinPosts(req) {
  return req.userRole === 'admin' || req.userCanPin === true;
}

function ensureCanPin(req, res, next) {
  if (!req.session || !req.session.userId) return res.redirect('/login');
  if (!canPinPosts(req)) return res.status(403).send('Pin permission required');
  return next();
}

// Check if user owns the resource or is admin
async function ensureOwnerOrAdmin(req, res, next) {
  if (!req.session || !req.session.userId) return res.redirect('/login');

  const entryId = req.params.id;
  const entry = await dbGetAsync('SELECT user_id FROM entries WHERE id = ?', [entryId]);

  if (!entry) return res.status(404).send('Entry not found');

  const isOwner = entry.user_id === req.session.userId;
  const isAdmin = req.userRole === 'admin';

  if (isOwner || isAdmin) return next();
  return res.status(403).send('You can only edit your own posts');
}

function getDayRangeMs(date = new Date()) {
  const start = new Date(date);
  start.setHours(0, 0, 0, 0);
  const end = new Date(start);
  end.setDate(end.getDate() + 1);
  return { startMs: start.getTime(), endMs: end.getTime() };
}

function getEntryCountInRange(startMs, endMs) {
  return new Promise((resolve, reject) => {
    db.get(
      'SELECT COUNT(*) AS c FROM entries WHERE created_at >= ? AND created_at < ?',
      [startMs, endMs],
      (err, row) => {
        if (err) return reject(err);
        resolve(row?.c || 0);
      }
    );
  });
}

function getRegistrationCountInRange(startMs, endMs) {
  return new Promise((resolve, reject) => {
    db.get(
      'SELECT COUNT(*) AS c FROM users WHERE email_verified_at >= ? AND email_verified_at < ?',
      [startMs, endMs],
      (err, row) => {
        if (err) return reject(err);
        resolve(row?.c || 0);
      }
    );
  });
}

app.get('/', async (req, res) => {
  try {
    const isAdmin = req.userRole === 'admin';
    const userCanPin = canPinPosts(req);
    const userId = req.session.userId;

    let rows;
    if (isAdmin) {
      // Admins see all posts
      rows = await dbAllAsync(
        `${ENTRY_SELECT_WITH_AUTHOR}
         ORDER BY COALESCE(e.is_pinned, 0) DESC, e.created_at DESC`
      );
    } else if (userId) {
      // Normal users see: pinned posts OR their own posts
      rows = await dbAllAsync(
        `${ENTRY_SELECT_WITH_AUTHOR}
         WHERE COALESCE(e.is_pinned, 0) = 1 OR e.user_id = ?
         ORDER BY COALESCE(e.is_pinned, 0) DESC, e.created_at DESC`,
        [userId]
      );
    } else {
      // Non-authenticated users see only pinned posts
      rows = await dbAllAsync(
        `${ENTRY_SELECT_WITH_AUTHOR}
         WHERE COALESCE(e.is_pinned, 0) = 1
         ORDER BY e.created_at DESC`
      );
    }

    const countRow = await dbGetAsync('SELECT COUNT(*) AS c FROM users');
    const ids = rows.map((row) => row.id);
    const entriesById = Object.fromEntries(rows.map((row) => [row.id, row]));
    const imagesMap = await getEntryImagesMap(ids, entriesById);
    const entries = rows.map((row) => ({ ...row, images: imagesMap[row.id] || [] }));

    const uploadError = req.query.error === 'daily_limit'
      ? `Daily upload limit reached (${DAILY_UPLOAD_LIMIT} posts). Try again tomorrow.`
      : null;

    res.render('index', {
      entries,
      userId: req.session.userId,
      userRole: req.userRole,
      userCanPin,
      canRegister: true, // Always allow registration now
      uploadError,
      maxImagesPerPost: MAX_IMAGES_PER_POST,
      showPinnedOnly: !isAdmin
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('DB error');
  }
});

app.post('/upload', ensureAuth, upload.array('photos', MAX_IMAGES_PER_POST), verifyCsrfToken, async (req, res) => {
  const note = req.body.note || '';
  const files = Array.isArray(req.files) ? req.files : [];
  const storedFiles = [];

  try {
    const { startMs, endMs } = getDayRangeMs();
    const dailyCount = await getEntryCountInRange(startMs, endMs);
    if (dailyCount >= DAILY_UPLOAD_LIMIT) {
      return res.redirect('/?error=daily_limit');
    }

    for (const file of files) {
      const stored = await storeUploadedFile(file);
      storedFiles.push(stored);
    }

    const first = storedFiles[0] || null;
    const createdAt = Date.now();
    const insertResult = await dbRunAsync(
      'INSERT INTO entries(filename, originalname, note, is_pinned, created_at, user_id) VALUES (?,?,?,?,?,?)',
      [first ? first.key : null, first ? first.originalname : null, note, 0, createdAt, req.session.userId]
    );

    for (let i = 0; i < storedFiles.length; i += 1) {
      const item = storedFiles[i];
      await dbRunAsync(
        'INSERT INTO entry_images(entry_id, filename, originalname, sort_order) VALUES (?,?,?,?)',
        [insertResult.lastID, item.key, item.originalname, i]
      );
    }

    res.redirect('/');
  } catch (err) {
    console.error(err);
    await Promise.allSettled(storedFiles.map((item) => deleteStoredFile(item.key)));
    res.status(500).send('Upload error');
  }
});

app.get('/entries/:id', async (req, res) => {
  const entryId = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(entryId) || entryId <= 0) {
    return res.status(400).send('Invalid entry id');
  }

  try {
    const row = await dbGetAsync(
      `${ENTRY_SELECT_WITH_AUTHOR}
       WHERE e.id = ?`,
      [entryId]
    );
    if (!row) return res.status(404).send('Entry not found');

    const isAdmin = req.userRole === 'admin';
    const isPinned = Number(row.is_pinned || 0) === 1;
    const isOwner = req.session.userId === row.user_id;

    // Can view if: admin, pinned, or owner
    if (!isAdmin && !isPinned && !isOwner) {
      return res.redirect('/login');
    }

    const images = await getEntryImagesForEntry(entryId, row);
    res.render('entry', {
      entry: { ...row, images },
      userId: req.session.userId,
      userRole: req.userRole,
      userCanPin: canPinPosts(req)
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('DB error');
  }
});

app.post('/entries/:id/pin', ensureCanPin, verifyCsrfToken, async (req, res) => {
  const entryId = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(entryId) || entryId <= 0) {
    return res.status(400).send('Invalid entry id');
  }

  const pinnedRaw = String(req.body.pinned || '').trim();
  const pinned = pinnedRaw === '1' ? 1 : 0;

  try {
    const row = await dbGetAsync('SELECT id FROM entries WHERE id = ?', [entryId]);
    if (!row) return res.status(404).send('Entry not found');
    await dbRunAsync('UPDATE entries SET is_pinned = ? WHERE id = ?', [pinned, entryId]);
    const returnToRaw = typeof req.body.returnTo === 'string' ? req.body.returnTo.trim() : '';
    const returnTo = (returnToRaw === '/' || returnToRaw.startsWith('/entries/')) ? returnToRaw : '/';
    res.redirect(returnTo);
  } catch (err) {
    console.error(err);
    res.status(500).send('Pin update error');
  }
});

app.get('/entries/:id/edit', ensureOwnerOrAdmin, async (req, res) => {
  const entryId = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(entryId) || entryId <= 0) {
    return res.status(400).send('Invalid entry id');
  }

  try {
    const row = await dbGetAsync('SELECT * FROM entries WHERE id = ?', [entryId]);
    if (!row) return res.status(404).send('Entry not found');
    const images = await getEntryImagesForEntry(entryId, row);
    res.render('edit', { entry: { ...row, images }, error: null, maxImagesPerPost: MAX_IMAGES_PER_POST });
  } catch (err) {
    console.error(err);
    res.status(500).send('DB error');
  }
});

app.post('/entries/:id/edit', ensureOwnerOrAdmin, upload.array('photos', MAX_IMAGES_PER_POST), verifyCsrfToken, async (req, res) => {
  const entryId = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(entryId) || entryId <= 0) {
    return res.status(400).send('Invalid entry id');
  }

  const note = req.body.note || '';
  const removeAllPhotos = req.body.removeAllPhotos === 'on';
  const removeImageIdsRaw = req.body.removeImageIds;
  const removeImageIds = new Set(
    (Array.isArray(removeImageIdsRaw) ? removeImageIdsRaw : [removeImageIdsRaw])
      .map((value) => Number.parseInt(value, 10))
      .filter((value) => Number.isInteger(value) && value > 0)
  );
  const newFiles = Array.isArray(req.files) ? req.files : [];
  const newlyStored = [];

  try {
    const row = await dbGetAsync('SELECT * FROM entries WHERE id = ?', [entryId]);
    if (!row) return res.status(404).send('Entry not found');

    const existingImages = await getEntryImagesForEntry(entryId, row);
    const imagesToRemove = removeAllPhotos
      ? existingImages
      : existingImages.filter((image) => removeImageIds.has(image.id));
    const retainedCount = existingImages.length - imagesToRemove.length;
    if (retainedCount + newFiles.length > MAX_IMAGES_PER_POST) {
      return res.status(400).render('edit', {
        entry: { ...row, images: existingImages },
        error: `You can store up to ${MAX_IMAGES_PER_POST} images in one post.`,
        maxImagesPerPost: MAX_IMAGES_PER_POST
      });
    }

    for (const file of newFiles) {
      const stored = await storeUploadedFile(file);
      newlyStored.push(stored);
    }

    if (imagesToRemove.length > 0) {
      if (removeAllPhotos) {
        await dbRunAsync('DELETE FROM entry_images WHERE entry_id = ?', [entryId]);
      } else {
        const ids = imagesToRemove.map((image) => image.id);
        const placeholders = ids.map(() => '?').join(',');
        await dbRunAsync(
          `DELETE FROM entry_images WHERE entry_id = ? AND id IN (${placeholders})`,
          [entryId, ...ids]
        );
      }

      for (const image of imagesToRemove) {
        try {
          await deleteStoredFile(image.filename);
        } catch (fileErr) {
          if (fileErr.code !== 'ENOENT' && fileErr.name !== 'NoSuchKey') {
            console.error('File delete error:', fileErr);
          }
        }
      }
    }

    const currentCountRow = await dbGetAsync('SELECT COUNT(*) AS c FROM entry_images WHERE entry_id = ?', [entryId]);
    let nextSort = currentCountRow?.c || 0;
    for (const item of newlyStored) {
      await dbRunAsync(
        'INSERT INTO entry_images(entry_id, filename, originalname, sort_order) VALUES (?,?,?,?)',
        [entryId, item.key, item.originalname, nextSort]
      );
      nextSort += 1;
    }

    const firstImage = await dbGetAsync(
      'SELECT filename, originalname FROM entry_images WHERE entry_id = ? ORDER BY sort_order, id LIMIT 1',
      [entryId]
    );

    await dbRunAsync(
      'UPDATE entries SET filename = ?, originalname = ?, note = ? WHERE id = ?',
      [firstImage ? firstImage.filename : null, firstImage ? firstImage.originalname : null, note, entryId]
    );

    res.redirect(`/entries/${entryId}`);
  } catch (err) {
    console.error(err);
    await Promise.allSettled(newlyStored.map((item) => deleteStoredFile(item.key)));
    res.status(500).send('Edit error');
  }
});

app.post('/entries/:id/delete', ensureOwnerOrAdmin, verifyCsrfToken, async (req, res) => {
  const entryId = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(entryId) || entryId <= 0) {
    return res.status(400).send('Invalid entry id');
  }

  try {
    const row = await dbGetAsync('SELECT * FROM entries WHERE id = ?', [entryId]);
    if (!row) return res.redirect('/');

    const images = await getEntryImagesForEntry(entryId, row);
    await dbRunAsync('DELETE FROM entry_images WHERE entry_id = ?', [entryId]);
    await dbRunAsync('DELETE FROM entries WHERE id = ?', [entryId]);

    for (const image of images) {
      try {
        await deleteStoredFile(image.filename);
      } catch (fileErr) {
        if (fileErr.code !== 'ENOENT' && fileErr.name !== 'NoSuchKey') {
          console.error('File delete error:', fileErr);
        }
      }
    }

    res.redirect('/');
  } catch (err) {
    console.error(err);
    res.status(500).send('Delete error');
  }
});

// Admin: User Management routes
app.get('/admin/users', ensureAdmin, async (req, res) => {
  try {
    const users = await dbAllAsync('SELECT id, username, role, can_pin FROM users ORDER BY id ASC');
    res.render('admin-users', { users, userId: req.session.userId, userRole: req.userRole });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error loading users');
  }
});

app.post('/admin/users/:id/role', ensureAdmin, verifyCsrfToken, async (req, res) => {
  const targetUserId = Number.parseInt(req.params.id, 10);
  const newRole = req.body.role;

  if (!Number.isInteger(targetUserId) || targetUserId <= 0) {
    return res.status(400).send('Invalid user id');
  }

  if (newRole !== 'admin' && newRole !== 'normal') {
    return res.status(400).send('Invalid role');
  }

  try {
    // Check if trying to demote the last admin
    if (newRole === 'normal') {
      const adminCount = await dbGetAsync('SELECT COUNT(*) as c FROM users WHERE role = "admin"');
      if (adminCount.c <= 1) {
        return res.status(400).send('Cannot demote the last admin');
      }
    }

    await dbRunAsync('UPDATE users SET role = ? WHERE id = ?', [newRole, targetUserId]);

    // If updating current user's role, update session
    if (targetUserId === req.session.userId) {
      req.session.userRole = newRole;
    }

    res.redirect('/admin/users');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error updating user role');
  }
});

app.post('/admin/users/:id/pin-permission', ensureAdmin, verifyCsrfToken, async (req, res) => {
  const targetUserId = Number.parseInt(req.params.id, 10);
  const canPin = String(req.body.canPin || '').trim() === '1' ? 1 : 0;

  if (!Number.isInteger(targetUserId) || targetUserId <= 0) {
    return res.status(400).send('Invalid user id');
  }

  try {
    const targetUser = await dbGetAsync('SELECT id, role FROM users WHERE id = ?', [targetUserId]);
    if (!targetUser) return res.status(404).send('User not found');

    // Admin users always have pin capability via role; this toggle is for non-admin users.
    if (targetUser.role !== 'admin') {
      await dbRunAsync('UPDATE users SET can_pin = ? WHERE id = ?', [canPin, targetUserId]);
    }

    if (targetUserId === req.session.userId) {
      req.session.userCanPin = canPin === 1;
    }

    res.redirect('/admin/users');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error updating pin permission');
  }
});

app.post('/admin/users/:id/delete', ensureAdmin, verifyCsrfToken, async (req, res) => {
  const targetUserId = Number.parseInt(req.params.id, 10);

  if (!Number.isInteger(targetUserId) || targetUserId <= 0) {
    return res.status(400).send('Invalid user id');
  }

  // Prevent deleting yourself
  if (targetUserId === req.session.userId) {
    return res.status(400).send('Cannot delete your own account');
  }

  try {
    // Check if trying to delete the last admin
    const user = await dbGetAsync('SELECT role FROM users WHERE id = ?', [targetUserId]);
    if (!user) return res.status(404).send('User not found');

    if (user.role === 'admin') {
      const adminCount = await dbGetAsync('SELECT COUNT(*) as c FROM users WHERE role = "admin"');
      if (adminCount.c <= 1) {
        return res.status(400).send('Cannot delete the last admin');
      }
    }

    // Delete user's entries and associated images
    const entries = await dbAllAsync('SELECT id FROM entries WHERE user_id = ?', [targetUserId]);
    for (const entry of entries) {
      const images = await dbAllAsync('SELECT filename FROM entry_images WHERE entry_id = ?', [entry.id]);
      for (const img of images) {
        await deleteStoredFile(img.filename);
      }
      await dbRunAsync('DELETE FROM entry_images WHERE entry_id = ?', [entry.id]);
    }
    await dbRunAsync('DELETE FROM entries WHERE user_id = ?', [targetUserId]);

    // Delete user
    await dbRunAsync('DELETE FROM users WHERE id = ?', [targetUserId]);

    res.redirect('/admin/users');
  } catch (err) {
    console.error(err);
    res.status(500).send('Error deleting user');
  }
});

// Authentication routes
app.get('/login', (req, res) => {
  if (req.session && req.session.userId) return res.redirect('/');
  res.render('login', { error: null });
});

app.post('/login', makeAuthRateLimiter('login'), verifyCsrfToken, (req, res) => {
  const username = (req.body.username || '').trim();
  const password = req.body.password || '';
  if (!username || !password) {
    return res.status(400).render('login', { error: 'Username and password are required' });
  }

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
    if (err) return res.status(500).send('DB error');
    if (!row) return res.render('login', { error: 'Invalid credentials' });
    if (!bcrypt.compareSync(password, row.password_hash)) return res.render('login', { error: 'Invalid credentials' });
    req.session.userId = row.id;
    req.session.userRole = row.role;
    req.session.userCanPin = Boolean(Number(row.can_pin || 0) === 1);
    res.redirect('/');
  });
});

app.post('/logout', verifyCsrfToken, (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// Keep GET /logout side-effect free.
app.get('/logout', (req, res) => {
  res.redirect('/');
});

// Registration with email confirmation code:
// Step 1 -> create pending registration + send code
// Step 2 -> verify code and create user
app.get('/register', async (req, res) => {
  if (req.session && req.session.userId) return res.redirect('/');
  delete req.session.pendingRegistrationUsername;
  try {
    const countRow = await dbGetAsync('SELECT COUNT(*) AS c FROM users');
    const userCount = countRow?.c || 0;
    res.render('register', {
      error: null,
      info: null,
      username: '',
      email: '',
      isFirstUser: userCount === 0,
      emailVerificationEnabled: EMAIL_VERIFICATION_ENABLED
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('DB error');
  }
});

app.post('/register', makeAuthRateLimiter('register'), verifyCsrfToken, async (req, res) => {
  const username = (req.body.username || '').trim();
  const email = normalizeEmail(req.body.email);
  const password = req.body.password || '';
  let isFirstUser = false;

  try {
    const countRow = await dbGetAsync('SELECT COUNT(*) AS c FROM users');
    isFirstUser = (countRow?.c || 0) === 0;
    const { startMs, endMs } = getDayRangeMs();
    const dailyRegistrationCount = await getRegistrationCountInRange(startMs, endMs);

    if (dailyRegistrationCount >= DAILY_REGISTRATION_LIMIT) {
      return res.status(400).render('register', {
        error: `Daily registration limit reached (${DAILY_REGISTRATION_LIMIT} users). Try again tomorrow.`,
        info: null,
        username,
        email,
        isFirstUser,
        emailVerificationEnabled: EMAIL_VERIFICATION_ENABLED
      });
    }

    if (!username || !email || !password) {
      return res.status(400).render('register', {
        error: 'Username, email, and password are required',
        info: null,
        username,
        email,
        isFirstUser,
        emailVerificationEnabled: EMAIL_VERIFICATION_ENABLED
      });
    }

    if (!isValidEmail(email)) {
      return res.status(400).render('register', {
        error: 'Please enter a valid email address',
        info: null,
        username,
        email,
        isFirstUser,
        emailVerificationEnabled: EMAIL_VERIFICATION_ENABLED
      });
    }

    if (!EMAIL_VERIFICATION_ENABLED) {
      return res.status(400).render('register', {
        error: 'Email verification is not configured. Set SMTP_HOST, SMTP_FROM, and install nodemailer.',
        info: null,
        username,
        email,
        isFirstUser,
        emailVerificationEnabled: EMAIL_VERIFICATION_ENABLED
      });
    }

    const existingUser = await dbGetAsync('SELECT id FROM users WHERE username = ? OR email = ?', [username, email]);
    if (existingUser) {
      return res.status(400).render('register', {
        error: 'Username or email already exists',
        info: null,
        username,
        email,
        isFirstUser,
        emailVerificationEnabled: EMAIL_VERIFICATION_ENABLED
      });
    }

    const now = Date.now();
    const hash = bcrypt.hashSync(password, 10);
    const code = generateVerificationCode();
    const expiresAt = now + REGISTRATION_CODE_TTL_MS;

    await dbRunAsync('DELETE FROM pending_registrations WHERE code_expires_at < ?', [now]);
    await dbRunAsync(
      `INSERT INTO pending_registrations(username, email, password_hash, verification_code, code_expires_at, created_at)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(username) DO UPDATE SET
         email = excluded.email,
         password_hash = excluded.password_hash,
         verification_code = excluded.verification_code,
         code_expires_at = excluded.code_expires_at,
         created_at = excluded.created_at`,
      [username, email, hash, code, expiresAt, now]
    );

    await sendRegistrationVerificationEmail(email, username, code);
    req.session.pendingRegistrationUsername = username;
    res.redirect('/register/verify');
  } catch (err) {
    console.error(err);
    res.status(500).render('register', {
      error: 'Failed to send verification email. Check SMTP settings and try again.',
      info: null,
      username,
      email,
      isFirstUser,
      emailVerificationEnabled: EMAIL_VERIFICATION_ENABLED
    });
  }
});

app.get('/register/verify', async (req, res) => {
  if (req.session && req.session.userId) return res.redirect('/');
  const username = (req.query.username || req.session.pendingRegistrationUsername || '').trim();
  if (!username) {
    return res.redirect('/register');
  }

  try {
    const pending = await dbGetAsync(
      'SELECT username, email, code_expires_at FROM pending_registrations WHERE username = ?',
      [username]
    );
    if (!pending) return res.redirect('/register');

    res.render('register-verify', {
      error: null,
      info: null,
      username: pending.username,
      emailHint: maskEmail(pending.email),
      codeTtlMinutes: REGISTRATION_CODE_TTL_MINUTES
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('DB error');
  }
});

app.post('/register/resend', makeAuthRateLimiter('register_resend'), verifyCsrfToken, async (req, res) => {
  if (req.session && req.session.userId) return res.redirect('/');
  const username = (req.body.username || req.session.pendingRegistrationUsername || '').trim();
  if (!username) return res.redirect('/register');

  try {
    const pending = await dbGetAsync(
      'SELECT username, email, password_hash FROM pending_registrations WHERE username = ?',
      [username]
    );
    if (!pending) return res.redirect('/register');

    const now = Date.now();
    const code = generateVerificationCode();
    const expiresAt = now + REGISTRATION_CODE_TTL_MS;
    await dbRunAsync(
      `UPDATE pending_registrations
       SET verification_code = ?, code_expires_at = ?, created_at = ?
       WHERE username = ?`,
      [code, expiresAt, now, username]
    );
    await sendRegistrationVerificationEmail(pending.email, username, code);

    res.render('register-verify', {
      error: null,
      info: `New code sent to ${maskEmail(pending.email)}.`,
      username,
      emailHint: maskEmail(pending.email),
      codeTtlMinutes: REGISTRATION_CODE_TTL_MINUTES
    });
  } catch (err) {
    console.error(err);
    res.status(500).render('register-verify', {
      error: 'Failed to resend code. Check SMTP settings and try again.',
      info: null,
      username,
      emailHint: '',
      codeTtlMinutes: REGISTRATION_CODE_TTL_MINUTES
    });
  }
});

app.post('/register/verify', makeAuthRateLimiter('register_verify'), verifyCsrfToken, async (req, res) => {
  if (req.session && req.session.userId) return res.redirect('/');
  const username = (req.body.username || req.session.pendingRegistrationUsername || '').trim();
  const code = String(req.body.code || '').trim();
  if (!username || !code) {
    return res.status(400).render('register-verify', {
      error: 'Username and confirmation code are required.',
      info: null,
      username,
      emailHint: '',
      codeTtlMinutes: REGISTRATION_CODE_TTL_MINUTES
    });
  }

  try {
    const now = Date.now();
    const { startMs, endMs } = getDayRangeMs(new Date(now));
    const dailyRegistrationCount = await getRegistrationCountInRange(startMs, endMs);
    if (dailyRegistrationCount >= DAILY_REGISTRATION_LIMIT) {
      return res.status(400).render('register-verify', {
        error: `Daily registration limit reached (${DAILY_REGISTRATION_LIMIT} users). Try again tomorrow.`,
        info: null,
        username,
        emailHint: '',
        codeTtlMinutes: REGISTRATION_CODE_TTL_MINUTES
      });
    }
    await dbRunAsync('DELETE FROM pending_registrations WHERE code_expires_at < ?', [now]);
    const pending = await dbGetAsync(
      `SELECT username, email, password_hash, verification_code, code_expires_at
       FROM pending_registrations
       WHERE username = ?`,
      [username]
    );
    if (!pending) {
      return res.status(400).render('register-verify', {
        error: 'Registration request not found or expired. Please register again.',
        info: null,
        username,
        emailHint: '',
        codeTtlMinutes: REGISTRATION_CODE_TTL_MINUTES
      });
    }

    if (pending.verification_code !== code) {
      return res.status(400).render('register-verify', {
        error: 'Invalid confirmation code.',
        info: null,
        username: pending.username,
        emailHint: maskEmail(pending.email),
        codeTtlMinutes: REGISTRATION_CODE_TTL_MINUTES
      });
    }

    const existingUser = await dbGetAsync('SELECT id FROM users WHERE username = ? OR email = ?', [pending.username, pending.email]);
    if (existingUser) {
      await dbRunAsync('DELETE FROM pending_registrations WHERE username = ?', [pending.username]);
      return res.status(400).render('register', {
        error: 'Username or email already exists. Please try registering again.',
        info: null,
        username: '',
        email: '',
        isFirstUser: false,
        emailVerificationEnabled: EMAIL_VERIFICATION_ENABLED
      });
    }

    const countRow = await dbGetAsync('SELECT COUNT(*) AS c FROM users');
    const role = (countRow?.c || 0) === 0 ? 'admin' : 'normal';
    const canPin = role === 'admin' ? 1 : 0;
    const insertResult = await dbRunAsync(
      'INSERT INTO users(username, email, password_hash, role, can_pin, email_verified_at) VALUES (?, ?, ?, ?, ?, ?)',
      [pending.username, pending.email, pending.password_hash, role, canPin, now]
    );
    await dbRunAsync('DELETE FROM pending_registrations WHERE username = ?', [pending.username]);

    req.session.userId = insertResult.lastID;
    req.session.userRole = role;
    req.session.userCanPin = canPin === 1;
    delete req.session.pendingRegistrationUsername;
    res.redirect('/');
  } catch (err) {
    console.error(err);
    res.status(500).render('register-verify', {
      error: 'Verification failed. Please try again.',
      info: null,
      username,
      emailHint: '',
      codeTtlMinutes: REGISTRATION_CODE_TTL_MINUTES
    });
  }
});

// Helper: expose file urls when rendering
app.locals.fileUrl = function(filename) {
  if (!filename) return null;
  return buildFileUrl(filename);
};

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_COUNT') {
    return res.status(400).send(`You can upload up to ${MAX_IMAGES_PER_POST} images per post.`);
  }
  if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).send(`Each image must be ${MAX_UPLOAD_FILE_SIZE_MB}MB or smaller.`);
  }
  if (err) {
    console.error(err);
    return res.status(500).send('Unexpected error');
  }
  return next();
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
