require('dotenv').config();
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const { spawn } = require('child_process');
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
const MAX_VIDEO_FILE_SIZE_MB = Math.max(1, Number.parseInt(process.env.MAX_VIDEO_FILE_SIZE_MB || '50', 10));
const MAX_VIDEO_FILE_SIZE_BYTES = MAX_VIDEO_FILE_SIZE_MB * 1024 * 1024;
const MAX_MEDIA_UPLOAD_FILE_SIZE_BYTES = Math.max(MAX_UPLOAD_FILE_SIZE_BYTES, MAX_VIDEO_FILE_SIZE_BYTES);
const MAX_FILES_PER_POST = MAX_IMAGES_PER_POST + 1;
const ENABLE_SERVER_VIDEO_PROCESSING = process.env.ENABLE_SERVER_VIDEO_PROCESSING === 'true';
const ENABLE_VIDEO_TRANSCODE = process.env.ENABLE_VIDEO_TRANSCODE !== 'false';
const FFMPEG_PATH = String(process.env.FFMPEG_PATH || 'ffmpeg').trim() || 'ffmpeg';
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
    files: MAX_FILES_PER_POST,
    fileSize: MAX_MEDIA_UPLOAD_FILE_SIZE_BYTES
  }
});
const uploadPostMedia = upload.fields([
  { name: 'photos', maxCount: MAX_IMAGES_PER_POST },
  { name: 'video', maxCount: 1 }
]);

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
  const hasColumn = (cols, name) => Array.isArray(cols) && cols.some((col) => col.name === name);
  const addColumnIfMissing = (tableName, cols, columnName, columnTypeSql, options = {}) => {
    const { errorLabel, onAdded } = options;
    if (hasColumn(cols, columnName)) return;
    db.run(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${columnTypeSql}`, (alterErr) => {
      if (alterErr) {
        console.error(errorLabel || `${tableName} ${columnName} migration error:`, alterErr);
        return;
      }
      if (typeof onAdded === 'function') onAdded();
    });
  };

  db.run(`CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT,
    originalname TEXT,
    video_filename TEXT,
    video_originalname TEXT,
    video_mimetype TEXT,
    video_poster_filename TEXT,
    video_poster_originalname TEXT,
    note TEXT,
    author_label TEXT,
    location_text TEXT,
    rating_value REAL,
    is_pinned INTEGER DEFAULT 0,
    created_at INTEGER,
    is_draft INTEGER DEFAULT 0,
    deleted_at INTEGER,
    deleted_by INTEGER,
    collection_id INTEGER
  )`);
  db.all('PRAGMA table_info(entries)', (pragmaErr, cols) => {
    if (pragmaErr) return console.error('PRAGMA entries error:', pragmaErr);
    addColumnIfMissing('entries', cols, 'is_pinned', 'INTEGER DEFAULT 0', {
      errorLabel: 'entries migration error:'
    });
    // Migration: Add user_id column to entries table
    addColumnIfMissing('entries', cols, 'user_id', 'INTEGER', {
      errorLabel: 'entries user_id migration error:',
      onAdded: () => {
        console.log('✓ Added user_id column to entries');
        // Set existing entries to first user (id=1)
        db.run('UPDATE entries SET user_id = 1 WHERE user_id IS NULL', (updateErr) => {
          if (updateErr) console.error('entries user_id backfill error:', updateErr);
          else console.log('✓ Backfilled existing entries to user_id = 1');
        });
        // Create index for faster queries
        db.run('CREATE INDEX IF NOT EXISTS idx_entries_user_id ON entries(user_id)');
      }
    });
    [
      ['is_draft', 'INTEGER DEFAULT 0'],
      ['deleted_at', 'INTEGER'],
      ['deleted_by', 'INTEGER'],
      ['collection_id', 'INTEGER'],
      ['author_label', 'TEXT'],
      ['location_text', 'TEXT'],
      ['rating_value', 'REAL'],
      ['video_filename', 'TEXT'],
      ['video_originalname', 'TEXT'],
      ['video_mimetype', 'TEXT'],
      ['video_poster_filename', 'TEXT'],
      ['video_poster_originalname', 'TEXT']
    ].forEach(([columnName, columnTypeSql]) => {
      addColumnIfMissing('entries', cols, columnName, columnTypeSql, {
        errorLabel: `entries ${columnName} migration error:`,
        onAdded: () => console.log(`✓ Added ${columnName} column to entries`)
      });
    });
    db.run('CREATE INDEX IF NOT EXISTS idx_entries_created_at ON entries(created_at)');
    db.run('CREATE INDEX IF NOT EXISTS idx_entries_deleted_at ON entries(deleted_at)');
    db.run('CREATE INDEX IF NOT EXISTS idx_entries_collection_id ON entries(collection_id)');
    db.run('CREATE INDEX IF NOT EXISTS idx_entries_user_id ON entries(user_id)');
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
    email_verified_at INTEGER,
    last_login_at INTEGER
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
  db.run(`CREATE TABLE IF NOT EXISTS tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE
  )`);
  db.run('CREATE UNIQUE INDEX IF NOT EXISTS idx_tags_name_unique ON tags(name)');
  db.run(`CREATE TABLE IF NOT EXISTS entry_tags (
    entry_id INTEGER NOT NULL,
    tag_id INTEGER NOT NULL,
    PRIMARY KEY(entry_id, tag_id)
  )`);
  db.run('CREATE INDEX IF NOT EXISTS idx_entry_tags_entry_id ON entry_tags(entry_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_entry_tags_tag_id ON entry_tags(tag_id)');
  db.run(`CREATE TABLE IF NOT EXISTS collections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL
  )`);
  db.run('CREATE INDEX IF NOT EXISTS idx_collections_user_id ON collections(user_id)');
  db.run('CREATE UNIQUE INDEX IF NOT EXISTS idx_collections_user_name_unique ON collections(user_id, name)');
  db.run(`CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    body TEXT NOT NULL,
    created_at INTEGER NOT NULL
  )`);
  db.run('CREATE INDEX IF NOT EXISTS idx_comments_entry_id ON comments(entry_id)');
  db.run('CREATE INDEX IF NOT EXISTS idx_comments_user_id ON comments(user_id)');
  db.run(`CREATE TABLE IF NOT EXISTS entry_reactions (
    entry_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    reaction TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY(entry_id, user_id)
  )`);
  db.run('CREATE INDEX IF NOT EXISTS idx_entry_reactions_entry_id ON entry_reactions(entry_id)');
  db.run(`CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_user_id INTEGER,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id INTEGER,
    meta_json TEXT,
    created_at INTEGER NOT NULL
  )`);
  db.run('CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at)');
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
    addColumnIfMissing('users', cols, 'role', 'TEXT DEFAULT "normal"', {
      errorLabel: 'users role migration error:',
      onAdded: () => {
        console.log('✓ Added role column to users');
        // Set first user to admin
        db.run('UPDATE users SET role = "admin" WHERE id = 1', (updateErr) => {
          if (updateErr) console.error('users role update error:', updateErr);
          else console.log('✓ First user set to admin role');
        });
      }
    });
    if (!hasColumn(cols, 'email')) {
      addColumnIfMissing('users', cols, 'email', 'TEXT', {
        errorLabel: 'users email migration error:',
        onAdded: () => {
          console.log('✓ Added email column to users');
          ensureUsersEmailIndex();
        }
      });
    } else {
      ensureUsersEmailIndex();
    }
    [
      ['email_verified_at', 'INTEGER'],
      ['can_pin', 'INTEGER DEFAULT 0'],
      ['last_login_at', 'INTEGER']
    ].forEach(([columnName, columnTypeSql]) => {
      addColumnIfMissing('users', cols, columnName, columnTypeSql, {
        errorLabel: `users ${columnName} migration error:`,
        onAdded: () => console.log(`✓ Added ${columnName} column to users`)
      });
    });
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
  SELECT e.*, u.username AS author_username, c.name AS collection_name
  FROM entries e
  LEFT JOIN users u ON u.id = e.user_id
  LEFT JOIN collections c ON c.id = e.collection_id
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

const HEIC_IMAGE_EXTENSIONS = new Set(['.heic', '.heif']);
const HEIC_IMAGE_MIME_TYPES = new Set(['image/heic', 'image/heif', 'image/heic-sequence', 'image/heif-sequence']);
const GENERIC_BINARY_MIME_TYPES = new Set(['', 'application/octet-stream', 'binary/octet-stream']);

function getFileExtensionFromUpload(file) {
  return path.extname(String(file?.originalname || '')).toLowerCase();
}

function getNormalizedMimeType(value) {
  return String(value || '').trim().toLowerCase();
}

function isHeicImageUpload(file) {
  const mime = getNormalizedMimeType(file?.mimetype);
  if (HEIC_IMAGE_MIME_TYPES.has(mime)) return true;
  const ext = getFileExtensionFromUpload(file);
  return HEIC_IMAGE_EXTENSIONS.has(ext) && GENERIC_BINARY_MIME_TYPES.has(mime);
}

function isSupportedPhotoUpload(file) {
  const mime = getNormalizedMimeType(file?.mimetype);
  if (mime.startsWith('image/')) return true;
  return isHeicImageUpload(file);
}

function getStorageContentType(file) {
  const mime = getNormalizedMimeType(file?.mimetype);
  if (mime && !GENERIC_BINARY_MIME_TYPES.has(mime)) return mime;
  if (isHeicImageUpload(file)) return 'image/heic';
  return mime || 'application/octet-stream';
}

async function storeUploadedFile(file) {
  const safeOriginalName = (file.originalname || 'upload.bin').replace(/[^a-z0-9.\-\_]/gi, '_');
  const key = `${Date.now()}-${safeOriginalName}`;

  if (hasR2UploadConfig) {
    const put = new PutObjectCommand({
      Bucket: process.env.R2_BUCKET,
      Key: key,
      Body: file.buffer,
      ContentType: getStorageContentType(file)
    });
    await s3.send(put);
  } else {
    await fs.promises.writeFile(path.join(UPLOADS_DIR, key), file.buffer);
  }

  return { key, originalname: file.originalname || null };
}

let ffmpegAvailabilityChecked = false;
let ffmpegAvailable = false;

function isLikelyMovVideo(videoFile) {
  const ext = path.extname(String(videoFile?.originalname || '')).toLowerCase();
  const mime = String(videoFile?.mimetype || '').toLowerCase();
  return ext === '.mov' || mime === 'video/quicktime';
}

async function checkFfmpegAvailable() {
  if (ffmpegAvailabilityChecked) return ffmpegAvailable;
  ffmpegAvailabilityChecked = true;
  ffmpegAvailable = await new Promise((resolve) => {
    const child = spawn(FFMPEG_PATH, ['-version'], { stdio: 'ignore' });
    child.on('error', () => resolve(false));
    child.on('close', (code) => resolve(code === 0));
  });
  if (!ffmpegAvailable) {
    console.warn('ffmpeg not available; MOV transcoding and poster generation are disabled.');
  }
  return ffmpegAvailable;
}

function runFfmpeg(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(FFMPEG_PATH, args, { stdio: ['ignore', 'ignore', 'pipe'] });
    let stderr = '';
    child.stderr.on('data', (chunk) => {
      if (!chunk) return;
      stderr += chunk.toString();
      if (stderr.length > 3000) stderr = stderr.slice(-3000);
    });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) return resolve();
      return reject(new Error(`ffmpeg exited with code ${code}: ${stderr}`));
    });
  });
}

function toMp4OriginalName(originalname) {
  const base = path.basename(String(originalname || 'video'), path.extname(String(originalname || 'video')));
  return `${base}.mp4`;
}

function toPosterOriginalName(originalname) {
  const base = path.basename(String(originalname || 'video'), path.extname(String(originalname || 'video')));
  return `${base}-poster.jpg`;
}

async function prepareVideoAssets(videoFile) {
  if (!videoFile) {
    return {
      videoFile: null,
      posterFile: null,
      transcoded: false
    };
  }

  const shouldAttemptMovTranscode = isLikelyMovVideo(videoFile) && ENABLE_VIDEO_TRANSCODE;
  const shouldGeneratePoster = ENABLE_SERVER_VIDEO_PROCESSING;
  if (!shouldGeneratePoster && !shouldAttemptMovTranscode) {
    return {
      videoFile,
      posterFile: null,
      transcoded: false
    };
  }

  const ffmpegReady = await checkFfmpegAvailable();
  if (!ffmpegReady) {
    if (shouldAttemptMovTranscode) {
      console.warn('MOV upload kept as-is because ffmpeg is unavailable; playback may fail in some browsers.');
    }
    return {
      videoFile,
      posterFile: null,
      transcoded: false
    };
  }

  const tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'myfood-video-'));
  const inputExt = path.extname(String(videoFile.originalname || '')).toLowerCase() || '.bin';
  const inputPath = path.join(tempDir, `input${inputExt}`);
  const outputPosterPath = path.join(tempDir, 'poster.jpg');
  const outputVideoPath = path.join(tempDir, 'video.mp4');

  let preparedVideo = videoFile;
  let posterFile = null;
  let transcoded = false;

  try {
    await fs.promises.writeFile(inputPath, videoFile.buffer);

    if (shouldGeneratePoster) {
      try {
        await runFfmpeg([
          '-y',
          '-i',
          inputPath,
          '-frames:v',
          '1',
          '-q:v',
          '3',
          outputPosterPath
        ]);
        const posterBuffer = await fs.promises.readFile(outputPosterPath);
        posterFile = {
          originalname: toPosterOriginalName(videoFile.originalname),
          mimetype: 'image/jpeg',
          size: posterBuffer.length,
          buffer: posterBuffer
        };
      } catch (posterErr) {
        console.warn('video poster generation failed:', posterErr.message);
      }
    }

    if (shouldAttemptMovTranscode) {
      try {
        await runFfmpeg([
          '-y',
          '-i',
          inputPath,
          '-c:v',
          'libx264',
          '-pix_fmt',
          'yuv420p',
          '-c:a',
          'aac',
          '-movflags',
          '+faststart',
          outputVideoPath
        ]);
        const videoBuffer = await fs.promises.readFile(outputVideoPath);
        preparedVideo = {
          originalname: toMp4OriginalName(videoFile.originalname),
          mimetype: 'video/mp4',
          size: videoBuffer.length,
          buffer: videoBuffer
        };
        transcoded = true;
      } catch (transcodeErr) {
        console.warn('video transcode failed; keeping original upload:', transcodeErr.message);
      }
    }
  } finally {
    await fs.promises.rm(tempDir, { recursive: true, force: true });
  }

  return {
    videoFile: preparedVideo,
    posterFile,
    transcoded
  };
}

function getUploadFieldFiles(req, fieldName) {
  if (!req || !req.files || typeof req.files !== 'object' || Array.isArray(req.files)) return [];
  const files = req.files[fieldName];
  return Array.isArray(files) ? files : [];
}

function validateUploadedMedia(photos, videoFile) {
  if (!Array.isArray(photos)) return 'Invalid image upload payload.';
  for (const file of photos) {
    if (!file || typeof file !== 'object') return 'Invalid image upload payload.';
    if (!isSupportedPhotoUpload(file)) {
      return 'Only image files are allowed for photos.';
    }
    if (Number(file.size || 0) > MAX_UPLOAD_FILE_SIZE_BYTES) {
      return `Each image must be ${MAX_UPLOAD_FILE_SIZE_MB}MB or smaller.`;
    }
  }
  if (videoFile) {
    if (!String(videoFile.mimetype || '').startsWith('video/')) {
      return 'Video must be a valid video file type.';
    }
    if (Number(videoFile.size || 0) > MAX_VIDEO_FILE_SIZE_BYTES) {
      return `Video must be ${MAX_VIDEO_FILE_SIZE_MB}MB or smaller.`;
    }
  }
  return null;
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

async function findRegistrationConflicts(username, email, options = {}) {
  const includePending = options.includePending === true;
  const normalizedUsername = String(username || '').trim();
  const normalizedEmail = normalizeEmail(email);
  const usernameLookup = normalizedUsername.toLowerCase();
  const nowMs = Date.now();

  const [usernameInUsers, emailInUsers] = await Promise.all([
    dbGetAsync('SELECT id FROM users WHERE LOWER(username) = ? LIMIT 1', [usernameLookup]),
    dbGetAsync('SELECT id FROM users WHERE email = ? LIMIT 1', [normalizedEmail])
  ]);

  if (!includePending) {
    return {
      usernameTaken: Boolean(usernameInUsers),
      emailTaken: Boolean(emailInUsers)
    };
  }

  const [usernameInPending, emailInPending] = await Promise.all([
    dbGetAsync(
      'SELECT id FROM pending_registrations WHERE LOWER(username) = ? AND code_expires_at >= ? LIMIT 1',
      [usernameLookup, nowMs]
    ),
    dbGetAsync(
      'SELECT id FROM pending_registrations WHERE email = ? AND code_expires_at >= ? LIMIT 1',
      [normalizedEmail, nowMs]
    )
  ]);

  return {
    usernameTaken: Boolean(usernameInUsers || usernameInPending),
    emailTaken: Boolean(emailInUsers || emailInPending)
  };
}

function getRegistrationConflictMessage(conflicts) {
  if (conflicts.usernameTaken && conflicts.emailTaken) {
    return 'Username and email are already registered or awaiting verification.';
  }
  if (conflicts.usernameTaken) return 'Username is already registered or awaiting verification.';
  if (conflicts.emailTaken) return 'Email is already registered or awaiting verification.';
  return null;
}

function normalizeTagList(input) {
  const raw = Array.isArray(input) ? input.join(',') : String(input || '');
  const seen = new Set();
  const tags = [];
  for (const token of raw.split(',')) {
    const cleaned = token.trim().toLowerCase().replace(/\s+/g, ' ');
    if (!cleaned) continue;
    if (cleaned.length > 30) continue;
    if (seen.has(cleaned)) continue;
    seen.add(cleaned);
    tags.push(cleaned);
    if (tags.length >= 10) break;
  }
  return tags;
}

function normalizeCollectionName(value) {
  const normalized = String(value || '').trim().replace(/\s+/g, ' ');
  if (!normalized) return '';
  return normalized.slice(0, 60);
}

function normalizeAuthorLabel(value) {
  const normalized = String(value || '').trim().replace(/\s+/g, ' ');
  if (!normalized) return '';
  return normalized.slice(0, 60);
}

function normalizeLocationText(value) {
  const normalized = String(value || '').trim().replace(/\s+/g, ' ');
  if (!normalized) return '';
  return normalized.slice(0, 120);
}

function normalizeRatingValue(value) {
  const raw = String(value == null ? '' : value).trim();
  if (!raw) return null;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed)) return null;
  const clamped = Math.min(10, Math.max(0, parsed));
  return Math.round(clamped * 10) / 10;
}

async function getOrCreateCollectionId(userId, collectionName) {
  const normalized = normalizeCollectionName(collectionName);
  if (!normalized || !userId) return null;
  const existing = await dbGetAsync(
    'SELECT id FROM collections WHERE user_id = ? AND LOWER(name) = LOWER(?) LIMIT 1',
    [userId, normalized]
  );
  if (existing) return existing.id;
  const inserted = await dbRunAsync(
    'INSERT INTO collections(user_id, name, created_at) VALUES (?, ?, ?)',
    [userId, normalized, Date.now()]
  );
  return inserted.lastID;
}

async function setEntryTags(entryId, tagNames) {
  const tags = normalizeTagList(tagNames);
  await dbRunAsync('DELETE FROM entry_tags WHERE entry_id = ?', [entryId]);
  for (const tagName of tags) {
    await dbRunAsync('INSERT OR IGNORE INTO tags(name) VALUES (?)', [tagName]);
    const tagRow = await dbGetAsync('SELECT id FROM tags WHERE name = ?', [tagName]);
    if (!tagRow) continue;
    await dbRunAsync('INSERT OR IGNORE INTO entry_tags(entry_id, tag_id) VALUES (?, ?)', [entryId, tagRow.id]);
  }
}

async function getEntryTagsMap(entryIds) {
  const map = {};
  if (!Array.isArray(entryIds) || entryIds.length === 0) return map;
  const placeholders = entryIds.map(() => '?').join(',');
  const rows = await dbAllAsync(
    `SELECT et.entry_id, t.name
     FROM entry_tags et
     JOIN tags t ON t.id = et.tag_id
     WHERE et.entry_id IN (${placeholders})
     ORDER BY t.name ASC`,
    entryIds
  );
  for (const row of rows) {
    if (!map[row.entry_id]) map[row.entry_id] = [];
    map[row.entry_id].push(row.name);
  }
  return map;
}

async function getEntryTags(entryId) {
  const rows = await dbAllAsync(
    `SELECT t.name
     FROM entry_tags et
     JOIN tags t ON t.id = et.tag_id
     WHERE et.entry_id = ?
     ORDER BY t.name ASC`,
    [entryId]
  );
  return rows.map((row) => row.name);
}

async function getUserCollections(userId) {
  if (!userId) return [];
  return dbAllAsync(
    'SELECT id, name FROM collections WHERE user_id = ? ORDER BY LOWER(name) ASC',
    [userId]
  );
}

function canViewEntry(row, req) {
  const isAdmin = req.userRole === 'admin';
  const isOwner = Number(req.session?.userId || 0) === Number(row.user_id || 0);
  const isPinnedPublished = Number(row.is_pinned || 0) === 1 && Number(row.is_draft || 0) === 0;
  const isDeleted = row.deleted_at != null;
  if (isDeleted) return isAdmin || isOwner;
  return isAdmin || isOwner || isPinnedPublished;
}

function canEditEntry(row, req) {
  const isAdmin = req.userRole === 'admin';
  const isOwner = Number(req.session?.userId || 0) === Number(row.user_id || 0);
  return isAdmin || isOwner;
}

function getCommentVisibilityClause(viewerUserId, viewerRole, entryAlias = 'c', userAlias = 'u') {
  if (viewerRole === 'admin') return { sql: '1=1', params: [] };
  if (viewerUserId) {
    return {
      sql: `(${userAlias}.role = ? OR ${entryAlias}.user_id = ?)`,
      params: ['admin', viewerUserId]
    };
  }
  return { sql: `${userAlias}.role = ?`, params: ['admin'] };
}

async function getEntryComments(entryId, viewerUserId, viewerRole) {
  const visibility = getCommentVisibilityClause(viewerUserId, viewerRole, 'c', 'u');
  return dbAllAsync(
    `SELECT c.id, c.entry_id, c.user_id, c.body, c.created_at, u.username, u.role AS user_role
     FROM comments c
     LEFT JOIN users u ON u.id = c.user_id
     WHERE c.entry_id = ?
       AND ${visibility.sql}
     ORDER BY c.created_at ASC`,
    [entryId, ...visibility.params]
  );
}

async function getEntryCommentsMap(entryIds, viewerUserId, viewerRole, limitPerEntry = 3) {
  const map = {};
  if (!Array.isArray(entryIds) || entryIds.length === 0) return map;
  const placeholders = entryIds.map(() => '?').join(',');
  const visibility = getCommentVisibilityClause(viewerUserId, viewerRole, 'c', 'u');
  const rows = await dbAllAsync(
    `SELECT c.id, c.entry_id, c.user_id, c.body, c.created_at, u.username, u.role AS user_role
     FROM comments c
     LEFT JOIN users u ON u.id = c.user_id
     WHERE c.entry_id IN (${placeholders})
       AND ${visibility.sql}
     ORDER BY c.entry_id ASC, c.created_at DESC`,
    [...entryIds, ...visibility.params]
  );
  for (const row of rows) {
    if (!map[row.entry_id]) map[row.entry_id] = [];
    if (limitPerEntry == null || map[row.entry_id].length < limitPerEntry) {
      map[row.entry_id].push(row);
    }
  }
  for (const key of Object.keys(map)) {
    map[key].reverse();
  }
  return map;
}

async function getVisibleCommentCountsMap(entryIds, viewerUserId, viewerRole) {
  const map = {};
  if (!Array.isArray(entryIds) || entryIds.length === 0) return map;
  const placeholders = entryIds.map(() => '?').join(',');
  const visibility = getCommentVisibilityClause(viewerUserId, viewerRole, 'c', 'u');
  const rows = await dbAllAsync(
    `SELECT c.entry_id, COUNT(*) AS c
     FROM comments c
     LEFT JOIN users u ON u.id = c.user_id
     WHERE c.entry_id IN (${placeholders})
       AND ${visibility.sql}
     GROUP BY c.entry_id`,
    [...entryIds, ...visibility.params]
  );
  for (const row of rows) {
    map[row.entry_id] = Number(row.c || 0);
  }
  return map;
}

const REACTION_OPTIONS = [
  { value: 'thumb_up', label: '👍' },
  { value: 'thumb_down', label: '👎' },
  { value: 'excited', label: '🤩' },
  { value: 'drooling', label: '🤤' }
];
const SUPPORTED_REACTIONS = REACTION_OPTIONS.map((option) => option.value);

function getReactionVisibilityClause(viewerUserId, viewerRole, reactionAlias = 'r', userAlias = 'u') {
  if (viewerRole === 'admin') return { sql: '1=1', params: [] };
  if (viewerUserId) {
    return {
      sql: `(${userAlias}.role = ? OR ${reactionAlias}.user_id = ?)`,
      params: ['admin', viewerUserId]
    };
  }
  return { sql: `${userAlias}.role = ?`, params: ['admin'] };
}

async function getEntryReactions(entryId, viewerUserId, viewerRole) {
  const visibility = getReactionVisibilityClause(viewerUserId, viewerRole, 'r', 'u');
  const rows = await dbAllAsync(
    `SELECT r.reaction, COUNT(*) AS c
     FROM entry_reactions r
     LEFT JOIN users u ON u.id = r.user_id
     WHERE r.entry_id = ?
       AND ${visibility.sql}
     GROUP BY r.reaction`,
    [entryId, ...visibility.params]
  );
  const counts = Object.fromEntries(SUPPORTED_REACTIONS.map((reaction) => [reaction, 0]));
  for (const row of rows) {
    if (counts[row.reaction] !== undefined) counts[row.reaction] = row.c;
  }
  let mine = null;
  if (viewerUserId) {
    const row = await dbGetAsync(
      'SELECT reaction FROM entry_reactions WHERE entry_id = ? AND user_id = ?',
      [entryId, viewerUserId]
    );
    mine = row ? row.reaction : null;
  }
  return { counts, mine };
}

async function getEntryReactionsMap(entryIds, viewerUserId, viewerRole) {
  const map = {};
  if (!Array.isArray(entryIds) || entryIds.length === 0) return map;
  const placeholders = entryIds.map(() => '?').join(',');
  const visibility = getReactionVisibilityClause(viewerUserId, viewerRole, 'r', 'u');
  const rows = await dbAllAsync(
    `SELECT r.entry_id, r.reaction, COUNT(*) AS c
     FROM entry_reactions r
     LEFT JOIN users u ON u.id = r.user_id
     WHERE r.entry_id IN (${placeholders})
       AND ${visibility.sql}
     GROUP BY r.entry_id, r.reaction`,
    [...entryIds, ...visibility.params]
  );
  for (const entryId of entryIds) {
    map[entryId] = {
      counts: Object.fromEntries(SUPPORTED_REACTIONS.map((reaction) => [reaction, 0])),
      mine: null
    };
  }
  for (const row of rows) {
    if (!map[row.entry_id]) {
      map[row.entry_id] = {
        counts: Object.fromEntries(SUPPORTED_REACTIONS.map((reaction) => [reaction, 0])),
        mine: null
      };
    }
    if (map[row.entry_id].counts[row.reaction] !== undefined) {
      map[row.entry_id].counts[row.reaction] = Number(row.c || 0);
    }
  }
  if (viewerUserId) {
    const myRows = await dbAllAsync(
      `SELECT entry_id, reaction
       FROM entry_reactions
       WHERE user_id = ?
         AND entry_id IN (${placeholders})`,
      [viewerUserId, ...entryIds]
    );
    for (const row of myRows) {
      if (!map[row.entry_id]) {
        map[row.entry_id] = {
          counts: Object.fromEntries(SUPPORTED_REACTIONS.map((reaction) => [reaction, 0])),
          mine: null
        };
      }
      map[row.entry_id].mine = row.reaction || null;
    }
  }
  return map;
}

async function appendAuditLog(req, action, targetType, targetId, meta = null) {
  try {
    await dbRunAsync(
      'INSERT INTO audit_logs(actor_user_id, action, target_type, target_id, meta_json, created_at) VALUES (?, ?, ?, ?, ?, ?)',
      [
        req.session?.userId || null,
        action,
        targetType || null,
        Number.isInteger(targetId) ? targetId : null,
        meta ? JSON.stringify(meta) : null,
        Date.now()
      ]
    );
  } catch (err) {
    console.error('audit log insert error:', err);
  }
}

function buildFilterQueryString(params = {}) {
  const q = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value == null) continue;
    const asString = String(value).trim();
    if (!asString) continue;
    q.set(key, asString);
  }
  const encoded = q.toString();
  return encoded ? `?${encoded}` : '';
}

app.get('/', async (req, res) => {
  try {
    const isAdmin = req.userRole === 'admin';
    const userCanPin = canPinPosts(req);
    const userId = req.session.userId;
    const filters = {
      q: String(req.query.q || '').trim(),
      tag: String(req.query.tag || '').trim().toLowerCase(),
      collection: String(req.query.collection || '').trim(),
      author: String(req.query.author || '').trim(),
      from: String(req.query.from || '').trim(),
      to: String(req.query.to || '').trim(),
      visibility: String(req.query.visibility || '').trim(),
      deleted: String(req.query.deleted || '').trim() === '1' ? '1' : '0'
    };
    const canUseAdvancedFilters = Boolean(userId);
    if (!canUseAdvancedFilters) {
      filters.visibility = 'published';
      filters.deleted = '0';
    } else if (!['all', 'published', 'drafts'].includes(filters.visibility)) {
      filters.visibility = 'all';
    }

    const where = [];
    const params = [];
    const showDeleted = filters.deleted === '1' && canUseAdvancedFilters;

    if (showDeleted) {
      if (isAdmin) {
        where.push('e.deleted_at IS NOT NULL');
      } else {
        where.push('e.deleted_at IS NOT NULL');
        where.push('e.user_id = ?');
        params.push(userId);
      }
    } else if (isAdmin) {
      where.push('e.deleted_at IS NULL');
    } else if (userId) {
      where.push('e.deleted_at IS NULL');
      where.push('((COALESCE(e.is_pinned, 0) = 1 AND COALESCE(e.is_draft, 0) = 0) OR e.user_id = ?)');
      params.push(userId);
    } else {
      where.push('e.deleted_at IS NULL');
      where.push('COALESCE(e.is_pinned, 0) = 1');
      where.push('COALESCE(e.is_draft, 0) = 0');
    }

    if (!showDeleted && canUseAdvancedFilters) {
      if (filters.visibility === 'published') {
        where.push('COALESCE(e.is_draft, 0) = 0');
      } else if (filters.visibility === 'drafts') {
        where.push('COALESCE(e.is_draft, 0) = 1');
        if (!isAdmin) {
          where.push('e.user_id = ?');
          params.push(userId);
        }
      }
    }

    if (filters.q) {
      const search = `%${filters.q}%`;
      where.push(`(
        COALESCE(e.note, '') LIKE ?
        OR COALESCE(e.author_label, '') LIKE ?
        OR COALESCE(u.username, '') LIKE ?
        OR COALESCE(c.name, '') LIKE ?
        OR EXISTS (
          SELECT 1
          FROM entry_tags et
          JOIN tags t ON t.id = et.tag_id
          WHERE et.entry_id = e.id AND t.name LIKE ?
        )
      )`);
      params.push(search, search, search, search, search);
    }

    if (filters.tag) {
      where.push(`
        EXISTS (
          SELECT 1
          FROM entry_tags et
          JOIN tags t ON t.id = et.tag_id
          WHERE et.entry_id = e.id AND LOWER(t.name) = LOWER(?)
        )
      `);
      params.push(filters.tag);
    }

    if (filters.collection) {
      where.push('LOWER(COALESCE(c.name, \'\')) LIKE LOWER(?)');
      params.push(`%${filters.collection}%`);
    }

    if (filters.author) {
      where.push('LOWER(COALESCE(e.author_label, u.username, \'\')) LIKE LOWER(?)');
      params.push(`%${filters.author}%`);
    }

    if (filters.from) {
      const fromDate = new Date(`${filters.from}T00:00:00`);
      if (!Number.isNaN(fromDate.getTime())) {
        where.push('e.created_at >= ?');
        params.push(fromDate.getTime());
      }
    }
    if (filters.to) {
      const toDate = new Date(`${filters.to}T00:00:00`);
      if (!Number.isNaN(toDate.getTime())) {
        const nextDay = new Date(toDate);
        nextDay.setDate(nextDay.getDate() + 1);
        where.push('e.created_at < ?');
        params.push(nextDay.getTime());
      }
    }

    const whereSql = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';
    const rows = await dbAllAsync(
      `${ENTRY_SELECT_WITH_AUTHOR}
       ${whereSql}
       ORDER BY COALESCE(e.is_pinned, 0) DESC, e.created_at DESC`,
      params
    );

    const ids = rows.map((row) => row.id);
    const entriesById = Object.fromEntries(rows.map((row) => [row.id, row]));
    const [imagesMap, tagsMap] = await Promise.all([
      getEntryImagesMap(ids, entriesById),
      getEntryTagsMap(ids)
    ]);
    const entriesBase = rows.map((row) => ({
      ...row,
      images: imagesMap[row.id] || [],
      tags: tagsMap[row.id] || []
    }));
    const [commentsMap, commentCountsMap, reactionsMap] = await Promise.all([
      getEntryCommentsMap(ids, userId, req.userRole, 2),
      getVisibleCommentCountsMap(ids, userId, req.userRole),
      getEntryReactionsMap(ids, userId, req.userRole)
    ]);
    const entries = entriesBase.map((row) => ({
      ...row,
      commentsPreview: commentsMap[row.id] || [],
      visibleCommentCount: Number(commentCountsMap[row.id] || 0),
      reactions: reactionsMap[row.id] || {
        counts: Object.fromEntries(SUPPORTED_REACTIONS.map((reaction) => [reaction, 0])),
        mine: null
      }
    }));
    const tagShortcutSet = new Set();
    for (const entry of entries) {
      if (!Array.isArray(entry.tags)) continue;
      for (const tag of entry.tags) {
        if (!tag) continue;
        tagShortcutSet.add(String(tag));
      }
    }
    if (filters.tag) tagShortcutSet.add(filters.tag);
    const tagShortcuts = Array.from(tagShortcutSet).sort((a, b) => a.localeCompare(b));
    const userCollections = await getUserCollections(userId);
    const filterCollections = isAdmin
      ? await dbAllAsync(
        `SELECT DISTINCT c.name
         FROM collections c
         JOIN entries e ON e.collection_id = c.id
         WHERE e.deleted_at IS NULL
         ORDER BY LOWER(c.name) ASC`
      )
      : userCollections.map((item) => ({ name: item.name }));
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
      maxVideoFileSizeMb: MAX_VIDEO_FILE_SIZE_MB,
      showPinnedOnly: !isAdmin,
      filters,
      tagShortcuts,
      filterCollections,
      userCollections,
      canSeeTotals: req.userRole === 'admin',
      reactionOptions: REACTION_OPTIONS,
      currentFilterQuery: buildFilterQueryString(filters)
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('DB error');
  }
});

app.get('/entries/new', ensureAuth, async (req, res) => {
  try {
    const uploadError = req.query.error === 'daily_limit'
      ? `Daily upload limit reached (${DAILY_UPLOAD_LIMIT} posts). Try again tomorrow.`
      : null;
    const userCollections = await getUserCollections(req.session.userId);
    res.render('create', {
      userId: req.session.userId,
      userRole: req.userRole,
      userCanPin: canPinPosts(req),
      uploadError,
      maxImagesPerPost: MAX_IMAGES_PER_POST,
      maxVideoFileSizeMb: MAX_VIDEO_FILE_SIZE_MB,
      userCollections
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('DB error');
  }
});

app.post('/upload', ensureAuth, uploadPostMedia, verifyCsrfToken, async (req, res) => {
  const note = req.body.note || '';
  const tagsInput = req.body.tags || '';
  const authorLabel = normalizeAuthorLabel(req.body.authorLabel || '');
  const locationText = normalizeLocationText(req.body.location || '');
  const ratingValue = normalizeRatingValue(req.body.rating);
  const collectionName = req.body.collection || '';
  const saveAsDraft = String(req.body.saveAsDraft || '').trim() === '1' || req.body.saveAsDraft === 'on';
  const photoFiles = getUploadFieldFiles(req, 'photos');
  const videoFile = getUploadFieldFiles(req, 'video')[0] || null;
  const mediaError = validateUploadedMedia(photoFiles, videoFile);
  if (mediaError) {
    return res.status(400).send(mediaError);
  }
  const storedPhotos = [];
  let storedVideo = null;
  let storedVideoPoster = null;
  let videoWasTranscoded = false;

  try {
    const { startMs, endMs } = getDayRangeMs();
    const dailyCount = await getEntryCountInRange(startMs, endMs);
    if (dailyCount >= DAILY_UPLOAD_LIMIT) {
      return res.redirect('/entries/new?error=daily_limit');
    }

    for (const file of photoFiles) {
      const stored = await storeUploadedFile(file);
      storedPhotos.push(stored);
    }
    if (videoFile) {
      const preparedVideo = await prepareVideoAssets(videoFile);
      const stored = await storeUploadedFile(preparedVideo.videoFile);
      storedVideo = { ...stored, mimetype: preparedVideo.videoFile.mimetype || null };
      videoWasTranscoded = preparedVideo.transcoded === true;
      if (preparedVideo.posterFile) {
        const storedPoster = await storeUploadedFile(preparedVideo.posterFile);
        storedVideoPoster = storedPoster;
      }
    }

    const first = storedPhotos[0] || null;
    const createdAt = Date.now();
    const collectionId = await getOrCreateCollectionId(req.session.userId, collectionName);
    const isDraft = saveAsDraft ? 1 : 0;
    const insertResult = await dbRunAsync(
      `INSERT INTO entries(
        filename, originalname, video_filename, video_originalname, video_mimetype,
        video_poster_filename, video_poster_originalname, note, author_label, location_text, rating_value,
        is_pinned, created_at, user_id, is_draft, collection_id
      ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [
        first ? first.key : null,
        first ? first.originalname : null,
        storedVideo ? storedVideo.key : null,
        storedVideo ? storedVideo.originalname : null,
        storedVideo ? storedVideo.mimetype : null,
        storedVideoPoster ? storedVideoPoster.key : null,
        storedVideoPoster ? storedVideoPoster.originalname : null,
        note,
        authorLabel || null,
        locationText || null,
        ratingValue,
        0,
        createdAt,
        req.session.userId,
        isDraft,
        collectionId
      ]
    );

    for (let i = 0; i < storedPhotos.length; i += 1) {
      const item = storedPhotos[i];
      await dbRunAsync(
        'INSERT INTO entry_images(entry_id, filename, originalname, sort_order) VALUES (?,?,?,?)',
        [insertResult.lastID, item.key, item.originalname, i]
      );
    }
    await setEntryTags(insertResult.lastID, tagsInput);
    await appendAuditLog(req, 'entry.create', 'entry', insertResult.lastID, {
      imageCount: storedPhotos.length,
      hasVideo: Boolean(storedVideo),
      hasVideoPoster: Boolean(storedVideoPoster),
      videoWasTranscoded,
      isDraft: isDraft === 1
    });

    res.redirect('/');
  } catch (err) {
    console.error(err);
    const cleanup = storedPhotos.map((item) => deleteStoredFile(item.key));
    if (storedVideo) cleanup.push(deleteStoredFile(storedVideo.key));
    if (storedVideoPoster) cleanup.push(deleteStoredFile(storedVideoPoster.key));
    await Promise.allSettled(cleanup);
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
    if (!canViewEntry(row, req)) return res.redirect('/login');
    const isDeleted = row.deleted_at != null;
    const canEdit = canEditEntry(row, req);
    const [images, tags, comments, reactions] = await Promise.all([
      getEntryImagesForEntry(entryId, row),
      getEntryTags(entryId),
      getEntryComments(entryId, req.session.userId, req.userRole),
      getEntryReactions(entryId, req.session.userId, req.userRole)
    ]);
    res.render('entry', {
      entry: { ...row, images, tags, isDeleted },
      userId: req.session.userId,
      userRole: req.userRole,
      userCanPin: canPinPosts(req),
      canEdit,
      reactions,
      comments,
      supportedReactions: SUPPORTED_REACTIONS,
      reactionOptions: REACTION_OPTIONS,
      canSeeTotals: req.userRole === 'admin'
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
    const row = await dbGetAsync('SELECT id, is_draft, deleted_at FROM entries WHERE id = ?', [entryId]);
    if (!row) return res.status(404).send('Entry not found');
    if (row.deleted_at != null) return res.status(400).send('Cannot pin a deleted post');
    if (Number(row.is_draft || 0) === 1) return res.status(400).send('Cannot pin a draft post');
    await dbRunAsync('UPDATE entries SET is_pinned = ? WHERE id = ?', [pinned, entryId]);
    await appendAuditLog(req, pinned === 1 ? 'entry.pin' : 'entry.unpin', 'entry', entryId, null);
    const returnToRaw = typeof req.body.returnTo === 'string' ? req.body.returnTo.trim() : '';
    const returnTo = (returnToRaw === '/' || returnToRaw.startsWith('/?') || returnToRaw.startsWith('/entries/')) ? returnToRaw : '/';
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
    const row = await dbGetAsync(
      `SELECT e.*, c.name AS collection_name
       FROM entries e
       LEFT JOIN collections c ON c.id = e.collection_id
       WHERE e.id = ?`,
      [entryId]
    );
    if (!row) return res.status(404).send('Entry not found');
    if (row.deleted_at != null) return res.status(400).send('Cannot edit a deleted post. Restore it first.');
    const [images, tags, userCollections] = await Promise.all([
      getEntryImagesForEntry(entryId, row),
      getEntryTags(entryId),
      getUserCollections(req.session.userId)
    ]);
    res.render('edit', {
      entry: { ...row, images, tags, tagText: tags.join(', ') },
      error: null,
      maxImagesPerPost: MAX_IMAGES_PER_POST,
      maxVideoFileSizeMb: MAX_VIDEO_FILE_SIZE_MB,
      userCollections
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('DB error');
  }
});

app.post('/entries/:id/edit', ensureOwnerOrAdmin, uploadPostMedia, verifyCsrfToken, async (req, res) => {
  const entryId = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(entryId) || entryId <= 0) {
    return res.status(400).send('Invalid entry id');
  }

  const note = req.body.note || '';
  const tagsInput = req.body.tags || '';
  const authorLabel = normalizeAuthorLabel(req.body.authorLabel || '');
  const locationText = normalizeLocationText(req.body.location || '');
  const ratingValue = normalizeRatingValue(req.body.rating);
  const collectionName = req.body.collection || '';
  const saveAsDraft = String(req.body.saveAsDraft || '').trim() === '1' || req.body.saveAsDraft === 'on';
  const removeAllPhotos = req.body.removeAllPhotos === 'on';
  const removeVideo = req.body.removeVideo === 'on';
  const removeImageIdsRaw = req.body.removeImageIds;
  const removeImageIds = new Set(
    (Array.isArray(removeImageIdsRaw) ? removeImageIdsRaw : [removeImageIdsRaw])
      .map((value) => Number.parseInt(value, 10))
      .filter((value) => Number.isInteger(value) && value > 0)
  );
  const newImageFiles = getUploadFieldFiles(req, 'photos');
  const newVideoFile = getUploadFieldFiles(req, 'video')[0] || null;
  const newlyStoredImages = [];
  let newlyStoredVideo = null;
  let newlyStoredVideoPoster = null;
  let videoWasTranscoded = false;

  try {
    const row = await dbGetAsync('SELECT * FROM entries WHERE id = ?', [entryId]);
    if (!row) return res.status(404).send('Entry not found');
    if (row.deleted_at != null) return res.status(400).send('Cannot edit a deleted post. Restore it first.');

    const existingImages = await getEntryImagesForEntry(entryId, row);
    const mediaError = validateUploadedMedia(newImageFiles, newVideoFile);
    if (mediaError) {
      return res.status(400).render('edit', {
        entry: {
          ...row,
          images: existingImages,
          tags: normalizeTagList(tagsInput),
          tagText: String(tagsInput || ''),
          author_label: authorLabel,
          location_text: locationText,
          rating_value: ratingValue,
          collection_name: normalizeCollectionName(collectionName),
          is_draft: saveAsDraft ? 1 : 0
        },
        error: mediaError,
        maxImagesPerPost: MAX_IMAGES_PER_POST,
        maxVideoFileSizeMb: MAX_VIDEO_FILE_SIZE_MB,
        userCollections: await getUserCollections(req.session.userId)
      });
    }

    const imagesToRemove = removeAllPhotos
      ? existingImages
      : existingImages.filter((image) => removeImageIds.has(image.id));
    const retainedCount = existingImages.length - imagesToRemove.length;
    if (retainedCount + newImageFiles.length > MAX_IMAGES_PER_POST) {
      return res.status(400).render('edit', {
        entry: {
          ...row,
          images: existingImages,
          tags: normalizeTagList(tagsInput),
          tagText: String(tagsInput || ''),
          author_label: authorLabel,
          location_text: locationText,
          rating_value: ratingValue,
          collection_name: normalizeCollectionName(collectionName),
          is_draft: saveAsDraft ? 1 : 0
        },
        error: `You can store up to ${MAX_IMAGES_PER_POST} images in one post.`,
        maxImagesPerPost: MAX_IMAGES_PER_POST,
        maxVideoFileSizeMb: MAX_VIDEO_FILE_SIZE_MB,
        userCollections: await getUserCollections(req.session.userId)
      });
    }

    for (const file of newImageFiles) {
      const stored = await storeUploadedFile(file);
      newlyStoredImages.push(stored);
    }
    if (newVideoFile) {
      const preparedVideo = await prepareVideoAssets(newVideoFile);
      const stored = await storeUploadedFile(preparedVideo.videoFile);
      newlyStoredVideo = { ...stored, mimetype: preparedVideo.videoFile.mimetype || null };
      videoWasTranscoded = preparedVideo.transcoded === true;
      if (preparedVideo.posterFile) {
        const storedPoster = await storeUploadedFile(preparedVideo.posterFile);
        newlyStoredVideoPoster = storedPoster;
      }
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
    for (const item of newlyStoredImages) {
      await dbRunAsync(
        'INSERT INTO entry_images(entry_id, filename, originalname, sort_order) VALUES (?,?,?,?)',
        [entryId, item.key, item.originalname, nextSort]
      );
      nextSort += 1;
    }

    let nextVideoFilename = row.video_filename || null;
    let nextVideoOriginalname = row.video_originalname || null;
    let nextVideoMimetype = row.video_mimetype || null;
    let nextVideoPosterFilename = row.video_poster_filename || null;
    let nextVideoPosterOriginalname = row.video_poster_originalname || null;
    let videoToDelete = null;
    let videoPosterToDelete = null;
    if (newlyStoredVideo) {
      videoToDelete = row.video_filename || null;
      videoPosterToDelete = row.video_poster_filename || null;
      nextVideoFilename = newlyStoredVideo.key;
      nextVideoOriginalname = newlyStoredVideo.originalname;
      nextVideoMimetype = newlyStoredVideo.mimetype;
      nextVideoPosterFilename = newlyStoredVideoPoster ? newlyStoredVideoPoster.key : null;
      nextVideoPosterOriginalname = newlyStoredVideoPoster ? newlyStoredVideoPoster.originalname : null;
    } else if (removeVideo) {
      videoToDelete = row.video_filename || null;
      videoPosterToDelete = row.video_poster_filename || null;
      nextVideoFilename = null;
      nextVideoOriginalname = null;
      nextVideoMimetype = null;
      nextVideoPosterFilename = null;
      nextVideoPosterOriginalname = null;
    }

    const firstImage = await dbGetAsync(
      'SELECT filename, originalname FROM entry_images WHERE entry_id = ? ORDER BY sort_order, id LIMIT 1',
      [entryId]
    );
    const collectionId = await getOrCreateCollectionId(req.session.userId, collectionName);
    const isDraft = saveAsDraft ? 1 : 0;
    const nextPinned = isDraft === 1 ? 0 : Number(row.is_pinned || 0);

    await dbRunAsync(
      `UPDATE entries
       SET filename = ?, originalname = ?, video_filename = ?, video_originalname = ?, video_mimetype = ?,
           video_poster_filename = ?, video_poster_originalname = ?, note = ?, author_label = ?, location_text = ?, rating_value = ?, is_draft = ?, collection_id = ?, is_pinned = ?
       WHERE id = ?`,
      [
        firstImage ? firstImage.filename : null,
        firstImage ? firstImage.originalname : null,
        nextVideoFilename,
        nextVideoOriginalname,
        nextVideoMimetype,
        nextVideoPosterFilename,
        nextVideoPosterOriginalname,
        note,
        authorLabel || null,
        locationText || null,
        ratingValue,
        isDraft,
        collectionId,
        nextPinned,
        entryId
      ]
    );

    if (videoToDelete) {
      try {
        await deleteStoredFile(videoToDelete);
      } catch (fileErr) {
        if (fileErr.code !== 'ENOENT' && fileErr.name !== 'NoSuchKey') {
          console.error('Video delete error:', fileErr);
        }
      }
    }
    if (videoPosterToDelete) {
      try {
        await deleteStoredFile(videoPosterToDelete);
      } catch (fileErr) {
        if (fileErr.code !== 'ENOENT' && fileErr.name !== 'NoSuchKey') {
          console.error('Video poster delete error:', fileErr);
        }
      }
    }

    await setEntryTags(entryId, tagsInput);
    await appendAuditLog(req, 'entry.edit', 'entry', entryId, {
      imageCount: nextSort,
      hasVideo: Boolean(nextVideoFilename),
      hasVideoPoster: Boolean(nextVideoPosterFilename),
      videoWasTranscoded,
      isDraft: isDraft === 1
    });

    res.redirect(`/entries/${entryId}`);
  } catch (err) {
    console.error(err);
    const cleanup = newlyStoredImages.map((item) => deleteStoredFile(item.key));
    if (newlyStoredVideo) cleanup.push(deleteStoredFile(newlyStoredVideo.key));
    if (newlyStoredVideoPoster) cleanup.push(deleteStoredFile(newlyStoredVideoPoster.key));
    await Promise.allSettled(cleanup);
    res.status(500).send('Edit error');
  }
});

app.post('/entries/:id/delete', ensureOwnerOrAdmin, verifyCsrfToken, async (req, res) => {
  const entryId = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(entryId) || entryId <= 0) {
    return res.status(400).send('Invalid entry id');
  }

  try {
    const row = await dbGetAsync('SELECT id, deleted_at FROM entries WHERE id = ?', [entryId]);
    if (!row) return res.redirect('/');
    if (row.deleted_at != null) return res.redirect('/');
    await dbRunAsync(
      'UPDATE entries SET deleted_at = ?, deleted_by = ?, is_pinned = 0 WHERE id = ?',
      [Date.now(), req.session.userId, entryId]
    );
    await appendAuditLog(req, 'entry.soft_delete', 'entry', entryId, null);
    const returnToRaw = typeof req.body.returnTo === 'string' ? req.body.returnTo.trim() : '';
    const returnTo = (returnToRaw === '/' || returnToRaw.startsWith('/?') || returnToRaw.startsWith('/entries/')) ? returnToRaw : '/';
    res.redirect(returnTo);
  } catch (err) {
    console.error(err);
    res.status(500).send('Delete error');
  }
});

app.post('/entries/:id/restore', ensureOwnerOrAdmin, verifyCsrfToken, async (req, res) => {
  const entryId = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(entryId) || entryId <= 0) {
    return res.status(400).send('Invalid entry id');
  }

  try {
    const row = await dbGetAsync('SELECT id, deleted_at FROM entries WHERE id = ?', [entryId]);
    if (!row) return res.redirect('/');
    if (row.deleted_at == null) return res.redirect(`/entries/${entryId}`);
    await dbRunAsync('UPDATE entries SET deleted_at = NULL, deleted_by = NULL WHERE id = ?', [entryId]);
    await appendAuditLog(req, 'entry.restore', 'entry', entryId, null);
    const returnToRaw = typeof req.body.returnTo === 'string' ? req.body.returnTo.trim() : '';
    const returnTo = (returnToRaw === '/' || returnToRaw.startsWith('/?') || returnToRaw.startsWith('/entries/')) ? returnToRaw : `/entries/${entryId}`;
    res.redirect(returnTo);
  } catch (err) {
    console.error(err);
    res.status(500).send('Restore error');
  }
});

app.post('/entries/:id/comments', ensureAuth, verifyCsrfToken, async (req, res) => {
  const entryId = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(entryId) || entryId <= 0) return res.status(400).send('Invalid entry id');
  const returnToRaw = typeof req.body.returnTo === 'string' ? req.body.returnTo.trim() : '';
  const returnTo = (returnToRaw === '/' || returnToRaw.startsWith('/?') || returnToRaw.startsWith('/entries/')) ? returnToRaw : `/entries/${entryId}`;
  const body = String(req.body.body || '').trim();
  if (!body) return res.redirect(returnTo);
  if (body.length > 500) return res.status(400).send('Comment is too long (max 500 characters).');

  try {
    const row = await dbGetAsync('SELECT id, user_id, is_pinned, is_draft, deleted_at FROM entries WHERE id = ?', [entryId]);
    if (!row) return res.status(404).send('Entry not found');
    if (!canViewEntry(row, req) || row.deleted_at != null) return res.status(403).send('Not allowed');
    await dbRunAsync(
      'INSERT INTO comments(entry_id, user_id, body, created_at) VALUES (?, ?, ?, ?)',
      [entryId, req.session.userId, body, Date.now()]
    );
    await appendAuditLog(req, 'comment.create', 'entry', entryId, null);
    res.redirect(returnTo);
  } catch (err) {
    console.error(err);
    res.status(500).send('Comment error');
  }
});

app.post('/entries/:id/reactions', ensureAuth, verifyCsrfToken, async (req, res) => {
  const expectsJson = (
    String(req.get('x-requested-with') || '').toLowerCase() === 'xmlhttprequest' ||
    String(req.get('accept') || '').toLowerCase().includes('application/json')
  );
  const sendError = (statusCode, message) => {
    if (expectsJson) return res.status(statusCode).json({ ok: false, error: message });
    return res.status(statusCode).send(message);
  };

  const entryId = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(entryId) || entryId <= 0) return sendError(400, 'Invalid entry id');
  const returnToRaw = typeof req.body.returnTo === 'string' ? req.body.returnTo.trim() : '';
  const returnTo = (returnToRaw === '/' || returnToRaw.startsWith('/?') || returnToRaw.startsWith('/entries/')) ? returnToRaw : `/entries/${entryId}`;
  const reaction = String(req.body.reaction || '').trim().toLowerCase();
  if (!SUPPORTED_REACTIONS.includes(reaction)) return sendError(400, 'Unsupported reaction');

  try {
    const row = await dbGetAsync('SELECT id, user_id, is_pinned, is_draft, deleted_at FROM entries WHERE id = ?', [entryId]);
    if (!row) return sendError(404, 'Entry not found');
    if (!canViewEntry(row, req) || row.deleted_at != null) return sendError(403, 'Not allowed');

    const existing = await dbGetAsync(
      'SELECT reaction FROM entry_reactions WHERE entry_id = ? AND user_id = ?',
      [entryId, req.session.userId]
    );
    if (existing && existing.reaction === reaction) {
      await dbRunAsync('DELETE FROM entry_reactions WHERE entry_id = ? AND user_id = ?', [entryId, req.session.userId]);
      await appendAuditLog(req, 'reaction.remove', 'entry', entryId, { reaction });
    } else {
      await dbRunAsync(
        `INSERT INTO entry_reactions(entry_id, user_id, reaction, created_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(entry_id, user_id) DO UPDATE SET
           reaction = excluded.reaction,
           created_at = excluded.created_at`,
        [entryId, req.session.userId, reaction, Date.now()]
      );
      await appendAuditLog(req, 'reaction.set', 'entry', entryId, { reaction });
    }
    const latestReactions = await getEntryReactions(entryId, req.session.userId, req.userRole);
    if (expectsJson) {
      return res.json({
        ok: true,
        reactions: latestReactions
      });
    }
    return res.redirect(returnTo);
  } catch (err) {
    console.error(err);
    if (expectsJson) return res.status(500).json({ ok: false, error: 'Reaction error' });
    return res.status(500).send('Reaction error');
  }
});

app.post('/comments/:id/delete', ensureAuth, verifyCsrfToken, async (req, res) => {
  const commentId = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(commentId) || commentId <= 0) return res.status(400).send('Invalid comment id');

  try {
    const comment = await dbGetAsync('SELECT id, entry_id, user_id FROM comments WHERE id = ?', [commentId]);
    if (!comment) return res.status(404).send('Comment not found');
    const isAdmin = req.userRole === 'admin';
    const isOwner = Number(req.session.userId) === Number(comment.user_id);
    if (!isAdmin && !isOwner) return res.status(403).send('Not allowed');
    await dbRunAsync('DELETE FROM comments WHERE id = ?', [commentId]);
    await appendAuditLog(req, 'comment.delete', 'comment', commentId, { entryId: comment.entry_id });
    res.redirect(`/entries/${comment.entry_id}`);
  } catch (err) {
    console.error(err);
    res.status(500).send('Delete comment error');
  }
});

// Admin: User Management routes
app.get('/admin/users', ensureAdmin, async (req, res) => {
  try {
    const users = await dbAllAsync(
      'SELECT id, username, role, can_pin, last_login_at FROM users ORDER BY id ASC'
    );
    const adminUserError = typeof req.query.error === 'string' ? req.query.error : null;
    const adminUserMessage = typeof req.query.success === 'string' ? req.query.success : null;
    res.render('admin-users', {
      users,
      userId: req.session.userId,
      userRole: req.userRole,
      adminUserError,
      adminUserMessage
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error loading users');
  }
});

app.get('/admin/audit', ensureAdmin, async (req, res) => {
  try {
    const logs = await dbAllAsync(
      `SELECT a.id, a.action, a.target_type, a.target_id, a.meta_json, a.created_at,
              a.actor_user_id, u.username AS actor_username
       FROM audit_logs a
       LEFT JOIN users u ON u.id = a.actor_user_id
       ORDER BY a.created_at DESC
       LIMIT 200`
    );
    const parsedLogs = logs.map((log) => {
      let meta = null;
      if (log.meta_json) {
        try {
          meta = JSON.parse(log.meta_json);
        } catch (err) {
          meta = { raw: log.meta_json };
        }
      }
      return { ...log, meta };
    });
    res.render('admin-audit', {
      logs: parsedLogs,
      userId: req.session.userId,
      userRole: req.userRole
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error loading audit logs');
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
    await appendAuditLog(req, 'user.role_change', 'user', targetUserId, { role: newRole });

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
      await appendAuditLog(req, 'user.pin_permission', 'user', targetUserId, { canPin: canPin === 1 });
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

app.post('/admin/users/:id/reset-password', ensureAdmin, verifyCsrfToken, async (req, res) => {
  const targetUserId = Number.parseInt(req.params.id, 10);
  const newPassword = String(req.body.newPassword || '');

  if (!Number.isInteger(targetUserId) || targetUserId <= 0) {
    return res.status(400).send('Invalid user id');
  }

  if (newPassword.length < 8) {
    return res.redirect('/admin/users?error=Password%20must%20be%20at%20least%208%20characters.');
  }

  try {
    const user = await dbGetAsync('SELECT id FROM users WHERE id = ?', [targetUserId]);
    if (!user) return res.status(404).send('User not found');

    const newHash = bcrypt.hashSync(newPassword, 10);
    await dbRunAsync('UPDATE users SET password_hash = ? WHERE id = ?', [newHash, targetUserId]);
    await appendAuditLog(req, 'user.password_reset', 'user', targetUserId, null);

    return res.redirect(`/admin/users?success=Password%20reset%20for%20user%20%23${targetUserId}.`);
  } catch (err) {
    console.error(err);
    return res.redirect('/admin/users?error=Failed%20to%20reset%20password.');
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

    // Delete user's entries and associated media
    const entries = await dbAllAsync(
      'SELECT id, video_filename, video_poster_filename FROM entries WHERE user_id = ?',
      [targetUserId]
    );
    for (const entry of entries) {
      const images = await dbAllAsync('SELECT filename FROM entry_images WHERE entry_id = ?', [entry.id]);
      for (const img of images) {
        await deleteStoredFile(img.filename);
      }
      if (entry.video_filename) {
        await deleteStoredFile(entry.video_filename);
      }
      if (entry.video_poster_filename) {
        await deleteStoredFile(entry.video_poster_filename);
      }
      await dbRunAsync('DELETE FROM comments WHERE entry_id = ?', [entry.id]);
      await dbRunAsync('DELETE FROM entry_reactions WHERE entry_id = ?', [entry.id]);
      await dbRunAsync('DELETE FROM entry_tags WHERE entry_id = ?', [entry.id]);
      await dbRunAsync('DELETE FROM entry_images WHERE entry_id = ?', [entry.id]);
    }
    await dbRunAsync('DELETE FROM entries WHERE user_id = ?', [targetUserId]);
    await dbRunAsync('DELETE FROM comments WHERE user_id = ?', [targetUserId]);
    await dbRunAsync('DELETE FROM entry_reactions WHERE user_id = ?', [targetUserId]);
    await dbRunAsync('DELETE FROM collections WHERE user_id = ?', [targetUserId]);

    // Delete user
    await dbRunAsync('DELETE FROM users WHERE id = ?', [targetUserId]);
    await appendAuditLog(req, 'user.delete', 'user', targetUserId, null);

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

app.post('/login', makeAuthRateLimiter('login'), verifyCsrfToken, async (req, res) => {
  const username = (req.body.username || '').trim();
  const password = req.body.password || '';
  if (!username || !password) {
    return res.status(400).render('login', { error: 'Username and password are required' });
  }

  try {
    const row = await dbGetAsync('SELECT * FROM users WHERE username = ?', [username]);
    if (!row) return res.render('login', { error: 'Invalid credentials' });
    if (!bcrypt.compareSync(password, row.password_hash)) return res.render('login', { error: 'Invalid credentials' });
    await dbRunAsync('UPDATE users SET last_login_at = ? WHERE id = ?', [Date.now(), row.id]);
    req.session.userId = row.id;
    req.session.userRole = row.role;
    req.session.userCanPin = Boolean(Number(row.can_pin || 0) === 1);
    return res.redirect('/');
  } catch (err) {
    console.error(err);
    return res.status(500).send('DB error');
  }
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

    const registerConflicts = await findRegistrationConflicts(username, email, { includePending: true });
    const registerConflictMessage = getRegistrationConflictMessage(registerConflicts);
    if (registerConflictMessage) {
      return res.status(400).render('register', {
        error: registerConflictMessage,
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
    if (err && err.code === 'SQLITE_CONSTRAINT') {
      const registerConflicts = await findRegistrationConflicts(username, email, { includePending: true });
      const registerConflictMessage = getRegistrationConflictMessage(registerConflicts) || 'Username or email is already registered.';
      return res.status(400).render('register', {
        error: registerConflictMessage,
        info: null,
        username,
        email,
        isFirstUser,
        emailVerificationEnabled: EMAIL_VERIFICATION_ENABLED
      });
    }
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

    const verifyConflicts = await findRegistrationConflicts(pending.username, pending.email, { includePending: false });
    const verifyConflictMessage = getRegistrationConflictMessage(verifyConflicts);
    if (verifyConflictMessage) {
      await dbRunAsync('DELETE FROM pending_registrations WHERE username = ?', [pending.username]);
      return res.status(400).render('register', {
        error: `${verifyConflictMessage} Please try registering again.`,
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
    if (err && err.code === 'SQLITE_CONSTRAINT') {
      await dbRunAsync('DELETE FROM pending_registrations WHERE username = ?', [username]);
      return res.status(400).render('register', {
        error: 'Username or email is already registered. Please try registering again.',
        info: null,
        username: '',
        email: '',
        isFirstUser: false,
        emailVerificationEnabled: EMAIL_VERIFICATION_ENABLED
      });
    }
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
    return res.status(400).send(`You can upload up to ${MAX_IMAGES_PER_POST} images and 1 video per post.`);
  }
  if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
    return res.status(400).send(`Each uploaded file must be ${Math.max(MAX_UPLOAD_FILE_SIZE_MB, MAX_VIDEO_FILE_SIZE_MB)}MB or smaller.`);
  }
  if (err instanceof multer.MulterError && err.code === 'LIMIT_UNEXPECTED_FILE') {
    if (err.field === 'photos') {
      return res.status(400).send(`You can upload up to ${MAX_IMAGES_PER_POST} images per post.`);
    }
    if (err.field === 'video') {
      return res.status(400).send('You can upload only 1 video per post.');
    }
    return res.status(400).send(`Unexpected upload field "${err.field || 'unknown'}".`);
  }
  if (err) {
    console.error(err);
    return res.status(500).send('Unexpected error');
  }
  return next();
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
