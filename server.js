require('dotenv').config();
const path = require('path');
const fs = require('fs');
const express = require('express');
const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { S3Client, PutObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');

const app = express();
const PORT = process.env.PORT || 3000;
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data.db');
const DAILY_UPLOAD_LIMIT = Math.max(1, Number.parseInt(process.env.DAILY_UPLOAD_LIMIT || '1000', 10));
const MAX_IMAGES_PER_POST = Math.max(1, Number.parseInt(process.env.MAX_IMAGES_PER_POST || '10', 10));
const TRUST_PROXY = process.env.TRUST_PROXY === 'true';
const SESSION_COOKIE_SECURE = process.env.SESSION_COOKIE_SECURE === 'true';
const SESSION_COOKIE_SAME_SITE = process.env.SESSION_COOKIE_SAME_SITE || 'lax';
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
  limits: { files: MAX_IMAGES_PER_POST }
});

// Setup view engine and static
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use('/static', express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOADS_DIR));
app.use(express.urlencoded({ extended: true }));

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

// Attach user role to request for authorization checks
app.use(async (req, res, next) => {
  if (req.session && req.session.userId) {
    // Use session cache if available
    if (req.session.userRole) {
      req.userRole = req.session.userRole;
    } else {
      // Fetch from DB and cache in session
      const user = await dbGetAsync('SELECT role FROM users WHERE id = ?', [req.session.userId]);
      req.userRole = user ? user.role : null;
      if (req.userRole) req.session.userRole = req.userRole;
    }
    res.locals.userRole = req.userRole; // Make available to views
  } else {
    req.userRole = null;
    res.locals.userRole = null;
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
    password_hash TEXT
  )`);
  // Migration: Add role column to users table
  db.all('PRAGMA table_info(users)', (pragmaErr, cols) => {
    if (pragmaErr) return console.error('PRAGMA users error:', pragmaErr);
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

app.get('/', async (req, res) => {
  try {
    const isAdmin = req.userRole === 'admin';
    const userId = req.session.userId;

    let rows;
    if (isAdmin) {
      // Admins see all posts
      rows = await dbAllAsync(
        'SELECT * FROM entries ORDER BY COALESCE(is_pinned, 0) DESC, created_at DESC'
      );
    } else if (userId) {
      // Normal users see: pinned posts OR their own posts
      rows = await dbAllAsync(
        'SELECT * FROM entries WHERE COALESCE(is_pinned, 0) = 1 OR user_id = ? ORDER BY COALESCE(is_pinned, 0) DESC, created_at DESC',
        [userId]
      );
    } else {
      // Non-authenticated users see only pinned posts
      rows = await dbAllAsync(
        'SELECT * FROM entries WHERE COALESCE(is_pinned, 0) = 1 ORDER BY created_at DESC'
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

app.post('/upload', ensureAuth, upload.array('photos', MAX_IMAGES_PER_POST), async (req, res) => {
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
    const row = await dbGetAsync('SELECT * FROM entries WHERE id = ?', [entryId]);
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
      userRole: req.userRole
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('DB error');
  }
});

app.post('/entries/:id/pin', ensureAdmin, async (req, res) => {
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

app.post('/entries/:id/edit', ensureOwnerOrAdmin, upload.array('photos', MAX_IMAGES_PER_POST), async (req, res) => {
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

app.post('/entries/:id/delete', ensureOwnerOrAdmin, async (req, res) => {
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
    const users = await dbAllAsync('SELECT id, username, role FROM users ORDER BY id ASC');
    res.render('admin-users', { users, userId: req.session.userId, userRole: req.userRole });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error loading users');
  }
});

app.post('/admin/users/:id/role', ensureAdmin, async (req, res) => {
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

app.post('/admin/users/:id/delete', ensureAdmin, async (req, res) => {
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

app.post('/login', (req, res) => {
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
    res.redirect('/');
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// Registration: first user becomes admin, subsequent users become normal users
app.get('/register', (req, res) => {
  if (req.session && req.session.userId) return res.redirect('/');
  db.get('SELECT COUNT(*) as c FROM users', (err, row) => {
    if (err) return res.status(500).send('DB error');
    const userCount = (row && row.c) || 0;
    res.render('register', { error: null, isFirstUser: userCount === 0 });
  });
});

app.post('/register', (req, res) => {
  const username = (req.body.username || '').trim();
  const password = req.body.password || '';
  if (!username || !password) {
    return res.status(400).render('register', { error: 'Username and password are required' });
  }

  db.get('SELECT COUNT(*) as c FROM users', (err, row) => {
    if (err) return res.status(500).send('DB error');

    const isFirstUser = row.c === 0;
    const role = isFirstUser ? 'admin' : 'normal';
    const hash = bcrypt.hashSync(password, 10);

    db.run('INSERT INTO users(username, password_hash, role) VALUES (?, ?, ?)',
      [username, hash, role],
      function(err) {
        if (err && err.code === 'SQLITE_CONSTRAINT') {
          return res.status(400).render('register', { error: 'Username already exists' });
        }
        if (err) return res.status(500).send('DB insert error');

        req.session.userId = this.lastID;
        req.session.userRole = role;
        res.redirect('/');
      }
    );
  });
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
  if (err) {
    console.error(err);
    return res.status(500).send('Unexpected error');
  }
  return next();
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
