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
const upload = multer({ storage: multer.memoryStorage() });

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

// DB
const db = new sqlite3.Database(DB_PATH);
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT,
    originalname TEXT,
    note TEXT,
    created_at INTEGER
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password_hash TEXT
  )`);
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

function ensureAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  res.redirect('/login');
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

app.get('/', (req, res) => {
  db.all('SELECT * FROM entries ORDER BY created_at DESC', (err, rows) => {
    if (err) return res.status(500).send('DB error');
    db.get('SELECT COUNT(*) AS c FROM users', (countErr, countRow) => {
      if (countErr) return res.status(500).send('DB error');
      const uploadError = req.query.error === 'daily_limit'
        ? `Daily upload limit reached (${DAILY_UPLOAD_LIMIT} posts). Try again tomorrow.`
        : null;
      res.render('index', {
        entries: rows,
        userId: req.session.userId,
        canRegister: (countRow?.c || 0) === 0,
        uploadError
      });
    });
  });
});

app.post('/upload', ensureAuth, upload.single('photo'), async (req, res) => {
  const note = req.body.note || '';
  const file = req.file || null;
  let storedKey = null;

  try {
    const { startMs, endMs } = getDayRangeMs();
    const dailyCount = await getEntryCountInRange(startMs, endMs);
    if (dailyCount >= DAILY_UPLOAD_LIMIT) {
      return res.redirect('/?error=daily_limit');
    }

    if (file) {
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

      storedKey = key;
    }

    const stmt = db.prepare('INSERT INTO entries(filename, originalname, note, created_at) VALUES (?,?,?,?)');
    stmt.run(storedKey, file ? file.originalname : null, note, Date.now(), (err) => {
      stmt.finalize();
      if (err) return res.status(500).send('DB insert error');
      res.redirect('/');
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Upload error');
  }
});

app.post('/entries/:id/delete', ensureAuth, (req, res) => {
  const entryId = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(entryId) || entryId <= 0) {
    return res.status(400).send('Invalid entry id');
  }

  db.get('SELECT filename FROM entries WHERE id = ?', [entryId], (fetchErr, row) => {
    if (fetchErr) return res.status(500).send('DB error');
    if (!row) return res.redirect('/');

    db.run('DELETE FROM entries WHERE id = ?', [entryId], async (deleteErr) => {
      if (deleteErr) return res.status(500).send('DB delete error');

      if (row.filename) {
        try {
          await deleteStoredFile(row.filename);
        } catch (fileErr) {
          if (fileErr.code !== 'ENOENT' && fileErr.name !== 'NoSuchKey') {
            console.error('File delete error:', fileErr);
          }
        }
      }

      res.redirect('/');
    });
  });
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
    res.redirect('/');
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// Simple registration: only allowed when no users exist
app.get('/register', (req, res) => {
  if (req.session && req.session.userId) return res.redirect('/');
  db.get('SELECT COUNT(*) as c FROM users', (err, row) => {
    if (err) return res.status(500).send('DB error');
    if (row && row.c > 0) return res.status(403).send('Registration disabled');
    res.render('register', { error: null });
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
    if (row && row.c > 0) return res.status(403).send('Registration disabled');
    const hash = bcrypt.hashSync(password, 10);
    db.run('INSERT INTO users(username, password_hash) VALUES (?, ?)', [username, hash], function(err) {
      if (err && err.code === 'SQLITE_CONSTRAINT') {
        return res.status(400).render('register', { error: 'Username already exists' });
      }
      if (err) return res.status(500).send('DB insert error');
      req.session.userId = this.lastID;
      res.redirect('/');
    });
  });
});

// Helper: expose file urls when rendering
app.locals.fileUrl = function(filename) {
  if (!filename) return null;
  return buildFileUrl(filename);
};

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
