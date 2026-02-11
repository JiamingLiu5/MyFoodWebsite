MyFoodWebsite

This is a minimal Node.js + Express site to upload photos, one optional video per post, and notes, persisted in a local SQLite database. A Dockerfile and docker-compose are included for containerized runs.

Post features:

- Multiple images per post (default max 10 per post, including HEIC/HEIF uploads).
- One optional video per post.
- Video poster preview from first frame generated on the client side.
- Client-side image optimization before upload (resize/compress) to reduce server and bandwidth load.
- Optional server-side ffmpeg poster generation and automatic `.mov` to `.mp4` transcoding for browser compatibility.
- Single-post detail page with full-size image viewer on click.
- Edit and delete existing posts.
- Optional per-post author label (for distinguishing multiple people sharing one account).
- Optional per-post location text input.
- Pin/unpin posts (pinned posts stay at top for logged-in users).
- Admin can grant non-admin users a separate pin permission.
- Admin can reset password for any user (including admin self).
- Public visitors (not logged in) can only see and view pinned posts.
- Security hardening: CSRF protection for all form POSTs, auth route rate limits, stricter security headers.

Storage behavior:

- If Cloudflare R2 variables are configured, uploaded files are stored in R2.
- If R2 variables are not configured, uploaded files are stored locally in `uploads/`.
- SQLite data is stored at `data.db` by default (or `DB_PATH` if set).

First-time setup:

- Configure SMTP variables first (see below), then open `http://localhost:3000`.
- Use the `Register` link, enter username/email/password, then verify with the 6-digit code sent by email.
- The first verified user becomes `admin`; later users become `normal`.

Run locally:

1. Install dependencies

```bash
npm install
```

Optional for server-side video processing support:

```bash
brew install ffmpeg
```

`ENABLE_VIDEO_TRANSCODE` defaults to `true` (recommended) so `.mov` uploads can be converted to browser-friendly `.mp4`.
Set `ENABLE_SERVER_VIDEO_PROCESSING=true` if you also want ffmpeg-generated poster images on the server.

2. Start the server

```bash
npm start
```

Open http://localhost:3000

Using Docker:

```bash
docker compose up --build
```

Docker persistence:

- Uploaded files persist in `./uploads`.
- SQLite data persists in `./data/data.db`.

Backup and Timeback:

- Create backup now:

```bash
sh back.sh
```

- Restore database to nearest backup from 3 days ago (or older):

```bash
sh timeback.sh 3
```

- Non-interactive restore:

```bash
sh timeback.sh 3 --yes
```

Files added:

- [package.json](package.json)
- [server.js](server.js)
- [views/index.ejs](views/index.ejs)
- [public/style.css](public/style.css)
- [Dockerfile](Dockerfile)
- [docker-compose.yml](docker-compose.yml)

Environment variables:

- `R2_ENDPOINT` — S3-compatible endpoint (optional; required for R2 uploads)
- `R2_BUCKET` — your R2 bucket name (required for R2 uploads)
- `R2_ACCESS_KEY_ID` and `R2_SECRET_ACCESS_KEY` — R2 credentials (required for R2 uploads)
- `R2_PUBLIC_BASE_URL` — optional public base URL to serve files (for R2-hosted objects)
- `SESSION_SECRET` — secret for session cookies
- `SESSION_COOKIE_SECURE` — set `true` behind HTTPS reverse proxy
- `SESSION_COOKIE_SAME_SITE` — cookie SameSite policy (default `lax`)
- `TRUST_PROXY` — set `true` when behind Caddy or another reverse proxy
- `SMTP_HOST` — SMTP server host for registration emails
- `SMTP_PORT` — SMTP server port (usually `587` or `465`)
- `SMTP_SECURE` — set `true` for SMTPS (usually with port `465`)
- `SMTP_USER` / `SMTP_PASS` — SMTP credentials (if required by provider)
- `SMTP_FROM` — sender address used for confirmation emails
- `REGISTRATION_CODE_TTL_MINUTES` — code expiry in minutes (default `10`)
- `SITE_DOMAIN` — primary domain used by Caddy in production
- `ACME_EMAIL` — email for Let's Encrypt certificate registration
- `DB_PATH` — optional SQLite path (default `./data.db`)
- `DAILY_UPLOAD_LIMIT` — max number of posts per day (default `1000`)
- `DAILY_REGISTRATION_LIMIT` — max number of new users per day (default `200`)
- `MAX_IMAGES_PER_POST` — max images allowed in one post (default `10`)
- `MAX_UPLOAD_FILE_SIZE_MB` — max size per uploaded image in MB (default `10`)
- `MAX_VIDEO_FILE_SIZE_MB` — max size for uploaded video in MB (default `50`)
- `ENABLE_SERVER_VIDEO_PROCESSING` — set `true` to enable ffmpeg-based server poster generation (default `false`)
- `ENABLE_VIDEO_TRANSCODE` — auto-transcode `.mov` uploads to `.mp4` when ffmpeg is available (default `true`)
- `FFMPEG_PATH` — ffmpeg binary path (default `ffmpeg`)
- `BODY_LIMIT` — max URL-encoded body size (default `256kb`)
- `AUTH_RATE_LIMIT_WINDOW_MINUTES` — auth brute-force window size (default `15`)
- `AUTH_RATE_LIMIT_MAX_ATTEMPTS` — max auth attempts per IP per window (default `25`)

Example run (local env):

```bash
export R2_ENDPOINT="https://<accountid>.r2.cloudflarestorage.com"
export R2_BUCKET="my-bucket"
export R2_ACCESS_KEY_ID="..."
export R2_SECRET_ACCESS_KEY="..."
export R2_PUBLIC_BASE_URL="https://<bucket>.<accountid>.r2.cloudflarestorage.com"
export SESSION_SECRET="yoursecret"
export SMTP_HOST="smtp.mailprovider.com"
export SMTP_PORT="587"
export SMTP_SECURE="false"
export SMTP_USER="smtp-user"
export SMTP_PASS="smtp-pass"
export SMTP_FROM="no-reply@ldnmeals.com"
export MAX_UPLOAD_FILE_SIZE_MB="10"
export MAX_VIDEO_FILE_SIZE_MB="50"
export ENABLE_SERVER_VIDEO_PROCESSING="false"
export ENABLE_VIDEO_TRANSCODE="true"
export FFMPEG_PATH="ffmpeg"
export AUTH_RATE_LIMIT_WINDOW_MINUTES="15"
export AUTH_RATE_LIMIT_MAX_ATTEMPTS="25"
npm start
```

Production deploy for `123.123.123.123` + `ldnmeals.com`:

1. Point DNS records:

- `A` record for `ldnmeals.com` -> `123.123.123.123`
- `A` record for `www.ldnmeals.com` -> `123.123.123.123`

2. On your server, install Docker:

```bash
sudo apt update
sudo apt install -y docker.io docker-compose-plugin
```

3. Upload project to server and create production env file:

```bash
cp .env.example .env
```

Set at least:

- `SESSION_SECRET=<strong-random-value>`
- `SITE_DOMAIN=ldnmeals.com`
- `ACME_EMAIL=<your-email>`
- `SMTP_HOST=<your-smtp-host>`
- `SMTP_PORT=587`
- `SMTP_FROM=no-reply@ldnmeals.com`
- `SMTP_USER=<smtp-user>`
- `SMTP_PASS=<smtp-pass>`

4. Start the app with production compose:

```bash
docker compose -f deploy/docker-compose.prod.yml --env-file .env up -d --build
```

5. Optional firewall rules:

```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
```

Caddy is included in `deploy/docker-compose.prod.yml` and handles HTTPS certificates automatically for `SITE_DOMAIN` and `www.SITE_DOMAIN`.
