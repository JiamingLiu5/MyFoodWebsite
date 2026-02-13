# MyFoodWebsite

Simple Node.js + Express app for food posts with:
- Multiple images + optional one video per post
- Notes, author, location, rating
- Pin/unpin posts (with admin-managed pin permission)
- User auth with email verification
- SQLite storage, optional Cloudflare R2 file storage

## Quick Start

```bash
npm install
npm start
```

Open: `http://localhost:3000`

First verified user becomes `admin`.

## Optional: ffmpeg

Install ffmpeg if you want server video processing/transcoding:

```bash
brew install ffmpeg
```

- `ENABLE_VIDEO_TRANSCODE=true` (default): convert `.mov` to `.mp4`
- `ENABLE_SERVER_VIDEO_PROCESSING=true`: generate poster images on server

## Docker

```bash
docker compose up --build
```

Persistent paths:
- uploads: `./uploads`
- database: `./data/data.db`

## Backup / Restore

```bash
sh back.sh                # create backup
sh timeback.sh 3          # restore to nearest backup from 3 days ago (or older)
sh timeback.sh 3 --yes    # non-interactive restore
```

## Required Env Vars (minimum)

- `SESSION_SECRET`
- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_FROM`
- `SMTP_USER`
- `SMTP_PASS`

## Common Env Vars

- `DB_PATH` (default `./data.db`)
- `MAX_IMAGES_PER_POST` (default `10`)
- `MAX_UPLOAD_FILE_SIZE_MB` (default `10`)
- `MAX_VIDEO_FILE_SIZE_MB` (default `50`)
- `DAILY_UPLOAD_LIMIT` (default `1000`)
- `DAILY_REGISTRATION_LIMIT` (default `200`)
- `ENABLE_VIDEO_TRANSCODE` (default `true`)
- `ENABLE_SERVER_VIDEO_PROCESSING` (default `false`)
- `FFMPEG_PATH` (default `ffmpeg`)
- `AUTH_RATE_LIMIT_WINDOW_MINUTES` (default `15`)
- `AUTH_RATE_LIMIT_MAX_ATTEMPTS` (default `25`)

## R2 Storage (optional)

Set these to store uploads in Cloudflare R2 instead of local `uploads/`:
- `R2_ENDPOINT`
- `R2_BUCKET`
- `R2_ACCESS_KEY_ID`
- `R2_SECRET_ACCESS_KEY`
- `R2_PUBLIC_BASE_URL` (optional public URL)

## Production (Docker + Caddy)

1. Point DNS `A` records for your domain (`@` and `www`) to your server IP.
2. Create `.env` (or copy from `.env.example`) and set at least:
   - `SESSION_SECRET`, `SITE_DOMAIN`, `ACME_EMAIL`
   - SMTP variables above
3. Run:

```bash
docker compose -f deploy/docker-compose.prod.yml --env-file .env up -d --build
```

Caddy in `deploy/docker-compose.prod.yml` handles HTTPS automatically.
