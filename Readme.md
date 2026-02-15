# MyFoodWebsite

Simple Node.js + Express app for food posts with:
- Multiple images + optional one video per post
- Notes, author, location, rating
- Pin/unpin posts (with admin-managed pin permission)
- Tools page (`/tools`) with admin-managed per-user tool access
- User auth with email verification
- SQLite storage, optional Cloudflare R2 file storage

## Quick Start

Requires Node.js `22+`.

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

## Optional: PDF Merge Tool (Ghostscript)

The first built-in tool is **PDF Merge** at `/tools`.
Install Ghostscript to enable server-side PDF merging:

```bash
brew install ghostscript
```

- `GHOSTSCRIPT_PATH` (default `gs`)
- `MAX_TOOL_PDF_FILES` (default `10`)
- `MAX_TOOL_PDF_FILE_SIZE_MB` (default `20`)
- `MAX_TOOL_PDF_TOTAL_INPUT_MB` (default `80`)
- `TOOL_RUN_TIMEOUT_SECONDS` (default `45`)

Security/resource controls for tool execution:
- `TOOL_RATE_LIMIT_WINDOW_SECONDS` (default `60`)
- `TOOL_RATE_LIMIT_MAX_RUNS` (default `6`)
- `TOOL_MAX_CONCURRENT_RUNS` (default `2`)
- `TOOL_MAX_CONCURRENT_RUNS_PER_TOOL` (default `1`)

Current guardrails for PDF Merge:
- Per-user tool run rate limiting.
- Global/per-tool concurrency caps.
- Disk-backed uploads (lower RAM usage vs in-memory upload buffers).
- PDF signature check before processing.
- Ghostscript runs with `-dSAFER` and timeout protection.
- Temp upload cleanup after each run.

## Extending The Tools Framework

Tools are now registered through a modular registry so you can add new tools without changing the core route shape.

1. Create a new tool module in `src/tools/` (follow `src/tools/pdf-merge-tool.js`).
2. Register it in `server.js` with `toolRegistry.register(...)`.
3. The tool will automatically:
   - appear in `/tools`,
   - use `/tools/:toolKey/run`,
   - support admin per-user permission controls in `/admin/users`.

## Docker

```bash
docker compose up --build
```

After image updates, rebuild so Ghostscript is included:

```bash
docker compose up -d --build
docker compose exec web gs --version
docker compose exec web node -e "require('http').get('http://127.0.0.1:3000/healthz',r=>console.log(r.statusCode))"
```

The web container now runs with:
- non-root user
- read-only root filesystem
- `no-new-privileges` + dropped Linux capabilities
- `/tmp` mounted as tmpfs for tool temp files

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

- `NODE_ENV` (default `development`, set `production` in prod)
- `DB_PATH` (default `./data.db`)
- `MAX_IMAGES_PER_POST` (default `10`)
- `MAX_UPLOAD_FILE_SIZE_MB` (default `10`)
- `MAX_VIDEO_FILE_SIZE_MB` (default `50`)
- `DAILY_UPLOAD_LIMIT` (default `1000`)
- `DAILY_REGISTRATION_LIMIT` (default `200`)
- `ENABLE_VIDEO_TRANSCODE` (default `true`)
- `ENABLE_SERVER_VIDEO_PROCESSING` (default `false`)
- `FFMPEG_PATH` (default `ffmpeg`)
- `GHOSTSCRIPT_PATH` (default `gs`)
- `MAX_TOOL_PDF_FILES` (default `10`)
- `MAX_TOOL_PDF_FILE_SIZE_MB` (default `20`)
- `MAX_TOOL_PDF_TOTAL_INPUT_MB` (default `80`)
- `TOOL_RUN_TIMEOUT_SECONDS` (default `45`)
- `TOOL_RATE_LIMIT_WINDOW_SECONDS` (default `60`)
- `TOOL_RATE_LIMIT_MAX_RUNS` (default `6`)
- `TOOL_MAX_CONCURRENT_RUNS` (default `2`)
- `TOOL_MAX_CONCURRENT_RUNS_PER_TOOL` (default `1`)
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
