# Foodgraphy

A visual diary for meals, places, and moments. Built with Node.js, Express, and SQLite.

## Features

- **Food Posts** — Upload multiple images + optional video, with notes, author, location, rating, and tags
- **Collections & Tags** — Organize posts into collections and tag them for filtering
- **Comments & Reactions** — Emoji reactions and comments on posts
- **AI Chat** — Built-in AI chat assistant with Claude, OpenAI, and custom provider support ([docs](docs/ai-chat.md))
- **PDF Merge** — Merge multiple PDFs into one ([docs](docs/pdf-merge.md))
- **User Auth** — Registration with email verification, role-based access control
- **Admin Panel** — User management, audit logs, per-user tool permissions
- **Auto-Backup** — Periodic database and uploads backup with configurable retention
- **Performance** — Gzip compression, image optimization, SQLite WAL mode, optional Redis caching

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Node.js 22+, Express |
| Database | SQLite3 (WAL mode) |
| Templates | EJS |
| Frontend | Vanilla JS, CSS |
| Storage | Local filesystem or Cloudflare R2 |
| Caching | Optional Redis |

## Quick Start

```bash
# Install dependencies
npm install

# Copy and configure environment
cp .env.example .env
# Edit .env with your settings (at minimum: SESSION_SECRET, SMTP_*)

# Start the server
npm start
```

Open `http://localhost:3000`. The first verified user becomes **admin**.

## Configuration

Copy `.env.example` to `.env`. Key settings:

### Required

| Variable | Description |
|----------|-------------|
| `SESSION_SECRET` | Session encryption secret (use a strong random value) |
| `SMTP_HOST` | SMTP server for email verification |
| `SMTP_PORT` | SMTP port (default `587`) |
| `SMTP_USER` | SMTP username |
| `SMTP_PASS` | SMTP password |
| `SMTP_FROM` | Sender email address |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_PATH` | `./data.db` | SQLite database path |
| `MAX_IMAGES_PER_POST` | `10` | Max images per post |
| `MAX_UPLOAD_FILE_SIZE_MB` | `10` | Max image upload size |
| `MAX_VIDEO_FILE_SIZE_MB` | `50` | Max video upload size |
| `POSTS_PER_PAGE` | `20` | Posts per page |
| `CACHE_ENABLED` | `true` | Enable Redis caching |
| `REDIS_URL` | — | Redis connection URL |
| `BACKUP_ENABLED` | `true` | Enable auto-backup |
| `BACKUP_INTERVAL_HOURS` | `24` | Hours between backups |

See [`.env.example`](.env.example) for the full list.

### AI Chat

Set at least one API key to enable the AI chat tool:

```env
ANTHROPIC_API_KEY=sk-ant-...     # Claude
OPENAI_API_KEY=sk-...            # OpenAI
CUSTOM_LLM_BASE_URL=https://...  # Any OpenAI-compatible endpoint
CUSTOM_LLM_API_KEY=...
CUSTOM_LLM_MODELS=model-1,model-2
```

See [docs/ai-chat.md](docs/ai-chat.md) for full setup details.

### Optional System Dependencies

```bash
# Video transcoding
brew install ffmpeg

# PDF merge tool
brew install ghostscript
```

## Docker

### Development

```bash
docker compose up --build
```

### Production (with Caddy for auto-HTTPS)

1. Point DNS to your server
2. Configure `.env` (set `SESSION_SECRET`, `SITE_DOMAIN`, `ACME_EMAIL`, SMTP vars)
3. Run:

```bash
docker compose -f deploy/docker-compose.prod.yml --env-file .env up -d --build
```

## Tools Framework

Tools are registered through a modular registry. To add a new tool:

1. Create a module in `src/tools/` (see `pdf-merge-tool.js` as reference)
2. Register it in `server.js` with `toolRegistry.register(...)`
3. It automatically appears in `/tools` with admin-managed per-user access

Tool documentation: [`docs/`](docs/)

## Backup & Restore

**Auto-backup** runs every 24 hours (configurable) and stores backups in `./backups/`.

**Manual backup/restore:**

```bash
sh back.sh                # create backup
sh timeback.sh 3          # restore to nearest backup from 3 days ago
sh timeback.sh 3 --yes    # non-interactive restore
```

## Project Structure

```
server.js                  # Main application
src/
  framework/tool-registry.js  # Tool plugin system
  tools/                       # Tool implementations
  backup-manager.js            # Auto-backup
  cache-manager.js             # Redis cache layer
views/                     # EJS templates
public/                    # Static assets (JS, CSS)
deploy/                    # Docker + Caddy production config
docs/                      # Tool documentation
```

## License

MIT
