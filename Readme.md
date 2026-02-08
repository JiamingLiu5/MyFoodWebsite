MyFoodWebsite

This is a minimal Node.js + Express site to upload photos and notes, persisted in a local SQLite database. A Dockerfile and docker-compose are included for containerized runs.

Post features:

- Multiple images per post (default max 10 per post).
- Single-post detail page with full-size image viewer on click.
- Edit and delete existing posts.
- Pin/unpin posts (pinned posts stay at top for logged-in users).
- Public visitors (not logged in) can only see and view pinned posts.

Storage behavior:

- If Cloudflare R2 variables are configured, uploaded files are stored in R2.
- If R2 variables are not configured, uploaded files are stored locally in `uploads/`.
- SQLite data is stored at `data.db` by default (or `DB_PATH` if set).

First-time setup:

- Open `http://localhost:3000` and use the `Register` link to create the first user.
- After one user exists, registration is disabled.

Run locally:

1. Install dependencies

```bash
npm install
```

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
- `SITE_DOMAIN` — primary domain used by Caddy in production
- `ACME_EMAIL` — email for Let's Encrypt certificate registration
- `DB_PATH` — optional SQLite path (default `./data.db`)
- `DAILY_UPLOAD_LIMIT` — max number of posts per day (default `1000`)
- `MAX_IMAGES_PER_POST` — max images allowed in one post (default `10`)

Example run (local env):

```bash
export R2_ENDPOINT="https://<accountid>.r2.cloudflarestorage.com"
export R2_BUCKET="my-bucket"
export R2_ACCESS_KEY_ID="..."
export R2_SECRET_ACCESS_KEY="..."
export R2_PUBLIC_BASE_URL="https://<bucket>.<accountid>.r2.cloudflarestorage.com"
export SESSION_SECRET="yoursecret"
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
