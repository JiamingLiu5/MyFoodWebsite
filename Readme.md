MyFoodWebsite

This is a minimal Node.js + Express site to upload photos and notes, persisted in a local SQLite database. A Dockerfile and docker-compose are included for containerized runs.

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

Files added:

- [package.json](package.json)
- [server.js](server.js)
- [views/index.ejs](views/index.ejs)
- [public/style.css](public/style.css)
- [Dockerfile](Dockerfile)
- [docker-compose.yml](docker-compose.yml)

Environment variables (for Cloudflare R2 + sessions):

- `R2_ENDPOINT` — S3-compatible endpoint (optional)
- `R2_BUCKET` — your R2 bucket name
- `R2_ACCESS_KEY_ID` and `R2_SECRET_ACCESS_KEY` — R2 credentials
- `R2_PUBLIC_BASE_URL` — optional public base URL to serve files (e.g. https://bucket.accountid.r2.cloudflarestorage.com)
- `SESSION_SECRET` — secret for session cookies

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

