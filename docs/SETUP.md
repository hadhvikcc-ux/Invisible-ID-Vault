# Setup

## Requirements

- Node.js 18+
- npm

## Run locally

```bash
cd invisible-id-vault
npm install
npm start
# http://localhost:3000
```

## Run in development

```bash
npm run dev
```

## Test

```bash
npm test
```

## Environment

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | HTTP port |
| `DATA_FILE` | `./data/users.json` | Where accounts are stored |

Copy `.env.example` to `.env` if you add secrets later. Never commit `.env` or `data/`.

## Push to GitHub

```bash
git init
git add .
git commit -m "feat: invisible ID vault v1"
git branch -M main
git remote add origin https://github.com/<you>/invisible-id-vault.git
git push -u origin main
```

CI (`.github/workflows/ci.yml`) runs `npm ci && npm test` on every push / pull request.

## Deploy

Render / Railway / Fly.io: set build command `npm install`, start command `npm start`, and set `DATA_FILE` to a persistent volume in production.
