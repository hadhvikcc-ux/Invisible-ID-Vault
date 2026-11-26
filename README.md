# Invisible ID Vault

An account system where **the user ID itself is invisible, opaque and unguessable**. There is no username, no email, and no public profile to target.

> Without the invisible ID, an account cannot even be **found** — let alone hacked.  
> That invisibility is one layer. The app also uses bcrypt, rate limiting, hashed IDs, constant-time comparison and generic errors. See `SECURITY.md` — invisibility alone is not magic.

## What it does

1. **Create an invisible identity** — server generates a 256-bit random ID (`UUID + 32 random bytes`). Shown **once** as a recovery key. Never shown, logged, or put in a URL again.
2. **Unlock** — enter the invisible ID + passphrase. Wrong ID and wrong passphrase return the *same* generic error.
3. **Vault** — save private notes. The UI shows only a fingerprint like `••••-a3f9`, never the ID.
4. **Try to hack it** — demo panel shows why brute force is infeasible (≈10⁶³ years at 1 trillion guesses/sec).

## Android app

There is an Android version built with Capacitor — an offline vault that
needs no server. GitHub Actions builds a downloadable debug APK on every
push to `main` touching the Android files.

**Download it:** repo → **Actions → Android** → latest run → Artifacts →
`invisible-id-vault-debug-apk` → unzip → install `app-debug.apk` on your
phone (allow "Install unknown apps" for your browser/file manager when asked).

Full details: [docs/ANDROID.md](docs/ANDROID.md) — including how the build
works, how to install, and how to make a signed release APK/AAB later.

## Quick start

```bash
npm install
npm start
# open http://localhost:3000
npm test
```

## Project structure

```
invisible-id-vault/
├── server.js                 # Express API: /api/create, /api/unlock, /api/me, /api/notes
├── src/
│   ├── invisible-id.js       # generate / hash / fingerprint / constant-time compare
│   └── store.js              # file-backed store (swap for Postgres in prod)
├── public/                   # frontend: index.html, app.js, styles.css
├── www/                      # offline Android web app (Capacitor, no server)
├── capacitor.config.json     # appId com.hadhvik.invisibleidvault
├── android/                  # generated locally / on CI, NOT committed (see docs/ANDROID.md)
├── tests/invisible-id.test.js
├── docs/                     # API, setup, threat model, Android
├── README.md  SECURITY.md  ARCHITECTURE.md
├── .github/workflows/ci.yml       # Node CI: install + test on push
└── .github/workflows/android.yml  # Android CI: build debug APK on GitHub Actions
```

## API

See [docs/API.md](docs/API.md).

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/create` | Create identity, returns recovery key **once** |
| POST | `/api/unlock` | Unlock with invisible ID + passphrase |
| GET | `/api/me` | Fingerprint + notes (auth required) |
| POST | `/api/notes` | Save notes (auth required) |
| POST | `/api/logout` | Revoke session |

## Deploy

- **Local / VPS:** `npm install && npm start`, set `PORT` and `DATA_FILE`.
- **GitHub:** push this repo, CI runs on every push (see `.github/workflows/ci.yml`). Deploy to Render / Railway / Fly.io with `npm start` as the start command.
- **Production hardening:** use Postgres instead of `data/users.json`, httpOnly secure cookies instead of Bearer tokens in the demo, and a real secret store for sessions. See `ARCHITECTURE.md`.

## If you lose the recovery key

There is **no password-reset by email** — there is no email on file, by design. Losing both the ID and the passphrase means the account is unrecoverable. That is the trade-off of invisibility. Save the key offline (password manager / paper).

## License

MIT — see `LICENSE`.
