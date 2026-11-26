# ARCHITECTURE.md

## Flow

```
Signup:  [browser] --label+passphrase--> [server]
         server: invisibleId = UUID + randomBytes(32)
                 idHash = sha256(invisibleId)
                 store { idHash, bcrypt(passphrase), label, notes: [] }
         server --recoveryKey (ONCE)--> [browser]  → user saves it offline

Unlock:  [browser] --invisibleId+passphrase--> [server]
         server: idHash = sha256(invisibleId); find by hash
                 bcrypt.compare(passphrase)  (dummy compare if not found)
                 → sessionToken (random 32 bytes) → [browser]
         All later calls: Authorization: Bearer <sessionToken>
         Server never returns the raw ID again.
```

## Why not a username?

A username is a public, guessable, enumerable handle. Removing it means:
- no directory to scrape,
- no "does this account exist?" oracle,
- no credential-stuffing list to reuse.

The invisible ID is effectively a high-entropy password *and* identifier in one, split from the human passphrase so losing one alone is not enough.

## Components

- `server.js` — Express, helmet, rate-limit, auth middleware, 5 API routes.
- `src/invisible-id.js` — pure functions, fully unit-tested. No I/O, no secrets in logs.
- `src/store.js` — JSON file store, replaceable interface (`findByHash` / `insert` / `update`).
- `public/` — static frontend, no framework, no build step.

## Data stored

| Field | Value |
|---|---|
| `idHash` | `sha256(invisibleId)` — hex |
| `passphraseHash` | bcrypt, cost 12 |
| `label` | private nickname only |
| `notes` | array (encrypt before production) |
| `createdAt` | ISO timestamp |

No email, no phone, no raw ID, no IP logs in the store.

## Scaling

Replace `store.js` with Postgres (`idHash` as primary key, indexed), move sessions to Redis, put the app behind TLS + a WAF, and add audit logging that records *only* fingerprints and timestamps, never IDs.
