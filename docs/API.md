# API

Base URL: `http://localhost:3000`

All auth errors return the same generic message, so an attacker cannot distinguish a wrong ID from a wrong passphrase.

## POST /api/create

Create an invisible identity.

```bash
curl -X POST http://localhost:3000/api/create \
  -H 'Content-Type: application/json' \
  -d '{"label":"My vault","passphrase":"correct-horse-battery"}'
```

Response `201`:
```json
{ "recoveryKey": "<invisible-id-shown-once>", "fingerprint": "••••-a3f9" }
```

## POST /api/unlock

```bash
curl -X POST http://localhost:3000/api/unlock \
  -H 'Content-Type: application/json' \
  -d '{"invisibleId":"<recovery-key>","passphrase":"correct-horse-battery"}'
```

Response `200`: `{ "sessionToken": "...", "label": "My vault", "fingerprint": "••••-a3f9", "notes": [] }`  
Response `401`: `{ "error": "No account matches that ID and passphrase." }`

## GET /api/me

Header: `Authorization: Bearer <sessionToken>`  
Response: `{ "label": "...", "fingerprint": "••••-a3f9", "notes": [], "createdAt": "..." }`

## POST /api/notes

Header: `Authorization: Bearer <sessionToken>`  
Body: `{ "notes": ["note 1", "note 2"] }` — max 200 notes.

## POST /api/logout

Revokes the session token.

## GET /api/health

`{ "ok": true, "service": "invisible-id-vault" }`
