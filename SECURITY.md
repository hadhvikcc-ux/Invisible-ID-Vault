# SECURITY.md

## The honest claim

**Invisibility helps a lot, but it does not by itself make a system "impossible to hack".** No honest system can claim that. What this project does is remove the easiest attack paths, then layer standard defences on top.

## Threat model — see also docs/THREAT-MODEL.md

| Attack | Defence in this repo |
|---|---|
| User enumeration (try `user/1`, `user/2`…) | No sequential IDs, no username/email, no `/users/:id` endpoint, no public profile |
| Targeted password attack | Attacker needs the 256-bit invisible ID *first*; there is no handle to target |
| Brute-forcing the ID | 2²⁵⁶ space, ≈10⁶³ years at 10¹² guesses/sec |
| Password brute force | bcrypt cost 12, 20 attempts / 15 min per IP (rate limit) |
| Timing leak (wrong ID vs wrong passphrase) | Same generic error, dummy bcrypt compare when user is missing, `timingSafeEqual` on hashes |
| ID leak from logs / URLs / UI | Raw ID never logged, never in a URL, never returned after creation; only `••••-xxxx` fingerprint shown |
| Database leak | Store holds only `sha256(ID)` + bcrypt(passphrase) — raw ID cannot be recovered from the DB |
| XSS / header attacks | `helmet`, JSON limit, escaped note rendering |

## What is NOT yet production-grade

- File store (`data/users.json`) — replace with Postgres + encrypted-at-rest storage.
- In-memory sessions — replace with Redis + httpOnly, Secure, SameSite cookies.
- Notes are stored as plain text in the demo — add client-side AES-GCM encryption with a key derived from the passphrase (PBKDF2) before production use.
- No 2FA / hardware key yet — the invisible ID *is* a second factor in practice (something you have + something you know), but add WebAuthn for high-value accounts.

## Reporting a vulnerability

Do not open a public issue for a security bug. Email the maintainer privately with steps to reproduce. Rotate any exposed recovery keys.
