# Threat model

## In scope

- Anonymous attacker on the internet, no prior knowledge of any user.
- Attacker with a leaked copy of the database file.
- Attacker trying credential stuffing / enumeration.

## Out of scope (for v1)

- Attacker with full server compromise (they could read IDs in memory at creation time — mitigate with HSM / separate ID service in v2).
- Phishing / device compromise — no app can prevent a user pasting their recovery key into a fake site. Mitigate with user education + domain-pinned recovery flow.
- Legal / coercion scenarios.

## Key trade-off

Losing the recovery key + passphrase = permanent loss. There is no email reset, because there is no email. This is intentional: a reset channel is an attack channel.
