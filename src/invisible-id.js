/**
 * Invisible ID — the core idea
 * ----------------------------
 * A normal app gives every user a visible identifier: username, email,
 * or a sequential / predictable id (user/123). An attacker can enumerate
 * those, target a specific account, and try passwords against it.
 *
 * Invisible ID removes the public handle entirely:
 *
 *  1. On signup the server generates a 256-bit random secret:
 *       invisibleId = randomUUID() + randomBytes(32).hex
 *     ~2^256 possibilities. Guessing it is computationally infeasible.
 *
 *  2. The raw ID is shown ONCE, as a recovery key the user saves offline.
 *     It is NEVER shown in the UI again, NEVER put in a URL, NEVER logged,
 *     and NEVER returned by any API.
 *
 *  3. The server stores ONLY sha256(invisibleId) — never the raw value.
 *     Lookup is by hash, with timingSafeEqual, so there is no timing leak.
 *
 *  4. There is no username / email / public profile to enumerate.
 *     Login requires BOTH the invisible ID and the passphrase.
 *     A wrong ID and a wrong passphrase return the SAME generic error,
 *     and the same response time, so an attacker cannot tell which failed.
 *
 *  IMPORTANT — honest security note:
 *  Invisibility alone does NOT make a system "impossible to hack".
 *  It removes enumeration and targeted attacks, but the system still
 *  needs bcrypt password hashing, rate limiting, helmet headers,
 *  encrypted vault data, and safe session handling — all implemented
 *  in this repo. Security is layered; the invisible ID is one layer.
 */
const crypto = require('crypto');

function generateInvisibleId() {
  // UUIDv4 (122 bits) + 256 bits of extra entropy = far beyond brute force.
  return `${crypto.randomUUID()}-${crypto.randomBytes(32).toString('hex')}`;
}

function hashInvisibleId(invisibleId) {
  if (typeof invisibleId !== 'string' || invisibleId.length < 32) {
    throw new Error('Invalid invisible ID');
  }
  return crypto.createHash('sha256').update(invisibleId, 'utf8').digest('hex');
}

/** Public fingerprint only — e.g. "••••-a3f9". Never the ID itself. */
function fingerprint(hashedId) {
  return `••••-${hashedId.slice(-4)}`;
}

/** Constant-time comparison of two hex hashes. */
function hashesEqual(a, b) {
  const ba = Buffer.from(a, 'hex');
  const bb = Buffer.from(b, 'hex');
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

/** Estimate brute-force time at 1 trillion guesses/sec (for the demo UI). */
function bruteForceYears() {
  // 2^256 / 1e12 guesses per sec / seconds per year
  const guesses = 2 ** 256;
  const years = guesses / 1e12 / (60 * 60 * 24 * 365);
  return years.toExponential(2);
}

module.exports = { generateInvisibleId, hashInvisibleId, fingerprint, hashesEqual, bruteForceYears };
