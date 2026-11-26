/**
 * Invisible ID Vault — Express server
 * Run:  npm install && npm start   →  http://localhost:3000
 */
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const { generateInvisibleId, hashInvisibleId, fingerprint, hashesEqual } = require('./src/invisible-id');
const store = require('./src/store');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Sessions: in-memory map of sessionToken -> idHash. Production: Redis + httpOnly secure cookies.
const sessions = new Map();
function newSession(idHash) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { idHash, createdAt: Date.now() });
  return token;
}
function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer /, '');
  const s = sessions.get(token);
  if (!s) return res.status(401).json({ error: 'Invalid or expired session.' });
  req.idHash = s.idHash;
  next();
}

// Strict rate limiting on auth endpoints — stops brute force even if an ID leaks.
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many attempts. Try again in 15 minutes.' } });

// POST /api/create — create an invisible identity.
// Body: { label, passphrase }  (label is only a private nickname, not a login)
// Response: { recoveryKey, fingerprint } — recoveryKey shown ONCE.
app.post('/api/create', authLimiter, async (req, res) => {
  const { label = 'My vault', passphrase } = req.body || {};
  if (!passphrase || passphrase.length < 8) {
    return res.status(400).json({ error: 'Passphrase must be at least 8 characters.' });
  }
  const invisibleId = generateInvisibleId();
  const idHash = hashInvisibleId(invisibleId);
  if (store.findByHash(idHash)) return res.status(500).json({ error: 'Collision — please try again.' });
  const passphraseHash = await bcrypt.hash(passphrase, 12);
  store.insert({ idHash, label: String(label).slice(0, 60), passphraseHash, notes: [], createdAt: new Date().toISOString() });
  // Raw ID leaves the server exactly once, in this response. It is never logged.
  res.status(201).json({ recoveryKey: invisibleId, fingerprint: fingerprint(idHash) });
});

// POST /api/unlock — Body: { invisibleId, passphrase }
// Same generic error + same timing for wrong ID vs wrong passphrase.
app.post('/api/unlock', authLimiter, async (req, res) => {
  const { invisibleId, passphrase } = req.body || {};
  const generic = { error: 'No account matches that ID and passphrase.' };
  if (!invisibleId || !passphrase) return res.status(401).json(generic);
  let idHash;
  try { idHash = hashInvisibleId(invisibleId); } catch { return res.status(401).json(generic); }
  const user = store.findByHash(idHash);
  // Dummy bcrypt compare keeps timing similar when the user does not exist.
  const ok = user ? await bcrypt.compare(passphrase, user.passphraseHash) : await bcrypt.compare(passphrase, '$2a$12$dummyhashdummyhashdummyhashdummyhashdummyhashdummyha');
  if (!user || !ok || !hashesEqual(user.idHash, idHash)) return res.status(401).json(generic);
  res.json({ sessionToken: newSession(idHash), label: user.label, fingerprint: fingerprint(idHash), notes: user.notes });
});

// GET /api/me — returns only the fingerprint, never the ID.
app.get('/api/me', auth, (req, res) => {
  const user = store.findByHash(req.idHash);
  if (!user) return res.status(404).json({ error: 'Account not found.' });
  res.json({ label: user.label, fingerprint: fingerprint(user.idHash), notes: user.notes, createdAt: user.createdAt });
});

// POST /api/notes — save encrypted notes (client encrypts before sending in the demo UI).
app.post('/api/notes', auth, (req, res) => {
  const { notes } = req.body || {};
  if (!Array.isArray(notes)) return res.status(400).json({ error: 'notes must be an array.' });
  const user = store.update(req.idHash, { notes: notes.slice(0, 200) });
  if (!user) return res.status(404).json({ error: 'Account not found.' });
  res.json({ ok: true, count: user.notes.length });
});

app.post('/api/logout', auth, (req, res) => {
  const token = (req.headers.authorization || '').replace(/^Bearer /, '');
  sessions.delete(token);
  res.json({ ok: true });
});

app.get('/api/health', (req, res) => res.json({ ok: true, service: 'invisible-id-vault' }));

app.listen(PORT, () => console.log(`Invisible ID Vault running at http://localhost:${PORT}`));
module.exports = app;
