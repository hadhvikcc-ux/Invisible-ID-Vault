// Tiny file-backed store. Swap for Postgres / SQLite in production.
// The file stores ONLY: hashed invisible ID, bcrypt passphrase hash,
// display label, created date, and encrypted vault blobs.
// It NEVER stores a raw invisible ID, email, or username.
const fs = require('fs');
const path = require('path');

const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, '..', 'data', 'users.json');

function load() {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch {
    return { users: [] };
  }
}
function save(db) {
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2));
}
function findByHash(hashedId) {
  return load().users.find(u => u.idHash === hashedId) || null;
}
function insert(user) {
  const db = load();
  db.users.push(user);
  save(db);
  return user;
}
function update(hashedId, patch) {
  const db = load();
  const i = db.users.findIndex(u => u.idHash === hashedId);
  if (i === -1) return null;
  db.users[i] = { ...db.users[i], ...patch };
  save(db);
  return db.users[i];
}
module.exports = { load, save, findByHash, insert, update, DATA_FILE };
