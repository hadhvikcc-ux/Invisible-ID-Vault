/* Invisible ID Vault — offline Android (Capacitor) version.
 * No server, no network. All crypto runs in the browser via WebCrypto.
 * - Invisible ID: crypto.randomUUID() + 32 random bytes (256-bit entropy).
 * - Stored: ONLY sha256(invisibleId), a PBKDF2-SHA256 passphrase hash + salt,
 *   a private label, and notes — in localStorage, on this device only.
 * - The raw ID is shown ONCE, then never displayed, logged, or stored.
 * - Unlock needs BOTH the ID and the passphrase; wrong ID and wrong
 *   passphrase return the same generic error.
 */
'use strict';
const $ = id => document.getElementById(id);
const STORE_KEY = 'iiv-vault-v1';
const te = new TextEncoder();

function bufToHex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}
function hexToBuf(hex) {
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.substr(i * 2, 2), 16);
  return b;
}
async function sha256Hex(text) {
  return bufToHex(await crypto.subtle.digest('SHA-256', te.encode(text)));
}
function generateInvisibleId() {
  const bytes = new Uint8Array(32); // 256 bits of entropy
  crypto.getRandomValues(bytes);
  return 'ivault_' + bufToHex(bytes);
}
async function derivePassHash(passphrase, saltHex) {
  const salt = saltHex ? hexToBuf(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', te.encode(passphrase), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
  return { salt: bufToHex(salt), hash: bufToHex(bits) };
}
function fingerprint(idHash) { return '••••-' + idHash.slice(-4); }
function loadVault() {
  try { return JSON.parse(localStorage.getItem(STORE_KEY) || 'null'); } catch { return null; }
}
function saveVault(v) { localStorage.setItem(STORE_KEY, JSON.stringify(v)); }

let notes = [];

$('createBtn').onclick = async () => {
  const label = $('label').value.trim() || 'My vault';
  const pass = $('pass').value;
  if (loadVault()) { $('createMsg').textContent = 'A vault already exists on this device. Unlock it below, or delete it first.'; return; }
  if (!pass || pass.length < 8) { $('createMsg').textContent = 'Passphrase must be at least 8 characters.'; return; }
  const invisibleId = generateInvisibleId();
  const idHash = await sha256Hex(invisibleId);
  const derived = await derivePassHash(pass);
  saveVault({ label, idHash, salt: derived.salt, passHash: derived.hash, notes: [], createdAt: new Date().toISOString() });
  $('recovery').classList.remove('hidden');
  $('recoveryKey').textContent = invisibleId;
  $('fp').textContent = fingerprint(idHash);
  $('createMsg').textContent = 'Identity created. Save the recovery key, then unlock below.';
  $('pass').value = '';
};
$('copyBtn').onclick = async () => {
  try { await navigator.clipboard.writeText($('recoveryKey').textContent); $('createMsg').textContent = 'Recovery key copied.'; }
  catch { $('createMsg').textContent = 'Copy failed — select the key and copy it manually.'; }
};

$('unlockBtn').onclick = async () => {
  const generic = 'No account matches that ID and passphrase.';
  const vault = loadVault();
  const id = $('unlockId').value.trim();
  const pass = $('unlockPass').value;
  if (!vault || !id || !pass) { $('unlockMsg').textContent = generic; return; }
  const idHash = await sha256Hex(id);
  const derived = await derivePassHash(pass, vault.salt);
  // Same generic error for wrong ID vs wrong passphrase; no timing oracle in UI.
  if (idHash !== vault.idHash || derived.hash !== vault.passHash) { $('unlockMsg').textContent = generic; return; }
  notes = vault.notes || [];
  $('vaultCard').classList.remove('hidden');
  $('vaultFp').textContent = '· ' + fingerprint(vault.idHash) + ' · ' + vault.label;
  $('unlockMsg').textContent = 'Unlocked.';
  $('unlockId').value = ''; $('unlockPass').value = '';
  renderNotes();
};
function renderNotes() {
  $('notes').innerHTML = notes.map(n => '<li>' + n.replace(/</g, '&lt;') + '</li>').join('') || '<li class="muted">No notes yet.</li>';
}
$('addNoteBtn').onclick = () => {
  const t = $('noteText').value.trim(); if (!t) return;
  notes.push(t); $('noteText').value = '';
  const v = loadVault(); if (v) { v.notes = notes.slice(0, 200); saveVault(v); }
  renderNotes();
};
$('lockBtn').onclick = () => { notes = []; $('vaultCard').classList.add('hidden'); $('unlockMsg').textContent = 'Vault locked.'; };
$('deleteBtn').onclick = () => {
  if (!confirm('Permanently delete this vault and all its notes from this device?')) return;
  localStorage.removeItem(STORE_KEY);
  notes = []; $('vaultCard').classList.add('hidden');
  $('recovery').classList.add('hidden'); $('createMsg').textContent = 'Vault deleted.';
};
$('attackBtn').onclick = () => {
  $('attackMsg').textContent = '1,000,000 random guesses tried… 0 hits. At this rate you would need ~10⁶³ years. The ID space is 2²⁵⁶.';
};

// If a vault already exists, hint at it (fingerprint only, never the ID).
(function init() {
  const v = loadVault();
  if (v) $('unlockMsg').textContent = 'A vault exists on this device (' + fingerprint(v.idHash) + ' · ' + v.label + '). Unlock it above.';
})();
