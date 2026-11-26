/* Invisible ID Vault — offline Android (Capacitor) version.
 * No server, no network. All crypto runs in the browser via WebCrypto.
 * - Invisible ID: crypto.randomUUID() + 32 random bytes (256-bit entropy).
 * - Stored: ONLY sha256(invisibleId), a PBKDF2-SHA256 passphrase hash + salt,
 *   a private label, secrets and notes — in localStorage, on this device only.
 * - The raw ID is shown ONCE, then never displayed, logged, or stored.
 * - Unlock needs BOTH the ID and the passphrase; wrong ID and wrong
 *   passphrase return the same generic error.
 * - PIN is a local convenience gate only (see setPin): it never replaces the
 *   ID + passphrase, and "Forgot PIN" falls back to the invisible ID.
 * - Fingerprint unlock is the same kind of local convenience gate, via the
 *   free @capgo/capacitor-native-biometric v8 plugin (see the biometric
 *   section below). A random 256-bit token is stored in the Android
 *   Keystore with BIOMETRY_ANY access control, and only its SHA-256 hash
 *   is kept in localStorage (vault.bioHash). Unlocking reads the token
 *   back with getSecureCredentials(), which shows ONE native biometric
 *   prompt bound to that Keystore read, and compares hashes — the raw
 *   invisible ID is never stored in the Keystore or in localStorage.
 *   Biometrics are Android-native only: the plugin's web implementation
 *   is a dummy that always "succeeds", so fingerprint is never offered
 *   unless window.Capacitor reports a native Android platform.
 * - Backups are AES-GCM encrypted with a user-chosen backup passphrase;
 *   plaintext passwords are NEVER exported.
 */
'use strict';
const $ = id => document.getElementById(id);
const STORE_KEY = 'iiv-vault-v1';
const te = new TextEncoder();
const td = new TextDecoder();

/* ---------- crypto helpers ---------- */
function bufToHex(buf) { return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join(''); }
function hexToBuf(hex) { const b = new Uint8Array(hex.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.substr(i * 2, 2), 16); return b; }
function bufToB64(buf) { let s = ''; const u = new Uint8Array(buf); for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]); return btoa(s); }
function b64ToBuf(b64) { const s = atob(b64); const u = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i); return u; }
async function sha256Hex(text) { return bufToHex(await crypto.subtle.digest('SHA-256', te.encode(text))); }
function generateInvisibleId() { const bytes = new Uint8Array(32); crypto.getRandomValues(bytes); return 'ivault_' + bufToHex(bytes); }
async function derivePassHash(passphrase, saltHex) {
  const salt = saltHex ? hexToBuf(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey('raw', te.encode(passphrase), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
  return { salt: bufToHex(salt), hash: bufToHex(bits) };
}
function fingerprint(idHash) { return '••••-' + idHash.slice(-4); }
function loadVault() { try { return JSON.parse(localStorage.getItem(STORE_KEY) || 'null'); } catch { return null; } }
function saveVault(v) { localStorage.setItem(STORE_KEY, JSON.stringify(v)); }
function migrate(v) { if (!v) return v; if (!Array.isArray(v.secrets)) v.secrets = []; if (!Array.isArray(v.notes)) v.notes = []; if (!('bioHash' in v)) v.bioHash = null; return v; }
const esc = s => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

/* ---------- social apps hub ---------- */
const PRESETS = {
  Facebook: { url: 'https://facebook.com', category: 'Social', letter: 'f', color: '#1877f2' },
  Instagram: { url: 'https://instagram.com', category: 'Social', letter: '◎', color: '#e1306c' },
  YouTube: { url: 'https://youtube.com', category: 'Video', letter: '▶', color: '#ff0000' },
  WhatsApp: { url: 'https://web.whatsapp.com', category: 'Messaging', letter: '✆', color: '#25d366' },
  X: { url: 'https://x.com', category: 'Social', letter: '𝕏', color: '#ffffff' },
  Gmail: { url: 'https://mail.google.com', category: 'Email', letter: 'M', color: '#ea4335' },
};
const CATEGORIES = ['All', 'Social', 'Video', 'Email', 'Messaging', 'Banking', 'Work', 'Other'];
const LAUNCH_URLS = Object.fromEntries(Object.entries(PRESETS).map(([k, v]) => [k, v.url]));

/* ---------- state ---------- */
let vault = null;          // vault record (no raw ID ever stored here)
let secrets = [];          // app logins, on this device only
let notes = [];
let unlocked = false;
let visiblePasswords = new Set(); // secret ids whose password is shown
let searchQuery = '', activeCategory = 'All';
let idleSecondsLeft = 120, idleTimer = null, countdownTimer = null;
let bioAvailable = false; // true only when native Android biometrics are enrolled

/* ---------- password generator + strength ---------- */
function passwordStrength(pw) {
  if (!pw) return { label: '', score: 0 };
  let score = 0;
  if (pw.length >= 8) score++; if (pw.length >= 12) score++; if (pw.length >= 16) score++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
  if (/\d/.test(pw)) score++; if (/[^A-Za-z0-9]/.test(pw)) score++;
  if (score <= 2) return { label: 'Weak', score };
  if (score <= 4) return { label: 'Medium', score };
  return { label: 'Strong', score };
}
function generatePassword(len = 16) {
  const lower = 'abcdefghjkmnpqrstuvwxyz', upper = 'ABCDEFGHJKMNPQRSTUVWXYZ', digits = '23456789', symbols = '!@#$%^&*_-+=';
  const all = lower + upper + digits + symbols;
  const rnd = new Uint8Array(len); crypto.getRandomValues(rnd);
  const chars = [lower[rnd[0] % lower.length], upper[rnd[1] % upper.length], digits[rnd[2] % digits.length], symbols[rnd[3] % symbols.length]];
  for (let i = 4; i < len; i++) chars.push(all[rnd[i] % all.length]);
  for (let i = chars.length - 1; i > 0; i--) { const j = rnd[i] % (i + 1); [chars[i], chars[j]] = [chars[j], chars[i]]; }
  return chars.join('');
}
function renderStrength(pw) {
  const s = passwordStrength(pw);
  const bar = $('pwStrengthBar'), label = $('pwStrengthLabel');
  if (!bar) return;
  bar.style.width = pw ? Math.min(100, (s.score / 6) * 100) + '%' : '0%';
  bar.style.background = s.label === 'Strong' ? '#22c55e' : s.label === 'Medium' ? '#f59e0b' : '#ef4444';
  label.textContent = pw ? 'Strength: ' + s.label : '';
}
async function copyText(text, msg) {
  try { await navigator.clipboard.writeText(text); }
  catch { const t = document.createElement('textarea'); t.value = text; document.body.appendChild(t); t.select(); try { document.execCommand('copy'); } catch {} t.remove(); }
  if (msg) toast(msg);
}
function toast(msg) { const el = $('toast'); if (el) { el.textContent = msg; el.classList.remove('hidden'); setTimeout(() => el.classList.add('hidden'), 3000); } }

/* ---------- create / unlock ---------- */
$('createBtn').onclick = async () => {
  const label = $('label').value.trim() || 'My vault';
  const pass = $('pass').value;
  if (loadVault()) { $('createMsg').textContent = 'A vault already exists on this device. Unlock it below, or delete it first.'; return; }
  if (!pass || pass.length < 8) { $('createMsg').textContent = 'Passphrase must be at least 8 characters.'; return; }
  const invisibleId = generateInvisibleId();
  const idHash = await sha256Hex(invisibleId);
  const derived = await derivePassHash(pass);
  saveVault(migrate({ label, idHash, salt: derived.salt, passHash: derived.hash, notes: [], secrets: [], pinHash: null, pinSalt: null, bioHash: null, createdAt: new Date().toISOString() }));
  $('recovery').classList.remove('hidden');
  $('recoveryKey').textContent = invisibleId;
  $('fp').textContent = fingerprint(idHash);
  $('createMsg').textContent = 'Identity created. Save the recovery key, then unlock below.';
  $('pass').value = '';
};
$('copyBtn').onclick = () => copyText($('recoveryKey').textContent, 'Recovery key copied.');

function showVault(v) {
  vault = migrate(v); secrets = vault.secrets; notes = vault.notes || [];
  unlocked = true;
  $('vaultCard').classList.remove('hidden');
  $('vaultFp').textContent = '· ' + fingerprint(vault.idHash) + ' · ' + vault.label;
  $('unlockMsg').textContent = 'Unlocked.';
  $('pinSection').classList.remove('hidden');
  updatePinUI();
  updateBioUI();
  startIdleTimer();
  renderAll();
}
$('unlockBtn').onclick = async () => {
  const generic = 'No account matches that ID and passphrase.';
  const v = loadVault();
  const id = $('unlockId').value.trim();
  const pass = $('unlockPass').value;
  if (!v || !id || !pass) { $('unlockMsg').textContent = generic; return; }
  const idHash = await sha256Hex(id);
  const derived = await derivePassHash(pass, v.salt);
  if (idHash !== v.idHash || derived.hash !== v.passHash) { $('unlockMsg').textContent = generic; return; }
  $('unlockId').value = ''; $('unlockPass').value = '';
  showVault(v);
};

/* ---------- PIN unlock (local gate only) ---------- */
function updatePinUI() {
  const hasPin = !!(vault && vault.pinHash);
  $('pinStatus').textContent = hasPin ? 'PIN is set on this device. You can unlock with it next time.' : 'No PIN set. Set one after unlocking with your invisible ID.';
  $('pinUnlockCard').classList.toggle('hidden', !hasPin);
  $('removePinBtn').classList.toggle('hidden', !hasPin);
}
$('setPinBtn').onclick = async () => {
  const pin = $('pinInput').value.trim();
  if (!/^\d{4,6}$/.test(pin)) { $('pinMsg').textContent = 'PIN must be 4–6 digits.'; return; }
  const salt = bufToHex(crypto.getRandomValues(new Uint8Array(16)));
  vault.pinSalt = salt; vault.pinHash = await sha256Hex(pin + ':' + salt);
  saveVault(vault); $('pinInput').value = ''; $('pinMsg').textContent = 'PIN set on this device.';
  updatePinUI();
};
$('removePinBtn').onclick = () => {
  vault.pinHash = null; vault.pinSalt = null; saveVault(vault); $('pinMsg').textContent = 'PIN removed. Use your invisible ID to unlock.'; updatePinUI();
};
$('pinUnlockBtn').onclick = async () => {
  const generic = 'Wrong PIN. Try again, or use your invisible ID below.';
  const v = migrate(loadVault());
  const pin = $('pinUnlockInput').value.trim();
  if (!v || !v.pinHash || !pin) { $('pinUnlockMsg').textContent = generic; return; }
  if ((await sha256Hex(pin + ':' + v.pinSalt)) !== v.pinHash) { $('pinUnlockMsg').textContent = generic; return; }
  $('pinUnlockInput').value = '';
  showVault(v);
  toast('Unlocked with PIN.');
};
$('useIdLink').onclick = (e) => { e.preventDefault(); $('pinUnlockCard').classList.add('hidden'); $('unlockId').focus(); };

/* ---------- Fingerprint / biometric unlock (Android native only) ----------
 * Plugin: @capgo/capacitor-native-biometric v8 (free, MPL-2.0, maintained
 * for Capacitor 8). NOT @capacitor/biometrics — there is no such install
 * for Capacitor 8 — and NOT Capawesome Biometrics, which needs a paid
 * Insiders licence.
 *
 * How it works, step by step:
 * 1. nativeBiometric() returns the plugin ONLY on a native Android
 *    Capacitor platform. On the web the plugin ships a dummy
 *    implementation whose isAvailable() always returns true and whose
 *    verifyIdentity() always succeeds, so fingerprint is never offered
 *    there — offering it would be fake security.
 * 2. isAvailable({ useFallback: false }) is the gate: device PIN/pattern
 *    alone must NOT count as a biometric, so useFallback is false and
 *    a DEVICE_CREDENTIAL / NONE biometry type does not count either.
 * 3. Enabling (after an ID+passphrase unlock) generates a random
 *    256-bit token, stores it in the Android Keystore via
 *    setCredentials({ server, accessControl: BIOMETRY_ANY }) — the
 *    plugin prompts for a biometric to protect it — and stores ONLY
 *    sha256(token) in the vault record (vault.bioHash). The token and
 *    the raw invisible ID are never written to localStorage.
 *    BIOMETRY_ANY (value 2) is used, not BIOMETRY_CURRENT_SET, so the
 *    token survives adding a new fingerprint; the invisible ID remains
 *    the recovery path if biometrics are ever reset.
 * 4. Unlocking calls getSecureCredentials({ server }), which shows ONE
 *    native biometric prompt cryptographically bound (CryptoObject) to
 *    that Keystore read and returns the token. The token's hash is
 *    compared with vault.bioHash; on a match the vault opens.
 *    verifyIdentity() is the prompt-only API: it is used as the
 *    fallback below, followed by getCredentials(), if
 *    getSecureCredentials() fails for a reason other than the user
 *    cancelling. A failed or cancelled biometric always falls back
 *    gracefully to PIN / invisible ID — never to an unlocked vault.
 * 5. Disabling / deleting the vault calls deleteCredentials() so no
 *    orphaned Keystore entry is left behind.
 */
const BIO_SERVER = 'com.hadhvik.invisibleidvault';
const BIO_ACCESS_BIOMETRY_ANY = 2; // AccessControl.BIOMETRY_ANY in the plugin
const BIO_TYPE_NONE = 0, BIO_TYPE_DEVICE_CREDENTIAL = 7;

function nativeBiometric() {
  try {
    if (typeof window === 'undefined' || !window.Capacitor) return null;
    if (typeof window.Capacitor.isNativePlatform === 'function' && !window.Capacitor.isNativePlatform()) return null;
    if (typeof window.Capacitor.getPlatform === 'function' && window.Capacitor.getPlatform() !== 'android') return null;
    const plugins = window.Capacitor.Plugins || {};
    return plugins.NativeBiometric || null;
  } catch { return null; }
}
function bioIsCancelError(e) {
  if (!e) return false;
  const code = String(e.code ?? '');
  const msg = String(e.message ?? '');
  return code === '16' || code === '15' || /cancel/i.test(msg) || /cancel/i.test(code);
}
async function checkBiometricAvailability() {
  const plugin = nativeBiometric();
  if (!plugin) { bioAvailable = false; return false; }
  try {
    const r = await plugin.isAvailable({ useFallback: false });
    // isAvailable alone is the decision; biometryType is display-only,
    // but a NONE / DEVICE_CREDENTIAL type must not count as a fingerprint.
    bioAvailable = !!(r && r.isAvailable && r.biometryType !== BIO_TYPE_NONE && r.biometryType !== BIO_TYPE_DEVICE_CREDENTIAL);
  } catch { bioAvailable = false; }
  updateBioUnlockCard();
  return bioAvailable;
}
function updateBioUnlockCard() {
  const card = $('bioUnlockCard');
  if (!card) return;
  const v = loadVault();
  card.classList.toggle('hidden', !(bioAvailable && v && v.bioHash));
}
function updateBioUI() {
  const section = $('bioSection');
  if (!section) return;
  section.classList.toggle('hidden', !bioAvailable);
  if (!bioAvailable) return;
  const enabled = !!(vault && vault.bioHash);
  $('bioStatus').textContent = enabled
    ? 'Fingerprint unlock is on for this device. It unlocks the same vault — your invisible ID is still the recovery path.'
    : 'No fingerprint set. Enable it after unlocking with your invisible ID — your phone will ask for your fingerprint to protect it.';
  $('enableBioBtn').classList.toggle('hidden', enabled);
  $('disableBioBtn').classList.toggle('hidden', !enabled);
}
$('enableBioBtn').onclick = async () => {
  const plugin = nativeBiometric();
  if (!plugin || !vault) { $('bioMsg').textContent = 'Fingerprint is not available on this device.'; return; }
  try {
    const tokenBytes = new Uint8Array(32); crypto.getRandomValues(tokenBytes);
    const token = bufToHex(tokenBytes);
    // setCredentials with BIOMETRY_ANY prompts for a biometric and stores
    // the token in the Android Keystore; it never touches localStorage.
    await plugin.setCredentials({
      username: fingerprint(vault.idHash), password: token, server: BIO_SERVER,
      accessControl: BIO_ACCESS_BIOMETRY_ANY, title: 'Protect fingerprint unlock', negativeButtonText: 'Cancel',
    });
    vault.bioHash = await sha256Hex(token);
    saveVault(vault);
    $('bioMsg').textContent = 'Fingerprint unlock enabled on this device.';
    updateBioUI(); updateBioUnlockCard();
    toast('Fingerprint unlock enabled.');
  } catch (e) {
    $('bioMsg').textContent = bioIsCancelError(e)
      ? 'Fingerprint setup cancelled — PIN still works.'
      : 'Could not enable fingerprint unlock. Use PIN or your invisible ID instead.';
  }
};
$('disableBioBtn').onclick = async () => {
  const plugin = nativeBiometric();
  if (plugin) { try { await plugin.deleteCredentials({ server: BIO_SERVER }); } catch {} }
  if (vault) { vault.bioHash = null; saveVault(vault); }
  $('bioMsg').textContent = 'Fingerprint unlock removed. Use PIN or your invisible ID to unlock.';
  updateBioUI(); updateBioUnlockCard();
};
$('bioUnlockBtn').onclick = async () => {
  const generic = 'Fingerprint did not unlock the vault. Try again, or use PIN / your invisible ID below.';
  const plugin = nativeBiometric();
  const v = migrate(loadVault());
  if (!plugin || !v || !v.bioHash) { $('bioUnlockMsg').textContent = generic; return; }
  try {
    // One native prompt, bound to the Keystore read. Returns the token.
    const creds = await plugin.getSecureCredentials({
      server: BIO_SERVER, title: 'Unlock Invisible ID Vault',
      subtitle: 'Use your fingerprint to unlock the vault', negativeButtonText: 'Use PIN instead',
    });
    if (creds && creds.password && (await sha256Hex(creds.password)) === v.bioHash) {
      showVault(v);
      toast('Unlocked with fingerprint.');
      return;
    }
    $('bioUnlockMsg').textContent = generic;
  } catch (e) {
    if (bioIsCancelError(e)) { $('bioUnlockMsg').textContent = 'Fingerprint cancelled — use PIN or your invisible ID below.'; return; }
    // Fallback path (older plugin behaviour): prompt-only check, then a
    // plain Keystore read. Still gated by a live biometric prompt.
    try {
      await plugin.verifyIdentity({ title: 'Unlock Invisible ID Vault', reason: 'Confirm your fingerprint to unlock the vault', negativeButtonText: 'Cancel' });
      const creds = await plugin.getCredentials({ server: BIO_SERVER });
      if (creds && creds.password && (await sha256Hex(creds.password)) === v.bioHash) {
        showVault(v);
        toast('Unlocked with fingerprint.');
        return;
      }
    } catch {}
    $('bioUnlockMsg').textContent = generic;
  }
};
$('usePinLink').onclick = (e) => { e.preventDefault(); $('bioUnlockCard').classList.add('hidden'); const pin = $('pinUnlockInput'); if (pin) pin.focus(); };
$('useIdLink2').onclick = (e) => { e.preventDefault(); $('bioUnlockCard').classList.add('hidden'); $('unlockId').focus(); };

/* ---------- auto-lock (2 minutes idle) ---------- */
function resetIdle() { idleSecondsLeft = 120; updateCountdown(); }
function updateCountdown() { const el = $('idleCountdown'); if (el && unlocked) el.textContent = 'Auto-lock in ' + Math.floor(idleSecondsLeft / 60) + ':' + String(idleSecondsLeft % 60).padStart(2, '0'); }
function startIdleTimer() {
  stopIdleTimer();
  ['click', 'keydown', 'input', 'touchstart'].forEach(ev => document.addEventListener(ev, resetIdle, { passive: true }));
  countdownTimer = setInterval(() => { if (!unlocked) return; idleSecondsLeft--; updateCountdown(); if (idleSecondsLeft <= 0) { lockVault(); toast('Locked after 2 minutes idle.'); } }, 1000);
}
function stopIdleTimer() { if (countdownTimer) clearInterval(countdownTimer); countdownTimer = null; }
function lockVault() {
  unlocked = false; secrets = []; notes = []; visiblePasswords.clear();
  stopIdleTimer();
  $('vaultCard').classList.add('hidden');
  $('unlockMsg').textContent = 'Vault locked.';
  const el = $('idleCountdown'); if (el) el.textContent = '';
}
$('lockBtn').onclick = lockVault;
$('deleteBtn').onclick = async () => {
  if (!confirm('Permanently delete this vault and all its secrets and notes from this device?')) return;
  const plugin = nativeBiometric();
  if (plugin) { try { await plugin.deleteCredentials({ server: BIO_SERVER }); } catch {} }
  localStorage.removeItem(STORE_KEY);
  lockVault(); $('recovery').classList.add('hidden'); $('createMsg').textContent = 'Vault deleted.';
};

/* ---------- secrets: add / list / search / favourites / categories ---------- */
function persist() { if (vault) { vault.secrets = secrets; vault.notes = notes; saveVault(vault); } }
function presetChanged() {
  const name = $('secretApp').value;
  const p = PRESETS[name];
  if (p) { $('secretUrl').value = p.url; $('secretCategory').value = p.category; }
}
$('secretApp').onchange = presetChanged;
$('genPwBtn').onclick = () => { const pw = generatePassword(16); $('secretPassword').value = pw; renderStrength(pw); };
$('secretPassword').addEventListener('input', e => renderStrength(e.target.value));
$('togglePwBtn').onclick = () => { const f = $('secretPassword'); f.type = f.type === 'password' ? 'text' : 'password'; $('togglePwBtn').textContent = f.type === 'password' ? 'Show' : 'Hide'; };

$('addSecretBtn').onclick = () => {
  const app = $('secretApp').value.trim() || $('secretCustomApp').value.trim();
  const username = $('secretUsername').value.trim();
  const password = $('secretPassword').value;
  const category = $('secretCategory').value;
  const url = $('secretUrl').value.trim();
  const favourite = $('secretFav').checked;
  if (!app) { $('secretMsg').textContent = 'Choose an app or type a custom app name.'; return; }
  if (!username || !password) { $('secretMsg').textContent = 'Username and password are required.'; return; }
  secrets.push({ id: 's' + Date.now().toString(36) + Math.floor(Math.random() * 1e4), app, username, password, category, url, favourite, createdAt: new Date().toISOString() });
  $('secretUsername').value = ''; $('secretPassword').value = ''; $('secretCustomApp').value = ''; $('secretFav').checked = false; renderStrength('');
  $('secretMsg').textContent = app + ' saved.';
  persist(); resetIdle(); renderAll();
};
function filteredSecrets() {
  const q = searchQuery.trim().toLowerCase();
  return secrets.filter(s =>
    (activeCategory === 'All' || s.category === activeCategory) &&
    (!q || s.app.toLowerCase().includes(q) || s.username.toLowerCase().includes(q) || (s.url || '').toLowerCase().includes(q))
  ).sort((a, b) => (b.favourite - a.favourite) || a.app.localeCompare(b.app));
}
function renderSecrets() {
  const list = filteredSecrets();
  const el = $('secrets');
  if (!secrets.length) { el.innerHTML = '<li class="muted">No app logins yet — add Facebook, Instagram, YouTube or any other app above.</li>'; return; }
  if (!list.length) { el.innerHTML = '<li class="muted">No matches. Try a different search or category.</li>'; return; }
  el.innerHTML = list.map(s => {
    const p = PRESETS[s.app] || { letter: esc(s.app[0] || '?').toUpperCase(), color: '#6366f1' };
    const shown = visiblePasswords.has(s.id);
    return '<li class="secret">' +
      '<span class="avatar" style="background:' + p.color + '">' + esc(p.letter) + '</span>' +
      '<span class="secret-main"><strong>' + esc(s.app) + '</strong> ' + (s.favourite ? '★' : '') +
      '<span class="muted small">' + esc(s.username) + ' · ' + esc(s.category) + '</span>' +
      '<span class="pw">' + (shown ? esc(s.password) : '••••••••') + '</span></span>' +
      '<span class="secret-actions">' +
      (s.url ? '<button data-act="launch" data-id="' + s.id + '">Launch</button>' : '') +
      '<button data-act="copyuser" data-id="' + s.id + '">Copy user</button>' +
      '<button data-act="copypass" data-id="' + s.id + '">Copy pass</button>' +
      '<button data-act="toggle" data-id="' + s.id + '">' + (shown ? 'Hide' : 'Show') + '</button>' +
      '<button data-act="fav" data-id="' + s.id + '">' + (s.favourite ? 'Unstar' : '★ Fav') + '</button>' +
      '<button data-act="del" data-id="' + s.id + '" class="ghost">Delete</button>' +
      '</span></li>';
  }).join('');
  el.querySelectorAll('button[data-act]').forEach(b => b.onclick = () => secretAction(b.dataset.act, b.dataset.id));
}
function secretAction(act, id) {
  const s = secrets.find(x => x.id === id); if (!s) return;
  resetIdle();
  if (act === 'launch') window.open(s.url, '_blank', 'noopener');
  if (act === 'copyuser') copyText(s.username, 'Username copied.');
  if (act === 'copypass') { copyText(s.password, 'Password copied — it will be hidden again in 30 seconds.'); setTimeout(() => { visiblePasswords.delete(id); if (unlocked) renderSecrets(); }, 30000); }
  if (act === 'toggle') { visiblePasswords.has(id) ? visiblePasswords.delete(id) : visiblePasswords.add(id); }
  if (act === 'fav') { s.favourite = !s.favourite; persist(); }
  if (act === 'del') { if (!confirm('Delete the login for ' + s.app + '?')) return; secrets = secrets.filter(x => x.id !== id); visiblePasswords.delete(id); persist(); }
  renderAll();
}
$('searchInput').addEventListener('input', e => { searchQuery = e.target.value; renderSecrets(); });
function renderChips() {
  $('categoryChips').innerHTML = CATEGORIES.map(c => '<button class="chip' + (c === activeCategory ? ' active' : '') + '" data-cat="' + c + '">' + c + '</button>').join('');
  $('categoryChips').querySelectorAll('button').forEach(b => b.onclick = () => { activeCategory = b.dataset.cat; renderChips(); renderSecrets(); });
}

/* ---------- vault health ---------- */
function renderHealth() {
  const el = $('health');
  if (!el) return;
  const byPw = {};
  secrets.forEach(s => { byPw[s.password] = (byPw[s.password] || 0) + 1; });
  const reused = secrets.filter(s => byPw[s.password] > 1);
  const weak = secrets.filter(s => passwordStrength(s.password).label === 'Weak');
  const byCat = {};
  secrets.forEach(s => { byCat[s.category] = (byCat[s.category] || 0) + 1; });
  el.innerHTML =
    '<p><strong>' + secrets.length + '</strong> app logins · <strong>' + weak.length + '</strong> weak passwords · <strong>' + reused.length + '</strong> logins sharing a reused password</p>' +
    (reused.length ? '<p class="warn">⚠️ Reused password: ' + esc([...new Set(reused.map(s => s.app))].join(', ')) + ' share the same password. Change at least one of them.</p>' : '<p class="ok">✓ No reused passwords found.</p>') +
    (weak.length ? '<p class="warn">⚠️ Weak passwords: ' + esc(weak.map(s => s.app).join(', ')) + ' — use the generator for a 16-character password.</p>' : '') +
    '<p class="muted small">By category: ' + esc(Object.entries(byCat).map(([k, v]) => k + ' ' + v).join(' · ') || '—') + '</p>';
}

/* ---------- encrypted backup (AES-GCM, never plaintext) ---------- */
async function backupKey(passphrase, salt) {
  const base = await crypto.subtle.importKey('raw', te.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
$('exportBtn').onclick = async () => {
  const bp = $('backupPass').value;
  if (!bp || bp.length < 8) { $('backupMsg').textContent = 'Choose a backup passphrase (8+ characters) first.'; return; }
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await backupKey(bp, salt);
  const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(JSON.stringify({ secrets, notes })));
  const backup = { format: 'iiv-backup-v1', salt: bufToHex(salt), iv: bufToHex(iv), data: bufToB64(data), count: secrets.length, createdAt: new Date().toISOString() };
  const blob = new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'invisible-id-vault-backup.json'; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
  $('backupMsg').textContent = 'Encrypted backup downloaded (' + secrets.length + ' logins). Keep the backup passphrase — without it the file is unreadable.';
  $('backupPass').value = '';
};
$('importBtn').onclick = () => $('importFile').click();
$('importFile').onchange = async (e) => {
  const file = e.target.files[0]; if (!file) return;
  const bp = $('backupPass').value;
  if (!bp) { $('backupMsg').textContent = 'Enter the backup passphrase first, then choose the backup file again.'; e.target.value = ''; return; }
  try {
    const backup = JSON.parse(await file.text());
    if (backup.format !== 'iiv-backup-v1') throw new Error('Not an Invisible ID Vault backup.');
    const key = await backupKey(bp, hexToBuf(backup.salt));
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: hexToBuf(backup.iv) }, key, b64ToBuf(backup.data));
    const obj = JSON.parse(td.decode(plain));
    if (!Array.isArray(obj.secrets)) throw new Error('Backup has no logins.');
    const seen = new Set(secrets.map(s => s.app + '|' + s.username));
    obj.secrets.forEach(s => { if (s.app && s.username && !seen.has(s.app + '|' + s.username)) secrets.push({ ...s, id: 's' + Date.now().toString(36) + Math.floor(Math.random() * 1e4) }); });
    if (Array.isArray(obj.notes)) notes = [...new Set([...notes, ...obj.notes])];
    persist(); renderAll();
    $('backupMsg').textContent = 'Backup imported (' + obj.secrets.length + ' logins in file).';
  } catch { $('backupMsg').textContent = 'Could not import — wrong backup passphrase, or the file is not a valid backup.'; }
  e.target.value = ''; $('backupPass').value = '';
};

/* ---------- notes (legacy) ---------- */
function renderNotes() { $('notes').innerHTML = notes.map(n => '<li>' + esc(n) + '</li>').join('') || '<li class="muted">No notes yet.</li>'; }
$('addNoteBtn').onclick = () => {
  const t = $('noteText').value.trim(); if (!t) return;
  notes.push(t); $('noteText').value = ''; persist(); resetIdle(); renderNotes();
};
$('attackBtn').onclick = () => { $('attackMsg').textContent = '1,000,000 random guesses tried… 0 hits. At this rate you would need ~10⁶³ years. The ID space is 2²⁵⁶.'; };

function renderAll() { renderChips(); renderSecrets(); renderHealth(); renderNotes(); }

// If a vault already exists, hint at it (fingerprint only, never the ID).
(async function init() {
  const v = migrate(loadVault());
  if (v) {
    $('unlockMsg').textContent = 'A vault exists on this device (' + fingerprint(v.idHash) + ' · ' + v.label + '). Unlock it above.';
    if (v.pinHash) $('pinUnlockCard').classList.remove('hidden');
  }
  renderChips();
  // Native Android only: show "Unlock with fingerprint" only when a
  // biometric is actually enrolled and a fingerprint token was saved.
  await checkBiometricAvailability();
})();
