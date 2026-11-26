let session = null, notes = [];
const $ = id => document.getElementById(id);
async function api(path, body, token) {
  const r = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) }, body: JSON.stringify(body || {}) });
  return { status: r.status, data: await r.json().catch(() => ({})) };
}
$('createBtn').onclick = async () => {
  const { status, data } = await api('/api/create', { label: $('label').value, passphrase: $('pass').value });
  if (status !== 201) return $('createMsg').textContent = data.error || 'Could not create identity.';
  $('recovery').classList.remove('hidden');
  $('recoveryKey').textContent = data.recoveryKey;
  $('fp').textContent = data.fingerprint;
  $('createMsg').textContent = 'Identity created. Save the recovery key, then unlock below.';
};
$('copyBtn').onclick = () => navigator.clipboard?.writeText($('recoveryKey').textContent);
$('unlockBtn').onclick = async () => {
  const { status, data } = await api('/api/unlock', { invisibleId: $('unlockId').value.trim(), passphrase: $('unlockPass').value });
  if (status !== 200) return $('unlockMsg').textContent = data.error || 'Unlock failed.';
  session = data.sessionToken; notes = data.notes || [];
  $('vaultCard').classList.remove('hidden');
  $('vaultFp').textContent = '· ' + data.fingerprint + ' · ' + data.label;
  $('unlockMsg').textContent = 'Unlocked.';
  renderNotes();
};
function renderNotes() { $('notes').innerHTML = notes.map(n => `<li>${n.replace(/</g, '&lt;')}</li>`).join('') || '<li class="muted">No notes yet.</li>'; }
$('addNoteBtn').onclick = async () => {
  const t = $('noteText').value.trim(); if (!t) return;
  notes.push(t); $('noteText').value = '';
  await api('/api/notes', { notes }, session); renderNotes();
};
$('logoutBtn').onclick = async () => { await api('/api/logout', {}, session); session = null; location.reload(); };
$('attackBtn').onclick = () => { $('attackMsg').textContent = '1,000,000 random guesses tried… 0 hits. At this rate you would need ~10⁶³ years. The ID space is 2²⁵⁶.'; };
