const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const wwwApp = fs.readFileSync(path.join(__dirname, '..', 'www', 'app.js'), 'utf8');
const wwwHtml = fs.readFileSync(path.join(__dirname, '..', 'www', 'index.html'), 'utf8');
const webApp = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');
const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));

// Fingerprint unlock must be real, native-only, and Keystore-gated —
// never a fake prompt, never offered on the web, and never a
// replacement for the invisible ID.
test('uses the free Capgo v8 plugin, not @capacitor/biometrics or Capawesome', () => {
  assert.ok(pkg.dependencies['@capgo/capacitor-native-biometric'], 'Capgo plugin must be a dependency');
  assert.match(pkg.dependencies['@capgo/capacitor-native-biometric'], /^8\./, 'plugin major must match Capacitor 8');
  assert.ok(!pkg.dependencies['@capacitor/biometrics'], '@capacitor/biometrics must not be installed');
  // The name may appear once in a comment explaining NOT to use it;
  // it must never be imported or called.
  assert.ok(!wwwApp.includes("from '@capacitor/biometrics'"), 'www/app.js must not import @capacitor/biometrics');
  assert.ok(!wwwApp.includes("require('@capacitor/biometrics')"), 'www/app.js must not require @capacitor/biometrics');
  assert.ok(!wwwApp.includes('capawesome'), 'Capawesome (paid Insiders) must not be used');
});

test('biometric gate is native Android only — the web dummy can never unlock', () => {
  assert.ok(wwwApp.includes("getPlatform() !== 'android'"), 'must check the Capacitor platform is android');
  assert.ok(wwwApp.includes('isNativePlatform()'), 'must check for a native platform');
  assert.ok(wwwApp.includes('isAvailable({ useFallback: false })'), 'device PIN alone must not count as a biometric');
  assert.ok(!webApp.includes('NativeBiometric'), 'the web version must not offer fingerprint unlock');
  assert.ok(!webApp.includes('bioHash'), 'the web version must not carry biometric state');
});

test('token lives in the Keystore with BIOMETRY_ANY; only its hash is stored locally', () => {
  assert.ok(wwwApp.includes('setCredentials'), 'must store the token via setCredentials');
  assert.ok(wwwApp.includes('getSecureCredentials'), 'must read the token via getSecureCredentials (biometric-bound read)');
  assert.ok(wwwApp.includes('accessControl: BIO_ACCESS_BIOMETRY_ANY'), 'must use BIOMETRY_ANY access control');
  assert.ok(wwwApp.includes('BIO_ACCESS_BIOMETRY_ANY = 2'), 'BIOMETRY_ANY is enum value 2');
  assert.ok(wwwApp.includes('bioHash'), 'only the token hash is kept in the vault record');
  assert.ok(!/localStorage\.setItem\([^)]*token/i.test(wwwApp), 'the raw token must never be written to localStorage');
  assert.ok(wwwApp.includes('deleteCredentials'), 'disabling / deleting must remove the Keystore entry');
});

test('biometric unlock is a convenience gate with PIN / invisible-ID fallback', () => {
  assert.ok(wwwApp.includes('verifyIdentity'), 'verifyIdentity must be present as the prompt-only fallback');
  assert.ok(wwwApp.includes('Unlock with fingerprint'), 'the fingerprint button must exist in the Android UI');
  assert.ok(wwwHtml.includes('id="bioUnlockBtn"'), 'the fingerprint button must exist in www/index.html');
  assert.ok(wwwHtml.includes('id="enableBioBtn"'), 'enable-fingerprint control must exist in www/index.html');
  assert.ok(!wwwHtml.includes('@capacitor/biometrics'), 'the old @capacitor/biometrics note must be gone from www/index.html');
  assert.ok(wwwApp.includes('showVault(v)'), 'a successful biometric check opens the same vault as PIN / ID');
});
