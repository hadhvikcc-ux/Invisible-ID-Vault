# Android app — Invisible ID Vault

## What it is

The Android app is the same Invisible ID Vault idea, packaged for a phone with
[Capacitor](https://capacitorjs.com/): a native Android shell (Kotlin/Java)
that loads a standalone, offline web app from `www/`.

The native `android/` platform is **not committed** to the repo — it contains
binary PNG/JAR assets — and is generated on the GitHub Actions runner with
`npx cap add android`, then synced with `npx cap sync android`. Locally you
can still generate it with `npm run android:sync` after `npx cap add android`.

It is **not** the Node/Express server in `server.js`. The Android app works
with **no server and no network**:

- Generate a 256-bit invisible ID on-device (`crypto.getRandomValues` +
  `crypto.randomUUID`), shown **once** as a recovery key.
- Store **only** `SHA-256(invisible ID)` plus a PBKDF2-SHA256 passphrase hash
  and salt, in `localStorage` on the device.
- Unlock with ID + passphrase; a wrong ID and a wrong passphrase give the
  same generic error.
- Show only a fingerprint like `••••-a3f9`, never the ID again.
- Add / list secure notes stored on the device only.
- A brute-force / entropy demo (guessing a 256-bit ID ≈ 10⁶³ years).

## New features (Nov 2026)

All of these are in `www/` (Android) and, where the server allows, in `public/` (web):

- **Social apps hub** — preset logins for Facebook, Instagram, YouTube,
  WhatsApp, X and Gmail, plus any custom app. Each login has an app name,
  icon (letter avatar, no external images), username, password, category,
  launch URL and a favourite star. **Launch** opens the app's site in a new
  tab (`facebook.com`, `instagram.com`, `youtube.com`, `web.whatsapp.com`,
  `x.com`, `mail.google.com`). The vault never logs you into an app — each
  app still needs its own sign-in; the vault stores the login and launches it.
  One-tap **Copy user / Copy pass**; a copied password is hidden again
  after 30 seconds. **Show / Hide** toggles a password per login.
- **Search, favourites, categories** — live search by app or username,
  category chips (All, Social, Video, Email, Messaging, Banking, Work,
  Other), favourite star; favourites are shown first.
- **PIN unlock (Android only)** — after unlocking once with your invisible
  ID + passphrase, set a 4–6 digit PIN. The PIN is stored only as a SHA-256
  hash + salt on the device, never in plaintext. Next time you can unlock
  with the PIN instead of pasting the long ID; "Forgot PIN" falls back to
  the invisible ID. The PIN is a convenience gate on this device only — it
  does not replace the ID + passphrase. Android fingerprint unlock is a
  future step via `@capacitor/biometrics`; it is not faked here.
- **Auto-lock** — the vault locks after 2 minutes idle (any tap, key or
  input resets the timer), with a countdown shown while unlocked, plus a
  **Lock now** button.
- **Password generator + strength meter** — 16-character generated
  passwords (letters, digits, symbols) with a copy button, and a
  weak / medium / strong meter based on length and character variety.
- **Vault health** — counts logins by category, flags weak passwords, and
  warns when the same password is reused across 2+ apps.
- **Encrypted backup** — Export downloads `invisible-id-vault-backup.json`
  in the `iiv-backup-v1` format: `{ format, salt, iv, data, count, createdAt }`,
  where `data` is the logins + notes encrypted with **AES-GCM** (WebCrypto),
  the key derived from a user-chosen backup passphrase with PBKDF2-SHA256
  (100,000 iterations, random 16-byte salt, random 12-byte IV). Import
  decrypts the file with that passphrase and merges logins it does not
  already have (same app + username is skipped). **Plaintext passwords are
  never exported.** Lose the backup passphrase and the file is unreadable.

On the web (`public/`), the same hub, search, generator, health, backup and
auto-lock are available, but app logins are stored in the browser (keyed by
vault fingerprint) and only shown after a server unlock, and PIN unlock is
not offered — it would require storing your ID + passphrase in the browser.

App ID: `com.hadhvik.invisibleidvault` · App name: `Invisible ID Vault` ·
Web directory: `www/` · See `capacitor.config.json`.

## How GitHub builds it

There is no Java or Android SDK on a normal dev machine, so the APK is built
on GitHub Actions — see `.github/workflows/android.yml`:

1. Push to `main` touching `www/**`, `capacitor.config.json`,
   `package.json` / `package-lock.json`, or the workflow itself — or run the
   workflow manually from the Actions tab (workflow_dispatch).
2. The job sets up Node 24, runs `npm ci`, generates the Android platform
   with `npx cap add android` (if not present), then `npx cap sync android`
   to copy `www/` into the Android project.
3. It sets up JDK 17 (Temurin) and the Android SDK, then runs
   `./gradlew -p android assembleDebug`.
4. The built APK is uploaded as an Actions artifact named
   **`invisible-id-vault-debug-apk`** (kept for 30 days).

Check the run status in the repo: **Actions → Android →** the latest run.
A green run means the APK artifact is ready.

## Download the APK

1. Open the repo on GitHub: https://github.com/hadhvikcc-ux/Invisible-ID-Vault
2. Go to **Actions** → **Android** → click the latest run.
3. Scroll to **Artifacts** at the bottom and download
   `invisible-id-vault-debug-apk`.
4. Unzip it — it contains `app-debug.apk`.

## Install on Android

1. Copy `app-debug.apk` to your Android phone (download, USB, or a file app).
2. Tap the APK file to install it.
3. Android will ask you to allow installing from that source — allow
   "Install unknown apps" for your browser / file manager when prompted,
   then tap **Install**.
4. Open **Invisible ID Vault**, create an identity, and **save the
   recovery key it shows once** — losing both the ID and the passphrase
   means the vault is unrecoverable, by design.

## Debug APK, not a Play Store release

This is a **debug APK** (`assembleDebug`): it is unsigned with a release
key, not optimised, and not distributed through Google Play. It is fine
for personal use and testing, but do not publish it as a production app.

## Making a release APK / AAB later

1. Create a release keystore (once, keep it private — never commit it):
   `keytool -genkey -v -keystore release.keystore -alias invisible-id-vault -keyalg RSA -keysize 2048 -validity 10000`
2. Add signing to `android/app/build.gradle` (or a `keystore.properties`
   file, git-ignored) and store the keystore + passwords as **GitHub
   Secrets** in the repo settings.
3. In a release workflow, run `./gradlew -p android bundleRelease`
   (for an `.aab` to upload to Google Play) or `assembleRelease` (for a
   signed `.apk`), then upload that file as the artifact instead of
   `app-debug.apk`.
4. Upload the `.aab` to Google Play Console to publish it.

## Developing locally

```bash
npm install
npm run android:sync    # copy www/ into android/
npm run android:open    # open the project in Android Studio (needs Android Studio + SDK)
```

You cannot build the APK locally without Java 17 and the Android SDK —
use the GitHub Actions workflow above instead. The web app itself can
be previewed in any browser by opening `www/index.html`.
