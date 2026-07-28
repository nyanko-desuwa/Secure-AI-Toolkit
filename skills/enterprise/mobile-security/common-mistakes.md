# Common Mobile Security Mistakes

What it looks like, why it fails, the fix, and why the fix works. The repeated theme is that the
client is attacker-controlled.

## Client-side authorization

`MASVS-AUTH-1` · `A01:2025` · ASVS V8 · `CWE-602`

```typescript
if (profile.role === "admin") {
  await fetch(`${API}/admin/users/${id}`, { method: "DELETE" });
}
```

The UI check is fine for hiding a button. It is not authorization. A patched JS bundle calls the
endpoint directly, and every native app has the same weakness under a different syntax.

Fix: derive the actor and role from the server-side session at the endpoint. The client branch
then becomes a usability feature, not a control. Signing or obfuscating the role does not help;
the server still accepts a request that should not exist.

## API key "encrypted" with a key in the app

`MASVS-STORAGE-1`, `MASVS-CRYPTO-2` · `A04:2025` · ASVS V14 · `CWE-798`

```kotlin
val key = decrypt(BuildConfig.API_KEY_CIPHERTEXT, BuildConfig.DECRYPTION_KEY)
```

Both ciphertext and decryption key ship together. The attacker sets a breakpoint after
`decrypt`, or just reproduces the function. Splitting the key across three classes, using JNI,
or base64-encoding it changes the grep command, not the design.

Fix: a backend proxy holds the credential. The app sends a user-authenticated request; the
backend constrains and forwards it. This works because the secret is no longer on the device.

## Token in a private sandbox mistaken for encrypted storage

`MASVS-STORAGE-1` · `A04:2025` · ASVS V14 · `CWE-312`, `CWE-921`

`MODE_PRIVATE`, the iOS app container, and the React Native sandbox are access-control boundaries
between ordinary apps. They are not encryption and do not protect against backup extraction,
root, jailbreak, memory inspection, or a vulnerability in the app itself.

Fix: Keychain or Android Keystore, with a non-migrating accessibility class where appropriate.
Why it works: the value is encrypted under key material enforced by the platform, not merely
stored in a directory whose path is private.

## Biometrics as a boolean

`MASVS-AUTH-2` · `A07:2025` · ASVS V6 · `CWE-287`

```kotlin
onAuthenticationSucceeded = { showVault(sharedPreferences.getString("vault", "")) }
```

The callback is in code the attacker controls, so they call `showVault` or patch the branch. It
also mistakes possession of an enrolled biometric for authentication to your remote account.

Fix: bind a Keystore key to `setUserAuthenticationRequired(true)` and perform the decrypt through
`BiometricPrompt.CryptoObject`; on iOS, use `kSecAttrAccessControl`. The plaintext does not exist
until a platform-enforced key operation succeeds. Remote identity still needs server auth.

## Pinning one leaf certificate with no backup

`MASVS-NETWORK-2` · `A02:2025` · ASVS V12 · `CWE-295`

It passes the pen test and takes the app offline the day the certificate renews. The tempting
wrong fix is a remote "disable pinning" flag, but fetching that flag requires a connection at the
exact moment the pin blocks all connections.

Fix: SPKI pin the issuing key where possible, ship an independent backup key, set and monitor pin
expiry, and practise rotation before the active key expires. Pin only hosts you control. The
backup shipped in the old binary is what makes rotation possible when the active certificate is
gone.

## Trust-all only in debug, according to a runtime flag

`MASVS-NETWORK-1` · `A02:2025` · ASVS V12, V13 · `CWE-295`

```kotlin
if (BuildConfig.ALLOW_PROXY || remoteConfig.allowProxy) installTrustAllManager()
```

A bad flavour or server-side toggle ships verification off. A flag does not make dangerous code
unreachable in release; the code is still there and patchable.

Fix: Android `<debug-overrides>` and a separate debug build configuration on iOS, with the release
artifact tested against a proxy. Why it works: the release binary does not contain the trust-all
path. Never fix pinning breakage by returning true from a certificate callback.

## Random action string on an exported component

`MASVS-PLATFORM-1` · `A01:2025` · ASVS V8 · `CWE-926`

```xml
<receiver android:name=".WipeReceiver" android:exported="true">
  <intent-filter><action android:name="com.example.SECRET_7d72c" /></intent-filter>
</receiver>
```

Every installed app can inspect the manifest. A UUID-shaped action is not a credential.

Fix: `exported="false"` if only your app calls it. If another same-publisher app must call it,
use a `signature` permission. This works because Android verifies the caller's signing
certificate rather than asking it to know a public string.

## Deep link checks `getReferrer()`

`MASVS-PLATFORM-1` · `A01:2025` · ASVS V8 · `CWE-939`

```kotlin
if (referrer?.host == "trusted.example") deleteAccount()
```

Android's `Activity.getReferrer()` documentation says it directly: "this is not a security
feature -- you can not trust the referrer information, applications can spoof it." iOS custom
schemes have the same caller-identity problem.

Fix: links navigate to a confirmation screen. A state-changing link carries a single-use,
short-lived server token bound to the authenticated account, and the API re-authorizes the
action. App Links or Universal Links stop scheme hijacking but do not authorize the operation.

## WebView bridge with an origin allowlist in `shouldOverrideUrlLoading`

`MASVS-PLATFORM-2` · `A01:2025` · ASVS V8 · `CWE-749`

The top-level URL is first-party, so the code installs `addJavascriptInterface`. Then the page
loads an ad or analytics iframe. Android injects the object into every frame and provides no API
to tell the Java side which frame called it.

Fix: remove the bridge from any WebView that can load untrusted or third-party content. If the
bridge is unavoidable, expose no privileged operation, use a narrow typed message schema, and
keep all server authorization. A top-level origin check does not fix subframes.

## Sensitive SQLite column with an encrypted token next to it

`MASVS-STORAGE-1`, `MASVS-STORAGE-2` · `A04:2025` · ASVS V14 · `CWE-311`

The refresh token is in Keychain, so the team calls local storage secure. The database beside it
still holds message bodies, medical readings, or document thumbnails in plaintext. SQLite does
not encrypt itself; neither do Room, Core Data, Realm, or a Flutter ORM unless configured to.

Fix: do not persist data you can fetch. Encrypt the database where offline access is required,
with the key in Keychain/Keystore, and delete it on logout. This works because the sensitive
columns and WAL/journal are encrypted together. Field-level encryption that forgets the search
index or journal is incomplete.

## Cache cleared, except the side caches

`MASVS-STORAGE-2` · `A04:2025` · ASVS V14 · `CWE-200`

Deleting the account database leaves image-loader caches, downloaded attachments, WebView cache,
cookies, `WKWebsiteDataStore`, crash breadcrumbs, and task snapshots. Logging out while one of
those writes is in flight can recreate data after the cleanup.

Fix: one session-owned data directory and an explicit cache inventory; cancel work first, then
clear database, files, image cache, WebView data, clipboard contents your app wrote, and local
notifications. Why it works: teardown has an order and owns every sink instead of relying on
feature teams to remember theirs.

## Root detection used as the access-control boundary

`MASVS-RESILIENCE-1` · `A06:2025` · ASVS V15 · `CWE-693`

Root checks look for files, packages, mounts, or failed attestations on a platform the attacker
controls. Every result and every branch can be hooked. Failing closed locks out legitimate
custom-ROM users and accessibility tooling while capable attackers patch around it.

Fix: send several integrity signals to the server, combine them with account and transaction
risk, and step up authentication or limit the highest-risk action. Keep authorization correct
when the signal says "clean" because a clean signal is not proof.

## Sensitive notification with "hide previews" as the control

`MASVS-PLATFORM-3`, `MASVS-PRIVACY-1` · `A01:2025` · ASVS V14 · `CWE-359`

User notification settings apply at display time. APNs/FCM, the OS, notification service
extensions, logs, and backups may already have the payload.

Fix: payload contains an opaque event ID and generic copy. The app authenticates and fetches the
detail. This works because sensitive content does not enter the push delivery system. Lock-screen
redaction is still useful, but it is not the primary control.

## Analytics SDK receives the whole object

`MASVS-PRIVACY-1`, `MASVS-PRIVACY-3` · `A03:2025` · ASVS V14, V15 · `CWE-359`

```typescript
analytics.capture("api_error", { request, response, user });
```

The request has a bearer token, the response has PII, and the user object has an email. SDKs
batch and forward this data under their own retention and subprocessor chain.

Fix: allowlist named event fields at the call site, block network bodies and auth headers in SDK
interceptors, verify Android manifest-merged permissions, and reconcile iOS privacy manifests.
The allowlist works because sensitive fields never enter the SDK, not because a later redactor
tries to remember every secret name.

## Source maps shipped "for crash reports"

`MASVS-RESILIENCE-3`, `MASVS-CODE-4` · `A02:2025` · ASVS V13 · `CWE-200`

A React Native source map in the APK turns a minified bundle back into named source. Flutter
symbol files and iOS dSYMs do the same for native crashes. Crash services need these files;
customers do not.

Fix: upload maps and symbols to the crash service in CI, access-restrict the project, then assert
they are absent from the release APK/IPA. This does not make the binary secret; it removes the
free index and raises reverse-engineering cost, which is exactly the limited claim resilience
controls should make.
