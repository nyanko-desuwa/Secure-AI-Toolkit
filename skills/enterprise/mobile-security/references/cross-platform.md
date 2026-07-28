> Verified 2026-07-28. Package versions from the npm and pub.dev registry APIs; option names
> from the shipped type definitions and the package README at that version.
> Sources: <https://github.com/oblador/react-native-keychain> ·
> <https://pub.dev/packages/flutter_secure_storage> ·
> <https://reactnative.dev/docs/security>

# Cross-platform exposure: React Native and Flutter

A cross-platform framework does not change the threat model. It changes what an attacker reads
first.

## React Native

### The bundle is readable

A release build ships `index.android.bundle` or `main.jsbundle` inside the app package. It is
JavaScript. Unzip the APK or IPA and read it. Minification renames locals; it does not remove
string literals, so every URL, feature flag, and API key in the JS is directly greppable. Hermes
bytecode raises the effort slightly and there are public tools that reverse it.

Practical consequence: `process.env.API_KEY` inlined at build time by a bundler plugin ends up as
a literal in the bundle. `react-native-config` and `react-native-dotenv` place values in the
binary too. Neither is a secret store. They are build-time configuration, and the difference
matters.

### AsyncStorage is not secure storage

`AsyncStorage` is unencrypted. On Android it is backed by SQLite or files in the app sandbox; on
iOS it is a file in the app container. It is readable on a rooted or jailbroken device, appears in
backups unless excluded, and is the single most common place a mobile token is found. Same class
of finding as `SharedPreferences` and `NSUserDefaults`.

### react-native-keychain

Latest release 10.0.0 (published 2025-03-23). It wraps iOS Keychain and Android Keystore.

Two option groups decide whether the storage is actually protective:

`ACCESSIBLE` — the iOS accessibility class:

| Value | Meaning |
|---|---|
| `WHEN_UNLOCKED` | Accessible only while the device is unlocked |
| `AFTER_FIRST_UNLOCK` | Accessible after the first unlock following a restart |
| `ALWAYS` | Accessible regardless of lock state |
| `WHEN_PASSCODE_SET_THIS_DEVICE_ONLY` | Requires a passcode; never migrates to a new device |
| `WHEN_UNLOCKED_THIS_DEVICE_ONLY` | As `WHEN_UNLOCKED`, does not migrate |
| `AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY` | As `AFTER_FIRST_UNLOCK`, never migrates |

`ACCESS_CONTROL` — the biometric or passcode constraint:

| Value | Meaning |
|---|---|
| `USER_PRESENCE` | Biometry or passcode |
| `BIOMETRY_ANY` | Any enrolled biometric |
| `BIOMETRY_CURRENT_SET` | Currently enrolled set; invalidated on enrolment change |
| `DEVICE_PASSCODE` | Passcode only |
| `APPLICATION_PASSWORD` | App-supplied password contributes to the key |
| `BIOMETRY_ANY_OR_DEVICE_PASSCODE` | Either |
| `BIOMETRY_CURRENT_SET_OR_DEVICE_PASSCODE` | Either, enrolment-bound |

Defaults are the permissive end of both lists. Calling `setGenericPassword(user, token)` with no
options stores the token with whatever the library's default accessibility is — pass the options
explicitly rather than relying on it, and re-check them when upgrading a major version.

`BIOMETRY_CURRENT_SET` is the value that survives the "attacker enrols their own face" case,
because the item is invalidated when the enrolled set changes. `BIOMETRY_ANY` is not.

### Other React Native specifics

- Remote debugging and the dev menu must be off in release. A shipped dev bundle exposes the
  whole JS context.
- Source maps uploaded to a crash reporter are fine. Source maps shipped inside the app package
  are not — they hand over readable original source.
- OTA update mechanisms (CodePush and equivalents) are a code-integrity surface. If an attacker
  can serve a bundle, they own the app. Verify signatures and pin the update endpoint.
- Native modules are still native. A bridge method that takes a path or a URL from JS needs the
  same validation any exported native entry point needs.
- `WebView` from `react-native-webview` has its own `javaScriptEnabled`,
  `allowFileAccess`, `allowingReadAccessToURL`, and `injectedJavaScript` props. The Android
  `addJavascriptInterface` risk applies through the bridge; treat any message handler as an
  untrusted input boundary and validate the message shape.

## Flutter

### The bundle

Release builds compile Dart to native code, so a Flutter binary is harder to read than a JS
bundle. Harder is not private. Strings survive in the snapshot and there are public tools for
extracting them. Treat a Dart-embedded key exactly as you would a Kotlin or Swift one: public.

### flutter_secure_storage

Latest release 10.3.1 (published 2026-05-27). Backed by Keychain on iOS and macOS and by
Keystore-derived ciphers on Android.

Version 10 changed the Android implementation. From the package's own notice: "The deprecated
Jetpack Security library's `encryptedSharedPreferences` is no longer recommended." The new
defaults are RSA OAEP for key wrapping plus AES-GCM for the stored value, with automatic
migration from the older ciphers controlled by `migrateOnAlgorithmChange` (on by default) and
`migrateWithBackup` for crash resistance. Minimum Android SDK is 23.

Constructors that matter:

| Constructor | Behaviour |
|---|---|
| `AndroidOptions()` | Default. RSA OAEP key cipher, AES-GCM storage cipher, no biometrics |
| `AndroidOptions.biometric(enforceBiometrics: false)` | Optional biometric gate, degrades gracefully when unavailable |
| `AndroidOptions.biometric(enforceBiometrics: true)` | Requires biometric, PIN, or pattern. Throws if the device has no security set |
| `AndroidOptions.biometric(enforceBiometrics: true, biometricType: AndroidBiometricType.strongBiometricOnly)` | Class 3 biometrics only; device credentials rejected |

On iOS, `IOSOptions(accessibility: ...)` takes `unlocked` (the default),
`first_unlock`, or `first_unlock_this_device`. Pick `first_unlock_this_device` for a refresh token
that a background task needs — it does not migrate to another device. `unlocked` is stricter and
correct when access only happens in the foreground.

Android auto-backup applies to the underlying preferences file. The package documents disabling
it; do that, or scope `dataExtractionRules` so the encrypted entries are excluded. Otherwise the
ciphertext leaves the device even though the key does not, and that is a data-retention problem
even when it is not immediately exploitable.

### Flutter network layer

Flutter does not use the platform HTTP stack by default, so:

- Android Network Security Config does not automatically govern Dart-level requests made through
  `dart:io` `HttpClient`. A `<domain-config cleartextTrafficPermitted="false">` may be silently
  bypassed. MASTG has a dedicated test for cross-platform configurations allowing cleartext
  (MASTG-TEST-0237) for exactly this reason.
- Pinning must be implemented in Dart, typically via `SecurityContext` or
  `badCertificateCallback` on `HttpClient`. `badCertificateCallback` returning `true` is the
  Flutter equivalent of an empty `TrustManager`, and it is common in copy-pasted samples.
- iOS ATS applies to `URLSession`, so the same gap exists there.

## Shared conclusions

| Claim | True on native | True on React Native | True on Flutter |
|---|---|---|---|
| Secrets in the app are public | yes | yes, and trivially so | yes, with more effort |
| Plain key-value store protects a token | no | no (`AsyncStorage`) | no (`SharedPreferences` directly) |
| Platform NSC/ATS covers all traffic | mostly | not for JS-layer fetch through some libs | often not |
| Keystore/Keychain is reachable | directly | via `react-native-keychain` | via `flutter_secure_storage` |

The framework question that actually matters in a review: which layer makes the HTTPS request,
and which layer holds the token. Answer those two and the rest of the mapping follows.
