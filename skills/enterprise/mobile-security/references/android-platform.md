> Verified 2026-07-28 against `developer.android.com`. Every default below is tied to a target
> API level, because these defaults changed and the old behaviour still applies to apps that
> target an old level.
> Sources: <https://developer.android.com/guide/topics/manifest/manifest-intro> ·
> <https://developer.android.com/privacy-and-security/security-config> ·
> <https://developer.android.com/reference/android/webkit/WebSettings> ·
> <https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder>

# Android platform behaviour

## Manifest flags that decide exposure

| Attribute | Element | Documented behaviour |
|---|---|---|
| `android:exported` | activity, service, receiver | `true` means any app can launch it by exact class name. `false` restricts to the same app, same user ID, or privileged system components. Default is `false` when there are no intent filters |
| `android:exported` (Android 12+) | activity, service, receiver | Apps targeting Android 12 or higher that use intent filters must declare it explicitly. Without it, manifest merger fails and the app cannot be installed on Android 12 or higher |
| `android:permission` | activity, service, receiver, provider | Requires the caller to hold the named permission |
| `android:allowBackup` | application | Default `true`. `false` means no backup or restore is ever performed, including a full-system `adb` backup |
| `android:debuggable` | application | Google's own note: set it to `false` before releasing. For apps targeting Android 12+, `adb backup` excludes app data unless `debuggable` is `true` |
| `android:dataExtractionRules` | application | Points at the rules file controlling what backup and device transfer include |
| `android:autoVerify` | intent-filter | Present on at least one filter makes the system verify the associated hosts on install, on Android 6.0 (API 23) and higher. Android 12+ also allows invoking verification manually for testing |

Two notes worth carrying into a review:

- `exported="false"` with an intent filter is a valid and common combination. The filter still
  routes internal intents; it just does not open the component to other apps.
- On apps targeting Android 12 or higher, device-to-device migration of app files cannot be
  disabled on devices from some manufacturers, even with `allowBackup="false"`. Cloud backup can
  be. Do not treat `allowBackup="false"` as "this never leaves the device".

## Network Security Config

Cleartext default depends on target level:

| Target | Cleartext |
|---|---|
| Up to Android 8.1 (API 27) | Enabled by default. You can opt out |
| Android 9 (API 28) and higher | Disabled by default. You can opt back in |

Documented default `base-config` by target level:

```xml
<!-- targeting API 28 and higher -->
<base-config cleartextTrafficPermitted="false">
  <trust-anchors><certificates src="system" /></trust-anchors>
</base-config>

<!-- targeting API 24 to 27 -->
<base-config cleartextTrafficPermitted="true">
  <trust-anchors><certificates src="system" /></trust-anchors>
</base-config>

<!-- targeting API 23 and lower: user CAs are trusted too -->
<base-config cleartextTrafficPermitted="true">
  <trust-anchors>
    <certificates src="system" />
    <certificates src="user" />
  </trust-anchors>
</base-config>
```

That last block is why an old `targetSdkVersion` is a network finding on its own: a
user-installed CA, which is how an interception proxy works, is trusted by default.

`<network-security-config>` accepts at most one `<base-config>`, any number of
`<domain-config>`, and at most one `<debug-overrides>`. A `<domain-config>` can contain
`<domain>`, `<trust-anchors>`, `<pin-set>`, `<certificateTransparency>`, `<domainEncryption>`,
and nested `<domain-config>` elements. Unset values inherit from the parent `domain-config`, then
`base-config`, then the platform default.

`<debug-overrides>` applies only to debug builds, which is the supported way to trust a proxy CA
without shipping that trust. From Android 17 (API 37), if no configuration is defined for
localhost, an implicit one applies that allows cleartext and does not enforce certificate
transparency or pinning.

## WebView settings

| Method | Verified behaviour |
|---|---|
| `setAllowFileAccess(boolean)` | Default `true` for apps targeting Android 10 (API 29) and below, `false` targeting Android 11 (API 30) and above. Android's guidance: do not open `file://` URLs from any external source, set it explicitly to `false`, and use `androidx.webkit.WebViewAssetLoader` over `http(s)://` instead |
| `setAllowFileAccessFromFileURLs(boolean)` | Deprecated in API level 30 |
| `setAllowUniversalAccessFromFileURLs(boolean)` | Deprecated in API level 30 |
| `setMixedContentMode(int)` | Controls whether a secure origin may load insecure resources |
| `setSafeBrowsingEnabled(boolean)` | Malware and phishing protection |

`addJavascriptInterface(Object, String)`, quoting the reference documentation:

- The object is injected into all frames of the page, including all iframes.
- For apps targeting API 17 and above, only public methods annotated `@JavascriptInterface` are
  reachable from JavaScript. For API 16 and below, all public methods including inherited ones
  are, and JavaScript can reach injected fields by reflection.
- "Because the object is exposed to all the frames, any frame could obtain the object name and
  call methods on it. There is no way to tell the calling frame's origin from the app side, so
  the app must not assume that the caller is trustworthy."

That last sentence is the whole risk. A single third-party iframe or one open redirect inside
the WebView reaches every bridge method with the app's own permissions.

## Keystore, and user authentication binding

`KeyGenParameterSpec.Builder` methods that matter for a review:

| Method | Effect |
|---|---|
| `setUserAuthenticationRequired(boolean)` | The key is usable only after the user authenticates |
| `setUserAuthenticationParameters(int timeout, int type)` | Timeout plus type. `KeyProperties.AUTH_BIOMETRIC_STRONG`, `KeyProperties.AUTH_DEVICE_CREDENTIAL`, or both |
| `setUserAuthenticationValidityDurationSeconds(int)` | Deprecated in API level 30, superseded by `setUserAuthenticationParameters` |
| `setInvalidatedByBiometricEnrollment(boolean)` | Invalidate the key when a new biometric is enrolled |
| `setIsStrongBoxBacked(boolean)` | Ask for a StrongBox security chip |

A timeout of `0` with `setUserAuthenticationParameters` is the per-use case: the key is unusable
until authentication happens for that specific operation, which is what you want behind a
`BiometricPrompt.CryptoObject`.

`setInvalidatedByBiometricEnrollment(true)` closes an attack that most implementations miss.
Without it, someone holding an unlocked device enrolls their own fingerprint and the existing
key still works.

## Jetpack Security is deprecated

`androidx.security:security-crypto` 1.1.0 shipped 2025-07-30. The 1.1.0-beta01 release note
(2025-06-04) reads: "Deprecated all APIs in favour of existing platform APIs and direct use of
Android Keystore." `EncryptedSharedPreferences` carries a `Deprecated in 1.1.0` marker on the
reference page.

Practical reading: `EncryptedSharedPreferences` is still far better than plain
`SharedPreferences` and is fine in existing code. For new code, generate a key with
`KeyGenParameterSpec` and encrypt with `javax.crypto.Cipher` against the Keystore directly, or
keep 1.0.0 knowingly. Do not present the deprecated wrapper as current guidance.

`androidx.biometric` stable is 1.1.0; 1.2.0 and 1.4.0 are alpha only as of the check date, and
`biometric-compose` exists only in 1.4.0 alphas. Check the current version before pinning.

## Leak surfaces the platform documents

| Surface | Control |
|---|---|
| Screenshots and the task snapshot | `WindowManager.LayoutParams.FLAG_SECURE` — "treat the content of the window as secure, preventing it from appearing in screenshots or from being viewed on non-secure displays". `View.setContentSensitivity(int)` marks a window secure during media projection |
| Lock-screen notifications | `Notification.VISIBILITY_PRIVATE` conceals sensitive content on secure lock screens; `VISIBILITY_SECRET` reveals no part of it; `setPublicVersion(Notification)` supplies a redacted variant |
| Caller identity | `Activity.getReferrer()` — "this is not a security feature -- you can not trust the referrer information, applications can spoof it" |
| Backups | `android:allowBackup`, `android:dataExtractionRules` |

`getReferrer()` being spoofable is the reason a deep link cannot authenticate its caller. If a
link triggers a state change, the state change needs a server-side token, not a package-name
check.
