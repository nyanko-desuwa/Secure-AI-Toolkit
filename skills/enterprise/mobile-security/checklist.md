# Mobile Verification Checklist

Run before returning mobile code. Mark each item pass, fail, or not applicable. "Not applicable"
needs a one-line reason.

Only run the sections the change touches. A layout file does not need the network section.

Two items apply to every section: state whether you read the code or actually observed the
behaviour on a device, and state the precondition (rooted, backup enabled, malicious app
installed) for anything you call a finding.

## Trust boundary (MASVS-AUTH-1 · A01 · ASVS V8)

- [ ] [critical] No authorization decision is made on-device and then trusted by the server
- [ ] [critical] No price, quantity, entitlement, or role is sent from the client and used unchecked
- [ ] [critical] Feature flags that gate paid or privileged features are enforced server-side
- [ ] [critical] Logout revokes the session server-side, not just clears local state
- [ ] [critical] The server rejects a request whose user ID does not match the bearer token

## Credential storage (MASVS-STORAGE-1 · A04 · ASVS V14 · CWE-312)

- [ ] [critical] No token, password, or key in `SharedPreferences`, `NSUserDefaults`, `AsyncStorage`, a
      plain file, or an unencrypted SQLite table
- [ ] [recommended] iOS items use the tightest `kSecAttrAccessible*` class the feature tolerates
- [ ] [recommended] iOS items that must not leave the device use a `ThisDeviceOnly` class
- [ ] [recommended] No use of `kSecAttrAccessibleAlways` or `kSecAttrAccessibleAlwaysThisDeviceOnly`
- [ ] [critical] Android keys are generated in the Keystore, not derived from a constant in the code
- [ ] [recommended] Biometric gating unlocks a stored key (`kSecAttrAccessControl`,
      `setUserAuthenticationRequired`), rather than only gating a UI branch
- [ ] [recommended] `setInvalidatedByBiometricEnrollment(true)` or `.biometryCurrentSet` where enrolment
      changes should invalidate the key

## Secrets in the binary (MASVS-STORAGE-1 · A04 · CWE-798)

- [ ] [critical] No API key, private key, or shared secret in source, resources, `BuildConfig`, plist,
      `.env`, or a JS bundle
- [ ] [critical] Any third-party credential that grants server-side capability sits behind a backend proxy
- [ ] [recommended] Obfuscation is not the only thing protecting a secret
- [ ] [critical] Committed secrets are rotated, not just deleted

## Data at rest and leakage (MASVS-STORAGE-2 · CWE-200 · CWE-359)

- [ ] [recommended] `android:allowBackup="false"` or `android:dataExtractionRules` excludes sensitive files
- [ ] [recommended] iOS files holding sensitive data are excluded from backup or stored in the Keychain
- [ ] [recommended] No sensitive value reaches `Log`, `NSLog`, `print`, or `console.log`, including in
      error paths
- [ ] [critical] SQLite or Realm databases holding sensitive data are encrypted, or hold nothing sensitive
- [ ] [recommended] WebView cache, cookies, and local storage cleared on logout
- [ ] [recommended] Screens showing secrets set `FLAG_SECURE` (Android) or blank the snapshot (iOS)
- [ ] [optional] Sensitive fields are not copied to the clipboard by default
- [ ] [optional] Keyboard caching disabled on secret input fields

## Transport (MASVS-NETWORK-1, MASVS-NETWORK-2 · A02 · CWE-295, CWE-319)

- [ ] [critical] No `TrustManager`, `HostnameVerifier`, or `URLSessionDelegate` that accepts everything
- [ ] [critical] No `NSAllowsArbitraryLoads` in the shipped `Info.plist`
- [ ] [critical] No `cleartextTrafficPermitted="true"` in `base-config`
- [ ] [critical] Proxy-CA trust lives in `<debug-overrides>`, not `base-config`
- [ ] [recommended] `targetSdkVersion` is 24 or higher so user-installed CAs are not trusted by default
- [ ] [recommended] Pinning, if used, covers only endpoints you control, carries a backup pin, and has a
      documented rotation and failure path
- [ ] [recommended] Pin expiry is set and tracked

## Platform IPC (MASVS-PLATFORM-1 · A01 · CWE-926, CWE-939)

- [ ] [recommended] Every activity, service, receiver, and provider declares `android:exported` explicitly
- [ ] [critical] Everything not intended for other apps is `exported="false"`
- [ ] [critical] Exported components that must stay exported are guarded by a `signature` permission or
      validate the request server-side
- [ ] [critical] No sensitive data sent by implicit intent
- [ ] [critical] `PendingIntent` uses `FLAG_IMMUTABLE` where possible and never wraps an implicit intent
- [ ] [critical] Deep links and Universal Links are treated as untrusted input: parameters validated,
      no state change without a server-side authorization check
- [ ] [recommended] Android App Links use `android:autoVerify="true"` with a served `assetlinks.json`
- [ ] [recommended] iOS uses Universal Links with associated domains for anything security-relevant, not a
      custom scheme
- [ ] [critical] Caller identity is not inferred from `getReferrer()` or a package name

## WebView (MASVS-PLATFORM-2 · CWE-749)

- [ ] [critical] `addJavascriptInterface` is absent, or the bridge exposes no privileged operation and the
      WebView loads only first-party content with no third-party iframes
- [ ] [critical] Bridge methods annotated `@JavascriptInterface` and each one re-checks authorization
- [ ] [recommended] `setAllowFileAccess(false)` set explicitly; assets served via `WebViewAssetLoader`
- [ ] [recommended] `setJavaScriptEnabled(true)` only where required
- [ ] [critical] `setMixedContentMode` not set to `MIXED_CONTENT_ALWAYS_ALLOW`
- [ ] [critical] URL loading restricted to an allowlisted origin
- [ ] [critical] No OAuth or login form inside an app-controlled WebView

## Authentication and session (MASVS-AUTH-1, MASVS-AUTH-3 · A07 · ASVS V6, V7, V9, V10)

- [ ] [critical] Native OAuth uses the authorization code flow with PKCE `S256` in a system browser
- [ ] [critical] No implicit flow, no client secret in the app
- [ ] [critical] Redirect URI is a claimed HTTPS URL or a reverse-domain private-use scheme, registered
      exactly, and validated by the server
- [ ] [critical] `state` is generated, stored, and checked on return
- [ ] [critical] Refresh tokens rotate on use and the server detects reuse of a consumed token
- [ ] [critical] Sensitive operations require re-authentication, not just an unlocked app
- [ ] [critical] Local PIN or biometric unlock is not treated as server-side authentication

## Notifications and UI (MASVS-PLATFORM-3 · CWE-359)

- [ ] [recommended] Push payloads carry no sensitive content; the app fetches detail after authenticating
- [ ] [recommended] Notification visibility set to `VISIBILITY_PRIVATE` or `VISIBILITY_SECRET`, or a redacted
      `setPublicVersion` supplied
- [ ] [recommended] iOS notifications rely on `mutable-content` plus a fetch, not the payload, for anything
      sensitive

## Build and release (MASVS-CODE · A02 · ASVS V13)

- [ ] [critical] `android:debuggable` absent or false in the release manifest
- [ ] [recommended] `WebView.setWebContentsDebuggingEnabled` off in release
- [ ] [recommended] Debug logging stripped, not just set to a higher level at runtime
- [ ] [recommended] Source maps and debug symbols not shipped in the app bundle
- [ ] [critical] Release build signed with the release key; no debug keystore
- [ ] [recommended] `minSdkVersion` high enough that the platform mitigations you rely on exist
- [ ] [recommended] Dependencies pinned and scanned; no SDK added without a stated purpose

## Third-party SDKs (MASVS-PRIVACY · A03 · ASVS V15)

- [ ] [recommended] Every SDK's purpose is stated, and its data collection is known
- [ ] [critical] No SDK receives tokens, PII, or full request bodies as a side effect of logging
- [ ] [recommended] Permissions added by SDK manifests reviewed after a merge
- [ ] [recommended] iOS: every shipped SDK carries a valid `PrivacyInfo.xcprivacy`; app manifest declares
      collected data types and required-reason APIs

## Resilience, last (MASVS-RESILIENCE)

- [ ] [optional] Root, jailbreak, and tamper checks are signals reported to the server, not local gates
- [ ] [optional] The app does not hard-fail on a root signal alone
- [ ] [recommended] No security control depends on a resilience check being unbypassable

## Before returning

- [ ] [critical] Build run for both platforms the change touches
- [ ] [critical] Relevant tests run, output reported honestly
- [ ] [recommended] Findings state the attacker precondition and what they gain beyond device-owner access
- [ ] [critical] Anything only read, not observed at runtime, labelled as such
