# Mobile Security Best Practices

Patterns that hold up on a device the attacker controls. Each maps to MASVS, OWASP Top 10 2025,
ASVS 5.0 at chapter level, and a CWE where one applies.

## Enforce the decision server-side

`MASVS-AUTH-1` · `A01:2025` · ASVS V6, V8 · `CWE-602`

The client is attacker-controlled. An entitlement check in Swift, Kotlin, Dart, or JavaScript can
be patched to return true. Make the server authoritative.

Vulnerable:

```kotlin
// A patched app changes hasPro to true and sends any export request.
if (preferences.getBoolean("has_pro", false)) {
    api.exportAllData()
}
```

Fixed:

```kotlin
// Client requests the action. The API derives plan and actor from the bearer token.
suspend fun exportAllData(): ExportJob = api.exportAllData()
```

```typescript
// Server: entitlement is loaded by token subject, never from the request body.
app.post("/v1/exports", requireSession, async (req, res) => {
  const account = await db.account.findUniqueOrThrow({ where: { id: req.user.id } });
  if (account.plan !== "PRO") return res.status(403).json({ error: "upgrade_required" });
  res.status(202).json(await exports.create(account.id));
});
```

Why this works: patching the UI can expose the button, but the server still sees the basic plan
and refuses the capability. Obfuscating `hasPro` or signing the preference only slows patching;
the signer is in the app too.

## Keep third-party credentials off the device

`MASVS-STORAGE-1` · `A04:2025` · ASVS V14 · `CWE-798`

An API key in the app bundle is public. A `.env` file, `BuildConfig`, plist entry, native string,
Flutter snapshot, and React Native bundle are all parts of the app bundle.

Vulnerable:

```swift
let mapsKey = "pk_mobile_EXAMPLE_NOT_A_REAL_KEY"
let url = URL(string: "https://vendor.invalid/geocode?key=\(mapsKey)&q=\(query)")!
```

Fixed:

```swift
var request = URLRequest(url: URL(string: "https://api.example.invalid/v1/geocode")!)
request.httpMethod = "POST"
request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
request.httpBody = try JSONEncoder().encode(["query": query])
let (data, _) = try await URLSession.shared.data(for: request)
```

The backend owns the vendor key, authorizes the user, constrains query shape, and rate-limits by
account. The app now holds only a revocable user-scoped token. Restricting a vendor key by bundle
ID is useful abuse throttling, not secrecy - a patched client can still call from inside the app.

## Store refresh tokens in hardware-backed storage

`MASVS-STORAGE-1`, `MASVS-CRYPTO-2` · `A04:2025` · ASVS V14 · `CWE-312`, `CWE-921`

Vulnerable:

```kotlin
getSharedPreferences("session", MODE_PRIVATE)
    .edit().putString("refresh_token", token).apply()
```

Fixed (new Android code, direct Keystore because Jetpack Security 1.1 APIs are deprecated):

```kotlin
private const val ALIAS = "refresh-token-key"

fun getOrCreateKey(): SecretKey {
    val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    (store.getKey(ALIAS, null) as? SecretKey)?.let { return it }

    return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
        init(
            KeyGenParameterSpec.Builder(
                ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
             .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
             .setRandomizedEncryptionRequired(true)
             .build()
        )
        generateKey()
    }
}
```

Encrypt with `AES/GCM/NoPadding`, generate a fresh 12-byte IV for every write, and store only
`version || IV || ciphertext || tag` in preferences. The key never leaves Keystore.

Existing apps using `EncryptedSharedPreferences` are materially safer than plain preferences;
do not migrate merely to remove a warning unless you have tested a crash-safe data migration.
For new code, direct Keystore is the current platform guidance.

On iOS, use Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, or
`AfterFirstUnlockThisDeviceOnly` only when a background task genuinely needs the token.

## Bind biometrics to key use

`MASVS-AUTH-2` · `A07:2025` · ASVS V6, V14 · `CWE-287`

A successful Face ID prompt returns a boolean to attacker-controlled code. The attacker patches
the callback. Bind the protected object to the authentication result instead.

Vulnerable:

```swift
context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                       localizedReason: "Open vault") { ok, _ in
    if ok { self.showPlaintextFromUserDefaults() }
}
```

Fixed:

```swift
var error: Unmanaged<CFError>?
let access = SecAccessControlCreateWithFlags(
    nil,
    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
    [.biometryCurrentSet, .privateKeyUsage],
    &error
)!

let attributes: [CFString: Any] = [
    kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrKeySizeInBits: 256,
    kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
    kSecPrivateKeyAttrs: [
        kSecAttrIsPermanent: true,
        kSecAttrApplicationTag: Data("com.example.vault".utf8),
        kSecAttrAccessControl: access
    ]
]
SecKeyCreateRandomKey(attributes as CFDictionary, &error)
```

The Secure Enclave key operation now cannot happen until the platform satisfies the access
control. `biometryCurrentSet` invalidates it when enrolment changes. This still proves local user
presence, not identity to your server. The server needs its own challenge and authenticated key
registration if it relies on the signature.

## Pin with a rotation path

`MASVS-NETWORK-2` · `A02:2025` · ASVS V12 · `CWE-295`

Pinning defends against a compromised or user-installed CA and some enterprise interception. It
does not defend a rooted device whose process is hooked after TLS, and it can brick every client
when the certificate rotates.

Vulnerable:

```kotlin
val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = Unit
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) = Unit
    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
})
```

Fixed (`res/xml/network_security_config.xml`):

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
  <base-config cleartextTrafficPermitted="false" />
  <domain-config>
    <domain includeSubdomains="true">api.example.invalid</domain>
    <pin-set expiration="2027-01-01">
      <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
      <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
    </pin-set>
  </domain-config>
  <debug-overrides>
    <trust-anchors><certificates src="@raw/debug_cas" /></trust-anchors>
  </debug-overrides>
</network-security-config>
```

One active SPKI pin, one offline backup key, expiry tracked in the release calendar. The
`debug-overrides` block is ignored by non-debuggable builds, so a proxy works in development
without shipping universal trust. Do not pin a third-party endpoint you cannot coordinate a
rotation with; MASVS-NETWORK-2 scopes pinning to endpoints under your control.

## Close exported Android components

`MASVS-PLATFORM-1` · `A01:2025` · ASVS V8 · `CWE-926`, `CWE-927`

Vulnerable:

```xml
<service
    android:name=".ExportService"
    android:exported="true">
  <intent-filter>
    <action android:name="com.example.EXPORT_ALL" />
  </intent-filter>
</service>
```

Fixed when no other app needs it:

```xml
<service
    android:name=".ExportService"
    android:exported="false" />
```

Fixed when a same-publisher companion app genuinely needs it:

```xml
<permission
    android:name="com.example.permission.EXPORT"
    android:protectionLevel="signature" />
<service
    android:name=".ExportService"
    android:exported="true"
    android:permission="com.example.permission.EXPORT" />
```

A random action string is not an access control. Any app reads it from the manifest. A signature
permission is granted only to apps signed with the same certificate. Server-side authorization
still runs before the service exports another user's data.

For outbound sensitive communication, use an explicit intent (`Intent(this, Service::class.java)`
or `intent.setPackage(...)`). An implicit intent lets a malicious app register a matching filter
and receive the payload.

## Make OAuth native

`MASVS-AUTH-1`, `MASVS-PLATFORM-2` · `A07:2025` · ASVS V10 · `CWE-522`

Vulnerable:

```swift
let login = WKWebView(frame: view.bounds)
login.load(URLRequest(url: URL(string: "https://id.example.invalid/authorize")!))
view.addSubview(login)
```

Fixed: authorization code with PKCE S256, in `ASWebAuthenticationSession`. A complete example is
in [examples/README.md](examples/README.md#oauth-in-an-embedded-webview).

Why this works: the app cannot read keystrokes or cookies in the system-owned session; the user
sees the identity provider's domain; PKCE makes an intercepted code useless. `state` still needs
to be checked - PKCE does not replace it. Never use the implicit flow; RFC 8252 says it cannot be
protected by PKCE and is not recommended for native apps.

## Rotate the refresh token and revoke the session

`MASVS-AUTH-1` · `A07:2025` · ASVS V7, V9, V10 · `CWE-613`

Vulnerable:

```typescript
app.post("/logout", requireAuth, (_req, res) => res.status(204).end());
// Client deletes its copy; a stolen refresh token still works until expiry.
```

Fixed:

```typescript
app.post("/oauth/token", async (req, res) => {
  const oldHash = sha256(req.body.refresh_token);
  await db.$transaction(async (tx) => {
    const current = await tx.refreshToken.findUniqueOrThrow({ where: { hash: oldHash } });
    if (current.consumedAt) {
      await tx.session.update({ where: { id: current.sessionId }, data: { revokedAt: new Date() } });
      throw new Error("refresh_token_reuse");
    }
    await tx.refreshToken.update({ where: { hash: oldHash }, data: { consumedAt: new Date() } });
    // Persist hash of a newly generated token, linked to the same session.
  });
  res.json(issueRotatedPair());
});

app.post("/logout", requireAuth, async (req, res) => {
  await db.session.update({ where: { id: req.session.id }, data: { revokedAt: new Date() } });
  res.status(204).end();
});
```

A token family links every rotated token to the session. Reuse of a consumed token means both
the legitimate client and an attacker have a copy, so revoke the family. Device binding can add
a hardware-backed proof key to each refresh request, but it is a replay barrier, not an excuse
to skip rotation and revocation.

## Treat root and jailbreak as signals

`MASVS-RESILIENCE-1`, `MASVS-RESILIENCE-2` · `A06:2025` · ASVS V15 · `CWE-693`

Vulnerable:

```kotlin
if (RootBeer(this).isRooted) finishAndRemoveTask()
```

Fixed:

```kotlin
val integritySignals = IntegritySignals(
    rooted = rootDetector.isLikelyRooted(),
    debugger = Debug.isDebuggerConnected(),
    appSignatureValid = signatureVerifier.matchesReleaseCertificate()
)
telemetry.report(integritySignals)
// Server applies step-up auth or limits high-risk actions based on multiple signals.
```

Why this works: it acknowledges that every local detector is bypassable. Failing closed on one
signal locks out accessibility users, researchers, enterprise test fleets, and devices with odd
ROMs while doing nothing to a capable attacker. Use the signal for risk-based server decisions,
and keep the underlying authorization intact when the signal is absent or forged.

## Keep sensitive content out of push payloads

`MASVS-PLATFORM-3`, `MASVS-PRIVACY-1` · `A01:2025` · ASVS V14 · `CWE-359`

Vulnerable:

```json
{"notification":{"title":"Lab result","body":"HIV test: positive"}}
```

Fixed:

```json
{"data":{"event_id":"evt_01HXYZ","type":"result_available"}}
```

The app authenticates after open, fetches the event by an ID scoped to the session, and renders
it inside a protected view. A redacted lock-screen notification is defence in depth; if the
sensitive content is in the payload, push providers, OS logs, and notification extensions
already received it.

## Review every third-party SDK

`MASVS-PRIVACY-1`, `MASVS-PRIVACY-3` · `A03:2025` · ASVS V14, V15 · `CWE-359`

Vulnerable:

```typescript
analytics.track("checkout", { ...cart, accessToken, email, shippingAddress });
```

Fixed:

```typescript
analytics.track("checkout_completed", {
  itemCount: cart.items.length,
  currency: cart.currency,
});
```

Why this works: the SDK receives only aggregate event data, not an object that happens to contain
PII and a bearer token. Review the transitive Android manifest after adding an SDK; manifest
merging can add permissions and exported components without a line changing in your manifest.
On iOS, require a valid `PrivacyInfo.xcprivacy` and reconcile its declared collection with your
own manifest before release.
