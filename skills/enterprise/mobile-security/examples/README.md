# Vulnerable and Fixed Mobile Examples

Eight pairs. Each names the MASVS control, OWASP Top 10 2025 category, ASVS 5.0 chapter, and CWE.
The vulnerable block is deliberately unsafe. Do not copy it.

## Token in SharedPreferences to Keystore-backed storage

`MASVS-STORAGE-1` · Mobile Top 10 M9 · `A04:2025` · ASVS V14 · `CWE-312`, `CWE-921`

An attacker with backup extraction or a rooted device reads the refresh token directly from the
preferences XML. `MODE_PRIVATE` is not encryption.

### Vulnerable: Kotlin

```kotlin
fun saveRefreshToken(context: Context, token: String) {
    context.getSharedPreferences("session", Context.MODE_PRIVATE)
        .edit().putString("refresh_token", token).apply()
}

fun loadRefreshToken(context: Context): String? =
    context.getSharedPreferences("session", Context.MODE_PRIVATE)
        .getString("refresh_token", null)
```

### Fixed: Kotlin

```kotlin
private const val ALIAS = "refresh-token-key"
private const val PREFS = "encrypted-session"

private fun key(): SecretKey {
    val keys = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    (keys.getKey(ALIAS, null) as? SecretKey)?.let { return it }
    return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
        init(KeyGenParameterSpec.Builder(
            ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
         .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
         .setRandomizedEncryptionRequired(true)
         .build())
        generateKey()
    }
}

fun saveRefreshToken(context: Context, token: String) {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
    val encoded = Base64.encodeToString(cipher.iv + cipher.doFinal(token.toByteArray()), Base64.NO_WRAP)
    context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        .edit().putString("refresh_token", encoded).apply()
}
```

Store the IV with the ciphertext; it is not secret. The Keystore key is not exported, and a
fresh GCM nonce is generated for each write. Production code also needs an atomic read/decrypt,
version marker, and a logout path that deletes both local and server-side state. The platform
documentation marks Jetpack Security 1.1 APIs deprecated in favour of direct Keystore APIs; an
existing `EncryptedSharedPreferences` migration needs testing, not a blind rewrite.

## Token in NSUserDefaults to Keychain

`MASVS-STORAGE-1` · Mobile Top 10 M9 · `A04:2025` · ASVS V14 · `CWE-312`, `CWE-921`

### Vulnerable: Swift

```swift
UserDefaults.standard.set(refreshToken, forKey: "refresh_token")
let token = UserDefaults.standard.string(forKey: "refresh_token")
```

`NSUserDefaults` is a preferences store. It is not the Keychain and may be present in backups or
app-container extraction.

### Fixed: Swift

```swift
import Security

func saveRefreshToken(_ token: String) throws {
    let data = Data(token.utf8)
    let query: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrAccount: "refresh_token",
        kSecValueData: data,
        kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    ]
    SecItemDelete(query as CFDictionary)
    let status = SecItemAdd(query as CFDictionary, nil)
    guard status == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(status)) }
}

func loadRefreshToken() throws -> String? {
    let query: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrAccount: "refresh_token",
        kSecReturnData: true,
        kSecMatchLimit: kSecMatchLimitOne
    ]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound { return nil }
    guard status == errSecSuccess, let data = result as? Data else {
        throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
    }
    return String(data: data, encoding: .utf8)
}
```

`WhenUnlockedThisDeviceOnly` keeps this foreground-only token out of a backup restored to a new
device. If a background refresh must read it after the first unlock, use
`AfterFirstUnlockThisDeviceOnly` and document the wider window.

## Hardcoded API key to backend proxy

`MASVS-STORAGE-1` · Mobile Top 10 M1 · `A04:2025` · ASVS V14 · `CWE-798`

### Vulnerable: TypeScript in a React Native bundle

```typescript
const VENDOR_KEY = "vendor_live_EXAMPLE_NOT_A_REAL_KEY";
export async function geocode(query: string) {
  return fetch(`https://vendor.example.invalid/geocode?key=${VENDOR_KEY}&q=${query}`);
}
```

The string is readable in `main.jsbundle`, even if a build plugin sourced it from `.env` and even
if Metro minified the bundle.

### Fixed: TypeScript

```typescript
export async function geocode(query: string, accessToken: string) {
  const response = await fetch("https://api.example.invalid/v1/geocode", {
    method: "POST",
    headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ query }),
  });
  if (!response.ok) throw new Error("geocode_failed");
  return response.json();
}
```

The backend proxy stores the vendor key, validates the query, authorizes the account, and rate
limits the call. The app only supplies a user-scoped token. Obfuscation is a delay, not a control.

## OAuth embedded WebView to system browser with PKCE

`MASVS-AUTH-1`, `MASVS-PLATFORM-2` · Mobile Top 10 M3 · `A07:2025` · ASVS V10 · `CWE-522`

RFC 8252 says native apps MUST NOT use embedded user-agents. RFC 7636 requires S256 when the
client can use it.

### Vulnerable: Swift

```swift
let webView = WKWebView(frame: view.bounds)
webView.load(URLRequest(url: URL(string:
    "https://id.example.invalid/authorize?client_id=mobile")!))
view.addSubview(webView)
```

The app can read login pages, keystrokes, cookies, and tokens. A malicious or compromised app
container has become the identity provider's credential collector.

### Fixed: Swift

```swift
import AuthenticationServices
import CryptoKit
import Security

private func base64URL(_ data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

func startOAuth() {
    var bytes = [UInt8](repeating: 0, count: 32)
    guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { return }
    let verifier = base64URL(Data(bytes))
    let challenge = base64URL(Data(SHA256.hash(data: Data(verifier.utf8))))
    let state = UUID().uuidString
    OAuthStateStore.save(verifier: verifier, state: state)

    var components = URLComponents(string: "https://id.example.invalid/authorize")!
    components.queryItems = [
        URLQueryItem(name: "client_id", value: "mobile-example"),
        URLQueryItem(name: "response_type", value: "code"),
        URLQueryItem(name: "redirect_uri", value: "https://app.example.invalid/oauth/callback"),
        URLQueryItem(name: "code_challenge", value: challenge),
        URLQueryItem(name: "code_challenge_method", value: "S256"),
        URLQueryItem(name: "state", value: state)
    ]
    let session = ASWebAuthenticationSession(url: components.url!, callback: .https(
        host: "app.example.invalid", path: "/oauth/callback")) { callbackURL, error in
        guard error == nil, let callbackURL,
              let result = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false),
              result.queryItems?.first(where: { $0.name == "state" })?.value == state,
              let code = result.queryItems?.first(where: { $0.name == "code" })?.value else { return }
        // POST code + verifier to the token endpoint; store the returned refresh token in Keychain.
        TokenClient.exchange(code: code, verifier: verifier)
    }
    session.presentationContextProvider = self
    session.start()
}
```

The verifier is 43 URL-safe characters from 32 random bytes, and `base64URL` removes padding as
RFC 7636 requires. The callback's state check is still required; PKCE protects code interception,
not redirect CSRF. The fixed flow uses an external user-agent, authorization code, S256, and no
client secret.

## Exported Android component with no permission

`MASVS-PLATFORM-1` · Mobile Top 10 M8 · `A01:2025` · ASVS V8 · `CWE-926`

### Vulnerable: AndroidManifest.xml

```xml
<receiver
    android:name=".SyncReceiver"
    android:exported="true">
  <intent-filter>
    <action android:name="com.example.SYNC_NOW" />
  </intent-filter>
</receiver>
```

Any installed app can send the broadcast. If the receiver accepts a file path, token, or account
ID, the caller controls a privileged operation.

### Fixed: AndroidManifest.xml

```xml
<permission
    android:name="com.example.permission.SYNC"
    android:protectionLevel="signature" />

<receiver
    android:name=".SyncReceiver"
    android:exported="true"
    android:permission="com.example.permission.SYNC" />
```

If no other app needs it, the safer fixed fragment is simply `android:exported="false"` with no
filter. A `signature` permission makes the platform check the signing certificate. An obscure
action name does not.

## Deep link performs state change without caller verification

`MASVS-PLATFORM-1`, `MASVS-AUTH-3` · Mobile Top 10 M3 · `A01:2025` · ASVS V8 · `CWE-939`

### Vulnerable: Kotlin

```kotlin
override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    if (intent.data?.path == "/delete-account") {
        accountApi.deleteAccount() // Any app can send this URI.
    }
}
```

Custom schemes can be claimed by another app, and Android's referrer is explicitly spoofable.
Universal Links/App Links improve routing but do not authorize an operation.

### Fixed: Kotlin

```kotlin
override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    val uri = intent.data ?: return
    if (uri.scheme != "https" || uri.host != "app.example.invalid" ||
        uri.path != "/account/delete") return

    val actionToken = uri.getQueryParameter("action_token") ?: return
    lifecycleScope.launch {
        // Server verifies: current session, one-time token, account binding, expiry, and action.
        accountApi.confirmDelete(actionToken)
    }
}
```

The link is now a navigation/input channel. The server-side, single-use token authorizes the
state change and binds it to the account. Do not replace that call with a `getReferrer()` or
package-name check.

## Sensitive push payload to opaque event

`MASVS-PLATFORM-3`, `MASVS-PRIVACY-1` · Mobile Top 10 M6 · `A01:2025` · ASVS V14 · `CWE-359`

### Vulnerable: FCM payload

```json
{
  "notification": { "title": "Payment", "body": "Card 4242 charged $900.00" }
}
```

Push services, notification extensions, OS storage, and a locked screen receive the sensitive
body before the user authenticates.

### Fixed: TypeScript server payload

```typescript
const payload = {
  data: { event_id: "evt_01HXYZ", type: "payment_available" },
  android: { notification: { visibility: "private" } },
  apns: { payload: { aps: { "content-available": 1 } } },
};
```

The client authenticates after opening, fetches `event_id` through the session API, and renders
the detail in-app. The platform redaction is defence in depth; the primary fix is that the
sensitive content never enters the push payload.

## WebView bridge exposes a native operation

`MASVS-PLATFORM-2` · Mobile Top 10 M4 · `A01:2025` · ASVS V8 · `CWE-749`

### Vulnerable: Kotlin

```kotlin
class Bridge(private val context: Context) {
    @JavascriptInterface
    fun exportPath(path: String) {
        File(path).copyTo(context.cacheDir.resolve("export"))
    }
}

webView.settings.javaScriptEnabled = true
webView.addJavascriptInterface(Bridge(this), "native")
webView.loadUrl(userSuppliedUrl)
```

The bridge is injected into every frame. Untrusted content can call it, and `path` is an
attacker-controlled file operation.

### Fixed: Kotlin

```kotlin
webView.settings.javaScriptEnabled = false
webView.settings.allowFileAccess = false
webView.settings.allowContentAccess = false
webView.webViewClient = object : WebViewClient() {
    override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean =
        request.url.host != "app.example.invalid"
}
webView.loadUrl("https://app.example.invalid/help")
```

Removing the bridge and restricting the origin removes the privileged IPC path. If a first-party
bridge is unavoidable, expose no file or account operation, validate a typed message, and keep
server authorization. A top-level origin check cannot authenticate a third-party iframe.

## Sources

- <https://owasp.org/Top10/2025/>
- <https://mas.owasp.org/MASVS/>
- <https://mas.owasp.org/MASTG/tests/>
- <https://www.rfc-editor.org/rfc/rfc8252>
- <https://www.rfc-editor.org/rfc/rfc7636>
- <https://developer.android.com/reference/android/webkit/WebSettings>
- <https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlockedthisdeviceonly>
