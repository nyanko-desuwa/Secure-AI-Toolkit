# Prompt Examples

Prompts that produce mobile findings rather than a recital of security categories. Each bounds
the platform, attacker, and evidence.

## Review Android storage

```text
Review app/src/main for MASVS-STORAGE-1 and MASVS-STORAGE-2. Search Room entities,
SharedPreferences, files, WebView storage, caches, logs, and AndroidManifest backup settings.
For each finding give file:line, data exposed, the attacker precondition, CWE, and a concrete
Keystore or minimisation fix. Do not call app-sandbox storage encrypted.
```

Why it works: names the side channels people forget and asks what the attacker gains. Without
the precondition, every plain preference gets reported as critical.

## Review iOS Keychain use

```text
Find every SecItemAdd, SecItemUpdate, and keychain wrapper call. For each item, identify its
kSecAttrAccessible class, whether it migrates in a backup, whether background access is needed,
and whether biometric gating is bound through SecAccessControl. Flag NSUserDefaults tokens.
Map findings to MASVS-STORAGE and CWE-312 or CWE-921.
```

## Audit the Android manifest

```text
Read the final merged AndroidManifest.xml, not only src/main. Inventory activities, services,
receivers, and providers with exported value, permission, and intent filters. Identify implicit
intents and mutable PendingIntents in code. Report only components another unprivileged installed
app can reach, with an adb am command that demonstrates each path where possible.
```

The merged manifest matters because an SDK can export a component or add a permission without a
line in your source manifest.

## Audit deep links on both platforms

```text
Trace every Android App Link, custom scheme, iOS Universal Link, and CFBundleURLScheme from
manifest/plist to its handler. Treat every URL parameter as attacker-controlled. Flag any state
change, token acceptance, arbitrary navigation, or file/URL load that happens before server-side
authorization. Check assetlinks.json and apple-app-site-association assumptions separately.
```

## Review mobile OAuth

```text
Trace login from authorization request through redirect and token storage. Verify an external
user-agent, authorization code flow, PKCE S256, state validation, exact redirect matching,
refresh rotation, and server-side logout revocation. Flag embedded WebViews, implicit flow,
client secrets, and custom-scheme collision. Map to RFC 8252, RFC 7636, MASVS-AUTH-1, and ASVS
5.0 V10 at chapter level.
```

## Test transport configuration

```text
Review Android Network Security Config, iOS ATS, every custom TrustManager/HostnameVerifier/
URLSession challenge handler, and cross-platform HTTP clients. Distinguish normal TLS validation
from pinning. For each pin, inventory active pin, backup pin, expiry, owned endpoint, and rotation
runbook. State which claims require MASTG dynamic traffic tests.
```

## Review React Native exposure

```text
Search the React Native app for AsyncStorage tokens, react-native-config values, process.env
inlining, API keys in the JS bundle, console logging, WebView bridges, deep-link handlers, and
source maps in release packaging. Verify react-native-keychain accessibility and accessControl
options are explicit. Assume the attacker can read and patch main.jsbundle.
```

## Review Flutter exposure

```text
Review flutter_secure_storage construction and per-call IOSOptions/AndroidOptions, Dart HttpClient
badCertificateCallback, deep links, MethodChannel handlers, logs, local databases, and backup
configuration. Check the exact installed flutter_secure_storage version before evaluating cipher
or migration behaviour. Assume strings in the AOT snapshot are recoverable.
```

## Review third-party SDK privacy

```text
Inventory direct and transitive mobile SDKs. For each, state purpose, permissions/components
added to the merged Android manifest, data passed at call sites, network destinations, iOS
PrivacyInfo.xcprivacy presence, and declared collected-data/required-reason API categories. Flag
whole-object analytics and request/response interception. Do not infer vendor behaviour without
evidence.
```

## Review a release artifact

```text
Inspect the release APK/AAB and IPA, not a debug build. Check debuggable/get-task-allow,
allowBackup/dataExtractionRules, WebView debugging, ATS/NSC exceptions, debug certificates,
source maps and symbols, logs, test endpoints, signing identity, and embedded secrets. Report the
artifact hash and distinguish source findings from properties observed in the built binary.
```

## Triage root/jailbreak findings

```text
Inventory root, jailbreak, debugger, signature, and attestation signals. For each, show what
happens when it says compromised, whether the decision is local or server-side, false-positive
impact, and the security control that still works after the check is bypassed. Do not rate a
missing detector above a server authorization flaw.
```

## Verify before returning code

```text
Run skills/enterprise/mobile-security/checklist.md against the change. Mark each relevant item
pass, fail, or not applicable with a reason. Separate what was read statically from what was
observed on a device. Do not mark pinning, backup exclusion, or logging pass without the matching
dynamic test.
```

## Finding format

```text
For every mobile finding return:
- title and severity
- platform and file:line
- MASVS 2.1.0 control, Mobile Top 10 2024 rank, Top 10 2025 category, ASVS 5.0 chapter, CWE
- attacker precondition
- exploitation path and impact beyond the device owner's normal access
- fixed code/configuration
- limitation or runtime test still needed
Omit any standard identifier you have not verified from the skill references.
```

## Anti-patterns

| Prompt | Problem |
|---|---|
| "Is this app secure?" | No platform, surface, attacker, or evidence boundary. Produces a checklist recital |
| "Make this MASVS compliant" | MASVS controls still need a verification profile and dynamic tests. Markdown review cannot certify an app |
| "Add root detection" | Starts at resilience before storage, auth, and server authorization |
| "Hide this API key" | Assumes a secret can remain secret in an attacker-owned binary. Ask for the backend architecture instead |
| "Add certificate pinning" | Ignores endpoint ownership, backup pin, expiry, and rotation. Can create a global outage |
| "Encrypt SharedPreferences" | Does not say who manages the key or whether backup, migration, and biometric binding matter |
| "Use biometrics for login" | Conflates local user presence with remote authentication |
| "Block bad deep-link parameters" | Invites a denylist. Ask for an allowlisted grammar and server authorization of the operation |
| "Fix all exported components" | May close intentional integrations. Inventory callers and permissions first |
| "Remove all logs" | Destroys useful security telemetry. Remove sensitive values and keep auth outcomes and denials |
