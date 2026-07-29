# Troubleshooting Mobile Security

What to do when the secure option does not fit cleanly.

## Product wants a secret in the app

Ask who the secret is from. If it is from the user, it cannot live on the user's device.

Some publishable API identifiers are designed to ship in apps: a maps project ID restricted by
bundle identifier and signing certificate, for example. Call it a public identifier, apply every
vendor-side restriction, monitor it, and do not grant it server capabilities. Anything that can
spend money, read private data, or act outside the current user's scope goes behind a backend
proxy.

`MASVS-STORAGE-1` · `A04:2025` · ASVS V14 · `CWE-798`

## Background refresh needs the Keychain while locked

`WhenUnlockedThisDeviceOnly` is intentionally unavailable while the device is locked.

If the feature is worth the extra exposure, use `AfterFirstUnlockThisDeviceOnly`; it becomes
available after the first unlock following restart and does not migrate to another device. State
the tradeoff: it remains readable while locked until the next restart. Do not jump to
`AccessibleAlways` - Apple documents it as not recommended and deprecated.

`MASVS-STORAGE-1` · `A04:2025` · ASVS V14 · `CWE-921`

## Migration from SharedPreferences could log everyone out

Do not weaken the destination to preserve a silent migration. Make migration transactional:
read the old token once, encrypt and write the new record, read it back and decrypt to verify,
then delete the old value. Keep the old path for one release behind a one-way migration marker,
and do not log either value.

A forced login is a product cost but may be safer than retaining a recoverable plaintext copy.
Ask before choosing. If the old token has already been in backups, shortening its lifetime and
rotating it server-side is part of the migration.

`MASVS-STORAGE-1` · `A04:2025` · ASVS V7, V14 · `CWE-312`

## EncryptedSharedPreferences is deprecated, but already deployed

Do not churn working encrypted storage to satisfy a lint warning. The deprecation is verified in
`androidx.security:security-crypto` 1.1.0, whose guidance is direct Keystore and platform APIs.
Existing `EncryptedSharedPreferences` remains materially safer than plain preferences.

For new code, use direct Keystore encryption. For existing code, document the deprecation, patch
the library, and plan a crash-safe migration when another reason justifies it. A half-migrated
refresh token that cannot be decrypted is an account lockout.

`MASVS-STORAGE-1`, `MASVS-CRYPTO-2` · `A04:2025` · ASVS V14 · `CWE-312`

## Certificate pinning breaks enterprise interception

That is pinning doing what it was designed to do: reject a valid-looking chain anchored in a CA
you did not pin.

Choose deliberately:

1. Consumer app protecting high-value traffic: keep pinning; provide a documented enterprise
   exception only if the threat model allows it.
2. Managed enterprise app where interception is a requirement: ship a separate managed build or
   managed app configuration that trusts the enterprise CA, and label the reduction in security.
3. Third-party endpoint whose rotation you cannot coordinate: do not pin it. Keep normal platform
   validation.

Never add the enterprise CA to the global production trust store just to fix one deployment.

`MASVS-NETWORK-2` · `A02:2025` · ASVS V12 · `CWE-295`

## A pin expires before the next app release reaches everyone

Expiry is an operational control, not a fallback switch. Ship the replacement backup pin before
the active certificate rotates, monitor version adoption, and keep overlap long enough for the
oldest supported app. If you are already inside the failure window, the only recovery path is a
new release signed with the existing store key; a remotely fetched bypass cannot be fetched over
the connection that now fails.

When availability outweighs CA-compromise resistance, remove pinning in a release rather than
shipping a hidden trust-all path.

`MASVS-NETWORK-2` · `A02:2025` · ASVS V12 · `CWE-295`

## OAuth provider only supports an embedded WebView

RFC 8252 says native apps MUST NOT use embedded user-agents. The host app can capture every
keystroke and cookie. This is not a preference to waive because an SDK sample uses a WebView.

Ask the provider for authorization code + PKCE in an external browser. If they cannot support it,
treat the provider as incompatible. A temporary exception needs a named owner, a removal date,
no password auto-fill, no native bridge, strict origin allowlist, and a warning that the app can
see credentials. It is still not compliant with RFC 8252.

`MASVS-AUTH-1`, `MASVS-PLATFORM-2` · `A07:2025` · ASVS V10 · `CWE-522`

## Existing customers use a custom URL scheme

Do not remove it in one release. Add Universal Links / App Links and register the claimed HTTPS
redirect with the authorization server. Accept the old scheme only for responses carrying PKCE
and a valid state tied to an in-progress flow. Measure use, then remove the old redirect in a
server change after adoption crosses the threshold.

A reverse-domain scheme reduces accidental collision but does not prevent a malicious app from
registering the same scheme. PKCE is the protection during migration.

`MASVS-AUTH-1`, `MASVS-PLATFORM-1` · `A07:2025` · ASVS V10 · `CWE-939`

## Deep link genuinely needs to perform an action

Separate navigation from authorization. The link may select the action and display a confirmation
screen. The API must validate a short-lived, single-use token bound to the actor, operation, and
target, then require a live authenticated session and optionally step-up auth.

Do not authenticate the caller using `getReferrer`, source application, or scheme ownership.
Android documents referrer as spoofable; custom URL schemes collide on both platforms.

`MASVS-PLATFORM-1`, `MASVS-AUTH-3` · `A01:2025` · ASVS V8 · `CWE-939`

## Root detection blocks legitimate users

Stop failing closed on the signal. Root and jailbreak detectors run in the environment they are
trying to assess, so they produce both false positives and bypasses. Keep the app usable, report
several signals to the server, and require step-up authentication or reduce transaction limits
only for high-risk actions.

If regulation requires a hard block, document it as a business rule, not a security boundary,
provide an appeal path, and keep server authorization correct because the check will be bypassed.

`MASVS-RESILIENCE-1` · `A06:2025` · ASVS V15 · `CWE-693`

## FLAG_SECURE breaks support screenshots or accessibility

Apply it to the smallest screen containing sensitive content, not the whole app. Offer an explicit
redacted export or a support bundle that the user confirms, rather than silently allowing the OS
task snapshot to contain secrets.

On iOS, replace sensitive content when the scene resigns active and restore it on activation.
Test VoiceOver and TalkBack. Security controls that make the app inaccessible are defects, not
proof that accessibility is dangerous.

`MASVS-PLATFORM-3` · `A01:2025` · ASVS V14 · `CWE-200`

## Push must show useful content on a locked screen

Use generic copy - "New secure message" - plus an opaque event ID. After the user opens the app,
authenticate and fetch the detail. If product insists on previews, make them opt-in, off by
default, and warn that the content reaches push infrastructure and the lock screen.

`VISIBILITY_PRIVATE` and iOS preview settings reduce shoulder-surfing. They do not remove the
sensitive text from the push payload, so they cannot be the only control.

`MASVS-PLATFORM-3`, `MASVS-PRIVACY-1` · `A01:2025` · ASVS V14 · `CWE-359`

## Third-party SDK has no privacy manifest

Ask for an updated SDK. Apple requires `PrivacyInfo.xcprivacy` for the app and third-party SDKs to
record collected data and required-reason API use. If the vendor cannot provide one, replace the
SDK or wrap the static library in a framework with an accurate manifest only after you have
audited what it does. Do not invent the vendor's collection practices.

The app's own manifest still needs to reconcile the aggregated result, and Android's merged
manifest still needs a permission review.

`MASVS-PRIVACY-3` · `A03:2025` · ASVS V14, V15 · `CWE-359`

## Static review cannot tell whether a control works

State the gap and name the test:

- Pinning config present; MASTG-TEST-0244 not run against traffic
- Backup exclusion present; restore not tested (MASTG-TEST-0009 / 0058)
- Log calls absent in source; third-party SDK logs not observed at runtime
- Root detector present; bypass resistance not tested (MASTG-TEST-0045 / 0088)

Reading a config proves intent. A dynamic test proves effect. Do not turn one into the other.

## Two standards seem to disagree

They usually answer different questions. MASVS is the mobile requirement; ASVS covers the API;
Mobile Top 10 is the risk label. Implement the MASVS control and the ASVS server control, then use
Mobile Top 10 in the summary.

If an exact MASVS ID or Mobile Top 10 rank is not in `references/`, fetch the source. Do not quote
it from memory. MASVS 1.x, MASVS 2.x, Mobile Top 10 2016, and Mobile Top 10 2024 all use different
numbering.
