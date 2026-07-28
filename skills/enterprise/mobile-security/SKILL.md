---
name: mobile-security
description: 'Apply mobile security controls when writing or reviewing iOS, Android, React Native, or Flutter code. Maps findings to OWASP MASVS 2.1.0, MASTG, Mobile Top 10 2024, OWASP Top 10 2025, and ASVS 5.0. Triggers: "mobile app security", "Keychain", "Keystore", "certificate pinning", "deep link", "exported activity", "jailbreak", "React Native", "Flutter", "bảo mật ứng dụng di động", "lỗ hổng".'
allowed-tools: Read, Write, Edit, Glob, Grep, Bash(ls:*), Bash(cat:*), WebSearch, WebFetch
---

# Mobile Security

The client is attacker-controlled. Start there, because almost every real mobile finding is a
server-side control that someone moved onto the device.

An installed app is a file the user owns. It can be pulled off the device, unzipped, decompiled,
re-signed, and run under a debugger on an emulator with a patched OS. Anything shipped in the
binary is readable. Anything checked on-device is bypassable. That is not a bug in the platform;
it is the threat model.

So the first question in any mobile review is not "is this check correct" but "who is this check
protecting". A check that protects the user from their own mistake is fine on the client. A check
that protects the server from the user must be on the server.

## When to Use

- Writing or reviewing Swift, Kotlin, Java, Dart, or React Native app code
- Reviewing `AndroidManifest.xml`, `Info.plist`, `PrivacyInfo.xcprivacy`, or build config
- Deciding where a credential, token, or key lives
- Designing an auth flow that starts on a phone
- Triaging a pen test report that cites MASVS or Mobile Top 10
- Choosing whether root/jailbreak detection is worth the support cost

## The Standards, and What Each Is For

| Standard | Use it for | Version here |
|---|---|---|
| OWASP MASVS | Mobile-specific requirements, organised by control group | 2.1.0 |
| OWASP MASTG | How to actually test each MASVS control | v2.0.0 |
| OWASP Mobile Top 10 | Risk ranking, talking to non-specialists | 2024 |
| OWASP Top 10 2025 | Cross-reporting alongside the backend findings | 2025 |
| OWASP ASVS 5.0 | The server side of every mobile auth and data finding | 5.0.0 |

MASVS says what the app must do. MASTG says how to prove it. Mobile Top 10 is for the summary
slide. Use ASVS for the backend half, because most mobile fixes end at a server change.

See [references/](references/) for the control lists with the date each was verified.

## Workflow

### 1. Draw the trust boundary

List everything the app holds and mark each item "user may see this" or "user must not see this".
Anything in the second column that lives on the device is a finding, not a design.

Three questions that settle most reviews:

- What secret is in the binary, and who is it a secret from?
- What decision happens on-device that the server then trusts?
- What lands on disk, and does it survive a backup?

### 2. Map to a control group

Pick the MASVS group that matches, not all eight. A token in `SharedPreferences` is
MASVS-STORAGE. An embedded WebView login is MASVS-AUTH plus MASVS-PLATFORM. Root detection is
MASVS-RESILIENCE and is almost never the top finding.

### 3. Apply controls, in this order

1. Move the decision server-side. If the server can enforce it, the client should not.
2. Remove the secret from the binary. A backend proxy holds the credential; the app holds a
   user-scoped token.
3. Store what is left in the platform keystore, with the tightest accessibility class the
   feature tolerates.
4. Authenticate the endpoint. TLS by default, pinning where you control both ends.
5. Close the IPC surface. Default `exported` to false, verify every deep link.
6. Stop the leaks. Logs, caches, screenshots, clipboard, notifications.
7. Add resilience last, and only as a signal.

That order is deliberate. Obfuscation and root detection are step seven because they raise cost
without removing capability. If step one is skipped, step seven is decoration.

### 4. Verify

Run [checklist.md](checklist.md). Mark each item pass, fail, or not applicable with a reason.
Static reading cannot confirm runtime behaviour on a real device — say which items you could
only read, not test.

### 5. Report

Per finding: MASVS group, location, what an attacker with an unlocked rooted device and a proxy
actually gets, and the fix. If the answer is "they read their own token", that is low severity.
Say so instead of inflating it.

## Severity

Rank by what the attacker gains beyond what they already have. The device owner already has
their own data.

- Critical — other users' data, or server-side privilege, reachable from one device
- High — credential theft from a device the attacker briefly controls; MITM on a network they
  control; state change triggered by any installed app
- Medium — leaks the device owner's own sensitive data to other apps or to backups
- Low — needs a rooted device to reach data the device owner is already entitled to

"Token in `SharedPreferences`, therefore critical" is wrong on a non-rooted device with no
backup enabled. It is high when `android:allowBackup` is true, because then it leaves the device.
State the precondition.

## Related Skills

- `owasp-security` — the backend half of every mobile finding
- `authentication` — OAuth, session lifecycle, refresh rotation
- `api-security` — the endpoints the app talks to

## Supporting Files

- [README.md](README.md) — purpose, layout, standards table, limitations
- [checklist.md](checklist.md) — pre-return verification, grouped by MASVS
- [best-practices.md](best-practices.md) — patterns, each with a vulnerable/fixed pair
- [common-mistakes.md](common-mistakes.md) — what goes wrong and why the fix works
- [troubleshooting.md](troubleshooting.md) — when the control cannot be applied
- [prompts.md](prompts.md) — prompts that produce findings
- [references/](references/) — MASVS, Mobile Top 10, platform APIs, RFCs
- [examples/](examples/) — eight vulnerable/fixed pairs
