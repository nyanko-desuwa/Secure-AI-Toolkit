# Mobile Security Skill

Controls for iOS, Android, and cross-platform apps, traced to OWASP MASVS and the MASTG.

## Purpose

Most mobile findings are not exotic. They are a server-side control that someone moved onto the
device, or a secret that someone assumed the app bundle would keep. This skill gives an
assistant a way to spot both, name the standard, and propose the fix that survives a rooted
device with a proxy attached.

The premise every control rests on: the client is attacker-controlled. The user can pull the
app off the device, unzip it, decompile it, patch it, re-sign it, and run it under a debugger.
Anything shipped in the binary is readable. Anything checked on-device is bypassable.

## How It Works

Plain Markdown. Nothing executes. An assistant reads `SKILL.md`, follows the five-step workflow
(trust boundary, map, apply, verify, report), and pulls in the file it needs at each step.

```text
SKILL.md                       workflow, severity, entry point
README.md                      this file
checklist.md                   pre-return verification, grouped by MASVS
best-practices.md              patterns, with vulnerable/fixed pairs
common-mistakes.md             what goes wrong and why the fix works
troubleshooting.md             when the control cannot be applied cleanly
prompts.md                     prompts that produce findings
references/
  masvs-2.1.0.md               eight control groups, 24 controls, quoted text
  mastg-v2.0.0.md              test IDs for the controls this skill covers
  mobile-top10-2024.md         M1 to M10, and how they map to Top 10 2025
  android-platform.md          manifest flags, NSC, WebView, Keystore, IPC
  ios-platform.md              Keychain classes, ATS, Universal Links, privacy manifest
  oauth-native-apps.md         RFC 8252 and RFC 7636, the parts that decide the design
  cross-platform.md            React Native and Flutter storage and bundle exposure
examples/
  README.md                    eight vulnerable/fixed pairs with CWE
```

## Standards Covered

| Standard | Version | Verified |
|---|---|---|
| OWASP MASVS | 2.1.0 (published 2024-01-18) | 2026-07-28, `mas.owasp.org/MASVS/` + repo releases |
| OWASP MASTG | v2.0.0 (released 2026-06-30) | 2026-07-28, `mas.owasp.org/MASTG/tests/` + repo releases |
| OWASP Mobile Top 10 | 2024 (final release) | 2026-07-28, `owasp.org/www-project-mobile-top-10/` |
| OWASP Top 10 | 2025 | pinned by this repository |
| OWASP ASVS | 5.0.0 (released 2025-05-30) | pinned by this repository |
| RFC 8252 | BCP 212, October 2017 | 2026-07-28, `rfc-editor.org` |
| RFC 7636 | September 2015 | 2026-07-28, `rfc-editor.org` |

Platform API behaviour (Android manifest defaults, Keychain accessibility classes, ATS keys) is
version-pinned inside `references/android-platform.md` and `references/ios-platform.md` with the
same check date. Defaults change by target API level and SDK, so those files state the level.

## Configuration

None. No build step, no dependency, no environment variable.

To use it in Claude Code, keep this repository in the working directory so
`skills/enterprise/mobile-security/SKILL.md` is readable, or copy the `mobile-security`
directory into `~/.claude/skills/`. The frontmatter `allowed-tools` limits it to read, search,
and web lookup plus `ls`/`cat`.

## Example Usage

Scope a review to storage and auth, which is where the real findings are:

```text
Review the Android app in app/src/main against MASVS-STORAGE and MASVS-AUTH. For each finding
give the control, file:line, what an attacker with a rooted device and a proxy actually gets,
and the fix. Ignore MASVS-RESILIENCE for now.
```

Audit the manifest and the plist before shipping:

```text
Read AndroidManifest.xml and Info.plist. List every exported component, every deep link, every
ATS exception, and every backup or debug flag. Flag anything an unprivileged installed app can
reach.
```

More in [prompts.md](prompts.md).

## Limitations

- Static reading only. It cannot confirm what a running app writes to disk, what a TLS handshake
  actually negotiates, or whether a pin is live. Pair it with a proxy, MASTG dynamic tests, and
  a rooted or jailbroken test device.
- No binary analysis. It will not decompile an APK or IPA, diff a Frida trace, or read a
  compiled `.so`. Secrets hidden in native code are outside its reach even though they are not
  outside an attacker's.
- ASVS mapping is at chapter level (V6, V9, V10, V14), not requirement IDs. MASVS mapping is at
  control level; 2.x controls have no sub-numbers, so any `MASVS-STORAGE-1.2` style citation is
  invented.
- Examples are Kotlin, Swift, and TypeScript, plus manifest and plist fragments. Flutter and
  Dart are covered in prose and in `references/cross-platform.md`, not with full examples.
- Says nothing about App Store or Play policy review outcomes, MDM, or app-shielding products.
- Third-party SDK behaviour cannot be verified by reading your own code. The skill tells you
  what to ask for; it cannot confirm what an SDK does at runtime.

## Security Notes

This skill contains deliberately vulnerable code in `best-practices.md`,
`common-mistakes.md`, and `examples/`. Every such block is labelled `Vulnerable:` and paired
with a fixed version. Do not copy a labelled-vulnerable block into a project.

All keys, hostnames, base64 pins, and bundle identifiers are placeholders. The pin values in
particular are not real hashes - a copied pin set will fail every connection, which is the
intended outcome.

## References

- OWASP MASVS - <https://mas.owasp.org/MASVS/>
- OWASP MASTG - <https://mas.owasp.org/MASTG/>
- OWASP Mobile Top 10 - <https://owasp.org/www-project-mobile-top-10/>
- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>
- OWASP ASVS - <https://owasp.org/www-project-application-security-verification-standard/>
- RFC 8252, OAuth 2.0 for Native Apps - <https://www.rfc-editor.org/rfc/rfc8252>
- RFC 7636, PKCE - <https://www.rfc-editor.org/rfc/rfc7636>
- Android security guidance - <https://developer.android.com/privacy-and-security/security-tips>
- Apple, preventing insecure network connections - <https://developer.apple.com/documentation/security/preventing-insecure-network-connections>
