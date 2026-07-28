> Verified 2026-07-28 against the MASTG tests index and the MASTG repository release metadata.
> Latest release v2.0.0, published 2026-06-30.
> Sources: <https://mas.owasp.org/MASTG/tests/> · <https://github.com/OWASP/owasp-mastg/releases>

# OWASP MASTG v2.0.0

The Mobile Application Security Testing Guide is the how-to next to MASVS. MASVS says the app
must securely store sensitive data; MASTG gives you a numbered test that either passes or fails
on a device.

Two things about the numbering, both of which trip up report readers:

- Test IDs are not sequential by topic and are not stable across editions. The guide is being
  migrated from prose tests to atomic tests, so older four-digit IDs coexist with newer ones and
  some topics have two IDs — one for the Android test, one for iOS.
- The same title appears under different IDs per platform. "Testing Backups for Sensitive Data"
  is MASTG-TEST-0009 and MASTG-TEST-0058. Quote the ID and the platform, not just the title.

If you need a test ID this file does not list, fetch the index rather than guessing. IDs are
easy to invent and impossible to defend.

## Tests relevant to this skill

Verified present in the v2.0.0 tests index on the date above.

| Test | Title | MASVS group |
|---|---|---|
| MASTG-TEST-0003 | Testing Logs for Sensitive Data | STORAGE |
| MASTG-TEST-0009 | Testing Backups for Sensitive Data | STORAGE |
| MASTG-TEST-0010 | Finding Sensitive Information in Auto-Generated Screenshots | STORAGE, PLATFORM |
| MASTG-TEST-0018 | Testing Biometric Authentication | AUTH |
| MASTG-TEST-0022 | Testing Custom Certificate Stores and Certificate Pinning | NETWORK |
| MASTG-TEST-0027 | Testing for URL Loading in WebViews | PLATFORM |
| MASTG-TEST-0028 | Testing Deep Links | PLATFORM |
| MASTG-TEST-0031 | Testing JavaScript Execution in WebViews | PLATFORM |
| MASTG-TEST-0032 | Testing WebView Protocol Handlers | PLATFORM |
| MASTG-TEST-0033 | Testing for Java Objects Exposed Through WebViews | PLATFORM |
| MASTG-TEST-0037 | Testing WebViews Cleanup | STORAGE |
| MASTG-TEST-0039 | Testing whether the App is Debuggable | CODE, RESILIENCE |
| MASTG-TEST-0041 | Testing for Debugging Code and Verbose Error Logging | CODE |
| MASTG-TEST-0045 | Testing Root Detection | RESILIENCE |
| MASTG-TEST-0053 | Checking Logs for Sensitive Data | STORAGE |
| MASTG-TEST-0058 | Testing Backups for Sensitive Data | STORAGE |
| MASTG-TEST-0059 | Testing Auto-Generated Screenshots for Sensitive Information | STORAGE, PLATFORM |
| MASTG-TEST-0064 | Testing Biometric Authentication | AUTH |
| MASTG-TEST-0068 | Testing Custom Certificate Stores and Certificate Pinning | NETWORK |
| MASTG-TEST-0076 | Testing iOS WebViews | PLATFORM |
| MASTG-TEST-0077 | Testing WebView Protocol Handlers | PLATFORM |
| MASTG-TEST-0078 | Determining Whether Native Methods Are Exposed Through WebViews | PLATFORM |
| MASTG-TEST-0082 | Testing whether the App is Debuggable | CODE, RESILIENCE |
| MASTG-TEST-0088 | Testing Jailbreak Detection | RESILIENCE |
| MASTG-TEST-0212 | Use of Hardcoded Cryptographic Keys in Code | CRYPTO |
| MASTG-TEST-0214 | Hardcoded Cryptographic Keys in Files | CRYPTO |
| MASTG-TEST-0215 | Sensitive Data Not Marked For Backup Exclusion | STORAGE |
| MASTG-TEST-0216 | Sensitive Data Not Excluded From Backup | STORAGE |
| MASTG-TEST-0226 | Debuggable Flag Enabled in the AndroidManifest | CODE |
| MASTG-TEST-0227 | Debugging Enabled for WebViews | PLATFORM |
| MASTG-TEST-0231 | References to Logging APIs | STORAGE |
| MASTG-TEST-0233 | Hardcoded HTTP URLs | NETWORK |
| MASTG-TEST-0235 | Android App Configurations Allowing Cleartext Traffic | NETWORK |
| MASTG-TEST-0236 | Cleartext Traffic Observed on the Network | NETWORK |
| MASTG-TEST-0237 | Cross-Platform Framework Configurations Allowing Cleartext Traffic | NETWORK |
| MASTG-TEST-0242 | Missing Certificate Pinning in Network Security Configuration | NETWORK |
| MASTG-TEST-0243 | Expired Certificate Pins in the Network Security Configuration | NETWORK |
| MASTG-TEST-0244 | Missing Certificate Pinning in Network Traffic | NETWORK |
| MASTG-TEST-0250 | References to Content Provider Access in WebViews | PLATFORM |
| MASTG-TEST-0252 | References to Local File Access in WebViews | PLATFORM |
| MASTG-TEST-0261 | Debuggable Entitlement Enabled in the entitlements.plist | CODE |
| MASTG-TEST-0266 | References to APIs for Event-Bound Biometric Authentication | AUTH |
| MASTG-TEST-0268 | References to APIs Allowing Fallback to Non-Biometric Authentication | AUTH |

Some of these come in static/dynamic pairs — 0242 and 0243 read the config, 0244 watches the
handshake. A static pass with no dynamic test is not a pass, because a pinning class can be
present and never installed on the client that makes the request.

## Using MASTG with this skill

Reading code covers the static half only. When you cite a test from a code review, say so:
"MASTG-TEST-0242, static review of `network_security_config.xml`; 0244 not run" is honest.
"Passes MASTG-TEST-0244" from a code read is not, because that test needs traffic.

MASTG also ships reference apps (MASTG-APP-xxxx) and demos. Those are useful for verifying your
own tooling, not for auditing someone's code.
