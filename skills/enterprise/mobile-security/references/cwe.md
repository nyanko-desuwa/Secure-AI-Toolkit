> Verified 2026-07-28 against the MITRE CWE pages. Source: <https://cwe.mitre.org/>

# CWE mappings used here

CWE describes weakness mechanisms. It is not a severity score and does not replace an
exploitation path.

| CWE | Title | Use in this skill |
|---|---|---|
| CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor | Caches, source maps, broad local leaks |
| CWE-295 | Improper Certificate Validation | Trust-all callbacks and unsafe transport exceptions |
| CWE-311 | Missing Encryption of Sensitive Data | Plain databases and local files |
| CWE-312 | Cleartext Storage of Sensitive Information | Preferences and defaults stores |
| CWE-359 | Exposure of Private Personal Information to an Unauthorized Actor | Notifications, analytics, screenshots |
| CWE-522 | Insufficiently Protected Credentials | OAuth WebView and token handling |
| CWE-602 | Client-Side Enforcement of Server-Side Security | Client-only entitlement decisions |
| CWE-613 | Insufficient Session Expiration | Non-revoked refresh tokens and logout |
| CWE-693 | Protection Mechanism Failure | Root/jailbreak checks used as sole controls |
| CWE-749 | Exposed Dangerous Method or Function | WebView JavaScript bridges |
| CWE-798 | Use of Hard-coded Credentials | API keys and private credentials in binaries |
| CWE-921 | Storage of Sensitive Data in a Mechanism without Access Control | Weak local stores |
| CWE-926 | Improper Export of Android Application Components | Exported activities, services, receivers |
| CWE-927 | Use of Implicit Intent for Sensitive Communication | Sensitive implicit Android intents |
| CWE-939 | Improper Authorization in Handler for Custom URL Scheme | Deep-link state changes |

The skill also discusses weaknesses that may map to adjacent CWEs depending on implementation.
Choose the CWE describing the actual mechanism you verified, and state uncertainty when the
source does not show the full data flow.
