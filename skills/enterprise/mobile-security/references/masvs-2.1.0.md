> Verified 2026-07-28 against the OWASP MAS project site and the MASVS repository release
> metadata. Version 2.1.0, published 2024-01-18.
> Sources: <https://mas.owasp.org/MASVS/> · <https://github.com/OWASP/masvs/releases>

# OWASP MASVS 2.1.0

Mobile Application Security Verification Standard. Eight control groups, 24 controls. The
control text below is quoted from the individual control pages on `mas.owasp.org`.

MASVS 2.x is not a renumbering of 1.x. The 1.x scheme was `MASVS-Vn.n` with numbered
requirements and L1/L2/R levels; 2.x replaced it with named groups and dropped the level
system in favour of profiles. A `MASVS-4.7` citation from an older report has no 2.x
equivalent - re-map it, do not translate it.

## Control groups

| Group | Title |
|---|---|
| MASVS-STORAGE | Storage |
| MASVS-CRYPTO | Cryptography |
| MASVS-AUTH | Authentication and Authorization |
| MASVS-NETWORK | Network Communication |
| MASVS-PLATFORM | Platform Interaction |
| MASVS-CODE | Code Quality |
| MASVS-RESILIENCE | Resilience Against Reverse Engineering and Tampering |
| MASVS-PRIVACY | Privacy |

## Controls

| ID | Control text |
|---|---|
| MASVS-STORAGE-1 | The app securely stores sensitive data. |
| MASVS-STORAGE-2 | The app prevents leakage of sensitive data. |
| MASVS-CRYPTO-1 | The app employs current strong cryptography and uses it according to industry best practices. |
| MASVS-CRYPTO-2 | The app performs key management according to industry best practices. |
| MASVS-AUTH-1 | The app uses secure authentication and authorization protocols and follows the relevant best practices. |
| MASVS-AUTH-2 | The app performs local authentication securely according to the platform best practices. |
| MASVS-AUTH-3 | The app secures sensitive operations with additional authentication. |
| MASVS-NETWORK-1 | The app secures all network traffic according to the current best practices. |
| MASVS-NETWORK-2 | The app performs identity pinning for all remote endpoints under the developer's control. |
| MASVS-PLATFORM-1 | The app uses IPC mechanisms securely. |
| MASVS-PLATFORM-2 | The app uses WebViews securely. |
| MASVS-PLATFORM-3 | The app uses the user interface securely. |
| MASVS-CODE-1 | The app requires an up-to-date platform version. |
| MASVS-CODE-2 | The app has a mechanism for enforcing app updates. |
| MASVS-CODE-3 | The app only uses software components without known vulnerabilities. |
| MASVS-CODE-4 | The app validates and sanitizes all untrusted inputs. |
| MASVS-RESILIENCE-1 | The app validates the integrity of the platform. |
| MASVS-RESILIENCE-2 | The app implements anti-tampering mechanisms. |
| MASVS-RESILIENCE-3 | The app implements anti-static analysis mechanisms. |
| MASVS-RESILIENCE-4 | The app implements anti-dynamic analysis techniques. |
| MASVS-PRIVACY-1 | The app minimizes access to sensitive data and resources. |
| MASVS-PRIVACY-2 | The app prevents identification of the user. |
| MASVS-PRIVACY-3 | The app is transparent about data collection and usage. |
| MASVS-PRIVACY-4 | The app offers user control over their data. |

MASVS-PRIVACY was introduced in 2.1.0. Reports written against 2.0.0 will not mention it.

## Notes worth carrying into a review

MASVS-STORAGE-1 covers data you meant to store. STORAGE-2 covers data you did not: backups,
logs, and side effects of platform APIs. Most findings in this area are STORAGE-2, because
nobody writes a token to a log on purpose.

MASVS-AUTH-1 says the enforcement must be on the remote endpoint and the app's job is to use
the protocol correctly. That is the sentence to quote when someone proposes a client-side
authorization check.

MASVS-AUTH-2 is local authentication - biometrics, app PIN. It is a separate control from
AUTH-1 precisely because unlocking an app is not the same as authenticating to a server.

MASVS-NETWORK-2 scopes pinning to "remote endpoints under the developer's control". Pinning a
third-party API you do not control is how apps break when someone else rotates a certificate.

MASVS-RESILIENCE is one group of four controls out of twenty-four. Treat a report that leads
with RESILIENCE findings and has nothing in STORAGE or AUTH with suspicion - it is usually a
tool run, not a review.

## Using MASVS in a review

Cite the group when the finding is general, the specific control when you have checked its
text. `MASVS-STORAGE-1` is a correct and useful citation. Inventing a sub-numbered requirement
like `MASVS-STORAGE-1.3` is not - 2.x controls have no sub-numbers.

## Testing

MASVS states the requirement; the MASTG supplies the test. See
[mastg-v2.0.0.md](mastg-v2.0.0.md).
