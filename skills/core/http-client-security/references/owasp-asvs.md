# OWASP and ASVS Mapping

> Sources checked 2026-07-29.

| Concern | OWASP | ASVS | CWE examples |
|---|---|---|---|
| SSRF/destination authority | A01, A06; API7 | V4, V13 | CWE-918 |
| TLS/certificate verification | A02, A04 | V12, V14 | CWE-295, CWE-319 |
| Redirect/proxy/credential handling | A01, A02 | V4, V12 | CWE-441, CWE-522 |
| Timeouts, retries, response bounds | A06, A10; API4 | V11, V13 | CWE-400, CWE-770 |
| Safe telemetry | A09 | V16 | CWE-532 |

OWASP SSRF guidance recommends avoiding complete user-controlled URLs where possible, validating
allowed destinations, and using network controls as defence in depth. DNS rebinding remains a
stated limitation unless connection/egress policy closes it.

Sources:

- <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>
- <https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html>
- <https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/>
- <https://owasp.org/Top10/2025/>
- <https://owasp.org/www-project-application-security-verification-standard/>
