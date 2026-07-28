# CWE Privacy and Security Weaknesses

Checked: 2026-07-28

Sources fetched from MITRE CWE 4.20 pages:

- <https://cwe.mitre.org/data/definitions/200.html>
- <https://cwe.mitre.org/data/definitions/311.html>
- <https://cwe.mitre.org/data/definitions/312.html>
- <https://cwe.mitre.org/data/definitions/359.html>
- <https://cwe.mitre.org/data/definitions/532.html>
- <https://cwe.mitre.org/data/definitions/778.html>
- <https://cwe.mitre.org/data/definitions/922.html>

## Verified titles

| ID | Official title | Use in this skill |
|---|---|---|
| CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor | Unscoped access or disclosure |
| CWE-311 | Missing Encryption of Sensitive Data | Unencrypted sensitive data |
| CWE-312 | Cleartext Storage of Sensitive Information | Cleartext persisted data |
| CWE-359 | Exposure of Private Personal Information to an Unauthorized Actor | Personal-data disclosure |
| CWE-532 | Insertion of Sensitive Information into Log File | PII, tokens, or secrets in logs |
| CWE-778 | Insufficient Logging | Missing or incomplete security events |
| CWE-922 | Insecure Storage of Sensitive Information | Weak or unsafe sensitive-data storage |

CWE is a weakness taxonomy, not a compliance standard. Use it to describe the technical failure,
then map the implemented control and evidence to the applicable framework requirement.

## Deliberate omissions

No additional CWE IDs are implied by a framework mapping. If a weakness is not one of the verified
rows above, fetch its MITRE page before citing its ID or title.
