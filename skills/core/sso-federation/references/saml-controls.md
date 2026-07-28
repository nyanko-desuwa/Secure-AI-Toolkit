# SAML Federation Controls

Sources: OASIS SAML 2.0 Technical Overview and core specifications; OWASP Top 10 2025;
<https://cwe.mitre.org/>. Checked: 2026-07-28.

Validate the signed assertion with the configured IdP trust key before application claim access.
Then bind issuer, audience, recipient, destination, issue time, conditions, subject confirmation,
and request correlation where the flow has one. Authenticate metadata/key changes; they alter the
trust root. CWE-347 covers signature verification failure; CWE-345 covers insufficient verification
of authenticity/validity; CWE-290 covers spoofed identity.
