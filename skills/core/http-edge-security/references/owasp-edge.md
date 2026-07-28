# OWASP Top 10 2025 at the HTTP Edge

Source: <https://owasp.org/Top10/2025/>. Checked: 2026-07-28.

- **A02 Security Misconfiguration** covers unsafe proxy trust, virtual-host defaults, exposed methods, and incorrect cache policy.
- **A04 Cryptographic Failures** applies when TLS termination or forwarded scheme handling causes a security decision to treat HTTP as HTTPS.
- **A05 Injection** applies where attacker-controlled Host or header values enter redirects, log sinks, routing, or backend requests.
- **A06 Insecure Design** applies to cache keys that cannot distinguish public and private representations.

The Top 10 is triage, not a reverse-proxy configuration guide. Use ASVS and vendor documentation for the control details.
