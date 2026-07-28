# Service Identity and Transport Controls

Verified 2026-07-28. This reference records design distinctions, not a claim about any live mesh or broker.

## Three separate decisions

| Decision | Question | Failure if omitted |
|---|---|---|
| Workload authentication | Which running workload is connected? | Spoofed service identity or shared credential |
| Endpoint authorization | May that workload call this operation? | Broad east-west access |
| Object authorization | May this subject perform this action on this object? | Tenant escape, confused deputy, BOLA |

mTLS provides authenticated, encrypted transport when certificate validation and identity binding are correctly configured. It does not answer the second or third question. A mesh policy can help with endpoint authorization; the owning service still needs object policy.

## Recommended controls

- Distinct workload identities, audience-bound credentials, short expiry, and rotation.
- Certificate chain, SAN/identity, hostname, audience, and algorithm validation.
- No trust in source IP, DNS name alone, `x-user`, `x-tenant`, or `x-role` headers from unverified callers.
- Strip or overwrite legacy identity headers at the trusted boundary.
- Do not forward broad bearer tokens to unrelated services.
- Fail closed for unknown identity or policy; use explicit, bounded availability exceptions only where the operation is non-sensitive.
- Keep secrets out of images, logs, traces, and error payloads.
- Bind authorization to the owner service and object store.

## Discovery and SSRF

Use a finite logical map such as `billing -> billing.service.invalid`, not a user-provided URL. Require HTTPS, reject embedded credentials and fragments, validate redirects, limit response bytes and time, and apply egress policy. DNS resolution can change after validation, so runtime network policy remains necessary. Source code cannot prove deployed egress rules.

## Cost and limits

TLS handshakes consume CPU and sockets; certificate rotation creates synchronized work if every replica reconnects at once. Discovery caches retain names and endpoints; bound entries and TTLs. Connection pools multiply by replicas and dependencies. Measure handshake failures, certificate age, pool wait, DNS latency, and outbound denial counts.

## Sources

- OWASP Top 10 2025 — <https://owasp.org/Top10/2025/> (A01, A02, A07; pinned 2026-07-28).
- OWASP ASVS 5.0.0 — <https://owasp.org/www-project-application-security-verification-standard/> (V6, V8, V12, V13, V15; chapter-level citation, pinned 2026-07-28).
- CWE-441 — <https://cwe.mitre.org/data/definitions/441.html>.
- CWE-918 — <https://cwe.mitre.org/data/definitions/918.html>.
