# HTTP Client Security Checklist

Mark pass, fail, or N/A with evidence.

- [ ] Every outbound client/destination/credential/proxy is inventoried.
- [ ] Full attacker-controlled URLs are avoided where a logical dependency ID can be used.
- [ ] Parsed scheme, host, port, userinfo, A/AAAA addresses, and redirect hops meet policy.
- [ ] Loopback, private, link-local, multicast, reserved, and metadata destinations are denied.
- [ ] Redirects are disabled or each hop is revalidated; credentials do not cross origins.
- [ ] TLS certificate and hostname verification remain enabled; custom CAs/mTLS are explicit.
- [ ] Connect/read/overall deadlines, response bytes, decompression, pool, and retry budgets are bounded.
- [ ] Retries are idempotency-aware and do not create storms or duplicate mutations.
- [ ] Response status, content type, size, and schema are checked before use.
- [ ] URLs with secrets, Authorization headers, cookies, and response bodies are redacted in telemetry.
- [ ] Live egress/proxy/DNS behavior is verified separately with `network-security` or `cloud-security`.

Stop release for TLS verification disabled, a proven private/metadata SSRF path, credentials forwarded
to arbitrary redirects, or an unbounded client reachable from untrusted destination input.
