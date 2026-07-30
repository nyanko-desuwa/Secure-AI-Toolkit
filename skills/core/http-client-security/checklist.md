# HTTP Client Security Checklist

Mark pass, fail, or N/A with evidence.

- [ ] [recommended] Every outbound client/destination/credential/proxy is inventoried.
- [ ] [recommended] Full attacker-controlled URLs are avoided where a logical dependency ID can be used.
- [ ] [critical] Parsed scheme, host, port, userinfo, A/AAAA addresses, and redirect hops meet policy.
- [ ] [critical] Loopback, private, link-local, multicast, reserved, and metadata destinations are denied.
- [ ] [critical] Redirects are disabled or each hop is revalidated; credentials do not cross origins.
- [ ] [critical] TLS certificate and hostname verification remain enabled; custom CAs/mTLS are explicit.
- [ ] [recommended] Connect/read/overall deadlines, response bytes, decompression, pool, and retry budgets are bounded.
- [ ] [recommended] Retries are idempotency-aware and do not create storms or duplicate mutations.
- [ ] [recommended] Response status, content type, size, and schema are checked before use.
- [ ] [recommended] URLs with secrets, Authorization headers, cookies, and response bodies are redacted in telemetry.
- [ ] [recommended] Live egress/proxy/DNS behavior is verified separately with `network-security` or `cloud-security`.

Stop release for TLS verification disabled, a proven private/metadata SSRF path, credentials forwarded
to arbitrary redirects, or an unbounded client reachable from untrusted destination input.
