# Network Security Verification Checklist

Run before returning a configuration or approving a network change. Mark each item pass, fail,
or not applicable. "Not applicable" needs a one-line reason.

Only run the sections that match the change. A TLS cipher change does not need the VPN section.

Reading a config file cannot confirm the running state. Where an item needs the live rule set or
the cloud API to verify, say which you checked and which you did not.

## Segmentation (A01 · ASVS V13)

- [ ] [critical] Every segment pair has an explicit policy. No implicit trust from being inside the VPC
- [ ] [critical] Datastores, caches, and queues reachable only from the tier that uses them
- [ ] [critical] Orchestrator and hypervisor APIs unreachable from workload segments
- [ ] [critical] Management and admin interfaces on a separate path, not a port on the public listener
- [ ] [recommended] Non-production cannot reach production, in either direction
- [ ] [recommended] A workload compromise has been traced on paper: what it reaches next, and what stops it

## Firewall Policy (A02 · ASVS V13 · CWE-1327)

- [ ] [critical] Default policy is drop on input and output, not accept
- [ ] [critical] Rules cover IPv4 and IPv6. `inet` table or a matching `ip6` rule set
- [ ] [critical] No `0.0.0.0/0` or `::/0` source on any port other than a deliberate public listener
- [ ] [recommended] Listeners bound to a specific interface, not `0.0.0.0`, unless public by design
- [ ] [recommended] ICMP fragmentation-needed and ICMPv6 packet-too-big permitted (path MTU)
- [ ] [recommended] ICMPv6 neighbour discovery permitted, or IPv6 will fail intermittently
- [ ] [recommended] Dropped traffic is logged with a rate limit
- [ ] [optional] Rules carry a comment naming the flow and the owner

## Egress (A01 · ASVS V2, V12 · CWE-918)

- [ ] [critical] Egress is allowlisted by destination, not open by default
- [ ] [critical] Workloads handling user-supplied URLs have no direct route out
- [ ] [critical] Cloud metadata addresses blocked in both address families
- [ ] [recommended] Token-based metadata mode enforced where the provider offers it
- [ ] [recommended] Outbound DNS restricted to the resolver you operate
- [ ] [recommended] Outbound 853 and known DoH endpoints blocked, or the resolver policy is bypassable
- [ ] [recommended] Egress proxy logs collected, with query strings redacted on ingest

## TLS (A04 · ASVS V12 · CWE-319, CWE-326, CWE-757)

- [ ] [critical] TLS 1.0 and 1.1 disabled (RFC 8996, BCP 195)
- [ ] [critical] TLS 1.2 restricted to ECDHE with AEAD suites; TLS 1.3 enabled
- [ ] [critical] Certificate verification on. No `--insecure`, `verify=False`, or `InsecureSkipVerify`
- [ ] [critical] Hostname verification on, not just chain validation (CWE-297)
- [ ] [recommended] Internal hops encrypted too, not only the edge
- [ ] [recommended] Certificate expiry monitored with an alert, not a calendar reminder
- [ ] [optional] HSTS decision made deliberately, with `includeSubDomains` scope understood
- [ ] [optional] CAA records published for domains you control

## Service Identity (A06 · ASVS V12 · CWE-295)

- [ ] [critical] Service-to-service calls authenticate, mTLS or a signed token. Network position is not identity
- [ ] [critical] Client certificate CN or SAN checked against an allowlist, not just chain-validated
- [ ] [critical] Identity headers set by the proxy and cleared from inbound requests
- [ ] [recommended] Certificate lifetime short, or a revocation path exists and is current

## Reverse Proxy (A01 · ASVS V12 · CWE-348)

- [ ] [critical] `X-Forwarded-For` trusted only from known upstream hops, IPv4 and IPv6
- [ ] [critical] `X-Forwarded-Proto` set from the server's own scheme, not copied from the client
- [ ] [recommended] Origin accepts connections only from the CDN or WAF egress ranges
- [ ] [recommended] Upstream response headers that leak version or backend identity removed
- [ ] [recommended] Request body and header size limits set
- [ ] [recommended] Timeouts set on connect, send, and read

## WAF (A02 · ASVS V13)

- [ ] [recommended] Ruleset in blocking mode, not detection only
- [ ] [critical] No path bypasses it: direct origin IP, admin listener, non-HTTP protocol
- [ ] [recommended] No finding recorded as mitigated solely because the WAF is present

## Remote Access (A01 · ASVS V6, V12)

- [ ] [critical] SSH is key-only. Password and keyboard-interactive authentication disabled
- [ ] [recommended] Bastion has `AllowTcpForwarding no`, or it is a general-purpose tunnel
- [ ] [recommended] VPN scope is a jump segment, not the whole estate
- [ ] [critical] Access is per-person and revocable. No shared credentials or shared keys
- [ ] [recommended] Session and authentication events logged with the key fingerprint used

## Observability (A09 · ASVS V16 · CWE-778)

- [ ] [recommended] Flow logs at every segment boundary, allows and denies
- [ ] [recommended] DNS query logs retained, at least as long as flow logs
- [ ] [recommended] Alerting on new outbound destinations, not volume alone
- [ ] [optional] Detection does not depend on SNI being readable

## Before Returning

- [ ] [critical] Config syntax validated with the tool's own checker (`nginx -t`, `nft -c -f`)
- [ ] [recommended] Change has a rollback path that does not require flushing the rule set
- [ ] [critical] Nothing suggested that disables a firewall or certificate verification to debug
- [ ] [critical] Anything you could not verify from the files stated plainly
