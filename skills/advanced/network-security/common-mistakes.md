# Common Mistakes

What goes wrong in real network configurations, why it goes wrong, and the fix.

## Ingress hardened, egress wide open

Security groups reviewed line by line on the inbound side, outbound left at "allow all". This
is the default in every cloud provider and in most host firewall images.

Why it goes wrong: inbound rules decide who starts a conversation. Every post-exploitation
step — pulling a second stage, reaching the metadata service, exfiltrating data — is outbound.
An SSRF in an application with unrestricted egress is a request to anywhere.

Fix: default-deny egress with a named destination list, and an egress proxy for anything that
needs the internet. `A01:2025`, ASVS V12, CWE-918. See
[best-practices.md](best-practices.md#egress-control-and-ssrf).

## IPv6 left unfiltered

An `nftables` `table ip filter` with a careful default-drop policy, and the host answering on
IPv6 with no rules at all. Same with a security group that lists IPv4 CIDRs and leaves the
IPv6 field blank.

Why it goes wrong: IPv6 is enabled by default on most base images and cloud subnets. A dual
rule set is two things to remember, and the second one gets forgotten.

Fix: use `table inet` so one rule set covers both families. In cloud policy, write the IPv6
rule in the same change as the IPv4 rule or omit the IPv6 address entirely. CWE-1327.

## Trusting X-Forwarded-For from anywhere

```nginx
set_real_ip_from 0.0.0.0/0;
real_ip_header X-Forwarded-For;
```

Why it goes wrong: the header is client-supplied. Every downstream control keyed on client IP
— rate limits, geo rules, internal-only allowlists, audit logs — now reads an attacker-chosen
value. `X-Forwarded-For: 127.0.0.1` is the whole attack.

Fix: list only the CIDRs of hops you operate, in both families, and set `X-Forwarded-Proto`
from `$scheme` rather than from the inbound header. CWE-348.

## Application-level SSRF filter treated as sufficient

A resolver call, a private-range check, then an HTTP request with the original URL.

Why it goes wrong: two resolutions. The check resolves the name, the HTTP client resolves it
again, and a DNS record with a one-second TTL returns a public address for the first and
`169.254.169.254` for the second. A hand-written private-range list also tends to miss
`100.64.0.0/10`, `::ffff:0:0/96`, and `64:ff9b::/96` — use the IANA special-purpose registries
(RFC 6890) instead of writing the list from memory.

Fix: keep the application check, and put the workload behind an egress proxy so the connection
cannot reach an internal address regardless of what DNS says. CWE-918.

## Cipher list copied from a 2015 blog post

```nginx
ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
ssl_ciphers HIGH:!aNULL:!MD5;
```

Why it goes wrong: `HIGH` is an OpenSSL grouping by key length, not by construction. It admits
static RSA key exchange (no forward secrecy) and CBC suites. TLS 1.0 and 1.1 are Historic per
RFC 8996 (BCP 195, March 2021).

Fix: `TLSv1.2 TLSv1.3` with an explicit ECDHE+AEAD list for the 1.2 path. RFC 9325 (BCP 195,
November 2022) is the document to cite. CWE-326, CWE-757.

## Certificate verification disabled to make it work

`curl --insecure`, `verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify: true`, or
`proxy_ssl_verify off`.

Why it goes wrong: it turns a name-mismatch or expired-CA error into no authentication at all.
The connection is still encrypted, which is why it looks fine — it is encrypted to whoever
answered. The flag added during an incident is the one that stays.

Fix: fix the trust store or the hostname. Add the internal CA to the client's trust bundle;
connect using the name in the certificate. If a name genuinely cannot match, pin the expected
certificate rather than disabling verification. CWE-295, CWE-297.

## mTLS enabled, authorisation forgotten

`ssl_verify_client on` with no check on which certificate arrived.

Why it goes wrong: it proves the peer holds a key signed by the CA. If the CA also issues
certificates to laptops, CI runners, or every other service, any of them authenticates
successfully. Authentication is not authorisation.

Fix: check the subject against an allowlist, and use a CA whose only purpose is workload
identity. See [best-practices.md](best-practices.md#mtls-and-service-identity).

## WAF cited as the fix for an injection

"SQL injection in the report endpoint — mitigated, the WAF blocks it."

Why it goes wrong: generic rulesets have a documented bypass corpus, the WAF does not see
traffic on paths that reach the origin directly, and a rule tuned to stop false positives
tomorrow stops blocking. A WAF in detection mode blocks nothing at all.

Fix: parameterize the query. Keep the WAF as compensating control, name it as such, and
confirm the origin only accepts connections from the WAF or CDN ranges.

## Bastion with TCP forwarding enabled

An SSH jump host with default `sshd_config`.

Why it goes wrong: `AllowTcpForwarding yes` (the default) makes the bastion a general-purpose
tunnel. Anyone who can log in reaches every host and port the bastion can reach, which is the
whole protected segment. The segmentation still exists on paper.

Fix: `AllowTcpForwarding no`, `PermitTunnel no`, `AuthenticationMethods publickey`, and session
recording. If port forwarding is genuinely required, scope it with `PermitOpen` to specific
host:port pairs. `A01:2025`, ASVS V6.

## Temporary rule with no expiry

`0.0.0.0/0` on a management port, added during an incident, with a comment saying it will be
removed.

Why it goes wrong: nothing removes it. The incident ends, the rule is not in anyone's ticket
queue, and it surfaces in an audit two years later.

Fix: put temporary rules in a separate, dated ruleset file or tag, and add the removal to the
same change that opened them. Review the diff of every network change against the previous
state — a rule set nobody diffs only accumulates. `A02:2025`.

## Deny rules with no logging

A default-drop policy and no `log` statement.

Why it goes wrong: you cannot distinguish a rule set that is protecting you from one that is
breaking a feature nobody has reported yet, and after an incident there is no record of what
the host tried to reach.

Fix: rate-limited logging on the drop paths, shipped off-host. Rate limit it, or a scan fills
the disk and takes the host down. `A09:2025`, CWE-778.

## Firewall disabled as a debugging step

`nft flush ruleset`, `systemctl stop firewalld`, or `iptables -F` to see whether the firewall
is the problem.

Why it goes wrong: it exposes every listener on the host for as long as it takes to test, and
if the change was not persisted, a reboot is the only thing that restores protection. The
answer it gives — "yes, the firewall" — is available without the exposure.

Fix: read the rule set, then add one specific counter or log rule. See
[troubleshooting.md](troubleshooting.md#safe-diagnosis).
