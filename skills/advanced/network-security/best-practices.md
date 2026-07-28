# Network Security Best Practices

Patterns that hold up under review. Each names the Top 10 2025 category, the ASVS 5.0 chapter,
and a CWE where one applies.

## Default Deny, Both Directions

`A02:2025` · ASVS V13 · `CWE-1327`

A host firewall with an accept policy and a few drop rules is a denylist. It protects against
the ports you thought of.

```bash
# Vulnerable: default accept, ipv4 only, and a listener bound everywhere
# nft list ruleset
table ip filter {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp dport 22 accept
    tcp dport 5432 accept
  }
}
```

Two holes. The policy is `accept`, so every port not mentioned is open. The table is `ip`, so
the same host is entirely unfiltered over IPv6 — which is on by default on most images.

```bash
# Fixed: inet covers both families, default drop, egress named
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;

    iif lo accept
    ct state established,related accept
    ct state invalid drop

    ip saddr 10.0.1.0/24 tcp dport 8443 accept comment "edge to app"
    ip saddr 10.0.9.0/24 tcp dport 22 accept comment "bastion to ssh"

    icmp type echo-request limit rate 5/second accept
    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept

    log prefix "in-drop " level info limit rate 10/minute
  }

  chain output {
    type filter hook output priority 0; policy drop;

    oif lo accept
    ct state established,related accept

    ip daddr 10.0.3.0/24 tcp dport 5432 accept comment "app to database"
    ip daddr 10.0.4.10 tcp dport 3128 accept comment "egress proxy only"
    udp dport 53 ip daddr 10.0.0.2 accept comment "internal resolver only"

    log prefix "out-drop " level info limit rate 10/minute
  }
}
```

Why this works: the `inet` family filters IPv4 and IPv6 from one rule set, so there is no
second file to forget. The output chain is what stops a compromised process from opening a
connection anywhere; without it, ingress hardening only changes which direction the attacker
works in. ICMPv6 neighbour discovery must be permitted or IPv6 breaks in ways that get
diagnosed by disabling the firewall.

Do not drop all ICMP. Path MTU discovery depends on ICMP fragmentation-needed and ICMPv6
packet-too-big; blocking them produces intermittent stalls on large responses that nobody
attributes to the firewall.

## Egress Control and SSRF

`A01:2025` · ASVS V2, V12 · `CWE-918`

An application-level IP check is the fix people reach for. It loses to DNS rebinding, because
the name is resolved once for the check and again by the HTTP client for the connection.

The network-level answer: workloads that fetch user-supplied URLs get no direct route out.

```bash
# Fixed: only the proxy can leave; metadata endpoints blocked in both families
table inet filter {
  chain output {
    type filter hook output priority 0; policy drop;
    oif lo accept
    ct state established,related accept

    ip daddr 169.254.169.254 drop comment "cloud metadata"
    ip6 daddr fd00:ec2::254 drop comment "cloud metadata v6"

    ip daddr 10.0.4.10 tcp dport 3128 accept comment "egress proxy"
  }
}
```

Why this works: the destination is decided after DNS by a component the workload does not
control, so a rebound name never reaches an internal address. The application check stays as
defence in depth, but it is no longer the only thing between an SSRF and the metadata service.

Require the token-based, hop-limited metadata mode where the provider has one (IMDSv2 on AWS).
Blocking only the IPv4 literal in application code is incomplete: the IPv6 literal, decimal
notation, and a DNS name pointing at the same address all get there.

## TLS Configuration

`A04:2025` · ASVS V12 · `CWE-326`, `CWE-757`

RFC 8996 (BCP 195, March 2021) moves TLS 1.0 and 1.1 to Historic. RFC 9325 (BCP 195, November
2022) is the current recommendation set and obsoletes RFC 7525.

```nginx
# Vulnerable: deprecated versions, no forward secrecy requirement, no OCSP
ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
ssl_ciphers HIGH:!aNULL:!MD5;
ssl_prefer_server_ciphers off;
```

`HIGH:!aNULL:!MD5` still admits static RSA key exchange and CBC suites, so a recorded session
is decryptable later if the key leaks.

```nginx
# Fixed: 1.3 preferred, 1.2 restricted to AEAD with ECDHE
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers on;
ssl_ecdh_curve X25519:prime256v1;
ssl_session_tickets off;

ssl_stapling on;
ssl_stapling_verify on;
resolver 10.0.0.2 valid=300s;

add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

Why this works: every permitted suite uses ECDHE, so a later key compromise does not decrypt
past sessions, and every suite is AEAD, which removes the CBC padding-oracle family. TLS 1.3
negotiates its own suites and ignores `ssl_ciphers`, so this list only constrains the 1.2 path.

`ssl_session_tickets off` is deliberate. Tickets encrypted under a long-lived key that nginx
rotates only on reload weaken forward secrecy. Turn them on only with an external rotation
mechanism.

On HSTS (RFC 6797, November 2012): the first request before any header is seen is unprotected
unless the domain is preloaded, and `includeSubDomains` with a one-year `max-age` commits every
subdomain — including internal-only names — to having a valid certificate. Say that out loud
before adding it.

## mTLS and Service Identity

`A01:2025`, `A06:2025` · ASVS V12 · `CWE-295`, `CWE-297`

A service that trusts its network is a service with no authentication. mTLS gives each peer a
verifiable identity that does not move with the IP address.

```nginx
# Vulnerable: TLS terminated, client unverified, and the caller's claimed
# identity comes from a header the caller sets
location /internal/ {
  proxy_set_header X-Service-Name $http_x_service_name;
  proxy_pass http://payments;
}
```

```nginx
# Fixed: client certificate required, and identity is derived from it
ssl_client_certificate /etc/nginx/ca/internal-ca.pem;
ssl_verify_client on;
ssl_verify_depth 2;
ssl_crl /etc/nginx/ca/internal.crl;

location /internal/ {
  if ($ssl_client_s_dn !~ "CN=(orders|billing)\.svc\.internal") { return 403; }
  proxy_set_header X-Service-Name $ssl_client_s_dn_cn;
  proxy_set_header X-Service-Name-Original "";
  proxy_pass https://payments;
}
```

Why this works: the identity comes from a certificate the CA issued, not from a header the
caller controls. Clearing the inbound copy of the header matters — otherwise a client sends its
own `X-Service-Name` and the upstream cannot tell which value the proxy set.

Limitations worth stating: `ssl_verify_client on` proves the peer holds a key the CA vouched
for. It does not authorise the request, which is why the `CN` allowlist is there. A CRL file is
only as fresh as the last time you shipped it — short-lived certificates (hours, issued by a
workload identity system) are the stronger revocation story. And mTLS at the edge proxy says
nothing about the hop from proxy to upstream; note `proxy_pass https://` above.

## Reverse Proxy Trust Boundary

`A01:2025` · ASVS V12, V13 · `CWE-348`

```nginx
# Vulnerable: any client can claim any source IP and any scheme
real_ip_header X-Forwarded-For;
set_real_ip_from 0.0.0.0/0;
proxy_set_header X-Forwarded-Proto $http_x_forwarded_proto;
```

Rate limits, allowlists, and audit logs downstream now key on an attacker-supplied value.
Sending `X-Forwarded-For: 127.0.0.1` bypasses an internal-only check.

```nginx
# Fixed: trust only the known upstream hops, and set the values yourself
set_real_ip_from 10.0.1.0/24;
set_real_ip_from 2001:db8:1::/64;
real_ip_header X-Forwarded-For;
real_ip_recursive on;

proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header Host $host;
```

Why this works: nginx walks `X-Forwarded-For` from the right and stops at the first address not
in a trusted range, so appended values cannot shift the result. `$scheme` is what this server
actually served, not what the client asserted.

Add every hop you actually have, including the IPv6 prefix. A missing IPv6 entry means the
proxy stops trusting the header exactly when the connection arrives over IPv6.

## What a WAF Does and Does Not Do

`A02:2025` · ASVS V13

A WAF is a signature layer in front of an application. It buys time between disclosure and
deploy, and it catches undirected scanning. It is not a control you can cite as the fix for an
injection or an authorisation flaw.

Where it genuinely helps:

- Virtual patching a known CVE while the upgrade ships.
- Rate limiting and bot pressure at the edge, before requests cost you application capacity.
- Blocking traffic patterns no legitimate client produces.

Where it does not:

- Business-logic abuse. A request that is valid but should not be permitted for this actor
  looks identical to one that should.
- Anything inside TLS it does not terminate, and anything on a path that bypasses it — a
  direct-to-origin IP, an internal admin listener, a non-HTTP protocol.
- Encoding variants. Every generic ruleset has a bypass corpus.

Two configuration requirements, or the WAF is decorative: the origin must accept connections
only from the WAF or CDN egress ranges, and the ruleset must run in blocking mode. A WAF in
detection mode is a logging product.

Never report an injection as mitigated because a WAF is present. Cite the WAF as compensating,
name the underlying finding, and fix the code.

## DNS

`A02:2025`, `A06:2025` · ASVS V12, V13

- Force workloads to a resolver you operate. Block outbound 853 (DoT, RFC 7858) and known DoH
  endpoints, or a client-side setting silently leaves your policy and your logs.
- Log queries at that resolver. DNS logs answer "what did it try to reach" when flow logs only
  show a blocked connection. `A09:2025`, `CWE-778`.
- Publish CAA records (RFC 8659, November 2019) to limit which CAs may issue for your domain.
  It reduces who can mis-issue; it does not stop a CA that ignores it and has no effect on
  already-issued certificates.
- Remove stale records pointing at deprovisioned cloud resources. A dangling CNAME to a
  released hostname is a subdomain takeover, and it inherits any cookie scoped to the parent
  domain.
- Enable DNSSEC validation on your resolver where the zones you depend on are signed. Signing
  your own zone protects your users' resolution; validating protects your workloads.

## Remote Access

`A01:2025` · ASVS V6, V12

Prefer per-application authorisation over network reachability.

```bash
# Fixed: bastion sshd, keys only, no forwarding, no shell escape to the network
# /etc/ssh/sshd_config
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AuthenticationMethods publickey
AllowTcpForwarding no
PermitTunnel no
X11Forwarding no
AllowAgentForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2
LogLevel VERBOSE
```

Why this works: `AllowTcpForwarding no` is the line that matters. A bastion with forwarding
enabled is a general-purpose network tunnel for anyone who can log in, which defeats the
segmentation it is supposed to enforce. `LogLevel VERBOSE` records the key fingerprint used, so
sessions are attributable to a specific credential.

A VPN that grants a `/16` turns one stolen laptop into access to the estate. Scope a VPN to a
jump segment and require a second authorisation step to reach a workload.

## Observability

`A09:2025` · ASVS V16 · `CWE-778`

- Flow logs on every segment boundary, allow and deny both. A rule set with no deny logging
  cannot tell you whether it is protecting anything.
- DNS query logs at your resolver, retained longer than flow logs. They compress well and they
  are where staged exfiltration shows up first.
- Egress proxy access logs, redacted on ingest. Full URLs contain tokens in query strings.
- Alert on new destinations from a workload, not on volume alone. Exfiltration that fits inside
  normal volume is the common case.

Do not build detection that assumes SNI is visible. Encrypted Client Hello removes it.

## Sources

- RFC 9325 (BCP 195) — <https://www.rfc-editor.org/rfc/rfc9325.html>
- RFC 8996 (BCP 195) — <https://www.rfc-editor.org/rfc/rfc8996.html>
- RFC 6797 (HSTS) — <https://www.rfc-editor.org/rfc/rfc6797.html>
- RFC 8659 (CAA) — <https://www.rfc-editor.org/rfc/rfc8659.html>
- NIST SP 800-207 — <https://csrc.nist.gov/pubs/sp/800/207/final>
- OWASP Top 10 2025 — <https://owasp.org/Top10/2025/>
- OWASP ASVS — <https://owasp.org/www-project-application-security-verification-standard/>
