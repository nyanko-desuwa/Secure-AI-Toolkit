# Segmentation and Egress Model

How to divide a network and decide what may cross each boundary. Maps to `A01:2025`
(Broken Access Control), `A02:2025` (Security Misconfiguration), `A06:2025` (Insecure Design),
ASVS V12 and V13, and `CWE-1327` (Binding to an Unrestricted IP Address).

Vocabulary here follows NIST SP 800-207, Zero Trust Architecture, August 2020
(<https://doi.org/10.6028/NIST.SP.800-207>). Checked 2026-07-28.

## Zones

Segmentation is worth doing only if the policy between zones is narrower than the policy
inside one. A VPC split into subnets with an allow-all rule between them is one zone with
extra diagram boxes.

| Zone | Holds | Accepts from | May reach |
|---|---|---|---|
| Edge | Load balancer, WAF, CDN origin | Internet on 443 | App zone, on the app port only |
| App | Application servers, workers | Edge, and app peers named in policy | Data zone on the DB port; declared external destinations |
| Data | Databases, caches, queues | App zone on one port each | Nothing outbound except backup storage |
| Control | CI runners, bastion, secret store | Identity-proxied admin sessions | Targets named per job |
| Management | Monitoring, log collectors | Agents pushing metrics and logs | Nothing inbound to workloads |

Two rules make the table mean something. First, every arrow is a named rule, and there is no
implicit allow between zones. Second, the data zone has no route to the internet - not a
restricted route, no route. A database that cannot open an outbound connection cannot be used
to exfiltrate over one.

## Identity, not location

SP 800-207's central claim for our purposes: no implicit trust is granted based on network
location, and authentication and authorization of both the subject and the device happen as
discrete functions before a session to a resource is established.

The practical consequence is that segmentation is a blast-radius control, not an authentication
mechanism. Two things follow:

- A service inside the app zone still authenticates its callers. mTLS or a signed token,
  verified per request. "It came from 10.0.2.0/24" is not an identity.
- Segmentation still earns its place. It bounds what a compromised workload can attempt, which
  is what limits an incident to one service instead of the estate.

Anyone who says zero trust means the firewall is obsolete has read the marketing. Anyone who
says the firewall means services need not authenticate has read neither.

## Egress: the half that gets skipped

Ingress rules get reviewed because someone asks "is this exposed". Egress rules get skipped
because nothing breaks when they are missing. Egress is what decides whether a compromised
dependency, an SSRF, or a leaked credential can reach anything useful.

Three levels, from weakest to strongest:

| Level | Mechanism | Stops | Does not stop |
|---|---|---|---|
| IP allowlist | Firewall rules to destination CIDRs | Random outbound connections | Anything hosted at an allowed IP; shared CDN and cloud ranges cover most of the internet |
| DNS-based policy | Resolver returns only allowed names, egress limited to resolved IPs | Name-based exfiltration to unlisted domains | DNS-over-HTTPS bypass, direct-to-IP connections, DNS tunnelling |
| Authenticated egress proxy | All outbound HTTP through a proxy that enforces a host allowlist and logs | Direct-to-IP, most SSRF, most tunnelling | Traffic on protocols the proxy does not handle; a proxy configured to allow `CONNECT` anywhere |

An egress proxy is the strongest of the three because the destination is decided from the
request, after DNS, by a component the workload does not control. Combine it with a firewall
that permits outbound only to the proxy, or the proxy is advice.

The one control that closes an SSRF class rather than narrowing it: workloads that handle
untrusted URLs get no direct route out, and the proxy applies the host allowlist. That way the
application's own IP checks stop being the last line, which matters because they lose to DNS
rebinding - the address is resolved once for the check and again for the connection.

## Cloud metadata endpoints

`169.254.169.254` and `fd00:ec2::254` are the reason SSRF on a cloud host is a credential
disclosure. Block them at the workload level for anything that fetches user-supplied URLs, and
require the hop-limited, token-based metadata mode where the provider offers one (IMDSv2 on
AWS). Blocking only the IPv4 literal in application code is the classic incomplete fix: the
IPv6 literal, decimal notation such as `2852039166`, and a DNS name that resolves there all
route to the same place.

## IPv6

IPv6 is enabled by default on most images and is frequently absent from the rule set. Two
failure modes worth naming:

- A dual-stack host with IPv4 rules and no IPv6 rules is unfiltered over IPv6. `nftables`
  `inet` tables cover both families; separate `iptables` and `ip6tables` rule sets do not
  unless you maintain both.
- Host addresses move. RFC 8981 (February 2021, obsoletes RFC 4941) specifies temporary
  SLAAC addresses, so an allowlist keyed to a single IPv6 host address breaks silently. Filter
  on prefix, or use identity.

Any SSRF or private-range check must cover IPv6 forms: `::1`, `fc00::/7`, `fe80::/10`,
IPv4-mapped `::ffff:0:0/96`, and NAT64 `64:ff9b::/96`. Use the IANA special-purpose registries
(RFC 6890, BCP 153, April 2013) as the source of truth rather than a hand-written list.

## Remote access

| Approach | Gives you | Watch for |
|---|---|---|
| VPN into a zone | Network reachability | Once connected, the user is inside a zone. Scope the VPN to a jump segment, not to the app zone |
| Bastion / jump host | A single audited entry point | Shared accounts, no session recording, and a bastion with unrestricted egress |
| Identity-aware proxy | Per-request authorisation, per-app scope | Correct group mapping; a wildcard rule defeats the point |

Prefer per-application authorisation over network reachability. A VPN that grants a `/16`
converts one stolen laptop into access to the estate. Where a bastion is the answer, give it
its own credentials per user, record sessions to storage the bastion cannot rewrite, and
restrict its outbound rules like any other workload.

## Observability

You cannot answer "what did it talk to" after the fact unless you collected it before.

| Source | Answers | Cost |
|---|---|---|
| Flow logs (VPC flow logs, conntrack, `nftables` counters) | Which pairs talked, volume, allowed or denied | Storage grows with connection count; sample carefully or you lose the rare event |
| DNS query logs at your resolver | What names were resolved, including staged exfiltration | High volume; retain longer than flow logs, it compresses well |
| Proxy access logs | Full outbound URLs and the deciding rule | Contains sensitive paths and tokens in query strings; redact on ingest |
| TLS handshake metadata (SNI, JA3-style fingerprints) | Destination and client stack without decryption | Encrypted Client Hello removes SNI; do not build detection that assumes it |

Log denied connections, not only allowed ones. A rule set with no deny logging cannot tell you
whether it is protecting anything or whether nothing has tried. `A09:2025`, `CWE-778`.

## Sources

- NIST SP 800-207, Zero Trust Architecture, August 2020 - <https://csrc.nist.gov/pubs/sp/800/207/final>
- RFC 6890, Special-Purpose IP Address Registries, BCP 153, April 2013 - <https://www.rfc-editor.org/rfc/rfc6890.html>
- RFC 8981, Temporary Address Extensions for SLAAC in IPv6, February 2021 - <https://www.rfc-editor.org/rfc/rfc8981.html>
- IANA IPv4 Special-Purpose Address Registry - <https://www.iana.org/assignments/iana-ipv4-special-registry/>
- IANA IPv6 Special-Purpose Address Registry - <https://www.iana.org/assignments/iana-ipv6-special-registry/>
- OWASP SSRF Prevention Cheat Sheet - <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>
- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>

All URLs checked 2026-07-28.
