# Troubleshooting

What to do when the guidance cannot be applied cleanly, or when applying it breaks something.

## Safe diagnosis

Read the rule set before touching it. Every command below is read-only.

```bash
nft list ruleset                      # authoritative rule set, both families
ss -tulpen                            # listeners, with the address each is bound to
ip -6 addr show                       # confirm whether IPv6 is even configured
resolvectl status                     # which resolver this host actually uses
openssl s_client -connect host:443 -servername host < /dev/null
```

`ss -tulpen` is the one people skip. A service on `127.0.0.1:5432` and one on `0.0.0.0:5432`
produce the same `netstat` line in a hurry and very different severities.

For a specific rule, add a counter rather than removing rules:

```bash
# Read the counter, do not change policy
nft add rule inet filter input tcp dport 8443 counter comment "diag-2026-07-28"
nft list chain inet filter input
```

What not to do, ever, as a diagnostic step:

- `nft flush ruleset`, `iptables -F`, `systemctl stop firewalld` — exposes every listener, and
  the "test" tells you nothing you could not get from reading the rules.
- `--insecure`, `verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify: true` — this
  is the flag that gets committed. Use `openssl s_client` to see the chain instead, then fix
  the trust store.
- Port scanners, traffic generators, or exploit tooling against any host. Reachability testing
  against shared or third-party infrastructure needs written authorisation, and a message
  saying "it's mine" is not that. Describe the test; let the owner run it.
- Widening a rule to `0.0.0.0/0` to confirm the source CIDR is wrong. Add the one candidate
  CIDR you suspect.

## The secure config breaks a client

TLS 1.2-only clients, or a client that cannot do ECDHE, appearing after you restrict the suite
list.

Do not restore TLS 1.0/1.1 — they are Historic per RFC 8996 and there is no configuration that
makes them acceptable. Instead:

1. Identify the client from the handshake failure logs. Get a count, not an impression.
2. If it is a fixed internal client, upgrade it. That is usually a library bump.
3. If it is a third party you cannot change, terminate their traffic on a separate hostname and
   listener with its own relaxed policy, scoped to the one endpoint they use. Document the
   exception with an owner and a review date.

Never relax the main listener for one caller. A per-hostname exception has a blast radius you
can describe; a global downgrade does not.

## You cannot tell whether a rule is in effect

Configuration files are not runtime state. A file in `/etc/nftables.conf` may not be loaded, a
security group may be attached to nothing, and a NetworkPolicy is inert if the CNI does not
enforce policy.

Report the uncertainty rather than resolving it by guessing:

"`nftables.conf` sets a default-drop input policy. I could not confirm it is loaded — `nft list
ruleset` was not available to me. If the service is not enabled, this file has no effect."

For Kubernetes specifically: check that the CNI enforces NetworkPolicy at all. Flannel without
an add-on does not. A carefully written policy on a non-enforcing CNI is documentation.

## Segmentation conflicts with a flat legacy application

A monolith whose components address each other by IP and break when you place a policy between
them.

Do not skip segmentation. Sequence it:

1. Put the whole application in one segment with a strict boundary to everything else. This is
   the cheap win and it removes lateral movement from outside.
2. Turn on flow logging inside the segment and let it run. You now have the real dependency
   map, which will not match the diagram.
3. Split by observed flows, one boundary at a time, in log-only mode before enforcing.

Say which stage you stopped at. "Perimeter enforced, internal flows observed but not yet
restricted" is a defensible position; implying full micro-segmentation is not.

## mTLS cannot be deployed everywhere

A managed service, a vendor appliance, or a language runtime with poor client-certificate
support.

Options in order of preference:

1. Terminate mTLS at a sidecar or local proxy on the same host, so the plaintext hop never
   leaves the network namespace.
2. Use a signed service token (short-lived, audience-bound) over TLS. Weaker than mTLS because
   a token is bearer-based and replayable within its lifetime — keep the lifetime short.
3. Restrict by network policy alone, and record it as an accepted gap. Network position is not
   identity; NIST SP 800-207 is the reference for why.

State which one you chose. Do not describe option 3 as mTLS-equivalent.

## Egress control blocks something you cannot identify

A workload fails after egress is restricted and the logs only show a dropped connection.

Set the egress policy to log-and-allow first, collect for a full business cycle including
weekly and monthly jobs, then enforce. Enforcing from day one on an application whose
dependencies were never inventoried produces an outage and a rollback, and the rollback is
permanent.

Prefer allowlisting by hostname at an egress proxy over allowlisting IPs. Cloud service IP
ranges change without notice, and an IP allowlist becomes an outage on someone else's
deployment schedule.

## A cloud control and a host control disagree

A security group allows a port the host firewall drops, or the reverse.

Both are in effect; the more restrictive wins for traffic, and the more permissive one is the
finding. A security group allowing `0.0.0.0/0` is still a misconfiguration even when the host
firewall saves you, because the next image in that group may not have the host rule.

Fix both. Note which layer you are relying on.

## The finding is real but the exploitation path is unconfirmed

Say so, with the precondition attached.

"Redis on `0.0.0.0:6379` with no `requirepass`. Exploitable from anywhere the subnet routing
allows — I could not determine whether the subnet is internet-reachable, so severity is High
pending that check, Critical if it is public."

That is useful. "Critical: exposed Redis" without checking the routing is the kind of noise
that gets a report ignored.

## The standard has moved on

The RFC numbers, titles, and dates in [references/tls-versions.md](references/tls-versions.md)
were checked on 2026-07-28. BCP 195 has been revised before — RFC 9325 obsoleted RFC 7525 — so
re-check `rfc-editor.org` before quoting it in a document with a long life.

Never assume undocumented behaviour, in a standard or in a proxy. Fetch it.
