# Prompt Examples

Prompts that produce findings instead of a lecture on defence in depth. Each one names the
scope, the standard, and the shape of the answer expected.

## Review a rule set

```
Read infra/nftables.conf and report what an attacker on 10.0.1.0/24 can reach, and what a
compromised process on this host can reach outbound. Map each finding to OWASP Top 10 2025
and ASVS V12 or V13. Do not suggest running any scan.
```

Why it works: asks about both directions. Ingress-only reviews miss the egress half, which is
where SSRF and data exfiltration live. The last sentence keeps the answer to reading config.

## Review a TLS configuration against the current standard

```
Check nginx/tls.conf against BCP 195 (RFC 9325 and RFC 8996). For each setting: compliant,
non-compliant, or not addressed by the RFC. Cite the RFC for anything you call non-compliant.
```

Naming BCP 195 rather than "best practice" is what stops the answer being a cipher-list
opinion. Asking for "not addressed by the RFC" is important - plenty of hardening advice is
reasonable but not in the standard, and conflating the two makes the citation worthless.

## Find the egress path for an SSRF

```
This handler fetches a user-supplied URL: src/preview.py. Assume the application-level IP
check can be defeated by DNS rebinding. What does the workload reach at the network layer,
and what would an egress policy have to look like to stop it? Include cloud metadata in both
IPv4 and IPv6.
```

Stating the rebinding assumption stops the answer from being "add an IP allowlist", which is
the fix that already failed. Naming IPv6 explicitly is necessary or it gets left out.

## Audit the reverse proxy trust boundary

```
In nginx/proxy.conf, tell me which request headers the upstream can trust and which the client
can forge. Specifically: is set_real_ip_from scoped to actual hops, and does any
proxy_set_header pass through a client-supplied value?
```

The second question is the one that finds the bug. Header spoofing through a proxy is CWE-348
and it silently breaks rate limiting, IP allowlists, and audit attribution downstream.

## Design review before building

```
I am adding a service that pulls reports from a customer-supplied HTTPS endpoint. Before I
write it, what network controls does it need? Cover egress, DNS, TLS verification, and what
the workload's identity should be. Map each to a Top 10 2025 category and an ASVS chapter.
```

Design-time prompts are cheaper than review-time ones. Outbound integrations in particular
need A01 (egress reachability), A02 (verification settings), and ASVS V12.

## Check what a compromised workload reaches

```
Assume the container running services/importer is fully compromised. Using only the
NetworkPolicy manifests and the security group definitions in this repo, list every
destination it can open a connection to. Flag anything unauthenticated.
```

Framing it as post-compromise produces a lateral-movement map rather than a config audit. The
"unauthenticated" flag separates reachable-but-authenticated from reachable-and-free.

## Verify before returning a config

```
Run skills/advanced/network-security/checklist.md against this change. Mark each item pass,
fail, or not applicable with a reason. Anything you cannot confirm from the files, mark as
unverified rather than pass.
```

The last sentence matters. Config review cannot confirm runtime state, and a wall of
checkmarks over unloaded rule files is worse than an honest gap.

## Question a control you disagree with

```
You said the bastion should set AllowTcpForwarding no, but our developers use SSH tunnels to
reach the database. Which should win, what breaks, and what is the migration path?
```

Conflicts between a control and an established workflow are normal. See
[troubleshooting.md](troubleshooting.md) for how they get resolved rather than quietly dropped.

## Anti-patterns

| Prompt | Problem |
|---|---|
| "Is my network secure?" | No scope, no artefact. Produces a topic list |
| "Scan my servers for open ports" | Out of scope for this skill and unsafe to run on shared infrastructure. Read the rule set instead |
| "Harden the firewall" | Invites speculative rules for services that may not exist. Name the host and the traffic it needs |
| "Give me the best nginx TLS config" | Best for whom? Ask against BCP 195, and say which clients must still connect |
| "Add a WAF to fix the SQL injection" | A WAF is compensating, not remediating. Fix the query |
| "Make it zero trust" | Not a switch. Ask for one specific thing: identity between two named services, or egress policy on one workload |
