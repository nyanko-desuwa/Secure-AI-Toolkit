---
name: network-security
description: 'Design and review network controls: segmentation, firewall and egress policy, DNS, TLS and mTLS, reverse proxies, VPN and bastion access, and traffic observability. Triggers: "firewall", "segmentation", "egress", "mTLS", "TLS config", "nginx", "nftables", "WAF", "bastion", "tường lửa", "mạng".'
allowed-tools: Read, Glob, Grep, WebSearch, WebFetch
---

# Network Security

The network decides what an attacker can reach after they get one thing wrong in the
application. This skill covers where the boundaries go, what crosses them, and how you can
tell afterwards.

## When to Use

- Writing or reviewing firewall rules, security groups, or network policy
- Configuring a reverse proxy, load balancer, or ingress
- Choosing TLS settings, or adding mTLS between services
- Adding an outbound integration and deciding what the app may reach
- Designing remote access: VPN, bastion, or an identity-aware proxy
- Investigating what a compromised pod, container, or host can talk to
- Reviewing a network change that is described as "temporary"

## Standards This Skill Maps To

| Standard | Use it for | Version here |
|---|---|---|
| OWASP Top 10 2025 | Risk triage and reporting language | 2025 |
| OWASP ASVS 5.0 | Verification of communication and configuration | 5.0.0 |
| BCP 195 (RFC 9325 + RFC 8996) | What TLS configuration is currently acceptable | RFC 9325, RFC 8996 |
| NIST SP 800-207 | Vocabulary for identity-based rather than location-based trust | August 2020 |

ASVS V12 (Secure Communication) is the chapter to verify against. A01 and A02 are how you
report the finding. BCP 195 is what you cite when someone asks why TLS 1.1 is not an option.
See [references/](references/).

## Workflow

### 1. Scope

Answer three questions before changing a rule:

- What can reach this listener today, and from where? Not what is documented - what the rules
  actually allow.
- If this host is compromised, what can it open a connection to?
- Which control is doing the work: the network rule, the application check, or neither?

If you cannot answer the second one, you are reviewing ingress and ignoring egress, which is
the half attackers use.

### 2. Map

Network findings usually land in three categories:

- A01:2025 - a service reachable by a party that should not reach it, including SSRF against
  an internal listener. Network-level access control is still access control.
- A02:2025 - a default left in place: `0.0.0.0/0`, an admin port on a public interface, a
  permissive security group, TLS verification disabled.
- A06:2025 - the design assumes the network is trusted, so nothing authenticates inside it.

Common miscategorisation: filing weak TLS under A05 because it involves protocol data. It is
A04 (Cryptographic Failures) with ASVS V12, and CWE-326 or CWE-757 depending on the flaw.

### 3. Apply Controls

Ordered by what fails hardest when missing:

1. Default deny, both directions. An allowlist you have to maintain beats a denylist you
   forget. See [best-practices.md](best-practices.md#default-deny-both-directions).
2. Egress control with an explicit destination list. This is what turns an SSRF or a
   compromised dependency from a breach into a blocked connection.
3. Authenticated identity between services - mTLS or a signed token - so a foothold on the
   network is not authorisation.
4. TLS configured to BCP 195, with verification on and hostname checking on.
5. Segmentation with a policy per segment pair, not a flat VPC with a firewall at the edge.
6. Observability: flow logs and DNS logs you actually retain, so the question "what did it
   talk to" has an answer.

### 4. Verify

Run [checklist.md](checklist.md) before returning a config. Every unchecked box is a fix or a
stated limitation. Reading a config file cannot confirm the runtime state - say so when that
is the case.

### 5. Report

For each finding: category, the file and rule, what an attacker reaches through it, and the
fix. Include the blast radius. "Security group allows 0.0.0.0/0 on 5432" is a fact; "the
database accepts connections from the internet and authenticates with a password in an
environment variable" is a finding.

## Severity

- **Critical** - a datastore, admin interface, or orchestrator API reachable from the internet;
  unauthenticated internal API reachable from a compromised low-trust workload
- **High** - unrestricted egress from a workload that handles untrusted input; TLS
  verification disabled; flat network with no policy between tiers
- **Medium** - TLS 1.2 with a weak suite where 1.3 is available; missing flow logs; a bastion
  with shared credentials
- **Low** - defence in depth missing where an authenticated control still holds

An open port on a listener bound to loopback is not the same as one bound to `0.0.0.0`. Check
which it is before assigning severity.

## Safe Investigation

This skill reads configuration and describes tests. It does not scan.

- Do not run port scanners, traffic floods, or exploit tooling against any host, including
  ones the user says they own. Testing reachability against third-party or shared
  infrastructure needs written authorisation that a chat message is not.
- Prefer reading the rule set over probing it. `nft list ruleset`, the cloud API, or the
  Kubernetes NetworkPolicy objects are authoritative and safe.
- Never suggest `iptables -F`, `nft flush ruleset`, disabling a firewall service, or
  `--insecure`/`verify=False` as a debugging step. See
  [troubleshooting.md](troubleshooting.md#safe-diagnosis).

## Related Skills

- `owasp` - the standards this skill maps to
- `cryptography` - key management and algorithm choice behind the TLS settings here
- `cloud-security` - security groups, VPC design, and provider-specific controls
- `secure-architecture` - trust boundaries at the design level

## Supporting Files

- [README.md](README.md) - purpose, standards table, limitations
- [checklist.md](checklist.md) - pre-return verification
- [best-practices.md](best-practices.md) - patterns, with vulnerable/fixed pairs
- [common-mistakes.md](common-mistakes.md) - what goes wrong and why the fix works
- [troubleshooting.md](troubleshooting.md) - when the guidance cannot be applied
- [prompts.md](prompts.md) - prompts that produce findings
- [references/tls-versions.md](references/tls-versions.md) - BCP 195, cipher profiles, certificate lifetime
- [references/segmentation-patterns.md](references/segmentation-patterns.md) - zones, egress, zero trust
- [references/cloud-network-controls.md](references/cloud-network-controls.md) - AWS, Azure, GCP, Kubernetes
- [examples/README.md](examples/README.md) - eight vulnerable/fixed configuration pairs
