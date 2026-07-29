# Network Security Skill

Guidance for the layer below the application: where the boundaries are, what crosses them, and
what an attacker reaches after the first thing goes wrong.

## Purpose

Application controls fail. When they do, the network decides whether the result is one
compromised process or the whole estate. This skill turns that into concrete configuration
decisions - firewall policy, egress control, TLS and mTLS, DNS, proxy trust, remote access -
each traceable to a published standard rather than to habit.

It also draws the line around what a network control cannot do. A WAF does not fix an injection
and an IP allowlist does not survive DNS rebinding. Saying so is part of the job.

## How It Works

Plain Markdown. Nothing executes. An assistant reads `SKILL.md`, follows the five-step workflow
(scope, map, apply, verify, report), and pulls in the supporting file it needs at each step.

```text
SKILL.md                        workflow, severity, safe-investigation rules
README.md                       this file
checklist.md                    pre-return verification, grouped by control area
best-practices.md               patterns, with vulnerable/fixed pairs
common-mistakes.md              what goes wrong and why the fix works
troubleshooting.md              when the guidance cannot be applied as written
prompts.md                      prompts that produce findings, plus anti-patterns
references/
  tls-versions.md               BCP 195, cipher profiles, HSTS, CAA, certificate lifetime
  segmentation-patterns.md      zones, egress posture, identity-based trust, DNS, remote access
  cloud-network-controls.md     AWS, Azure, GCP, and Kubernetes equivalents in a table
examples/
  README.md                     eight vulnerable/fixed configuration pairs
```

## Standards Covered

| Standard | Version | Verified |
|---|---|---|
| OWASP Top 10 | 2025 | 2026-07-28, against `owasp.org/Top10/2025/` |
| OWASP ASVS | 5.0.0 (released 2025-05-30) | 2026-07-28, against the ASVS project page |
| BCP 195 - RFC 9325 | November 2022 (obsoletes RFC 7525) | 2026-07-28, against `rfc-editor.org` |
| BCP 195 - RFC 8996 | March 2021 | 2026-07-28, against `rfc-editor.org` |
| RFC 8446 (TLS 1.3) | August 2018 | 2026-07-28, against `rfc-editor.org` |
| RFC 6797 (HSTS) | November 2012 | 2026-07-28, against `rfc-editor.org` |
| RFC 8659 (CAA) | November 2019 (obsoletes RFC 6844) | 2026-07-28, against `rfc-editor.org` |
| RFC 7858 (DoT) · RFC 8484 (DoH) | May 2016 · October 2018 | 2026-07-28, against `rfc-editor.org` |
| RFC 6890 (BCP 153) · RFC 8981 | April 2013 · February 2021 | 2026-07-28, against `rfc-editor.org` |
| NIST SP 800-207 (Zero Trust Architecture) | August 2020 | 2026-07-28, against `csrc.nist.gov` |

The primary ASVS chapter is V12 (Secure Communication). V13 (Configuration), V2 (Validation),
V6 (Authentication), and V16 (Logging and Error Handling) come up where noted.

Version numbers are pinned in `references/` with the date checked. When a document is
superseded, update the reference file and this table together.

## Configuration

None. No build step, no dependency, no environment variable.

To use it in Claude Code, keep this repository in the working directory so
`skills/advanced/network-security/SKILL.md` is readable, or copy the `network-security`
directory into `~/.claude/skills/`. The frontmatter `allowed-tools` restricts the skill to
read, search, and web lookup plus `ls`/`cat`. It cannot run arbitrary commands, which is
deliberate for a topic where the obvious next step is often a scan.

## Example Usage

Review a rule set in both directions:

```text
Read infra/nftables.conf. Report what an attacker on the app subnet can reach, and what a
compromised process on this host can reach outbound. Map each finding to Top 10 2025 and
ASVS V12 or V13. Do not suggest running a scan.
```

Check TLS against the current standard rather than an opinion:

```text
Check nginx/tls.conf against BCP 195 (RFC 9325, RFC 8996). For each setting say compliant,
non-compliant, or not addressed by the RFC, and cite the RFC for anything non-compliant.
```

More in [prompts.md](prompts.md).

## Limitations

- Markdown guidance, not a scanner and not a config linter. It has no view of the running
  system, so it cannot tell you whether a rule file is loaded, whether a policy is enforced by
  the CNI in use, or whether a certificate on disk is the one being served.
- Reading a config cannot confirm reachability. A `deny` rule below an `allow` on the same
  traffic, a cloud NACL layered under a security group, or a service mesh sidecar that bypasses
  host rules all change the answer and none of them are visible in one file.
- Examples are nftables, nginx, OpenSSH, and cloud-neutral policy pseudo-config. Provider
  specifics - AWS security group semantics, Azure NSG priority ordering, GCP firewall targets -
  are `cloud-security` territory. The reasoning transfers; the syntax does not.
- No coverage of the physical and link layer: 802.1X, VLAN hopping, ARP and NDP spoofing,
  wireless, or BGP hijacking. Nor of DDoS capacity planning.
- ASVS mapping is at chapter level (V1 to V17), not requirement IDs. For formal verification
  work from the official ASVS repository.
- Deliberately excludes offensive tooling. No scanning, traffic capture against third parties,
  or exploitation. It will describe what to test and refuse to run it.

## Security Notes

This skill contains deliberately insecure configuration in `best-practices.md`,
`common-mistakes.md`, and `examples/`. Every such block is labelled `Vulnerable:` and paired
with a fixed version. Do not copy a labelled-vulnerable block into a project.

All addresses, hostnames, and prefixes are placeholders from documentation ranges
(`10.0.0.0/8`, `192.0.2.0/24`, `2001:db8::/32`, `example.com`). There are no real hostnames,
credentials, certificates, or keys anywhere in this skill.

The troubleshooting guidance deliberately never offers "disable the firewall", "flush the rule
set", or "skip certificate verification" as a diagnostic step. Those are the three changes most
likely to be made under pressure and left in place.

## References

- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>
- OWASP ASVS - <https://owasp.org/www-project-application-security-verification-standard/>
- RFC 9325, Recommendations for Secure Use of TLS and DTLS - <https://www.rfc-editor.org/rfc/rfc9325.html>
- RFC 8996, Deprecating TLS 1.0 and TLS 1.1 - <https://www.rfc-editor.org/rfc/rfc8996.html>
- RFC 8446, TLS 1.3 - <https://www.rfc-editor.org/rfc/rfc8446.html>
- RFC 6890, Special-Purpose IP Address Registries - <https://www.rfc-editor.org/rfc/rfc6890.html>
- NIST SP 800-207, Zero Trust Architecture - <https://csrc.nist.gov/pubs/sp/800/207/final>
- OWASP Transport Layer Security Cheat Sheet - <https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html>
- CWE - <https://cwe.mitre.org/>
