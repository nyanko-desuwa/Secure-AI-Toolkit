# SSH and Server Operations

## Purpose

Give an assistant practical controls for operating a Linux server under pressure: remote access,
least-privilege services, the web edge, safe file transfer, deployment, and incident triage. The
skill prefers removing exposure over decorating it. An sshd behind SSM/IAP or a bastion is safer
than an internet-facing sshd with fail2ban and a different port.

## How It Works

Read `SKILL.md`, establish the access and network boundaries, apply the concrete configurations,
then run `checklist.md`. Supporting files separate decisions from lookup material:

```text
SKILL.md                           workflow, severity, file index
README.md                          this file
checklist.md                       pre-return verification
best-practices.md                  sshd, systemd, nginx, deploy, triage
common-mistakes.md                 tempting failures and fixes
troubleshooting.md                 lockout and compatibility paths
prompts.md                         prompts that produce findings
references/sshd-config-hardening.md directive map and complete config
references/tls-configuration.md     version-pinned TLS values
examples/README.md                 seven vulnerable/fixed pairs
```

## Standards Covered

| Standard | Version | Use here | Verified |
|---|---|---|---|
| OWASP Top 10 | 2025 | A02 misconfiguration, A07 authentication, A08 deploy integrity, A09 logging | 2026-07-28 |
| OWASP ASVS | 5.0.0 | V6 auth, V12 communication, V13 configuration, V16 logging | 2026-07-28 |
| CIS Ubuntu Linux | 24.04 v2.0.0; 22.04 v3.0.0 | SSH, firewall, services, updates, kernel | 2026-07-28 catalogue |
| CIS NGINX | 3.0.0 | TLS and web-server hardening | 2026-07-28 catalogue |
| Mozilla Server Side TLS | 5.7 | TLS protocols and ciphers | 2026-07-28 |

CWE mappings used: CWE-16 (Configuration), CWE-250 (Unnecessary Privilege), CWE-732
(Incorrect Permission Assignment), CWE-295 (Improper Certificate Validation), CWE-345
(Insufficient Verification of Data Authenticity), and CWE-1391 (Weak Credentials).

## Configuration

None. The skill is Markdown and executes nothing. Copy the directory into your assistant's skill
location or keep it readable in the project. Frontmatter limits tools to file reads/writes,
search, web lookup, and `ls`/`cat`.

The example hostnames, addresses, users, and key fragments are placeholders. Replace proxy
subnets and paths before applying. Never copy a vulnerable-labelled block.

## Example Usage

```text
Review /etc/ssh/sshd_config and every file under sshd_config.d. Show the effective value of each
authentication directive, identify lockout risk, and map findings to A07, ASVS V6, and CWE.
```

```text
Harden this systemd service and nginx server block. Preserve only the filesystem paths and Linux
capabilities the process demonstrably needs. Give config tests and a reload sequence.
```

```text
Write an atomic deployment using versioned release directories, a current symlink, a health check,
and one-command rollback. Mark every destructive command immediately before it appears.
```

More in [prompts.md](prompts.md).

## Limitations

- Guidance is not a host audit. It cannot prove the effective config, open sockets, loaded unit,
  package patch level, or firewall rules. Run the verification commands on the target.
- Exact distro paths and service names differ. Debian uses `ssh`; RHEL commonly uses `sshd`.
- Kernel parameters can break routing, containers, IPv6, and asymmetric networks. Apply only the
  controls matching the host role; this skill avoids a universal sysctl dump.
- Header policy is application-specific. A generic CSP can break a site or create false confidence.
- OCSP depends on the issuing CA. Let's Encrypt no longer offers OCSP; another CA may.
- Short-lived SSH certificates require a protected CA and issuance service. A compromised CA has a
  larger blast radius than one stolen static key.
- systemd sandbox directives depend on systemd version and application filesystem needs. Use
  `systemd-analyze security` and test the service.
- A successful health endpoint does not prove application correctness or migration compatibility.
- Incident logs can be altered by root. Off-host logs are required for high-assurance forensics.

## Security Notes

Do not expose SSH publicly when SSM, IAP, a VPN, or a dedicated bastion is available. If it must be
public, restrict source addresses at the cloud firewall and host firewall. Fail2ban and port
changes reduce noise only.

Deployment credentials are single-purpose, short-lived where possible, and never root. Docker
group membership is root-equivalent; the deploy user must not control the Docker daemon. Configure
container log rotation and explicit restart policies.

A compromised host is rebuilt from a known-good image. Triage determines scope and credentials to
rotate; it does not certify the old host as clean.

## References

- OWASP Top 10 2025 — <https://owasp.org/Top10/2025/>
- OWASP ASVS 5.0.0 — <https://owasp.org/www-project-application-security-verification-standard/>
- CIS Benchmarks — <https://www.cisecurity.org/cis-benchmarks>
- OpenSSH manuals — <https://man.openbsd.org/sshd_config>
- Mozilla TLS guidelines 5.7 — <https://ssl-config.mozilla.org/guidelines/5.7.json>
- Nginx documentation — <https://nginx.org/en/docs/>
- systemd execution sandboxing — <https://www.freedesktop.org/software/systemd/man/systemd.exec.html>
