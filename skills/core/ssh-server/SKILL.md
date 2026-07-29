---
name: ssh-server
description: 'Operate a Linux server safely: SSH access, sshd hardening, systemd sandboxing, nginx/Apache TLS and headers, firewalls, and deployments that roll back. Maps to OWASP Top 10 2025 A02/A07, ASVS 5.0 V12/V13, and CIS Benchmarks. Triggers: "ssh", "sshd_config", "nginx", "systemd", "deploy", "server hardening", "bastion", "máy chủ", "triển khai".'
allowed-tools: Read, Glob, Grep, WebSearch, WebFetch
---

# SSH and Server Operations

Running a Linux box that holds production without handing out root.

## When to Use

- Writing or reviewing `sshd_config`, `ssh_config`, or an `authorized_keys` deployment
- Setting up remote access: keys, bastions, jump hosts, SSH certificates, CI access
- Writing a systemd unit for a service that faces the network
- Configuring nginx or Apache: TLS, headers, rate limits, reverse proxy
- Writing or reviewing a deploy script, especially one that runs migrations or restarts a service
- Triaging a host after a suspected compromise
- Setting a firewall default, sudo rule, or file mode on a server

## The Four Surfaces

A server gets compromised through one of four doors. They are independent; sealing one does not
seal the others.

| Surface | The question | Standards |
|---|---|---|
| Remote access | Who can get a shell, and with what key? | A07:2025 · ASVS V6, V12 · CIS 5.x |
| Process privilege | What can the service do once it starts? | A02:2025 · CWE-250 · CIS 1.x, 4.x |
| Web edge | What does an unauthenticated request reach? | A02:2025 · ASVS V12, V13 · CIS NGINX |
| Deploy path | Who or what can push code, and can it be undone? | A08:2025 · ASVS V13 |

Most real intrusions are not an sshd exploit. They are a leaked deploy key, a service running as
root, or an nginx block that serves `.git`. Weight your attention accordingly.

## Workflow

### 1. Establish who needs access, and to what

Before editing config, write down the actual access needs. Three columns: principal, what they
do, minimum privilege that allows it.

Most answers collapse. "The deploy pipeline needs to restart the app" does not need a root key -
it needs one sudo rule for one systemctl verb. "The developer needs to read logs" does not need
a shell on the box if logs ship to a collector.

If SSH can be removed from the internet entirely - a bastion, AWS SSM Session Manager, GCP
IAP TCP forwarding, Tailscale/WireGuard - do that first. It is worth more than every directive
in this skill combined, because an sshd that is not reachable cannot be attacked. See
[best-practices.md](best-practices.md#do-not-expose-sshd-to-the-internet).

### 2. Harden access

Key-only auth, no root login, explicit `AllowUsers` or `AllowGroups`. Work line by line from
[references/sshd-config-hardening.md](references/sshd-config-hardening.md), which says what each
directive buys rather than just listing it.

Then verify against the running daemon, not the file:

```bash
sudo sshd -T | grep -Ei 'permitrootlogin|passwordauthentication|kbdinteractive|allowusers|permitemptypasswords'
```

`sshd -T` prints the effective configuration after includes and defaults. A directive placed
below a `Match` block, or after an earlier occurrence of the same keyword, does not do what the
file looks like it does - first occurrence wins in OpenSSH.

### 3. Confine the service

Nothing that serves traffic runs as root. Give it a system account with no shell, then sandbox it
with systemd: `NoNewPrivileges=`, `ProtectSystem=strict`, `PrivateTmp=`, `ProtectHome=`,
`CapabilityBoundingSet=`, and an explicit `ReadWritePaths=` allowlist. Full unit in
[best-practices.md](best-practices.md#systemd-as-a-sandbox).

This is the highest-value, least-used control on the list. A sandboxed unit turns "RCE in the app"
into "RCE inside a read-only filesystem with no capabilities and no route to `/home`".

### 4. Configure the edge

TLS from a generated profile, not from memory. Security headers, request size limits, timeouts,
rate limits, no directory listing, no dotfiles served, no version banner. Values in
[references/tls-configuration.md](references/tls-configuration.md), the server block in
[best-practices.md](best-practices.md#nginx-server-block).

Check what the proxy trusts. If the app reads `X-Forwarded-For` and nginx does not overwrite it,
every client sets their own IP - and your rate limiter, audit log, and IP allowlist all become
decorative.

### 5. Make the deploy reversible

Atomic symlink switch, health check before the switch takes traffic, and a rollback that is one
command against a release that is still on disk. Migrations run separately from the code swap and
are backward compatible for one release. See
[best-practices.md](best-practices.md#atomic-deploys-and-rollback).

### 6. Verify

Run [checklist.md](checklist.md). State what you could not check - reading a config file does not
prove the daemon reloaded it, and this skill cannot run commands on the target host.

## Severity

Rank by what an attacker gains, not by which directive is missing.

- **Critical** - password auth on an internet-facing sshd, root login permitted, a service running
  as root with a network listener, a deploy key with root or full-account scope, `.git` or `.env`
  served over HTTP
- **High** - agent forwarding to an untrusted host, `StrictHostKeyChecking no` in an automated
  path, sudo rule granting a shell or a wildcard command, spoofable `X-Forwarded-For` trusted for
  access control, TLS 1.0/1.1 enabled
- **Medium** - no rate limiting, missing HSTS, no unattended security updates, world-readable
  secret file, no log rotation on a disk that fills
- **Low** - version banner exposed, SSH on port 22, no fail2ban. These are noise reduction, not
  controls

Say which it is. "SSH on port 22" reported as high severity is how a report gets ignored.

## Destructive Commands

This skill contains commands that delete data or cut access. Every one is marked. The three that
end careers:

- `rsync --delete` - deletes on the destination. Dry-run first, always
- Reloading sshd with a broken config, having closed your only session
- `systemctl disable` on something you did not identify

Read the warning before running the command, not after.

## After a Compromise

A host you believe was compromised is rebuilt from a known-good image, not cleaned. Rotate every
credential that touched it. `journalctl` triage exists to learn what happened and what else to
rotate - not to decide the box is fine now. See
[best-practices.md](best-practices.md#incident-triage-with-journalctl).

## Related Skills

- `docker-security` - container images and runtime, if the service runs in a container
- `secrets-management` - where deploy keys and TLS private keys actually live
- `devsecops` - CI/CD pipeline permissions and the credentials it holds
- `cloud-security` - security groups, IAM, and SSM/IAP as an SSH replacement
- `logging-audit` - shipping and retaining what `journalctl` shows you

## Supporting Files

- [README.md](README.md) - purpose, standards table, limitations, security notes
- [checklist.md](checklist.md) - pre-return verification, grouped by surface
- [best-practices.md](best-practices.md) - real configs: sshd, systemd, nginx, deploy
- [common-mistakes.md](common-mistakes.md) - what goes wrong and why the fix works
- [troubleshooting.md](troubleshooting.md) - when the hardening breaks the thing
- [prompts.md](prompts.md) - prompts that produce findings
- [references/](references/) - version-pinned standard summaries
- [examples/](examples/) - vulnerable and fixed configs side by side
