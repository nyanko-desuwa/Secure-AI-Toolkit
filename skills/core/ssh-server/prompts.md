# Prompt Examples

Each prompt bounds the host, asks for runtime evidence, and specifies the expected finding shape.

## Review SSH without causing lockout

```text
Read /etc/ssh/sshd_config and sshd_config.d/*.conf. Report the effective authentication and
forwarding values, not only visible lines. For each finding give directive, exploitation path,
A07/ASVS/CWE mapping, exact fix, sshd -t verification, and a two-session reload sequence. Do not
recommend changing access unless an out-of-band path exists.
```

Why it works: it accounts for includes and OpenSSH first-value semantics and demands a recovery
path.

## Design fleet access

```text
Design SSH access for 200 private Linux hosts. Humans authenticate through a bastion with
short-lived user certificates; CI deploys without a shell. Cover CA custody, principals, expiry,
revocation, host certificates, ProxyJump, per-key restrictions, and audit logs. Compare this with
static authorized_keys and state remaining CA compromise risk.
```

## Harden a systemd unit

```text
Review example.service against A02, ASVS V13, CWE-250, and CIS Linux. Produce a complete unit using
an unprivileged account, NoNewPrivileges, ProtectSystem=strict, ProtectHome, PrivateTmp, empty
CapabilityBoundingSet, exact ReadWritePaths, and resource limits. Identify required writes from the
application before selecting paths. Give systemd-analyze verification commands.
```

## Review the web edge

```text
Review this nginx/Apache config for TLS, HSTS, OCSP applicability, size and timeout limits, slowloris,
rate limiting, directory listing, dotfile/.git exposure, version headers, edge security headers,
and reverse-proxy header trust. Report each finding as location, exploit, standard/CWE, fixed config,
and runtime test. Test error responses as well as 200 responses.
```

## Review proxy client-IP trust

```text
Trace the client IP from load balancer through nginx to the application. List which source networks
may set X-Forwarded-For, whether each hop appends or overwrites it, and every security decision that
uses it. Demonstrate a spoofed request and provide a trusted-proxy-only fixed configuration.
```

## Write a safe deployment

```text
Write a deployment for /srv/example using immutable release directories, an atomic current symlink,
pre-switch health check, nginx/systemd syntax checks, zero-downtime reload, and a tested rollback.
Use expand/contract database migrations. Scope CI credentials to upload, switch, and reload only.
Place an immediate warning before every destructive command and dry-run it where possible.
```

## Review file transfer

```text
Compare scp, sftp, and rsync for this 3 GB release tree. Include OpenSSH 9.0's SFTP-backed scp
default, ownership without root SSH, partial transfer/resume, and deletion semantics. If you propose
rsync --delete, show a dry run first and warn immediately before the destructive command.
```

## Triage a suspected compromise

```text
The host may have been compromised at 14:00 UTC. Give read-only journalctl/systemctl/ss commands to
preserve and review SSH successes, key fingerprints, sudo, users, units, timers, boots, package
changes, listeners, kernel, and service logs. Separate evidence collection from containment. End
with credential rotation and rebuild; do not propose cleaning the host in place.
```

## Review Docker operations on a host

```text
Review the deploy user's Docker/Compose privileges. Determine whether docker-group or socket access
is root-equivalent, whether daemon TCP is exposed, and whether logs rotate and restart policies are
explicit. Provide least-privilege changes without making the deploy user the daemon owner.
```

## Anti-patterns

| Prompt | Problem |
|---|---|
| "Secure my server" | No distro, role, exposure, or acceptable downtime |
| "Give me the best sshd_config" | Ignores version, includes, compatibility, and lockout recovery |
| "Hide SSH from hackers" | Produces port-knocking/fail2ban theatre instead of removing exposure |
| "Add all sysctl hardening" | Can break routing, containers, IPv6, and asymmetric networking |
| "Make nginx OWASP compliant" | Top 10 is not a configuration certification |
| "Restart everything after deploy" | Invites downtime and skips syntax/health checks |
| "Clean this hacked server" | Assumes a root-compromised machine can attest to its own cleanliness |
| "Use X-Forwarded-For for the user IP" | Omits who is allowed to set the header |

## Output contract

For reviews, ask for:

```text
Severity · standard and CWE · file:line/directive · exploit or failure path · exact fix · runtime
verification · lockout/downtime/destructive warning · residual limitation
```

A missing exploit path is a hardening opportunity, not automatically a vulnerability. A command
not run is unverified; the answer must say so.
