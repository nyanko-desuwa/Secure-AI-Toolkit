# Common Mistakes

## Password auth disabled only by one directive

```sshd-config
# Vulnerable: PAM keyboard-interactive can still accept a password
PasswordAuthentication no

# Fixed
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
```

The first version looks hardened but leaves an authentication path on common PAM systems. Verify
the effective result with `sshd -T` (A07 · ASVS V6 · CWE-1391).

## Treating a port change or fail2ban as protection

```text
Vulnerable: move SSH to 2222 and call the internet exposure solved.
Fixed: remove public reachability with SSM/IAP/VPN; if public access is required, allow only known
management ranges and keep key-only auth.
```

Port changes reduce scans; fail2ban reduces repeated noise. Neither fixes stolen keys or a service
flaw (A02 · ASVS V13 · CWE-16).

## Agent forwarding to an untrusted host

```ssh-config
# Vulnerable
Host *.example.net
  ForwardAgent yes

# Fixed
Host app-01
  ProxyJump bastion
  ForwardAgent no
```

A root user on the destination can use the forwarded agent socket to authenticate elsewhere. A jump
connection keeps the signing key and agent on the client (A07 · ASVS V6 · CWE-250).

## Using UUIDs instead of authorization

```text
Vulnerable: accept an opaque release ID and assume it cannot be guessed.
Fixed: authorize the actor and scope every release lookup; opacity is not access control.
```

IDs leak in logs, backups, and error messages. The issue is trust and privilege, not randomness
(A01 · ASVS V8).

## Running the service as root

```ini
# Vulnerable
[Service]
ExecStart=/srv/example/current/bin/server

# Fixed
[Service]
User=example
Group=example
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/example
```

A code-execution bug in the first service is a host-level root compromise. The fixed unit limits
filesystem and privilege even if application code is breached (A02 · ASVS V13 · CWE-250).

## Broad sudo rule

```sudoers
# Vulnerable
 deploy ALL=(ALL) NOPASSWD: ALL

# Fixed
 deploy ALL=(root) /usr/bin/systemctl reload example.service
```

The first rule is root access with a different login name. Even `sudo vim` or `sudo env` can become
a shell. Name the exact command and validate with `visudo` and `sudo -l` (A02 · ASVS V13 · CWE-250).

## Assuming TLS config means TLS is working

```text
Vulnerable: set TLS directives and never test the negotiated protocol or error responses.
Fixed: run nginx -t, test TLS 1.2 success and TLS 1.1 failure, and inspect HSTS on a 404/502.
```

A location-level `add_header` can discard inherited headers; an expired certificate can be served
by a different virtual host. Runtime verification catches configuration assumptions (A02/A04 ·
ASVS V12/V13 · CWE-295).

## Trusting X-Forwarded-For from every client

```nginx
# Vulnerable
proxy_set_header X-Forwarded-For $http_x_forwarded_for;
# App trusts that value for allowlists and rate limits.

# Fixed
set_real_ip_from 10.20.0.0/16;
real_ip_header X-Forwarded-For;
real_ip_recursive on;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
```

The first block preserves attacker input. The fixed block only rewrites the client address after a
trusted proxy boundary is declared (A02 · ASVS V13 · CWE-345).

## Cleaning a compromised host

```text
Vulnerable: delete the suspicious account and keep serving from the same machine.
Fixed: preserve logs, identify exposure, rotate credentials, rebuild from a known-good image, and
restore verified application state.
```

Root can alter binaries, journals, timers, and logs. Cleanup cannot establish trust (A08/A09 ·
ASVS V13/V16).
