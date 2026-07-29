# SSH and Server Examples

Seven vulnerable/fixed pairs. Every example names its category and CWE. Vulnerable blocks are
deliberate; do not copy them.

## StrictHostKeyChecking no in CI

`A04:2025` · ASVS V12 · CWE-295

```yaml
# Vulnerable: accepts whichever machine answers as production
- run: ssh -o StrictHostKeyChecking=no deploy@prod.example.com deploy
```

```yaml
# Fixed: CI receives the expected host key through a protected variable
- run: |
    install -d -m 700 ~/.ssh
    printf '%s\n' "$PROD_SSH_KNOWN_HOSTS" > ~/.ssh/known_hosts
    chmod 600 ~/.ssh/known_hosts
    ssh -o BatchMode=yes -o StrictHostKeyChecking=yes deploy@prod.example.com deploy
```

Why this works: the server must prove possession of the pinned host key. `ssh-keyscan` inside the
same untrusted job is the tempting wrong fix; it pins the MITM that is answering right now.

---

## systemd unit running as root

`A02:2025` · ASVS V13 · CWE-250

```ini
# Vulnerable: User omitted means root; the network app owns the host on RCE
[Service]
ExecStart=/srv/example/server --listen 0.0.0.0:8000
```

```ini
# Fixed: unprivileged account and a read-only host filesystem
[Service]
User=example
Group=example
ExecStart=/srv/example/server --listen 127.0.0.1:8000
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
CapabilityBoundingSet=
ReadWritePaths=/var/lib/example
```

Why this works: compromised application code has neither root privilege nor general write access.
A container alone is not the fix; a root/privileged container with the host socket is root too.

---

## Spoofable X-Forwarded-For trust

`A02:2025` · ASVS V13 · CWE-345

```nginx
# Vulnerable: preserves attacker input; app trusts it for admin IP allowlisting
proxy_set_header X-Forwarded-For $http_x_forwarded_for;
```

```nginx
# Fixed: only the actual load-balancer subnet may supply the prior hop
set_real_ip_from 10.20.0.0/16;
real_ip_header X-Forwarded-For;
real_ip_recursive on;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
```

Why this works: the first untrusted address is retained as the client. `set_real_ip_from 0.0.0.0/0`
is the tempting wrong fix; it makes every attacker a trusted proxy. IP is still a weak identity and
should not be the sole authorization control.

---

## Nginx serves `.git`

`A02:2025` · ASVS V13 · CWE-552

```nginx
# Vulnerable: repository metadata sits beneath the served root
server {
  root /srv/example/current;
  location / { try_files $uri $uri/ =404; }
}
```

```nginx
# Fixed: build artefacts are separate and metadata/dotfiles are denied
server {
  root /srv/example/current/public;
  autoindex off;
  location ~* (^|/)(\.git|\.env|\.svn|\.hg)(/|$) { return 404; }
  location ~ /\.(?!well-known/) { deny all; }
  location / { try_files $uri $uri/ =404; }
}
```

Why this works: the web root contains only publishable artefacts and a backstop rejects metadata.
Removing directory listing alone does not help; a client can request `/.git/config` directly.

---

## Overbroad sudo rule

`A02:2025` · ASVS V13 · CWE-250

```sudoers
# Vulnerable: deploy has passwordless root and can start a shell
 deploy ALL=(ALL) NOPASSWD: ALL
```

```sudoers
# Fixed: exact executable, verb, and unit; environment cannot be injected
Defaults:deploy !setenv
 deploy ALL=(root) /usr/bin/systemctl reload example.service
```

Why this works: the credential performs the one deploy action. Allowing `vim`, `less`, `python`,
`env`, a shell, or wildcard arguments still grants a route to arbitrary root execution.

---

## `rsync --delete` without a dry run

`A08:2025` · ASVS V13 · CWE-73

Warning: the vulnerable command below deletes destination files immediately and must not be run.

```bash
# Vulnerable: a wrong slash or destination deletes production files immediately
rsync -az --delete build/ deploy@app:/srv/example/current/
```

```bash
# Fixed: preview exact deletions against a new release directory
rsync -azn --delete --itemize-changes build/ deploy@app:/srv/example/releases/20260728/
# WARNING: destructive operation follows. Verify source, destination, trailing slashes, and dry run.
rsync -az --delete --itemize-changes build/ deploy@app:/srv/example/releases/20260728/
```

Why this works: the operator sees every deletion before it occurs, and an immutable new release
limits the blast radius. A backup is not a substitute for the preview; both are appropriate.

---

## Deployment credential has root access

`A07:2025` · ASVS V6/V13 · CWE-250, CWE-798

```text
# Vulnerable: long-lived CI private key logs in directly as root
root@host:~/.ssh/authorized_keys
ssh root@host /usr/local/bin/deploy
```

```text
# Fixed authorized_keys entry for a non-root account
restrict,command="/usr/local/bin/deploy-receive",from="198.51.100.0/24" ssh-ed25519 AAAAC3Nz... ci-deploy
```

```sudoers
# If reload truly requires root, grant only that operation
 deploy ALL=(root) /usr/bin/systemctl reload example.service
```

Why this works: theft grants one source-bound command, no PTY, forwarding, or arbitrary root shell.
Prefer an eight-hour SSH certificate over the static key; source restrictions do not help when the
CI runner itself is compromised.

## Sources

- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>
- OWASP ASVS 5.0.0 - <https://owasp.org/www-project-application-security-verification-standard/>
- CWE - <https://cwe.mitre.org/>
