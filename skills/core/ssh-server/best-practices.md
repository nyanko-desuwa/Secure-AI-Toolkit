# Server Hardening Best Practices

Each control names the standard. Replace placeholder paths, users, and subnets.

## Keep SSH private

`A02:2025` · ASVS V12/V13 · CWE-16. Prefer SSM Session Manager, GCP IAP, VPN, or a dedicated
bastion over public SSH. Use `ProxyJump`, not agent forwarding:

```ssh-config
Host app-01
  HostName 10.20.3.14
  User deploy
  ProxyJump bastion
  IdentityFile ~/.ssh/id_ed25519_prod
  IdentitiesOnly yes
  ForwardAgent no
```

A bastion should forward and audit; it should not run application workloads. Port changes and
fail2ban reduce noise, not attack surface.

## Accounts, sudo, and permissions

`A02:2025` · ASVS V13 · CWE-250, CWE-732. Services have no shell and deploy sudo is exact:

```bash
sudo useradd --system --home /nonexistent --shell /usr/sbin/nologin example
sudo install -d -o example -g example -m 0750 /var/lib/example
```

```sudoers
# /etc/sudoers.d/deploy-example; validate with visudo
Defaults:deploy !setenv
deploy ALL=(root) /usr/bin/systemctl reload example.service
```

Never allow a deployer `ALL`, `bash`, `sh`, `vim`, `less`, `python`, `env`, or wildcard arguments.
Set `UMask=027` for services. Private keys are `600`; `.ssh` is `700`; secrets are owner-readable.

## systemd sandbox

`A02:2025` · ASVS V13 · CWE-250. This is a complete hardened unit:

```ini
[Unit]
Description=Example web service
After=network-online.target
Wants=network-online.target
[Service]
Type=exec
User=example
Group=example
ExecStart=/srv/example/current/bin/server --listen 127.0.0.1:8000
WorkingDirectory=/srv/example/current
EnvironmentFile=/etc/example/example.env
Restart=on-failure
RestartSec=5s
UMask=027
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
PrivateDevices=yes
RestrictSUIDSGID=yes
LockPersonality=yes
CapabilityBoundingSet=
AmbientCapabilities=
ReadWritePaths=/var/lib/example /var/cache/example
MemoryMax=512M
TasksMax=128
LimitNOFILE=4096
```

`ReadWritePaths` is an allowlist. Validate with `systemd-analyze verify` and
`systemd-analyze security`; add one narrow exception rather than removing the sandbox.

## Firewall, services, updates, kernel

`A02:2025` · ASVS V13 · CIS Ubuntu · CWE-16. Inventory with `ss -lntup` and enabled units first.

Warning: the following firewall commands can cut off your only session. Confirm the source range
and keep an out-of-band console open.

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow from 198.51.100.0/24 to any port 22 proto tcp
sudo ufw allow 80/tcp && sudo ufw allow 443/tcp
sudo ufw enable && sudo ufw status verbose
```

Warning: disabling a unit can remove a required dependency. Identify it before this command.

```bash
sudo systemctl disable --now unused.service
```

Enable unattended security updates and define a reboot owner/window. Host-role-safe sysctls include
rejecting redirects and source routing; do not apply `ip_forward=0` to routers or container hosts:

```sysctl
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
```

## Transfer and atomic deployment

`A08:2025` · ASVS V13 · CWE-73, CWE-732. Use SFTP for humans, rsync for incremental trees, and
never root SSH. OpenSSH 9.0+ `scp` uses SFTP; `scp -O` is legacy mode.

Warning: `rsync --delete` deletes destination files. Dry-run and inspect first.

```bash
rsync -azn --delete --itemize-changes build/ deploy@app:/srv/example/releases/20260728/
# WARNING: destructive operation follows. Verify source, destination, and dry-run output.
rsync -az --delete --itemize-changes build/ deploy@app:/srv/example/releases/20260728/
```

Build a new release, verify it, health-check, then atomically switch; retain the prior release:

```bash
set -eu
release=/srv/example/releases/20260728183000
mkdir -p "$release"
rsync -az --chown=example:example build/ "$release/"
"$release/bin/server" --check-config
curl --fail --max-time 5 http://127.0.0.1:8000/healthz >/dev/null
ln -sfnT "$release" /srv/example/current
sudo systemctl reload example.service
```

Use expand/contract migrations. Rollback is the same switch to a verified previous release:

```bash
previous=/srv/example/releases/20260727183000
"$previous/bin/server" --check-config
ln -sfnT "$previous" /srv/example/current
sudo systemctl reload example.service
```

Do not drop columns or delete data in the code-switch transaction. Back up destructive migrations.

## Nginx edge

`A02:2025` · ASVS V12/V13 · CWE-16, CWE-345. TLS values belong in the reference file; this block
adds limits, headers, metadata denial, and trusted proxy handling:

```nginx
upstream example_app { server 127.0.0.1:8000; }
server {
  listen 443 ssl http2; server_name example.com; include snippets/tls-intermediate.conf;
  client_max_body_size 10m; client_header_timeout 10s; client_body_timeout 10s; send_timeout 30s;
  keepalive_timeout 30s; server_tokens off; autoindex off;
  add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
  add_header X-Content-Type-Options nosniff always;
  add_header Referrer-Policy strict-origin-when-cross-origin always;
  set_real_ip_from 10.20.0.0/16; real_ip_header X-Forwarded-For; real_ip_recursive on;
  location ~* (^|/)(\.git|\.env|\.svn|\.hg)(/|$) { return 404; }
  location ~ /\.(?!well-known/) { deny all; }
  location / {
    proxy_set_header Host $host; proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme; proxy_pass http://example_app;
    proxy_read_timeout 30s;
  }
}
```

Never trust `X-Forwarded-For` from arbitrary clients. Rate-limit login and expensive routes.

## Docker and incident triage

`A02:2025` · ASVS V13 · CWE-250. Docker group/socket access is root-equivalent; do not give it
to deploy. Do not expose the daemon over unauthenticated TCP. Compose should rotate logs and set
restart policy:

```yaml
services:
  app:
    image: registry.example.com/app@sha256:PLACEHOLDER
    restart: unless-stopped
    logging: {driver: json-file, options: {max-size: "10m", max-file: "5"}}
```

`A09:2025` · ASVS V16. Preserve/export logs before containment, then inspect:

```bash
sudo journalctl -u ssh --since '48 hours ago' --no-pager
sudo journalctl _COMM=sudo --since '48 hours ago' --no-pager
sudo journalctl -p warning..alert --since '48 hours ago' --no-pager
sudo systemctl list-timers --all; sudo getent passwd; sudo ss -lntup
```

Review keys, source addresses, sudo, new users, units, timers, packages, listeners, kernel/OOM,
and time changes. Off-host logs are essential. A credible compromise means credential rotation
and rebuild from a known-good image, not cleaning the host in place.
