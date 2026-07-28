# Server Operations Verification Checklist

Mark each applicable item pass, fail, or not applicable with a reason. Do not mark a file value
pass until the effective running configuration has been checked.

## Exposure and Firewall (A02 · ASVS V13 · CWE-16)

- [ ] SSH is absent from the public internet where SSM, IAP, VPN, or a bastion is available
- [ ] Cloud firewall and host firewall both default-deny inbound traffic
- [ ] Only 80/443 and the approved management source ranges are allowed
- [ ] UFW or nftables rules cover IPv4 and IPv6
- [ ] A rule change has an out-of-band recovery path before application
- [ ] Fail2ban or a nonstandard SSH port is documented as noise reduction, not security
- [ ] Unused listeners and services were identified before disabling them

## SSH Authentication (A07 · ASVS V6, V12 · CWE-295, CWE-1391)

- [ ] `PermitRootLogin no` is effective
- [ ] `PasswordAuthentication no` and `KbdInteractiveAuthentication no` are both effective
- [ ] `AuthenticationMethods publickey` is effective
- [ ] Login is restricted with `AllowUsers` or `AllowGroups`
- [ ] User keys are Ed25519 unless a documented compatibility constraint requires otherwise
- [ ] Host key verification is enabled; automation has a pinned key or trusted host CA
- [ ] No script uses `StrictHostKeyChecking no` or silently accepts a changed host key
- [ ] Agent forwarding is disabled; `ProxyJump` is used instead
- [ ] TCP/X11/tunnel forwarding is disabled unless the host's purpose requires it
- [ ] Static keys have owner, purpose, and rotation date; stale keys are removed
- [ ] Fleet access uses short-lived SSH certificates where feasible
- [ ] `sshd -t` passes and `sshd -T` confirms includes and first-match values
- [ ] Existing session stays open until a second login succeeds after reload

## Accounts, Sudo, and Files (A02 · ASVS V13 · CWE-250, CWE-732)

- [ ] Network services run as unprivileged system accounts with `/usr/sbin/nologin`
- [ ] Service accounts are not members of SSH login groups
- [ ] Sudo rules name exact absolute commands and arguments; no wildcard, editor, shell, or interpreter
- [ ] Sudo actions are logged and no deploy credential is a root key
- [ ] Default umask is `027` for services and deploy paths where group sharing is not required
- [ ] `.ssh` is `700`; private keys and `authorized_keys` are `600`
- [ ] Secrets are owner-readable only and are not in environment dumps or command-line arguments
- [ ] Application code is not writable by its runtime account
- [ ] Upload/state paths are the only application-writable directories

## Host Hardening (A02 · ASVS V13 · CWE-16)

- [ ] Unused packages and services have been inventoried and disabled deliberately
- [ ] Automatic security updates are enabled with reboot/maintenance ownership defined
- [ ] Kernel controls match the host role; forwarding is not disabled on a router/container host
- [ ] ICMP redirects and source routing are disabled where unsupported by the network design
- [ ] Audit and journal retention cannot fill the root filesystem
- [ ] Time synchronisation is healthy so logs and certificates are trustworthy

## systemd Sandbox (A02 · ASVS V13 · CWE-250)

- [ ] `User=` and `Group=` name an unprivileged dedicated account
- [ ] `NoNewPrivileges=yes` is set
- [ ] `ProtectSystem=strict`, `ProtectHome=yes`, and `PrivateTmp=yes` are set or exceptions explained
- [ ] `CapabilityBoundingSet=` and `AmbientCapabilities=` are empty unless exact capabilities are needed
- [ ] `ReadWritePaths=` lists only state, cache, and upload paths
- [ ] `PrivateDevices=yes`, `ProtectKernelTunables=yes`, and `ProtectControlGroups=yes` are considered
- [ ] Memory, task, and file descriptor limits bound resource exhaustion
- [ ] `systemd-analyze security service.service` was reviewed
- [ ] Service starts, writes required state, and reloads successfully under the sandbox

## Web Tier (A02 · A04 · ASVS V12, V13 · CWE-16, CWE-295)

- [ ] TLS 1.2/1.3 only; certificate chain and hostname validate
- [ ] HSTS uses `always`; `includeSubDomains` is enabled only after all subdomains support HTTPS
- [ ] OCSP configuration matches the issuing CA and is tested rather than assumed
- [ ] Request body and header limits match the application
- [ ] Header/body/send/proxy timeouts constrain slow clients and upstream hangs
- [ ] Rate limits protect login, expensive, and sensitive routes
- [ ] Directory listing is off; dotfiles, `.git`, `.env`, and backups return 404/deny
- [ ] Server version disclosure is reduced and treated as low severity
- [ ] Security headers are present on success and error responses
- [ ] Proxy overwrites forwarding headers and trusts only actual proxy subnets
- [ ] Application does not use a client-supplied `X-Forwarded-For` for authorization
- [ ] `nginx -t` or `apachectl configtest` passes before zero-downtime reload

## File Transfer (A02 · ASVS V13 · CWE-732)

- [ ] `sftp` is preferred for interactive transfer; `rsync` for incremental trees
- [ ] Legacy `scp -O` is not used without a compatibility reason
- [ ] Every `rsync --delete` has an immediately preceding dry run and destination review
- [ ] Transfer does not preserve attacker-controlled owner/group or require a root login
- [ ] Ownership is set by a restricted deploy step or directory policy, not remote root

## Deployment (A08 · ASVS V13 · CWE-250)

- [ ] Release artefact is immutable, versioned, and verified before activation
- [ ] `current` switch is atomic and previous release remains available
- [ ] Health check runs before traffic is declared healthy
- [ ] Reload is zero-downtime and configuration syntax is checked first
- [ ] Database migration is backward compatible for at least one application release
- [ ] Destructive migration has a tested backup and separate approval
- [ ] Rollback command has been exercised and does not depend on rebuilding
- [ ] Deployment credential can upload/switch/reload only, not obtain a shell or root

## Docker and Compose (A02 · ASVS V13 · CWE-250)

- [ ] Deploy user is not in the `docker` group and cannot reach the Docker socket
- [ ] Daemon is not exposed over unauthenticated TCP
- [ ] Container logs rotate (`max-size`, `max-file`) and cannot fill the host
- [ ] Restart policy is explicit (`unless-stopped` or `on-failure`), not omitted blindly
- [ ] Containers do not run privileged and drop unnecessary capabilities

## Incident Triage (A09 · ASVS V16)

- [ ] Logs were preserved/exported before investigative commands changed evidence
- [ ] SSH successes, failures, key fingerprints, sudo, new users, units, timers, and package changes reviewed
- [ ] Unexpected boots, kernel messages, OOM, network failures, and time changes reviewed
- [ ] Credentials used from or stored on the host are inventoried for rotation
- [ ] Rebuild from a known-good image is planned; "clean in place" is not the remediation
- [ ] Off-host logs are checked because a root attacker can alter local journal data

## Before Returning

- [ ] Every destructive command has an immediate warning and safer preview/backup step
- [ ] Commands and paths match the stated distribution
- [ ] Tests performed and output reported honestly
- [ ] Unknown runtime state is stated as unknown
