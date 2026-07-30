# Server Operations Verification Checklist

Mark each applicable item pass, fail, or not applicable with a reason. Do not mark a file value
pass until the effective running configuration has been checked.

## Exposure and Firewall (A02 · ASVS V13 · CWE-16)

- [ ] [recommended] SSH is absent from the public internet where SSM, IAP, VPN, or a bastion is available
- [ ] [critical] Cloud firewall and host firewall both default-deny inbound traffic
- [ ] [critical] Only 80/443 and the approved management source ranges are allowed
- [ ] [recommended] UFW or nftables rules cover IPv4 and IPv6
- [ ] [recommended] A rule change has an out-of-band recovery path before application
- [ ] [optional] Fail2ban or a nonstandard SSH port is documented as noise reduction, not security
- [ ] [optional] Unused listeners and services were identified before disabling them

## SSH Authentication (A07 · ASVS V6, V12 · CWE-295, CWE-1391)

- [ ] [critical] `PermitRootLogin no` is effective
- [ ] [critical] `PasswordAuthentication no` and `KbdInteractiveAuthentication no` are both effective
- [ ] [critical] `AuthenticationMethods publickey` is effective
- [ ] [recommended] Login is restricted with `AllowUsers` or `AllowGroups`
- [ ] [recommended] User keys are Ed25519 unless a documented compatibility constraint requires otherwise
- [ ] [critical] Host key verification is enabled; automation has a pinned key or trusted host CA
- [ ] [critical] No script uses `StrictHostKeyChecking no` or silently accepts a changed host key
- [ ] [recommended] Agent forwarding is disabled; `ProxyJump` is used instead
- [ ] [recommended] TCP/X11/tunnel forwarding is disabled unless the host's purpose requires it
- [ ] [recommended] Static keys have owner, purpose, and rotation date; stale keys are removed
- [ ] [optional] Fleet access uses short-lived SSH certificates where feasible
- [ ] [recommended] `sshd -t` passes and `sshd -T` confirms includes and first-match values
- [ ] [optional] Existing session stays open until a second login succeeds after reload

## Accounts, Sudo, and Files (A02 · ASVS V13 · CWE-250, CWE-732)

- [ ] [critical] Network services run as unprivileged system accounts with `/usr/sbin/nologin`
- [ ] [recommended] Service accounts are not members of SSH login groups
- [ ] [critical] Sudo rules name exact absolute commands and arguments; no wildcard, editor, shell, or interpreter
- [ ] [critical] Sudo actions are logged and no deploy credential is a root key
- [ ] [recommended] Default umask is `027` for services and deploy paths where group sharing is not required
- [ ] [critical] `.ssh` is `700`; private keys and `authorized_keys` are `600`
- [ ] [critical] Secrets are owner-readable only and are not in environment dumps or command-line arguments
- [ ] [critical] Application code is not writable by its runtime account
- [ ] [recommended] Upload/state paths are the only application-writable directories

## Host Hardening (A02 · ASVS V13 · CWE-16)

- [ ] [recommended] Unused packages and services have been inventoried and disabled deliberately
- [ ] [recommended] Automatic security updates are enabled with reboot/maintenance ownership defined
- [ ] [recommended] Kernel controls match the host role; forwarding is not disabled on a router/container host
- [ ] [recommended] ICMP redirects and source routing are disabled where unsupported by the network design
- [ ] [recommended] Audit and journal retention cannot fill the root filesystem
- [ ] [recommended] Time synchronisation is healthy so logs and certificates are trustworthy

## systemd Sandbox (A02 · ASVS V13 · CWE-250)

- [ ] [critical] `User=` and `Group=` name an unprivileged dedicated account
- [ ] [recommended] `NoNewPrivileges=yes` is set
- [ ] [recommended] `ProtectSystem=strict`, `ProtectHome=yes`, and `PrivateTmp=yes` are set or exceptions explained
- [ ] [recommended] `CapabilityBoundingSet=` and `AmbientCapabilities=` are empty unless exact capabilities are needed
- [ ] [recommended] `ReadWritePaths=` lists only state, cache, and upload paths
- [ ] [recommended] `PrivateDevices=yes`, `ProtectKernelTunables=yes`, and `ProtectControlGroups=yes` are considered
- [ ] [recommended] Memory, task, and file descriptor limits bound resource exhaustion
- [ ] [optional] `systemd-analyze security service.service` was reviewed
- [ ] [recommended] Service starts, writes required state, and reloads successfully under the sandbox

## Web Tier (A02 · A04 · ASVS V12, V13 · CWE-16, CWE-295)

- [ ] [critical] TLS 1.2/1.3 only; certificate chain and hostname validate
- [ ] [recommended] HSTS uses `always`; `includeSubDomains` is enabled only after all subdomains support HTTPS
- [ ] [recommended] OCSP configuration matches the issuing CA and is tested rather than assumed
- [ ] [recommended] Request body and header limits match the application
- [ ] [recommended] Header/body/send/proxy timeouts constrain slow clients and upstream hangs
- [ ] [recommended] Rate limits protect login, expensive, and sensitive routes
- [ ] [critical] Directory listing is off; dotfiles, `.git`, `.env`, and backups return 404/deny
- [ ] [optional] Server version disclosure is reduced and treated as low severity
- [ ] [recommended] Security headers are present on success and error responses
- [ ] [critical] Proxy overwrites forwarding headers and trusts only actual proxy subnets
- [ ] [critical] Application does not use a client-supplied `X-Forwarded-For` for authorization
- [ ] [recommended] `nginx -t` or `apachectl configtest` passes before zero-downtime reload

## File Transfer (A02 · ASVS V13 · CWE-732)

- [ ] [optional] `sftp` is preferred for interactive transfer; `rsync` for incremental trees
- [ ] [optional] Legacy `scp -O` is not used without a compatibility reason
- [ ] [recommended] Every `rsync --delete` has an immediately preceding dry run and destination review
- [ ] [critical] Transfer does not preserve attacker-controlled owner/group or require a root login
- [ ] [recommended] Ownership is set by a restricted deploy step or directory policy, not remote root

## Deployment (A08 · ASVS V13 · CWE-250)

- [ ] [recommended] Release artefact is immutable, versioned, and verified before activation
- [ ] [recommended] `current` switch is atomic and previous release remains available
- [ ] [recommended] Health check runs before traffic is declared healthy
- [ ] [recommended] Reload is zero-downtime and configuration syntax is checked first
- [ ] [recommended] Database migration is backward compatible for at least one application release
- [ ] [critical] Destructive migration has a tested backup and separate approval
- [ ] [recommended] Rollback command has been exercised and does not depend on rebuilding
- [ ] [critical] Deployment credential can upload/switch/reload only, not obtain a shell or root

## Docker and Compose (A02 · ASVS V13 · CWE-250)

- [ ] [critical] Deploy user is not in the `docker` group and cannot reach the Docker socket
- [ ] [critical] Daemon is not exposed over unauthenticated TCP
- [ ] [recommended] Container logs rotate (`max-size`, `max-file`) and cannot fill the host
- [ ] [optional] Restart policy is explicit (`unless-stopped` or `on-failure`), not omitted blindly
- [ ] [critical] Containers do not run privileged and drop unnecessary capabilities

## Incident Triage (A09 · ASVS V16)

- [ ] [recommended] Logs were preserved/exported before investigative commands changed evidence
- [ ] [recommended] SSH successes, failures, key fingerprints, sudo, new users, units, timers, and package changes reviewed
- [ ] [recommended] Unexpected boots, kernel messages, OOM, network failures, and time changes reviewed
- [ ] [critical] Credentials used from or stored on the host are inventoried for rotation
- [ ] [recommended] Rebuild from a known-good image is planned; "clean in place" is not the remediation
- [ ] [recommended] Off-host logs are checked because a root attacker can alter local journal data

## Before Returning

- [ ] [critical] Every destructive command has an immediate warning and safer preview/backup step
- [ ] [recommended] Commands and paths match the stated distribution
- [ ] [critical] Tests performed and output reported honestly
- [ ] [critical] Unknown runtime state is stated as unknown
