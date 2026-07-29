# sshd_config Hardening

What to set, and why. Verified 2026-07-28 against OpenSSH release notes
(<https://www.openssh.org/releasenotes.html>) and the CIS Benchmarks catalogue.

## Version notes

| Change | Version | Date |
|---|---|---|
| `scp` uses SFTP by default; `-O` restores legacy mode | 9.0 | 2022-04-08 |
| Strict KEX/Terrapin countermeasures | 9.6 | 2023-12-18 |
| `sshd-session` split; `PerSourcePenalties` enabled | 9.8 | 2024-07-01 |
| Hybrid post-quantum KEX introduced | 9.9 | 2024-09-19 |
| DSA removed; `sshd-auth` split; hybrid KEX default | 10.0 | 2025-04-09 |

Do not add a hand-written `KexAlgorithms` line merely to sound modern. It can remove safe
vendor defaults. Check the installed version and effective configuration first.

```bash
sshd -V 2>&1 | head -1
sudo sshd -T | grep -Ei 'permitroot|password|kbdinteractive|allowgroups|authenticationmethods'
```

## Hardened server configuration

Place this in `/etc/ssh/sshd_config.d/10-hardening.conf` where the main file includes that
directory. OpenSSH uses the first value encountered for most keywords. Inspect `sshd -T`; do not
assume the last visible line wins.

```sshd-config
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
PubkeyAuthentication yes
AuthenticationMethods publickey
MaxAuthTries 3
LoginGraceTime 30
AllowGroups ssh-users
AuthorizedKeysFile .ssh/authorized_keys
StrictModes yes
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
GatewayPorts no
PermitTunnel no
ClientAliveInterval 300
ClientAliveCountMax 2
MaxSessions 4
MaxStartups 10:30:60
TCPKeepAlive no
PrintLastLog yes
DebianBanner no
LogLevel VERBOSE
```

## Directive map

| Directive | Security gain |
|---|---|
| `PermitRootLogin no` | Forces attributable user-plus-sudo administration; removes a known account (CWE-250). |
| `PasswordAuthentication no` + `KbdInteractiveAuthentication no` | Removes password and PAM keyboard-interactive guessing (A07 · ASVS V6 · CWE-1391). |
| `AuthenticationMethods publickey` | Positively requires a key; a future auth module is not silently accepted. |
| `MaxAuthTries`, `LoginGraceTime`, `MaxStartups` | Bounds guesses, unauthenticated slots, and slow connections. |
| `AllowGroups ssh-users` | Denies SSH by default to service accounts and new users (A01 · ASVS V8). |
| `StrictModes yes` | Rejects keys in writable homes or `.ssh` directories (CWE-732). |
| `AllowAgentForwarding no` | Stops a remote host using the forwarded agent to authenticate elsewhere. |
| `AllowTcpForwarding no` | Prevents unapproved tunnels; enable only on a dedicated bastion. |
| `X11Forwarding no`, `PermitTunnel no` | Removes unused channels. |
| `ClientAlive*` | Reaps abandoned sessions using encrypted probes (ASVS V7). |
| `LogLevel VERBOSE` | Records public-key fingerprints for attribution (A09 · ASVS V16). |

`fail2ban` and changing port 22 reduce scanner noise. They are not security controls. OpenSSH
9.8+ also provides built-in source throttling through `PerSourcePenalties`.

## Key hygiene and certificates

Use Ed25519 user keys:

```bash
ssh-keygen -t ed25519 -a 64 -f ~/.ssh/id_ed25519 -C "alice@example.com"
```

Private keys mode `600`; `.ssh` `700`; `authorized_keys` `600`; home not group-writable; host
private keys root-owned and `600`. Comment each key with owner and expiry.

For fleets, trust a user CA and issue short-lived certificates:

```bash
# Run in the protected CA service; 8-hour certificate for the deploy principal.
ssh-keygen -s /secure/user_ca -I "alice@example.com" -n deploy -V +8h \
  -O clear -O permit-pty ~/.ssh/id_ed25519.pub
```

```sshd-config
TrustedUserCAKeys /etc/ssh/user_ca.pub
AuthorizedPrincipalsFile /etc/ssh/principals/%u
RevokedKeys /etc/ssh/revoked_keys
```

A static key has no expiry. An eight-hour certificate limits a theft window and revocation becomes
"stop issuing", not an edit on every host (A07 · ASVS V6 · CWE-798). Keep the CA private key
offline or in an HSM/KMS.

## Safe reload

```bash
sudo sshd -t
sudo systemctl reload ssh       # sshd on RHEL-family
# Keep the current session. From a second terminal:
ssh -o IdentitiesOnly=yes -i ~/.ssh/id_ed25519 alice@host 'echo ok'
```

Never close the existing session until the second login succeeds. Know the serial console, SSM,
IAP, or provider console before changing access. `ProxyJump` keeps keys on the client; agent
forwarding exposes their use on the remote host.

## Sources

- OpenSSH release notes - <https://www.openssh.org/releasenotes.html>, checked 2026-07-28
- `sshd_config(5)` - <https://man.openbsd.org/sshd_config>
- CIS Benchmarks - <https://www.cisecurity.org/cis-benchmarks>, Ubuntu 24.04 v2.0.0 and Ubuntu
  22.04 v3.0.0, checked 2026-07-28
- OWASP ASVS 5.0.0 - <https://owasp.org/www-project-application-security-verification-standard/>
