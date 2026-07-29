# Troubleshooting

## Key-only auth locks out a user

Keep the working session open. Run `sshd -t`, then inspect effective values with `sshd -T -C
user=alice,host=host,addr=198.51.100.10`. Check `journalctl -u ssh` while attempting a second
connection with `ssh -vvv`.

Most failures are ownership or modes:

```bash
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
chmod go-w ~
```

Do not turn `StrictModes` off. Fix the writable path that made key replacement possible
(A07 · ASVS V6 · CWE-732). Also check that the user is in `AllowGroups`, the offered key appears
under `ssh-add -L`, and `IdentitiesOnly=yes` points to it.

## The hardening file is ignored

OpenSSH usually takes the first occurrence of a keyword. A value in an earlier include can beat the
line you added. Inspect `Include` ordering and `sshd -T`; do not append another conflicting value.
A directive accidentally placed after `Match User` applies only inside that match block.

For conditional values use:

```bash
sudo sshd -T -C user=deploy,host=app-01,addr=10.0.4.20
```

## `MaxAuthTries 3` rejects a valid key

An agent with many keys offers each one as an attempt. Do not raise the server limit without first
pinning the identity:

```ssh-config
Host app-01
  IdentitiesOnly yes
  IdentityFile ~/.ssh/id_ed25519_prod
```

This removes accidental offers and leaves the brute-force bound intact (A07 · ASVS V6).

## The host key changed

Stop. Do not delete the known-host entry just to clear the warning. Confirm whether the host was
rebuilt and verify the new fingerprint through a provider console, CMDB, DNS SSHFP with DNSSEC, or
another authenticated channel. An unexplained change is a possible MITM (ASVS V12 · CWE-295).

Once verified, remove only the exact stale entry with `ssh-keygen -R host` and install the confirmed
key. In fleets, use host certificates and a pinned host CA.

## systemd sandbox prevents startup

Read the denial, do not remove every directive:

```bash
systemctl status example.service
journalctl -u example.service -b --no-pager
systemd-analyze security example.service
```

Add the narrow path to `ReadWritePaths=` or an exact capability to `CapabilityBoundingSet=`. If the
service binds port 80, prefer nginx on 80 proxying to an unprivileged high port over granting
`CAP_NET_BIND_SERVICE`. Record any exception (A02 · ASVS V13 · CWE-250).

## Nginx reload fails

A failed `nginx -t` must stop the deploy; the old worker configuration remains active.

```bash
sudo nginx -t
sudo journalctl -u nginx -n 100 --no-pager
sudo nginx -T | less
```

Check duplicate `listen`, missing certificate files, unresolved upstream hostnames, and directives
unsupported by the installed version. Do not restart as a debugging step. Fix syntax, retest, then
`systemctl reload nginx` for zero downtime.

## HSTS or security headers disappear on one route

Nginx stops inheriting parent `add_header` values when a child location declares any `add_header`.
Move all headers to server scope and remove child declarations, or repeat the complete set. Test a
success, 404, and upstream 502; `always` is required for error responses (A02 · ASVS V13).

## Client IP is always the proxy-or is spoofable

Choose one trust boundary. If nginx is internet-facing, `$remote_addr` is the client and input
forwarding headers are untrusted. If a known load balancer is in front, list only its subnet in
`set_real_ip_from` and enable `real_ip_header`. Never use `0.0.0.0/0` as a trusted proxy range.

Verify with a request that supplies a fake header and compare nginx/app logs:

```bash
curl -H 'X-Forwarded-For: 127.0.0.1' https://example.com/whoami
```

The fake value must not become the trusted client identity (A02 · ASVS V13 · CWE-345).

## Rsync ownership needs root

Do not solve this with root SSH. Upload into a deploy-owned staging directory. Use a root-owned
wrapper with fixed source/destination, or `rsync --chown` when the remote account owns the target.
A sudo rule may invoke only that audited wrapper; it must reject paths and flags from the caller
(A02 · ASVS V13 · CWE-250/CWE-732).

## A migration prevents rollback

Code rollback cannot undo a destructive schema change. Stop and restore only from a tested backup
under the database recovery procedure. For the next release, use expand/contract: additive schema,
compatible code, backfill, cutover, and removal in separate deploys. A migration marked "down"
does not mean data lost by `DROP COLUMN` can be reconstructed (A08 · ASVS V13).

## Unattended updates require a reboot

Define ownership rather than disabling updates. Monitor `/var/run/reboot-required` on Debian-family
systems, schedule the reboot, drain traffic, and confirm health afterward. For a singleton, build a
replacement and fail over. A kernel patched on disk but never booted is still vulnerable.

## Suspected compromise but logs look clean

Clean local logs do not establish a clean host. Root can alter journal files and binaries. Check
cloud control-plane, load-balancer, identity-provider, DNS, and external log stores. Snapshot only
if policy permits forensic preservation. Rotate exposed credentials and rebuild from a known-good
image. Do not reconnect restored data before validating it (A09 · ASVS V16).

## Guidance conflicts with the application

State the exact control, breakage, and smallest exception. Do not silently weaken it. Example:
`ProtectSystem=strict` blocks runtime template compilation under `/srv`; move the cache to
`/var/cache/example` and allow that path rather than making `/srv` writable. If no narrow exception
exists, document residual risk and ask the owner to decide.
