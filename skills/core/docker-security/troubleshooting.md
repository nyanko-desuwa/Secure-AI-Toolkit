# Troubleshooting

What to do when the hardening breaks the container, or when the guidance cannot be applied.

## The container will not start after `USER 10001`

Read the error before changing anything. Three distinct causes look the same.

- `Permission denied` on a path under the app directory — the files are owned by root. Fix with
  `COPY --chown=10001:10001`, not by reverting `USER`.
- `Permission denied` binding a port — the port is below 1024. Listen on 8080 and map it with
  `-p 80:8080`. Adding `NET_BIND_SERVICE` back also works and is the weaker option, because it keeps
  a capability you do not need.
- `unable to find user app` — `USER` used a name that does not exist in the base image's
  `/etc/passwd`. Use the numeric UID.

If a writable path is genuinely required, mount a volume owned by that UID rather than widening
permissions in the image. `chmod 777` in a Dockerfile is a finding on its own (CWE-732).

## `--read-only` breaks the application

Do not guess which paths it needs. Run it and collect the failures:

```bash
docker run --rm --read-only myimage 2>&1 | grep -iE 'read-only|EROFS|permission'
```

Then add the narrowest writable mounts:

```bash
--tmpfs /tmp:rw,noexec,nosuid,size=64m \
--tmpfs /var/run:rw,noexec,nosuid,size=8m \
-v app_cache:/app/.cache
```

Known offenders: Python `__pycache__` (set `PYTHONDONTWRITEBYTECODE=1` instead of a mount), JVM
`/tmp/hsperfdata_*` (or `-XX:-UsePerfData`), nginx `/var/cache/nginx` and `/var/run`, Next.js
`.next/cache`.

If the application writes to its own installation directory and cannot be configured otherwise,
`--read-only` is not achievable. Say that, and compensate: non-root UID, dropped capabilities,
`no-new-privileges`, and no bind mount of a host path the host executes from.

## Dropping capabilities breaks the entrypoint

Entrypoints that `chown` a data directory and then `su-exec` to an app user need `CHOWN`, `SETUID`,
`SETGID`, and often `DAC_OVERRIDE`. That is a large fraction of what you just dropped.

Better answer: remove the need. Build the image so the files are already owned correctly and start as
the app user directly, so the entrypoint has nothing privileged to do. Where the entrypoint belongs to
an upstream image you do not control, add back exactly those four and write down why.

To find which capability is missing, run with `--cap-drop=ALL` and read the `EPERM`. Adding
capabilities one at a time until it works is slow but produces a defensible minimum set. Do not skip
to `--privileged` to "find out later".

## A CIS control does not apply to your platform

Sections 1 and 3 assume a Linux host with systemd and auditd. On Docker Desktop, a managed runtime,
or Fargate you do not control the daemon, the unit files, or the audit rules.

Report it as not applicable with the reason, and note who does own it. "CIS 3.15/3.16 are the
platform provider's responsibility on ECS Fargate; we cannot verify them" is a complete answer.
Marking them pass is not.

Section 4 and 5 controls still apply everywhere, because they are properties of your image and your
task definition.

## Rootless Docker cannot bind port 80

Expected. Unprivileged users cannot bind below 1024.

Options, in order of preference: publish 8080 and terminate TLS in a reverse proxy that runs
elsewhere; use `--privileged`-free port forwarding via the host's own load balancer; or lower
`net.ipv4.ip_unprivileged_port_start` on the host, which weakens a host-wide protection for every
process, not just yours. Prefer the proxy.

Other rootless friction worth knowing before committing: slirp4netns or pasta networking is slower
than the bridge, some storage drivers are unavailable, cgroup v2 with delegation is required for
`--memory` and `--cpus` to work at all, and NFS-backed home directories cause storage errors.

## The container genuinely needs the docker socket

Almost always this is a CI runner or a container-management UI. Work through the alternatives in
[best-practices.md](best-practices.md#the-docker-socket) first — a dedicated build host, rootless
BuildKit, Kaniko, or a DinD sidecar on a private network.

If none is possible, the position to take is: this container is a host-root-equivalent trust zone.
That means only trusted code runs in it (no builds from fork pull requests), a socket proxy with an
explicit endpoint allowlist sits in front, the container is on an isolated network with no inbound
exposure, and the arrangement is recorded as an accepted risk with an owner. Do not describe it as
mitigated. CIS 5.32 is failed and the honest report says so.

## Scanner findings with no fix available

`ignore-unfixed` in the gate, tracked in the report. There is no action to take on an unfixed CVE
except to know it is there.

If it is unfixed and reachable and critical, the real options are: change base image (a distroless or
Alpine base often does not contain the package at all), remove the dependency, or add a compensating
control at the network or capability layer. Blocking the build changes nothing about the risk.

## Two scanners disagree

Normal. Trivy and Grype use different vulnerability databases and different version-matching logic,
so one will report findings the other does not, and both produce false positives on backported
distro patches.

Do not average them. Pick one as the gate so the pipeline behaviour is predictable, and treat the
second as a cross-check at release time. When they disagree on a specific package, read the upstream
advisory and the distro's changelog — the distro backport is usually the reason.

## Digest pinning conflicts with a multi-arch build

Pinning a platform-specific digest breaks `--platform` for other architectures. Pin the digest of the
manifest list instead — `docker buildx imagetools inspect <tag> --format '{{.Manifest.Digest}}'`
returns the list digest when the tag is multi-arch.

If your registry or mirror does not preserve manifest lists, digest pinning per architecture with
separate Dockerfiles is the fallback. State the extra maintenance rather than dropping the pin
silently.

## The hardened config conflicts with a project requirement

Report the conflict rather than weakening the control quietly:

1. What the current configuration does
2. What the hardened version changes
3. What breaks, and for whom
4. The migration path

Then ask. Removing `--network=host` from a working deployment can break service discovery in ways
that are not obvious from the compose file.

## You cannot verify runtime configuration from the repository

Common and worth stating. A correct compose file does not prove production runs it, and a Dockerfile
says nothing about the `docker run` flags a deploy script uses.

Report what you read and what you could not see. "Dockerfile and compose.yaml are hardened; I could
not verify the production task definition or the daemon configuration" is useful. Implying the whole
deployment is hardened because two files are is not.

## Sources

- <https://docs.docker.com/engine/security/rootless/>
- <https://docs.docker.com/reference/cli/docker/container/run/>
- <https://github.com/docker/docker-bench-security>
- <https://trivy.dev/> · <https://github.com/anchore/grype>
