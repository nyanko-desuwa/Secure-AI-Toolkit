# Common Mistakes

What goes wrong, why it goes wrong, and why the fix actually works. These are the failures that
survive code review because they look finished.

## Deleting a secret in a later layer

```dockerfile
COPY id_rsa /root/.ssh/id_rsa
RUN git clone git@github.com:myorg/private.git
RUN rm -rf /root/.ssh
```

Written by someone who understood the problem and picked the wrong mechanism. Layers are additive.
The `rm` creates a whiteout entry in a new layer; the earlier layer still contains the key, and
anyone who pulls the image can extract it:

```bash
docker save myimage | tar -xO --wildcards '*/layer.tar' | tar -tv | grep id_rsa
```

Fix: `RUN --mount=type=secret,id=sshkey,target=/root/.ssh/id_rsa git clone ...`, or do the clone in a
discarded build stage. Why it works: with BuildKit the file exists on a tmpfs for one instruction and
is never written into any layer, so there is nothing to recover.

If the image was already pushed, rotate the key. Layers are content-addressed and may be mirrored or
already pulled; deleting the tag does not un-publish the bytes.

## `USER` set before the files it needs to write

```dockerfile
USER 10001
RUN pip install -r requirements.txt        # permission denied on site-packages
COPY . /app                                # copied as root anyway
```

`COPY` ignores `USER` — it copies as root unless told otherwise. Meanwhile `RUN` after `USER` loses
the ability to install anything system-wide, so people revert the `USER` line and forget to put it
back.

Fix: do privileged build steps first, use `COPY --chown=10001:10001`, and put `USER` immediately
before `CMD`/`ENTRYPOINT`. Why it works: the ordering separates build-time privilege from run-time
privilege, which is the actual distinction the Dockerfile is expressing.

## `USER` set but overridden at runtime

```yaml
services:
  api:
    image: myapp:1.4.0     # Dockerfile says USER 10001
    user: root             # added to fix a volume permission error
```

The image is correct and the container runs as root. This is how a hardened image ends up running as
root in production — someone hit an `EACCES` on a mounted volume and took the shortest path.

Fix: `chown` the volume on the host or in an init container to match the container UID, and keep
`user: "10001:10001"` in compose so the intent is stated at both layers. Why it works: the ownership
mismatch is the real bug; running as root hides it rather than fixing it.

## Treating scanner severity as finding severity

Trivy reports 340 vulnerabilities on a Node image, 12 CRITICAL. The team either fixes all of them or,
more often, sets `exit-code: 0` and stops reading.

Scanner severity is the CVSS score of the CVE in isolation. It knows nothing about whether your code
reaches the vulnerable function. A CRITICAL in `libtiff` inside an image that never opens a TIFF is
not a critical finding for you. A MEDIUM in your HTTP framework's header parser, on a
public endpoint, may be worse than everything above it.

Fix: triage in this order.

1. Is the vulnerable package reachable from your process at all, or is it a binary nothing executes?
2. Is there a fix available? `--ignore-unfixed` / `--only-fixed` for the gate — no patch means no
   action, so blocking on it just trains people to bypass the gate.
3. Does the vulnerable code path take untrusted input in your usage?
4. Is there a mitigating control already — read-only filesystem, dropped capabilities, no network
   egress?

Then gate on fixable CRITICAL and HIGH only, report everything, and re-triage on a schedule.

Why this works: the gate stays credible. A gate people bypass provides no protection, and the honest
version of this advice is that scanner output is noisy and the noise is the main threat to the
control. Say which findings you could not determine reachability for rather than guessing.

## Pinning by digest and never updating

The Dockerfile is pinned correctly. The digest is eight months old. The image has every base OS
vulnerability disclosed since.

This is the direct cost of digest pinning and it is routinely omitted from the advice. A floating tag
gets patches and unreviewed changes; a digest gets neither.

Fix: pin the digest and add automation that bumps it. Renovate handles Docker digests, including the
`tag@digest` form:

```json
{
  "extends": ["config:recommended"],
  "packageRules": [
    {
      "matchDatasources": ["docker"],
      "pinDigests": true,
      "schedule": ["before 6am on monday"]
    }
  ]
}
```

Why this works: the pin makes the build reproducible, and the automation makes the change reviewed
rather than silent. Pin without automation and you have swapped one problem for another.

## `--privileged` to fix a permission error

Almost always added to make something work, then never removed. Common triggers: a device that is not
visible, a mount that fails, a profiler that cannot ptrace.

`--privileged` is not "more capabilities". It disables seccomp, disables AppArmor, allows all devices
including `/dev/mem`, and remounts `/sys` writable. Container root becomes effectively host root.

Fix: identify the one thing that is missing and grant exactly that. `--cap-add=NET_ADMIN` for
iptables inside the container. `--device=/dev/fuse` for a FUSE mount. `--cap-add=SYS_PTRACE` for a
debugger, in a debug run only. Why it works: the failure told you which single permission was needed;
`--privileged` grants that one plus everything else.

If nothing narrower works, the workload probably wants a VM. Say that instead of shipping
`--privileged`.

## `--network=host` for convenience

Added to reach a service on the host, or because port mapping was fiddly.

The container now has no network namespace. It sees every host interface, `-p` and `EXPOSE` stop
applying, and any service bound to `127.0.0.1` on the host — often a database or an admin port that is
unauthenticated precisely because it is loopback-only — is reachable from the container.

Fix: use a user-defined bridge network and, on Linux, `host.docker.internal` via
`--add-host=host.docker.internal:host-gateway` when the host really must be reached. Why it works:
the namespace stays intact, so reachability is explicit per-address rather than total.

## Published port bypassing the host firewall

`ufw` denies 5432, the Postgres container publishes `-p 5432:5432`, and the database is on the
internet.

On Linux, Docker inserts DNAT rules into its own `DOCKER` iptables chain, traversed before most
`ufw`/`firewalld` INPUT rules. The firewall is not consulted for the published port. People find this
out from a scan report.

Fix: bind to loopback — `-p 127.0.0.1:5432:5432` — and reach it through an SSH tunnel or a reverse
proxy. For containers that only talk to each other, publish nothing and use a shared user-defined
network. Why it works: the DNAT rule now targets `127.0.0.1`, so there is no path from an external
interface regardless of firewall configuration.

## Compose `expose` mistaken for a security boundary

```yaml
services:
  db:
    expose: ["5432"]
```

`expose` is documentation. It publishes nothing to the host, which is fine, but it also restricts
nothing between containers — every container on the same network can reach every port on `db`,
`expose` or not.

Fix: separate networks. Put the database on an internal network the public-facing service joins and
nothing else does:

```yaml
services:
  proxy:
    networks: [edge, app]
  api:
    networks: [app, data]
  db:
    networks: [data]
networks:
  edge:
  app:
    internal: true
  data:
    internal: true
```

Why this works: `internal: true` removes the external gateway, and network membership is the actual
enforcement point. Container-to-container reachability follows shared networks, nothing else.

## Believing the default bridge isolates containers

Containers on the default `docker0` bridge can reach each other on every port, and `NET_RAW` is
granted by default so ARP spoofing between them is possible. CIS 5.30 says not to use the default
bridge; the reason is that it is one flat network shared by everything you forgot to configure.

Fix: user-defined networks per trust zone, `--cap-drop=ALL` (which removes `NET_RAW`), and
`icc=false` on the daemon if you want the default bridge to deny inter-container traffic. Why it
works: user-defined networks are separate L2 segments with their own DNS scope.

## `HEALTHCHECK` that always passes

```dockerfile
HEALTHCHECK CMD curl -f http://localhost:8080/ || exit 0
```

`|| exit 0` makes the check unconditionally healthy. A variant is checking `/` when `/` is served by
a static handler that responds while the database connection is dead.

Fix: exit non-zero on failure, and check a path that exercises the dependencies the container needs:

```dockerfile
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD ["/server", "-healthcheck"]
```

Why this works: the readiness path touches the database and the cache, so a healthy result means the
container can actually serve. Note `--start-period`, without which a slow-starting app is killed
during boot and the team disables the healthcheck entirely.

## Secrets passed as build args in CI

```yaml
- run: docker build --build-arg AWS_SECRET_ACCESS_KEY=${{ secrets.AWS_KEY }} .
```

`ARG` values are recorded in image metadata and visible in `docker history`. The CI log masking gives
false comfort — the secret is masked in the log and present in the artefact.

Fix: `--secret id=aws,env=AWS_SECRET_ACCESS_KEY` with a matching `--mount=type=secret` in the
Dockerfile. Why it works: BuildKit keeps the value out of layers, metadata, and the build cache, so
`docker history` has nothing to show.

## Root user in the container plus a bind-mounted host directory

```yaml
volumes:
  - ./data:/data          # container runs as root
```

Files the container creates are owned by host UID 0. If the mounted path is anywhere the host
executes from — a web root, a scripts directory, a systemd unit path — a compromised container writes
files the host will run as root.

Fix: run as a non-root UID, `chown` the host directory to that UID, and mount `:ro` where the
container only reads. Why it works: the container's write capability is bounded by ordinary
filesystem permissions again, which is what was bypassed by running as UID 0.

## Trusting `docker scan`-style output as an SBOM

A vulnerability report is not a bill of materials. It lists what the scanner matched, not what is in
the image, and it is not consumable by anything else later.

Fix: generate an SBOM at build time with Syft or BuildKit's `--sbom=true`, attach it as an
attestation, and store it. Why it works: when the next widely-exploited library vulnerability lands,
"which of our 200 images contain this package and version" is a query against stored SBOMs rather
than 200 rebuild-and-rescan runs.

## Signing the tag instead of the digest

```bash
cosign sign --yes ghcr.io/myorg/api:v1.4.0
```

Cosign resolves the tag to a digest and signs that, so this specific command is not broken. The
mistake is the mental model that follows: the tag is then repointed to a new build, and deployments
that reference `:v1.4.0` pull an unsigned image while the verification step passes against the old
signature or fails confusingly.

Fix: resolve the digest yourself, sign it, and deploy the digest. Why it works: the deployed artefact
and the verified artefact are the same immutable object, which is the property signing is supposed to
provide.

## Verifying a signature without pinning the identity

```bash
cosign verify ghcr.io/myorg/api@sha256:...
```

With keyless signing this checks that some identity in the transparency log signed the image. Anyone
can sign any public image. Without `--certificate-identity-regexp` and
`--certificate-oidc-issuer` the check passes on an image signed by an attacker's own GitHub workflow.

Fix: pin both flags to your workflow identity and issuer. Why it works: verification then answers
"was this signed by our release pipeline", which is the question that matters.

## Mounting the socket to "just read container status"

The monitoring agent needs container names. Someone mounts the socket `:ro` and moves on.

`:ro` on a socket restricts nothing meaningful — the API is request/response over that socket, and
`POST /containers/create` works fine. Any RCE in the monitoring agent is host root.

Fix: a socket proxy with an explicit endpoint allowlist, or an agent that reads from the container
runtime's read-only metrics endpoint instead:

```yaml
services:
  socket-proxy:
    image: tecnativa/docker-socket-proxy:0.2.0
    environment:
      CONTAINERS: 1        # GET /containers/json only
      POST: 0              # no write endpoints at all
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks: [proxy_only]
  monitor:
    environment:
      DOCKER_HOST: tcp://socket-proxy:2375
    networks: [proxy_only]
```

Why this works: the agent can no longer reach any endpoint that creates or starts a container, so an
RCE in the agent does not become host root. The proxy itself still holds the socket, so it is now the
thing to keep small and patched. That is a smaller problem, not no problem.

## `latest` in production compose files

```yaml
image: myapp:latest
```

Two failures at once. You cannot tell what is running, and `docker compose up` on a host with a
cached `latest` pulls nothing while a different host pulls something newer. Rollback has no target
because the previous `latest` is unnamed.

Fix: deploy by digest, or by an immutable tag your CI never reuses (the commit SHA). Configure the
registry to reject tag overwrites where it supports that — ECR tag immutability, GCR/Artifact
Registry equivalents. Why it works: the running artefact becomes identifiable, and rollback is
pulling a digest you still have.

## Sources

- <https://docs.docker.com/build/building/secrets/>
- <https://docs.docker.com/engine/network/packet-filtering-firewalls/>
- <https://docs.docker.com/reference/compose-file/networks/>
- <https://docs.sigstore.dev/cosign/verifying/verify/>
- <https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html>
