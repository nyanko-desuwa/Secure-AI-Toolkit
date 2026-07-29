# Docker Best Practices

Patterns that hold up under review. Each names the Top 10 category, ASVS chapter, and CIS control it
serves. Digests shown are illustrative placeholders in valid `sha256:` form - they will not pull.

## Run as a non-root UID

`A02:2025` · ASVS V13 · CIS 4.1 · CWE-250

The default is root. A process running as UID 0 inside the container is UID 0 on the host unless
user namespace remapping is on, and most installs do not have it on. Any escape, any writable bind
mount, any setuid binary becomes worth more.

```dockerfile
# Vulnerable: no USER, so this runs as root
FROM python:3.12-slim
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
CMD ["python", "server.py"]
```

```dockerfile
# Fixed: explicit numeric UID, owned files, no shell for the account
FROM python:3.12-slim@sha256:1111aaaa2222bbbb3333cccc4444dddd5555eeee6666ffff7777aaaa8888bbbb

RUN groupadd --gid 10001 app \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin app

WORKDIR /app
COPY --chown=10001:10001 requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY --chown=10001:10001 . .

USER 10001:10001
CMD ["python", "server.py"]
```

Why the numeric UID matters: `USER app` resolves through the image's `/etc/passwd`. If a base image
change alters that file, or the image has no `/etc/passwd` (scratch, distroless), the name does not
resolve and Kubernetes `runAsNonRoot` cannot verify it. A number always resolves.

Pick a UID above 10000. Low UIDs collide with host system accounts, which matters the moment a
volume is shared with the host.

The tempting wrong fix is `USER nobody`. UID 65534 is shared by every container that does this, so
two unrelated containers sharing a volume have identical filesystem identity.

## Pin the base image by digest

`A03:2025` · ASVS V15 · CIS 4.2 · CWE-1104

A tag is a mutable pointer. `FROM node:22-alpine` today and next week are different images. That is
usually a patched rebuild and occasionally a compromised or mistakenly published one, and you cannot
tell which from the Dockerfile.

```dockerfile
# Vulnerable: mutable, unreproducible, and silently changes under you
FROM node:latest
```

```dockerfile
# Fixed: digest is content-addressed. Same bytes or the pull fails
FROM node:22.11-alpine@sha256:2222bbbb3333cccc4444dddd5555eeee6666ffff7777aaaa8888bbbb9999cccc0
```

Keep the tag next to the digest. The digest is what enforces; the tag tells a human what they are
looking at.

Resolve a digest with:

```bash
docker buildx imagetools inspect node:22.11-alpine --format '{{.Manifest.Digest}}'
```

The cost, stated honestly: you stop getting base image patches automatically. A digest pinned in
January is missing six months of fixes by July, and nothing warns you. The pin is only defensible
with an update mechanism attached - Renovate or Dependabot both raise PRs that bump the digest, which
turns a silent change into a reviewed one. If you pin and do not automate the bump, you have traded
a supply chain risk for a patching risk. Pick deliberately.

One caveat: a digest names one manifest. If you pin the digest of a multi-arch manifest list, multi-arch
builds still work. Pin a platform-specific digest and `--platform linux/arm64` breaks.

## Multi-stage builds so build tooling never ships

`A03:2025` · ASVS V15 · CIS 4.3

Compilers, package managers, headers, `git`, and `curl` in a runtime image give an attacker who
achieves code execution the tools to fetch a second stage and build it. They also carry their own
CVEs, which is most of what your scanner is reporting.

```dockerfile
# Vulnerable: build toolchain, git history, and dev dependencies all ship
FROM golang:1.23
WORKDIR /src
COPY . .
RUN go build -o /app/server ./cmd/server
CMD ["/app/server"]
```

```dockerfile
# Fixed: build stage is discarded, runtime stage holds one static binary
FROM golang:1.23@sha256:3333cccc4444dddd5555eeee6666ffff7777aaaa8888bbbb9999cccc0000dddd1 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot@sha256:4444dddd5555eeee6666ffff7777aaaa8888bbbb9999cccc0000dddd1111eeee2
COPY --from=build /out/server /server
USER 65532:65532
ENTRYPOINT ["/server"]
```

Why this works: the runtime image contains a binary and CA certificates. There is no shell to spawn,
no package manager to install with, and nothing to compile. The `.git` directory, `go.sum`, and the
whole module cache stayed in the discarded stage.

`COPY --from=build` copies from the build stage's filesystem, so nothing in that stage's layer
history reaches the final image. This is also why a multi-stage build is the correct fix for a secret
used at build time and not needed at runtime - provided the secret was used in the build stage and
never copied forward.

## Build-time secrets with `--mount=type=secret`

`A03:2025` · ASVS V13, V14 · CIS 4.10 · CWE-522, CWE-798

Every other approach leaves the secret in the image. `ARG` values appear in `docker history`. A
`COPY` of a key file creates a layer that keeps the file even after a later `RUN rm`, because layers
are additive and deletion is recorded as a whiteout over content that is still there.

```dockerfile
# Vulnerable: three ways to leak the same token
FROM node:22-alpine
ARG NPM_TOKEN                                   # visible in docker history
ENV NPM_TOKEN=$NPM_TOKEN                        # visible in docker inspect
COPY .npmrc /root/.npmrc                        # persists in the layer
RUN npm ci
RUN rm /root/.npmrc                             # deletes nothing from the layer
```

```dockerfile
# Fixed: secret is mounted for one RUN and is not part of any layer
# syntax=docker/dockerfile:1.7
FROM node:22.11-alpine@sha256:2222bbbb3333cccc4444dddd5555eeee6666ffff7777aaaa8888bbbb9999cccc0 AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc,mode=0400 \
    npm ci --omit=dev
```

Built with:

```bash
docker build --secret id=npmrc,src="$HOME/.npmrc" -t app:build .
```

Why this works: BuildKit exposes the file on a tmpfs for the duration of that one `RUN` and it is
absent from the resulting layer, from `docker history`, and from the build cache. The `# syntax` line
matters - without a BuildKit frontend the `--mount` flag is a syntax error rather than a silent
downgrade, which is the failure mode you want.

Verify with `docker history --no-trunc <image>` and by grepping the layer tarballs:

```bash
docker save app:build | tar -xO --wildcards '*/layer.tar' | tar -tv 2>/dev/null | grep npmrc
```

If a secret has already been built into a pushed image, deleting the tag is not remediation. Rotate
the credential. Registry layers are content-addressed and may be cached, mirrored, or pulled already.

## `.dockerignore` before anything else

`A03:2025` · ASVS V13 · CWE-538

`COPY . .` copies the build context. Without a `.dockerignore` that includes `.git`, `.env`, and
`node_modules`, you ship your commit history, your local credentials, and whatever native modules
were compiled for your laptop.

```text
# Vulnerable: no .dockerignore, so COPY . . ships all of this
.git/                 full history - every secret ever committed and reverted
.env                  local credentials
*.pem *.key           keys
node_modules/         host-compiled binaries, possibly wrong architecture
.aws/ .ssh/           if the context is a home directory, which happens
```

```text
# Fixed: .dockerignore - deny broadly, then allow what the build needs
*
!package.json
!package-lock.json
!tsconfig.json
!src/
!public/
```

Why deny-all-then-allow works: an allowlist fails closed. A denylist `.dockerignore` misses the next
secret file someone adds, and nobody notices because the build still succeeds. The allowlist form
breaks the build when a needed file is missing, which is a visible failure.

`.dockerignore` also shrinks the context, which speeds builds and stops unrelated file changes from
invalidating the cache.

## `COPY`, not `ADD`

`A03:2025` · CIS 4.9 · CWE-494

`ADD` does two extra things: it auto-extracts local tar archives, and it fetches remote URLs. Both
are surprising, and the URL form fetches without verifying anything.

```dockerfile
# Vulnerable: unverified remote fetch, and archive auto-extraction
ADD https://example.com/tool.tar.gz /opt/
ADD release.tar.gz /opt/app/
```

```dockerfile
# Fixed: explicit fetch with a verified checksum, explicit extraction
RUN --mount=type=cache,target=/var/cache/apk \
    apk add --no-cache curl \
 && curl -fsSL --proto '=https' --tlsv1.2 -o /tmp/tool.tar.gz https://example.com/tool.tar.gz \
 && echo "9f2c...  /tmp/tool.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/tool.tar.gz -C /opt \
 && rm /tmp/tool.tar.gz
```

Why this works: the checksum makes the artefact's identity a build-time assertion. If upstream
replaces the file, the build fails instead of shipping different code. Use `COPY` for everything in
the build context and reserve remote fetches for cases where a checksum is available.

Recent BuildKit supports `ADD --checksum=sha256:...` for the URL form. If your builder supports it,
that is an acceptable alternative - the point is the verification, not the instruction name.

## Read-only root filesystem

`A02:2025` · ASVS V13 · CIS 5.13

A writable root filesystem lets an attacker with code execution drop a binary, modify the
application, or overwrite a cron file if one is reachable. Read-only removes persistence.

```yaml
# Vulnerable: everything writable, no limits, root
services:
  api:
    image: myapp:latest
    ports: ["8080:8080"]
```

```yaml
# Fixed
services:
  api:
    image: registry.example.com/myapp@sha256:5555eeee6666ffff7777aaaa8888bbbb9999cccc0000dddd1111eeee2222ffff3
    user: "10001:10001"
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=64m
    cap_drop: ["ALL"]
    security_opt:
      - no-new-privileges:true
    ports: ["127.0.0.1:8080:8080"]
```

Why this works: `noexec` on the one writable path means a dropped binary cannot be executed, so
`--read-only` plus a `noexec` tmpfs closes the obvious workaround rather than just moving it.

The work is finding what the process writes. Common cases: `/tmp`, a PID file, a framework cache
directory, and `/var/run`. Run with `--read-only` and read the errors; do not guess. Language
runtimes are the usual surprise - Python writes `__pycache__`, Node writes to `/tmp` for some
native modules, JVM writes `hsperfdata`.

## `HEALTHCHECK`, and why `depends_on` is not readiness

`A02:2025` · CIS 4.6, 5.27

A container whose process has deadlocked is still "running". Without a healthcheck the orchestrator
keeps routing to it.

```dockerfile
# Fixed: no shell needed, checks the app's own readiness path
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["/server", "-healthcheck"]
```

For a distroless or scratch image there is no `curl` and no shell, so the binary needs a self-check
mode. That is a design decision to make before choosing the base image.

```yaml
# Vulnerable: depends_on means "started", not "ready"
services:
  api:
    depends_on: [db]
```

```yaml
# Fixed: gate on the healthcheck condition
services:
  db:
    image: postgres:16.4-alpine@sha256:6666ffff7777aaaa8888bbbb9999cccc0000dddd1111eeee2222ffff3333aaaa4
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres -d app"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s
  api:
    depends_on:
      db:
        condition: service_healthy
```

Why this matters for security and not just uptime: an application that starts before its database is
reachable often falls back to a default configuration, an in-memory store, or a permissive
"bootstrap" mode. Startup ordering bugs turn into authorization bugs.

## Choosing a base image

`A03:2025` · CIS 4.3

| Base | Attack surface | Debuggability | Use when |
|---|---|---|---|
| `scratch` | Nothing but your binary | None. No shell, no `ls` | Static Go or Rust binary, no CA certs needed |
| `distroless/static` | libc-less, CA certs, tzdata | None by default | Static binary that makes TLS calls |
| `distroless/base` or `java` | glibc or a JRE | None by default | Dynamically linked or JVM |
| Alpine | busybox, apk, musl libc | Full shell | You need a shell and small size |
| `-slim` Debian | dpkg, apt, coreutils | Full shell | glibc compatibility matters |
| Full `debian` / `ubuntu` | Hundreds of packages | Everything | Rarely justified for a runtime image |

The size argument, made concretely rather than as a slogan: a `debian:bookworm` base is roughly 120 MB
and carries a package manager, `wget`, `passwd`, and a shell. `distroless/static` is under 3 MB with
no shell. The difference is not the megabytes - it is that post-exploitation in the first image is
`apt-get install` and in the second there is no way to run a command at all, because there is no
`/bin/sh` for a reverse shell or a `system()` call to land on. Fewer packages also means fewer
scanner findings, which means the findings you do get are readable.

What you lose with distroless, said plainly: `docker exec` gives you nothing. No shell, no `ps`, no
`cat`. Debugging requires `docker debug`, `kubectl debug` with an ephemeral container, or a `:debug`
image variant that ships busybox. Teams that have not set that up before an incident will discover
it during one.

Distroless `:nonroot` tags run as UID 65532 already. Confirm with `docker inspect` rather than
assuming, and still set `USER` explicitly so the Dockerfile states its intent.

The practical middle ground is Alpine or `-slim`. Alpine costs you musl libc, which breaks some
Python wheels and anything expecting glibc-specific behaviour, and its DNS resolver historically
differed on edge cases. `-slim` keeps glibc and dpkg at a moderate size. Both are defensible; a full
`ubuntu` runtime image usually is not.

## The docker socket

`A02:2025` · ASVS V13 · CIS 5.32 · CWE-269, CWE-668

Mounting `/var/run/docker.sock` into a container is granting root on the host. Not "a risk", not
"elevated privilege". The socket is the daemon's full API, the daemon runs as root, and the API can
start a container with `--privileged` and `-v /:/host`.

```bash
# What any process with the socket can do, in one command
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock docker:cli \
  docker run --rm --privileged -v /:/host alpine chroot /host sh -c 'id; cat /etc/shadow'
```

`:ro` does not help. The socket is a bidirectional API; read-only affects the inode, not the requests
you can send through it.

```yaml
# Vulnerable: CI runner with the socket, the standard "docker-in-docker" shortcut
services:
  runner:
    image: ci-runner:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
```

Any pipeline that runs, including one from a fork's pull request, has host root.

Alternatives, best first:

| Approach | Blast radius | Trade-off |
|---|---|---|
| Build on a dedicated host or ephemeral VM per job | Job cannot touch other jobs | Infrastructure cost |
| Rootless BuildKit (`buildkitd` rootless, or `buildctl`) | Daemon runs as an unprivileged user | Some build features need config |
| Kaniko or Buildah in userspace | No daemon, no socket | No BuildKit cache features; Kaniko is less actively developed |
| `docker:dind` sidecar with a private network | Escape lands in the DinD container, not the host | DinD itself needs `--privileged` |
| Socket proxy (`tecnativa/docker-socket-proxy`) allowing only specific endpoints | Restricted API surface | Still a path to the daemon. Correct only if the allowlist is genuinely minimal |
| Socket mounted directly | Host root | None. This is the finding |

```yaml
# Fixed: rootless BuildKit, no socket anywhere
services:
  buildkit:
    image: moby/buildkit:v0.16.0-rootless@sha256:7777aaaa8888bbbb9999cccc0000dddd1111eeee2222ffff3333aaaa4444bbbb5
    security_opt:
      - seccomp=unconfined       # rootless buildkitd needs unconfined seccomp/apparmor
      - apparmor=unconfined
    environment:
      BUILDKITD_FLAGS: --oci-worker-no-process-sandbox
    networks: [ci]
```

Honest note on that fix: rootless BuildKit requires `seccomp=unconfined` and
`--oci-worker-no-process-sandbox`, which look like the things this skill warns about. The difference
is that the whole thing runs as an unprivileged user, so what a break-out reaches is that user's
scope rather than the host. It is a real reduction, not a complete solution. A dedicated build host
remains the stronger answer.

If a read-only monitoring agent genuinely needs container metadata, a socket proxy restricted to
`GET /containers/json` is a reasonable compromise. Write it down and review it, because
"temporarily" allowing `POST /containers/create` restores full host root.

## Runtime secrets

`A04:2025` · ASVS V14 · CWE-522

`ENV` is the wrong place. Environment variables appear in `docker inspect`, in
`/proc/<pid>/environ`, in every child process, in crash dumps, and in whatever monitoring agent
scrapes container metadata.

```yaml
# Vulnerable: readable by anyone with daemon access, and by the app's own error reporter
services:
  api:
    environment:
      DATABASE_PASSWORD: hunter2
      STRIPE_SECRET_KEY: sk_live_placeholder
```

```yaml
# Fixed: file-mounted, read by path; protect the host source file
services:
  api:
    image: registry.example.com/myapp@sha256:8888bbbb9999cccc0000dddd1111eeee2222ffff3333aaaa4444bbbb5555cccc6
    environment:
      DATABASE_PASSWORD_FILE: /run/secrets/db_password
    secrets:
      - db_password

secrets:
  db_password:
    file: ./secrets/db_password        # 0400, gitignored, or use an external secret
```

Why this works: the file is mounted at `/run/secrets/db_password`, file permissions apply, and it does not appear in `docker inspect` output. Passing the path in `ENV` rather than the value is the pattern - `_FILE` suffix conventions exist in the official Postgres, MySQL, and Redis images for exactly this reason.

Compose's ordinary `secrets:` implementation bind-mounts the configured source file under `/run/secrets`; it is not automatically a tmpfs. Protect the host source file (`0400`, gitignored), or use Swarm secrets or an external injector when disk-backed source material is not acceptable.

Check any container you inherit:

```bash
docker inspect api --format '{{json .Config.Env}}'
```

Compose `secrets:` with a `file:` source means the plaintext sits on the host disk and is bind-mounted into the container. That is better than the image and worse than an injected secret. For tmpfs-backed delivery or rotation without a redeploy you need Swarm secrets or an agent (Vault Agent, a cloud secret CSI driver) writing into a tmpfs.

## Image scanning in CI

`A03:2025` · ASVS V15 · CIS 4.4

```yaml
# .github/workflows/image.yaml
name: image
on: [push]

permissions:
  contents: read
  packages: write
  id-token: write            # keyless cosign signing needs this

jobs:
  build-scan-sign:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4

      - uses: docker/setup-buildx-action@v3

      - name: Build
        run: |
          docker build \
            --secret id=npmrc,env=NPM_TOKEN \
            --provenance=true --sbom=true \
            -t "ghcr.io/${{ github.repository }}:${{ github.sha }}" .
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}

      - name: Scan - fail the build on fixable critical and high
        uses: aquasecurity/trivy-action@0.24.0
        with:
          image-ref: ghcr.io/${{ github.repository }}:${{ github.sha }}
          severity: CRITICAL,HIGH
          ignore-unfixed: true
          exit-code: "1"
          vuln-type: os,library

      - name: Scan - full report, never fails
        uses: aquasecurity/trivy-action@0.24.0
        with:
          image-ref: ghcr.io/${{ github.repository }}:${{ github.sha }}
          format: sarif
          output: trivy.sarif
          exit-code: "0"

      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trivy.sarif

      - name: SBOM
        run: |
          syft "ghcr.io/${{ github.repository }}:${{ github.sha }}" \
            -o spdx-json=sbom.spdx.json

      - name: Push and sign
        run: |
          IMAGE="ghcr.io/${{ github.repository }}:${{ github.sha }}"
          docker push "$IMAGE"
          DIGEST=$(docker buildx imagetools inspect "$IMAGE" --format '{{.Manifest.Digest}}')
          cosign sign --yes "ghcr.io/${{ github.repository }}@${DIGEST}"
          cosign attest --yes --predicate sbom.spdx.json --type spdxjson \
            "ghcr.io/${{ github.repository }}@${DIGEST}"
```

Two scan steps is deliberate. The gating scan uses `ignore-unfixed: true` and `CRITICAL,HIGH`,
because failing a build on a vulnerability with no available patch teaches people to add
`--exit-code 0` and stop looking. The reporting scan captures everything without blocking.

Sign the digest, not the tag. A tag can be repointed after signing; a digest cannot.

Two scanners find slightly different things - Trivy and Grype use different databases and different
matching logic. Running both is defensible for a release gate and excessive on every push.

```yaml
      - name: Grype, release gate only
        if: startsWith(github.ref, 'refs/tags/')
        run: |
          grype "ghcr.io/${{ github.repository }}:${{ github.sha }}" \
            --fail-on high --only-fixed
```

## Verify signatures at admission, not just at build

`A08:2025` · ASVS V15 · CIS 4.12 · CWE-347

Producing a signature nobody checks changes nothing. Verification has to happen where the image is
pulled.

```bash
# Fixed: keyless verification pinned to the identity and issuer that may sign
cosign verify \
  --certificate-identity-regexp '^https://github\.com/myorg/myrepo/\.github/workflows/.+@refs/heads/main$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/myorg/myrepo@sha256:9999cccc0000dddd1111eeee2222ffff3333aaaa4444bbbb5555cccc6666dddd7
```

Why the identity flags are not optional: `cosign verify` without them accepts a signature from any
identity in the transparency log. That verifies a signature exists, not that you trust the signer.
This is the single most common way keyless signing gets deployed as decoration.

Keyless signing uses an OIDC token from the CI provider to obtain a short-lived Fulcio certificate,
and the signature is recorded in the Rekor transparency log. The benefit is no long-lived signing key
to steal or rotate. The costs are real: verification needs network access to Rekor unless you run a
mirror, air-gapped verification needs extra setup, and your trust root is now the CI provider's OIDC
issuer - compromise of the workflow identity means a valid signature on a malicious image.

For Kubernetes, enforce at admission with Sigstore Policy Controller or Kyverno. Docker alone has no
admission hook, so with plain Docker or compose the verification step belongs in the deploy script,
before `docker run`, and it must abort on failure.

## Sources

- <https://owasp.org/Top10/2025/>
- <https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html>
- <https://docs.docker.com/build/building/secrets/>
- <https://docs.docker.com/engine/security/>
- <https://github.com/GoogleContainerTools/distroless>
- <https://docs.sigstore.dev/cosign/signing/overview/>
- <https://trivy.dev/> · <https://github.com/anchore/grype> · <https://github.com/anchore/syft>
