# Docker Security Examples

Eight vulnerable/fixed pairs. Every fixed block is intended to run once placeholder digests and
application filenames are replaced with real values. Digests shown here are illustrative and will
not pull.

## Contents

- [Root container and unpinned base](#root-container-and-unpinned-base) - A02/A03, CWE-250/1104
- [Secret baked into a layer](#secret-baked-into-a-layer) - A03, CWE-798
- [Build toolchain shipped to production](#build-toolchain-shipped-to-production) - A03, CWE-1104
- [Docker socket mounted into CI](#docker-socket-mounted-into-ci) - A02, CWE-269
- [Privileged container with host namespaces](#privileged-container-with-host-namespaces) - A02, CWE-250
- [Writable runtime with every default capability](#writable-runtime-with-every-default-capability) - A02, CWE-269
- [Compose startup and network exposure](#compose-startup-and-network-exposure) - A02, CWE-668
- [Unsigned, unscanned mutable release](#unsigned-unscanned-mutable-release) - A03/A08, CWE-345

---

## Root container and unpinned base

`A02:2025` · `A03:2025` · ASVS V13, V15 · CIS 4.1, 4.2 · `CWE-250`, `CWE-1104`

### Vulnerable

```dockerfile
FROM node:latest
WORKDIR /app
COPY . .
RUN npm install
EXPOSE 3000
CMD ["npm", "start"]
```

`latest` is a mutable pointer, so the same commit produces different images on different days. No
`USER` means PID 1 is UID 0. `COPY . .` ships `.git`, `.env`, and local `node_modules` if there is no
`.dockerignore`. `npm install` ignores the lockfile's reproducibility guarantees.

### Fixed

```dockerfile
# syntax=docker/dockerfile:1.7
FROM node:22.11-alpine@sha256:1111aaaa2222bbbb3333cccc4444dddd5555eeee6666ffff7777aaaa8888bbbb AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci
COPY src ./src
RUN npm run build

FROM node:22.11-alpine@sha256:1111aaaa2222bbbb3333cccc4444dddd5555eeee6666ffff7777aaaa8888bbbb
RUN addgroup -g 10001 app && adduser -D -u 10001 -G app app
WORKDIR /app
COPY --from=build --chown=10001:10001 /src/package.json /src/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --omit=dev && npm cache clean --force
COPY --from=build --chown=10001:10001 /src/dist ./dist
USER 10001:10001
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["node", "dist/healthcheck.js"]
CMD ["node", "dist/server.js"]
```

```text
# .dockerignore
*
!package.json
!package-lock.json
!src/
```

Why this works: the digest fixes the base bytes, lockfile install fixes JavaScript dependencies, the
build stage is discarded, and a numeric unprivileged UID is the only runtime identity. The deny-all
`.dockerignore` makes a new file unavailable to the build until explicitly allowed.

Operational cost: automate digest bumps. Otherwise the pinned image stops receiving base patches.

---

## Secret baked into a layer

`A03:2025` · ASVS V13, V14 · CIS 4.10 · `CWE-798`

### Vulnerable

```dockerfile
FROM python:3.12-slim
ARG PIP_INDEX_TOKEN
ENV PIP_INDEX_URL=https://token:${PIP_INDEX_TOKEN}@packages.example.com/simple
COPY pip.conf /root/.config/pip/pip.conf
RUN pip install -r requirements.txt
RUN rm -rf /root/.config/pip
ENV PIP_INDEX_URL=
```

All three attempted secret mechanisms leak. `ARG` appears in `docker history`; `ENV` appears in
image configuration; `COPY` puts the file in a layer. The later `rm` and empty `ENV` only overlay the
content. Anyone who pulls the image recovers it.

### Fixed

```dockerfile
# syntax=docker/dockerfile:1.7
FROM python:3.12-slim@sha256:2222bbbb3333cccc4444dddd5555eeee6666ffff7777aaaa8888bbbb9999cccc AS build
WORKDIR /build
COPY requirements.txt ./
RUN --mount=type=secret,id=pipconf,target=/etc/pip.conf,mode=0400 \
    pip wheel --require-hashes --no-cache-dir --wheel-dir=/wheels -r requirements.txt

FROM python:3.12-slim@sha256:2222bbbb3333cccc4444dddd5555eeee6666ffff7777aaaa8888bbbb9999cccc
RUN groupadd -g 10001 app && useradd -u 10001 -g 10001 -M -s /usr/sbin/nologin app
COPY --from=build /wheels /wheels
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --no-index --find-links=/wheels --require-hashes \
      -r /tmp/requirements.txt \
 && rm -rf /wheels /tmp/requirements.txt
COPY --chown=10001:10001 src /app
USER 10001:10001
CMD ["python", "/app/server.py"]
```

```bash
docker build --secret id=pipconf,src="$HOME/.config/pip/pip.conf" -t app:test .
docker history --no-trunc app:test
```

Why this works: BuildKit mounts the credential only for the wheel-build instruction, outside the
layer filesystem. Only wheels cross into the final stage. The token is absent from metadata, cache,
and both image histories.

The tempting wrong fix is combining `COPY`, install, and `rm` in one `RUN`. `COPY` is its own layer
before `RUN` begins, so same-line deletion cannot erase it.

---

## Build toolchain shipped to production

`A03:2025` · ASVS V15 · CIS 4.3 · `CWE-1104`

### Vulnerable

```dockerfile
FROM golang:1.23
WORKDIR /src
COPY . .
RUN apt-get update && apt-get install -y git curl gcc \
 && go build -o /usr/local/bin/api ./cmd/api
CMD ["api"]
```

The runtime image contains the Go toolchain, GCC, git, curl, apt, all source, and `.git` history. An
attacker with command execution has everything needed to fetch and compile a second-stage payload,
and the scanner reports vulnerabilities in tools the application never calls.

### Fixed

```dockerfile
FROM golang:1.23@sha256:3333cccc4444dddd5555eeee6666ffff7777aaaa8888bbbb9999cccc0000dddd AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/api ./cmd/api

FROM gcr.io/distroless/static-debian12:nonroot@sha256:4444dddd5555eeee6666ffff7777aaaa8888bbbb9999cccc0000dddd1111eeee
COPY --from=build /out/api /api
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD ["/api", "-healthcheck"]
ENTRYPOINT ["/api"]
```

Why this works: the shipped image has one static binary, CA certificates, and no shell. Removing 800
MB is not the security property; removing `curl`, compiler, package manager, source, and shell is.

What you lose: `docker exec -it api sh` cannot work. Prepare a debug container or a `:debug` variant
before production. Distroless without a debugging path is an incident-response tax.

---

## Docker socket mounted into CI

`A02:2025` · ASVS V13 · CIS 5.32 · `CWE-269`, `CWE-668`

### Vulnerable

```yaml
services:
  runner:
    image: gitlab/gitlab-runner:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./config:/etc/gitlab-runner
```

This is host root. `:ro` does not restrict a socket API. A build script can ask the daemon to start
`--privileged -v /:/host` and write anywhere on the host. If fork pull requests run here, any fork
owner owns the CI host and every credential on it.

### Fixed

```yaml
services:
  buildkit:
    image: moby/buildkit:v0.16.0-rootless@sha256:5555eeee6666ffff7777aaaa8888bbbb9999cccc0000dddd1111eeee2222ffff
    user: "1000:1000"
    security_opt:
      - seccomp=unconfined
      - apparmor=unconfined
    environment:
      BUILDKITD_FLAGS: --oci-worker-no-process-sandbox
    networks: [ci]
    volumes:
      - buildkit_state:/home/user/.local/share/buildkit

  runner:
    image: registry.example.com/runner@sha256:6666ffff7777aaaa8888bbbb9999cccc0000dddd1111eeee2222ffff3333aaaa
    user: "10001:10001"
    read_only: true
    tmpfs: [/tmp]
    environment:
      BUILDKIT_HOST: tcp://buildkit:1234
    networks: [ci]
    depends_on: [buildkit]

networks:
  ci:
    internal: true
volumes:
  buildkit_state:
```

Why this works: the runner has no daemon socket. BuildKit itself is rootless, so a builder escape
lands as an unprivileged host UID rather than host root. The unconfined seccomp/AppArmor settings are
a documented rootless BuildKit cost, not a free pass. A dedicated ephemeral VM per job is stronger.

Alternatives: Buildah, Kaniko, a privileged DinD sidecar whose blast radius is its own VM, or an
endpoint-allowlisted socket proxy for a monitoring-only use case. Direct socket mount is not an
alternative.

---

## Privileged container with host namespaces

`A02:2025` · ASVS V13 · CIS 5.5, 5.10, 5.16 · `CWE-250`

### Vulnerable

```bash
docker run --privileged --network=host --pid=host \
  --security-opt seccomp=unconfined \
  -v /etc:/host/etc \
  registry.example.com/debug:latest
```

Every isolation boundary is gone. The process can load kernel modules, access all devices, see and
signal host processes, reach loopback-only host services, and overwrite `/etc`. This is not a
container security finding; it is a host-root process packaged as an image.

### Fixed

```bash
docker run --rm \
  --user 10001:10001 \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=32m \
  --cap-drop=ALL \
  --cap-add=SYS_PTRACE \
  --security-opt=no-new-privileges:true \
  --memory=256m --memory-swap=256m --cpus=0.5 --pids-limit=100 \
  --network=none \
  registry.example.com/debug@sha256:7777aaaa8888bbbb9999cccc0000dddd1111eeee2222ffff3333aaaa4444bbbb
```

Why this works: the debugger gets the one capability it needs (`SYS_PTRACE`) for one short-lived run.
There are no host namespaces, devices, or bind mounts to turn that capability into host control.
`--network=none` removes an exfiltration path.

If the tool truly needs kernel modules or `/dev/mem`, it belongs in a VM. There is no narrower
container configuration that makes those safe.

---

## Writable runtime with every default capability

`A02:2025` · ASVS V13 · CIS 5.4, 5.11, 5.13, 5.26, 5.29 · `CWE-269`, `CWE-770`

### Vulnerable

```bash
docker run -d -p 8080:8080 registry.example.com/api:1.2.0
```

The root filesystem is writable. Docker's default capabilities include `NET_RAW`, `CHOWN`, `SETUID`,
and `SETGID`. No memory, CPU, or PID limit means a memory leak or fork bomb takes down every
container on the host. `-p 8080:8080` binds every host interface.

### Fixed

```bash
docker network create api_net

docker run -d --name api \
  --user 10001:10001 \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop=ALL \
  --security-opt=no-new-privileges:true \
  --memory=512m --memory-swap=512m \
  --cpus=1.0 --pids-limit=200 \
  --restart=on-failure:5 \
  --network=api_net \
  -p 127.0.0.1:8080:8080 \
  registry.example.com/api@sha256:8888bbbb9999cccc0000dddd1111eeee2222ffff3333aaaa4444bbbb5555cccc
```

Why this works: code execution cannot persist to the image, cannot gain a new privilege through a
setuid binary, has no kernel capabilities, and cannot exhaust host memory, CPU, or PIDs. Loopback
binding prevents Docker's iptables rules from making the service public.

Resource limits are a DoS control, not performance tuning. Without them the host is the quota.

---

## Compose startup and network exposure

`A02:2025` · ASVS V13 · CIS 5.9, 5.14, 5.27, 5.30 · `CWE-668`

### Vulnerable

```yaml
services:
  api:
    image: myorg/api:latest
    ports:
      - "8080:8080"
    depends_on:
      - db
    environment:
      DATABASE_PASSWORD: dev-password

  db:
    image: postgres:latest
    ports:
      - "5432:5432"
    environment:
      POSTGRES_PASSWORD: dev-password
```

Both services are public on every interface. `depends_on` means the database container was started,
not that Postgres accepts connections. Both secret values appear in `docker inspect`. Every service
joins one shared default network and can reach every other port, whether `expose` lists it or not.

### Fixed

```yaml
services:
  api:
    image: registry.example.com/api@sha256:9999cccc0000dddd1111eeee2222ffff3333aaaa4444bbbb5555cccc6666dddd
    user: "10001:10001"
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=64m
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    mem_limit: 512m
    cpus: 1.0
    pids_limit: 200
    ports:
      - "127.0.0.1:8080:8080"
    networks: [app, data]
    environment:
      DATABASE_PASSWORD_FILE: /run/secrets/db_password
    secrets: [db_password]
    depends_on:
      db:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "/app/server", "-healthcheck"]
      interval: 30s
      timeout: 3s
      retries: 3
      start_period: 10s

  db:
    image: postgres:16.4-alpine@sha256:aaaa0000bbbb1111cccc2222dddd3333eeee4444ffff5555aaaa6666bbbb7777
    user: "999:999"
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=64m
      - /var/run/postgresql:rw,noexec,nosuid,size=16m
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    mem_limit: 1g
    cpus: 2.0
    pids_limit: 200
    networks: [data]
    volumes:
      - db_data:/var/lib/postgresql/data
    environment:
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    secrets: [db_password]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres -d app"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s

networks:
  app:
    internal: true
  data:
    internal: true

volumes:
  db_data:

secrets:
  db_password:
    file: ./secrets/db_password
```

Why this works: Postgres is not published at all, the API is loopback-only, and each service joins
only the networks it needs. Startup is gated on real database readiness. The secret is a mounted file
and absent from `docker inspect`. Each writable path is explicit.

Practical note: the official Postgres image's entrypoint may need capabilities or root for first-run
volume ownership depending on the host volume. Pre-own the volume for UID 999 and test this compose
file on the target platform rather than restoring root silently.

---

## Unsigned, unscanned mutable release

`A03:2025` · `A08:2025` · ASVS V15 · CIS 4.4, 4.12 · `CWE-345`

### Vulnerable

```yaml
- name: Build and push
  run: |
    docker build -t ghcr.io/myorg/api:latest .
    docker push ghcr.io/myorg/api:latest
```

No scan, no SBOM, no signature, mutable tag. The registry account can repoint `latest` after review,
and deployment has no way to distinguish the reviewed image from a replacement.

### Fixed

```yaml
name: release
on:
  push:
    tags: ["v*"]

permissions:
  contents: read
  packages: write
  id-token: write

jobs:
  release:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-buildx-action@v3

      - name: Build
        run: |
          IMAGE="ghcr.io/myorg/api:${GITHUB_SHA}"
          docker buildx build --load --provenance=true --sbom=true -t "$IMAGE" .

      - name: Trivy gate
        run: |
          trivy image --exit-code 1 --ignore-unfixed \
            --severity CRITICAL,HIGH "ghcr.io/myorg/api:${GITHUB_SHA}"

      - name: Grype cross-check
        run: grype "ghcr.io/myorg/api:${GITHUB_SHA}" --fail-on high --only-fixed

      - name: SBOM, push, and keyless sign
        run: |
          IMAGE="ghcr.io/myorg/api:${GITHUB_SHA}"
          syft "$IMAGE" -o spdx-json=sbom.spdx.json
          docker push "$IMAGE"
          DIGEST=$(docker buildx imagetools inspect "$IMAGE" --format '{{.Manifest.Digest}}')
          REF="ghcr.io/myorg/api@${DIGEST}"
          cosign sign --yes "$REF"
          cosign attest --yes --predicate sbom.spdx.json --type spdxjson "$REF"
          printf '%s\n' "$REF" > release-image.txt
```

Deploy only after verification:

```bash
#!/usr/bin/env bash
set -euo pipefail
REF=$(cat release-image.txt)
cosign verify \
  --certificate-identity-regexp '^https://github\.com/myorg/api/\.github/workflows/release\.yml@refs/tags/v.+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$REF" >/dev/null
docker pull "$REF"
docker run --detach "$REF"
```

Why this works: scanners gate only fixable high-severity findings while a full SBOM preserves what
was actually shipped. Keyless signing binds the digest to the release workflow's OIDC identity, and
the deploy script verifies both identity and issuer before pulling. The deployed reference is the
same immutable digest that was scanned and signed.

Registry controls still matter. Make the repository private where the image is not public, use a
short-lived read-only token on hosts, and enable tag immutability so even human-readable release tags
cannot be overwritten. A private registry without immutable tags protects confidentiality, not
integrity.

---

## Sources

- <https://owasp.org/Top10/2025/>
- <https://docs.docker.com/build/building/secrets/>
- <https://docs.docker.com/compose/how-tos/startup-order/>
- <https://docs.docker.com/engine/security/>
- <https://github.com/GoogleContainerTools/distroless>
- <https://trivy.dev/> · <https://github.com/anchore/grype> · <https://github.com/anchore/syft>
- <https://docs.sigstore.dev/cosign/signing/overview/>
