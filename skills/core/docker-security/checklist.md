# Docker Verification Checklist

Run before returning a Dockerfile, compose file, or CI pipeline. Mark each item pass, fail, or not
applicable. "Not applicable" needs a one-line reason - an unexplained skip is a gap.

Only run the sections the change touches. A compose-only change does not need the build section.

## Stop conditions

If any of these is true, report it first and rank it Critical. The rest of the checklist is secondary.

- [ ] [critical] `/var/run/docker.sock` is not mounted into any container (CIS 5.32, CWE-269)
- [ ] [critical] No `--privileged` or `privileged: true` (CIS 5.5)
- [ ] [critical] No `--network=host` / `network_mode: host` (CIS 5.10)
- [ ] [critical] No `--pid=host` / `pid: host` (CIS 5.16)
- [ ] [critical] No bind mount of `/`, `/etc`, `/proc`, `/sys`, `/dev`, `/var/lib/docker`, or a host SSH
      directory (CIS 5.6)
- [ ] [critical] No `--userns=host` (CIS 5.31)
- [ ] [critical] No `--cap-add=SYS_ADMIN` or `SYS_MODULE` without a written justification

## Image build (A03 · ASVS V15 · CIS 4.x)

- [ ] [recommended] Base image pinned by digest, with the tag kept alongside for readability (CIS 4.2, CWE-1104)
- [ ] [recommended] An automated digest bump exists (Renovate, Dependabot) - a pin with no update path is a
      patching gap, not a control
- [ ] [critical] `USER` set to a numeric UID above 10000, or 65532 for distroless `:nonroot` (CIS 4.1, CWE-250)
- [ ] [recommended] Multi-stage build: no compiler, package manager, `git`, `curl`, or dev dependency in the
      shipped stage (CIS 4.3)
- [ ] [critical] `COPY` used, not `ADD`. Any remote fetch verifies a checksum (CIS 4.9, CWE-494)
- [ ] [critical] `.dockerignore` present and written deny-all-then-allow. `.git`, `.env`, keys, and
      `node_modules` cannot reach the context
- [ ] [recommended] `apt-get update` never on its own `RUN` line (CIS 4.7)
- [ ] [recommended] setuid/setgid bits stripped, or their presence justified (CIS 4.8)
- [ ] [recommended] `HEALTHCHECK` present, and it works without a shell if the base image has none (CIS 4.6)
- [ ] [recommended] Dependencies installed from a lockfile with hashes where the ecosystem supports it

## Build-time secrets (A03 · ASVS V13 · CIS 4.10 · CWE-522)

- [ ] [critical] No credential in `ARG`, `ENV`, or a `COPY`-ed file
- [ ] [critical] Build credentials use `RUN --mount=type=secret`, with `# syntax=docker/dockerfile:1.x` present
- [ ] [critical] `docker history --no-trunc` shows no secret value
- [ ] [critical] Any secret that ever reached a pushed image is rotated, not just deleted

## Runtime (A02 · ASVS V13 · CIS 5.x)

- [ ] [recommended] `--cap-drop=ALL`, then only the capabilities the process demonstrably needs (CIS 5.4)
- [ ] [recommended] `NET_RAW` dropped unless the container needs raw sockets
- [ ] [recommended] `--read-only` root filesystem, with writable paths as sized `noexec,nosuid` tmpfs (CIS 5.13)
- [ ] [recommended] `no-new-privileges` set - per container, and on the daemon if you control it (CIS 5.26, 2.14)
- [ ] [recommended] Default seccomp profile not disabled (CIS 5.22)
- [ ] [recommended] AppArmor or SELinux left enabled where the host provides it (CIS 5.2, 5.3)
- [ ] [recommended] `--memory` and `--memory-swap` set (CIS 5.11)
- [ ] [recommended] `--cpus` set (CIS 5.12)
- [ ] [recommended] `--pids-limit` set (CIS 5.29)
- [ ] [recommended] `--restart=on-failure:5`, not `always` (CIS 5.15)
- [ ] [recommended] Ports bound to `127.0.0.1` unless the service is genuinely public (CIS 5.14)
- [ ] [recommended] Only required ports published. No port below 1024 mapped inside the container (CIS 5.8, 5.9)
- [ ] [recommended] A user-defined network, not the default `docker0` bridge (CIS 5.30)
- [ ] [recommended] No `sshd` in the container (CIS 5.7)
- [ ] [recommended] Mount propagation not `shared` (CIS 5.20)

## Runtime secrets (A04 · ASVS V14 · CWE-522)

- [ ] [critical] No secret value in `environment:` or `-e`. Pass a path, not a value
- [ ] [critical] `docker inspect --format '{{json .Config.Env}}'` shows no credential
- [ ] [critical] Secrets arrive as files: bind-mounted by Compose from a protected host source, or tmpfs-backed via Swarm/an injector
- [ ] [recommended] Secret files are `0400` and owned by the runtime UID
- [ ] [critical] Any host-side secret file is gitignored and not world-readable

## Compose (A02 · ASVS V13)

- [ ] [recommended] No unintended `ports:` - internal services talk over the network, not published ports
- [ ] [recommended] `depends_on` uses `condition: service_healthy` where startup order matters
- [ ] [recommended] Every service that accepts traffic has a `healthcheck`
- [ ] [recommended] Volumes are `:ro` unless the service must write
- [ ] [critical] No `env_file` pointing at a committed file with real credentials

## Supply chain (A03, A08 · ASVS V15 · CIS 4.4, 4.12)

- [ ] [recommended] Image scanned in CI, with a gating scan (`--ignore-unfixed`, critical and high) separate from
      a full reporting scan
- [ ] [recommended] The gate can actually fail the build. Confirm `exit-code` is not `0` on the gating step
- [ ] [recommended] Base image update cadence defined and running, not "when someone notices"
- [ ] [recommended] SBOM generated and stored with the image, not regenerated later from a rebuilt image
- [ ] [critical] Image signed by digest, never by tag
- [ ] [critical] Signature verification happens at pull or admission time, with
      `--certificate-identity-regexp` and `--certificate-oidc-issuer` pinned
- [ ] [recommended] Registry is private, or the image contains nothing that should not be public
- [ ] [recommended] Release tags are immutable, or deployments reference digests only
- [ ] [recommended] Pull credentials are short-lived tokens, scoped to read, and not shared across environments

## Host and daemon, where you control them (A02 · CIS 1.x, 2.x, 3.x)

- [ ] [recommended] Rootless mode or `userns-remap` in use, or a written reason it is not (CIS 2.1, 2.9)
- [ ] [recommended] `docker` group membership limited - it is equivalent to root (CIS 1.1.2)
- [ ] [recommended] `"no-new-privileges": true` in `daemon.json` (CIS 2.14)
- [ ] [critical] No insecure registries configured (CIS 2.5)
- [ ] [recommended] Docker Engine version current (CIS 1.2.2)

## Findings report

- [ ] [recommended] Each finding names the layer (image, runtime, host), a standard, and what the attacker gains
- [ ] [recommended] Severity reflects attacker gain, not scanner severity
- [ ] [recommended] Scanner findings separated into reachable, unreachable, and undetermined - with
      "undetermined" said out loud rather than guessed
- [ ] [critical] Anything unverifiable from reading files is stated as unverifiable
