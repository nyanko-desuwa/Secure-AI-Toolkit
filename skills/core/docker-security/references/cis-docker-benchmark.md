# CIS Docker Benchmark

Control IDs used by this skill. Every ID and title below was read on 2026-07-28 from the source of
`docker/docker-bench-security`, which states in its README that its tests implement
CIS Docker Benchmark v1.6.0.

- Tool source — <https://github.com/docker/docker-bench-security>
- Benchmark landing page — <https://www.cisecurity.org/benchmark/docker>
- Docker Content Trust retirement notice — <https://docs.docker.com/engine/security/trust/>

## Read this before citing a control

The benchmark PDF itself is distributed through a CIS account and is not quoted here. What is
quoted is the ID and title as implemented by the bench tool. That is enough to say "CIS 5.32
covers the docker socket" and defend it. It is not enough to quote rationale text, remediation
wording, or a Level 1 / Level 2 profile assignment — those live in the PDF and are not reproduced
below.

If a control ID is not in the tables on this page, do not cite it. Newer benchmark revisions
renumber and add controls; an ID recalled from memory is likely to be wrong, and a wrong control
number discredits an otherwise correct finding. Cite the OWASP category and CWE instead.

## Section 1 — Host configuration

1.1.3 through 1.1.18 are auditd rules for Docker paths (`/var/lib/docker`, `/etc/docker`,
`docker.service`, `docker.socket`, `containerd.sock`, `/etc/docker/daemon.json`,
`/etc/containerd/config.toml`, `/usr/bin/containerd*`, `/usr/bin/runc`, and others). The first two
checks in this subsection cover a separate partition for containers (1.1.1) and restricting who may
control the daemon (1.1.2).

| ID | Title (abbreviated) | Why it matters here |
|---|---|---|
| 1.1.2 | Ensure only trusted users are allowed to control Docker daemon | Membership of the `docker` group is equivalent to root |
| 1.2.1 | Ensure the container host has been hardened | The kernel is shared; the host is in scope |
| 1.2.2 | Ensure that the version of Docker is up to date | Runtime escapes get fixed in the runtime |

## Section 2 — Daemon configuration

| ID | Title (abbreviated) |
|---|---|
| 2.1 | Run the Docker daemon as a non-root user, if possible |
| 2.2 | Ensure network traffic is restricted between containers on the default bridge |
| 2.5 | Ensure insecure registries are not used |
| 2.9 | Enable user namespace support |
| 2.13 | Ensure centralized and remote logging is configured |
| 2.14 | Ensure containers are restricted from acquiring new privileges |
| 2.17 | Ensure that a daemon-wide custom seccomp profile is applied if appropriate |
| 2.18 | Ensure that experimental features are not implemented in production |

2.1 is rootless mode. 2.14 is the daemon-wide equivalent of `--security-opt=no-new-privileges`, and
setting it on the daemon is stronger than hoping every `docker run` remembers the flag.

## Section 3 — Daemon configuration files

Twenty-four ownership and permission checks (3.1 to 3.24) on `docker.service`, `docker.socket`,
`/etc/docker`, registry and TLS certificate files, `daemon.json`, `/etc/default/docker`,
`/etc/sysconfig/docker`, and the containerd socket.

| ID | Title (abbreviated) |
|---|---|
| 3.15 | Ensure that the Docker socket file ownership is set to `root:docker` |
| 3.16 | Ensure that the Docker socket file permissions are set to 660 or more restrictively |

3.15 and 3.16 are the host-side half of the socket problem. 5.32 is the container-side half.

## Section 4 — Container images and build file

This is the Dockerfile section. Twelve controls.

| ID | Title (abbreviated) | Automated? |
|---|---|---|
| 4.1 | Ensure that a user for the container has been created | Automated |
| 4.2 | Ensure that containers use only trusted base images | Manual |
| 4.3 | Ensure that unnecessary packages are not installed in the container | Manual |
| 4.4 | Ensure images are scanned and rebuilt to include security patches | Manual |
| 4.5 | Ensure Content trust for Docker is enabled | Automated |
| 4.6 | Ensure that HEALTHCHECK instructions have been added to container images | Automated |
| 4.7 | Ensure update instructions are not used alone in the Dockerfile | Manual |
| 4.8 | Ensure setuid and setgid permissions are removed | Manual |
| 4.9 | Ensure that COPY is used instead of ADD in Dockerfiles | Manual |
| 4.10 | Ensure secrets are not stored in Dockerfiles | Manual |
| 4.11 | Ensure only verified packages are installed | Manual |
| 4.12 | Ensure all signed artifacts are validated | Manual |

Note on 4.5: Docker Content Trust is the Notary v1 mechanism, driven by `DOCKER_CONTENT_TRUST=1`.
Docker's documentation now states that DCT is being retired and that the public Notary v1 service at
`notary.docker.io` shuts down on 2026-12-08. Sigstore cosign is the approach this skill's CI examples
use. They are different systems solving the same control. Do not introduce a retiring Notary v1
dependency into a new pipeline solely to make this check pass.

Note on 4.7: `RUN apt-get update` on its own line creates a cached layer whose package index goes
stale, so a later `apt-get install` may install from a months-old index. Combine them in one `RUN`.

## Section 5 — Container runtime

Thirty-two controls, 5.1 to 5.32. The ones this skill leans on:

| ID | Title (abbreviated) | Flag |
|---|---|---|
| 5.2 | Ensure that, if applicable, an AppArmor profile is enabled | `--security-opt apparmor=...` |
| 5.3 | Ensure that, if applicable, SELinux security options are set | `--security-opt label=...` |
| 5.4 | Ensure that Linux kernel capabilities are restricted within containers | `--cap-drop=ALL` |
| 5.5 | Ensure that privileged containers are not used | absence of `--privileged` |
| 5.6 | Ensure sensitive host system directories are not mounted on containers | bind mounts |
| 5.7 | Ensure sshd is not run within containers | — |
| 5.8 | Ensure privileged ports are not mapped within containers | port `< 1024` |
| 5.9 | Ensure that only needed ports are open on the container | `EXPOSE`, `-p` |
| 5.10 | Ensure that the host's network namespace is not shared | `--network=host` |
| 5.11 | Ensure that the memory usage for containers is limited | `--memory` |
| 5.12 | Ensure that CPU priority is set appropriately on containers | `--cpu-shares`, `--cpus` |
| 5.13 | Ensure that the container's root filesystem is mounted as read only | `--read-only` |
| 5.14 | Ensure that incoming container traffic is bound to a specific host interface | `-p 127.0.0.1:...` |
| 5.15 | Ensure that the 'on-failure' container restart policy is set to '5' | `--restart=on-failure:5` |
| 5.16 | Ensure that the host's process namespace is not shared | `--pid=host` |
| 5.17 | Ensure that the host's IPC namespace is not shared | `--ipc=host` |
| 5.18 | Ensure that host devices are not directly exposed to containers | `--device` |
| 5.19 | Ensure that the default ulimit is overwritten at runtime if needed | `--ulimit` |
| 5.20 | Ensure mount propagation mode is not set to shared | `:shared` |
| 5.21 | Ensure that the host's UTS namespace is not shared | `--uts=host` |
| 5.22 | Ensure the default seccomp profile is not disabled | `--security-opt seccomp=unconfined` |
| 5.23 | Ensure that docker exec commands are not used with the privileged option | `docker exec --privileged` |
| 5.24 | Ensure that docker exec commands are not used with the user=root option | `docker exec --user=root` |
| 5.25 | Ensure that cgroup usage is confirmed | `--cgroup-parent` |
| 5.26 | Ensure that the container is restricted from acquiring additional privileges | `no-new-privileges` |
| 5.27 | Ensure that container health is checked at runtime | `HEALTHCHECK` present and reported |
| 5.28 | Ensure that Docker commands always make use of the latest version of their image | pull policy |
| 5.29 | Ensure that the PIDs cgroup limit is used | `--pids-limit` |
| 5.30 | Ensure that Docker's default bridge `docker0` is not used | user-defined network |
| 5.31 | Ensure that the host's user namespaces are not shared | `--userns=host` |
| 5.32 | Ensure that the Docker socket is not mounted inside any containers | `/var/run/docker.sock` |

Six of the thirty-two are Manual: 5.9, 5.18, 5.19, 5.24, 5.28, 5.30. A Manual control cannot be
satisfied by a passing bench run — someone has to look.

## Running the bench tool

```bash
docker run --rm --net host --pid host --userns host --cap-add audit_control \
  -e DOCKER_CONTENT_TRUST="$DOCKER_CONTENT_TRUST" \
  -v /etc:/etc:ro \
  -v /var/lib:/var/lib:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  --label docker_bench_security \
  docker/docker-bench-security
```

Read that invocation before you run it. It shares the host PID and user namespaces, adds
`audit_control`, and mounts the docker socket — the exact things this skill tells you not to do.
That is defensible for a short-lived audit run on a host you already administer, and not defensible
as a long-running service. Prefer running the script directly from a checkout on the host.

`:ro` on a socket mount is not a meaningful restriction. The socket is a bidirectional API; read-only
prevents nothing that matters.

## What the benchmark does not cover

- Image provenance beyond content trust. No SBOM, no cosign, no attestation verification
- Registry access control and credential handling
- Multi-stage build hygiene
- BuildKit build-time secrets
- Anything orchestrator-level. For Kubernetes use the CIS Kubernetes Benchmark and Pod Security
  Standards instead
