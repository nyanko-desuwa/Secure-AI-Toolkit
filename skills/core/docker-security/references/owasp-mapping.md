# OWASP and CWE Mapping

How container findings map to the standards this skill cites. Verified 2026-07-28 against:

- <https://owasp.org/Top10/2025/>
- <https://owasp.org/www-project-application-security-verification-standard/>
- <https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html>
- <https://cwe.mitre.org/>

## Top 10 2025 categories that apply

Containers land in two categories. Claiming more than that dilutes the report.

### A02:2025 - Security Misconfiguration

Everything about how the container runs. Defaults left in place, privilege not dropped, ports
exposed wider than intended, a writable filesystem where none is needed.

The 2025 edition moved this up the list. Container runtime configuration is the most common place a
correct application is deployed insecurely.

Report under A02: root user, missing `--cap-drop`, `--privileged`, host namespaces, docker socket
mount, missing resource limits, `0.0.0.0` port publishing, seccomp disabled.

### A03:2025 - Software Supply Chain Failures

Everything about what is in the image and where it came from. This is a new 2025 category and it is
broader than the old "vulnerable and outdated components" - it covers the base image, the registry,
the build tooling, and the artefact.

Report under A03: `FROM` a floating tag, no digest pin, unscanned images, no SBOM, unsigned images,
signatures produced but never verified, mutable tags in a registry, build pulling from an unverified
source.

### Categories that do not apply

- A04 Cryptographic Failures - a secret in an image layer is not a crypto failure. It is A02 if it
  is a runtime configuration leak, A03 if it shipped in the artefact. Cite CWE-522 or CWE-798.
- A05 Injection - a Dockerfile is not an interpreter boundary. `ARG` interpolation into a `RUN`
  during a build from an untrusted PR is closer to A08.
- A08 Software or Data Integrity Failures - applies when an unverified artefact is executed. An
  unsigned image deployed without verification can be reported as A08 instead of A03 when the point
  is the missing verification step rather than the source.

## ASVS 5.0 chapters

| Chapter | Container relevance |
|---|---|
| V13 Configuration | Build, deploy, and secret configuration. The primary chapter for container runtime settings, secret injection, and hardening flags |
| V15 Secure Coding and Architecture | Design-level and supply chain requirements. Base image provenance, dependency pinning, artefact integrity |
| V12 Secure Communication | TLS for the registry and the daemon socket when exposed over TCP |
| V14 Data Protection | Sensitive data in volumes, in image layers, and in logs |
| V16 Logging and Error Handling | Container log configuration, and not shipping secrets to a log driver |

Cite at chapter level. ASVS 5.0 requirement IDs are new enough that a recalled number is likely
wrong, and an invented ID is worse than a chapter citation. Pull exact text from
<https://github.com/OWASP/ASVS> if a requirement-level citation is needed.

## CWE

| CWE | Title | Container form |
|---|---|---|
| CWE-250 | Execution with Unnecessary Privileges | Container runs as root, or with capabilities it does not use |
| CWE-269 | Improper Privilege Management | Privilege dropped incompletely; setuid binaries left in the image; `no-new-privileges` absent |
| CWE-1104 | Use of Unmaintained Third Party Components | Base image never rebuilt; abandoned image on Docker Hub |
| CWE-522 | Insufficiently Protected Credentials | Secret in `ENV`, visible in `docker inspect` |
| CWE-798 | Use of Hard-coded Credentials | Secret baked into an image layer |
| CWE-732 | Incorrect Permission Assignment for Critical Resource | World-writable files in the image; loose permissions on a mounted secret |
| CWE-668 | Exposure of Resource to Wrong Sphere | Docker socket or host path mounted into a container |
| CWE-770 | Allocation of Resources Without Limits | No memory, CPU, or PID limit |
| CWE-16 | Configuration | Fallback when nothing more specific fits. Prefer a specific CWE |

Docker socket mount: CWE-668 is the closest structural fit, with CWE-250 for the privilege gained.
There is no CWE that says "container escape", so describe the mechanism instead of hunting for one.

## Finding-to-standard lookup

| Finding | Top 10 | ASVS | CWE |
|---|---|---|---|
| `FROM node:latest` | A03 | V15 | CWE-1104 |
| No digest pin | A03 | V15 | CWE-1104 |
| Runs as root | A02 | V13 | CWE-250 |
| No `--cap-drop=ALL` | A02 | V13 | CWE-250 |
| `--privileged` | A02 | V13 | CWE-250, CWE-269 |
| Docker socket mounted | A02 | V13 | CWE-668, CWE-250 |
| Host network or PID namespace | A02 | V13 | CWE-668 |
| Secret in `ENV` or `ARG` | A02 | V13, V14 | CWE-522 |
| Secret in an image layer | A03 | V14 | CWE-798 |
| Writable root filesystem | A02 | V13 | CWE-732 |
| No resource limits | A02 | V13 | CWE-770 |
| setuid binaries retained | A02 | V13 | CWE-269 |
| No image scanning in CI | A03 | V15 | CWE-1104 |
| No SBOM | A03 | V15 | - |
| Unsigned image, unverified deploy | A03 or A08 | V15 | CWE-345 |
| Insecure registry over HTTP | A03 | V12 | CWE-319 |
| Build tooling in the shipped image | A03 | V15 | CWE-1104 |
| Port published on `0.0.0.0` | A02 | V13 | CWE-668 |

## CIS Docker Benchmark

The CIS benchmark is the control-by-control reference for the same ground. Where a finding has a CIS
control, cite it alongside the OWASP category - CIS is more specific and more useful to whoever has
to fix it. See [cis-docker-benchmark.md](cis-docker-benchmark.md) for verified IDs.
