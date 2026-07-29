---
name: docker-security
description: 'Harden container images and runtime. Covers Dockerfile hygiene, digest pinning, capability dropping, the docker socket, secrets, scanning, SBOM, and signing. Maps to OWASP Top 10 2025 A02/A03, ASVS 5.0 V13/V15, and the CIS Docker Benchmark. Triggers: "Dockerfile", "docker", "container", "compose", "image scan", "docker socket", "bảo mật Docker", "container".'
allowed-tools: Read, Glob, Grep, WebSearch, WebFetch
---

# Docker Security

Building, shipping, and running containers without handing the host away.

## When to Use

- Writing or reviewing a `Dockerfile`, `compose.yaml`, or container build in CI
- Choosing a base image, or being asked why `latest` is a problem
- Deciding what a container is allowed to do at runtime: capabilities, mounts, network
- Getting build-time or run-time credentials into a container
- Wiring image scanning, SBOM generation, or signing into a pipeline
- Triaging scanner output that has 400 findings and no obvious priority

## The Three Layers

A container has three independent places to get this wrong. Fixing one does not fix the others.

| Layer | Question | Standards |
|---|---|---|
| Image | What is in it, and where did it come from? | A03:2025 · ASVS V15 · CIS 4.x |
| Runtime | What can the process do once it starts? | A02:2025 · ASVS V13 · CIS 5.x |
| Host and daemon | Who can talk to the daemon? | A02:2025 · CIS 1.x, 2.x, 3.x |

A distroless image running `--privileged` with the docker socket mounted is not secure because
the image is small. Most real incidents are runtime, not image contents.

## Workflow

### 1. Establish the trust boundary

Before reading the Dockerfile, answer: does this container process untrusted input? A container
serving public HTTP is a boundary. A batch job reading an internal queue is not, and does not
justify the same cost.

Then: is a container the boundary at all? A container is a process isolation feature that shares
a kernel. If the threat model is "attacker runs their own code", the boundary is a VM or gVisor,
not a namespace. Say this rather than hardening a container that was never going to hold.

### 2. Read the image build

In order, because each one is cheap to check and expensive to miss:

1. Base image - pinned by digest, or a floating tag? `FROM node:latest` is A03.
2. `USER` - is there one, and is it a numeric UID? See
   [best-practices.md](best-practices.md#run-as-a-non-root-uid).
3. Secrets - any `ARG` or `ENV` holding a credential, any `COPY` of a `.env` or key file.
   Layers are immutable; a later `RUN rm` deletes nothing.
4. Multi-stage - does the shipped stage contain compilers, package managers, git, curl?
5. `ADD` vs `COPY`, `.dockerignore` presence, `HEALTHCHECK`.

### 3. Read the runtime configuration

The compose file, the `docker run` invocation, or the Kubernetes `securityContext`. Look for the
four that end the conversation:

- `/var/run/docker.sock` mounted in - this is root on the host, full stop
- `--privileged`
- `--network=host` or `--pid=host`
- a bind mount of `/`, `/etc`, `/proc`, or `/var/lib/docker`

Then the defaults nobody set: no `--cap-drop`, writable root filesystem, no memory limit, no
`no-new-privileges`. See [references/runtime-flags.md](references/runtime-flags.md).

### 4. Check the supply chain

Is the image scanned in CI and does the pipeline fail on anything? Is there an SBOM? Is the image
signed and is that signature verified at deploy time, or only produced? Producing signatures
nobody checks is theatre - say so.

### 5. Verify

Run [checklist.md](checklist.md). Every unchecked box is a fix or a stated limitation.

## Severity

Rank by what an attacker gets, not by how the finding looks in a scanner.

- **Critical** - host compromise from inside the container: docker socket mounted,
  `--privileged`, a bind mount of a host path with an executable the host runs
- **High** - root inside the container plus a writable filesystem and a network-facing process;
  a live secret readable from the image or `docker inspect`
- **Medium** - unpinned base image, missing capability drop, no resource limits, root user in a
  container that processes no untrusted input
- **Low** - missing `HEALTHCHECK`, no SBOM, image larger than it needs to be

A CVE in a package the image never executes is not High because the scanner said so. State
whether the vulnerable code path is reachable. See
[common-mistakes.md](common-mistakes.md#treating-scanner-severity-as-finding-severity).

## Related Skills

- `devsecops` - pipeline controls, gating, and policy as code
- `cloud-security` - orchestrator-level controls, IAM for registries
- `secrets-management` - where the secret comes from before it reaches the container
- `redis-security` - Redis/Valkey listener, ACL, TLS, mounted data, and persistence controls inside the container
- `owasp-security` - the standards this maps to

## Supporting Files

- [README.md](README.md) - purpose, layout, standards table, limitations
- [checklist.md](checklist.md) - pre-return verification
- [best-practices.md](best-practices.md) - patterns, with vulnerable/fixed pairs
- [common-mistakes.md](common-mistakes.md) - what goes wrong and why the fix works
- [troubleshooting.md](troubleshooting.md) - when hardening breaks the container
- [prompts.md](prompts.md) - prompts that produce findings
- [references/cis-docker-benchmark.md](references/cis-docker-benchmark.md) - verified control IDs
- [references/runtime-flags.md](references/runtime-flags.md) - flag-by-flag reference
- [references/owasp-mapping.md](references/owasp-mapping.md) - Top 10, ASVS, CWE mapping
- [examples/README.md](examples/README.md) - eight vulnerable/fixed pairs
