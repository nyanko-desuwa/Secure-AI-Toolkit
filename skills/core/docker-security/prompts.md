# Prompt Examples

Prompts that produce findings rather than a Docker folklore recital. Each states the files, the
standard, and the expected answer shape.

## Review a Dockerfile and its context

```text
Review Dockerfile and .dockerignore against skills/core/docker-security. For each finding give
Dockerfile:line, OWASP Top 10 2025 category, ASVS chapter, CIS control, CWE, what reaches the final
image, and a fixed Dockerfile block. Check layer history risks, not only the final filesystem.
```

Why it works: asking what reaches the final image forces a multi-stage and layer-history review.
Without it, a later `rm` looks like remediation.

## Review the runtime configuration

```text
Review compose.yaml and every docker run command in scripts/. Start with host-compromise paths:
docker socket, privileged mode, host namespaces, and dangerous bind mounts. Then check non-root,
capability drop, no-new-privileges, read-only root, seccomp, AppArmor, and resource limits. Report
what an attacker gains for each finding.
```

The order matters. Finding a missing healthcheck before a docker socket mount is a failed review.

## Harden an existing image

```text
Rewrite this Dockerfile as a multi-stage build with a digest-pinned base, numeric UID above 10000,
BuildKit secret mounts, COPY instead of ADD, and a healthcheck. Produce the matching .dockerignore.
State what debugging capability the chosen runtime base removes and how to debug it in production.
```

Naming the cost prevents a cargo-cult distroless choice.

## Design a base image policy

```text
We ship Go, Python, and Java services. Propose an allowed base image list: scratch, distroless,
Alpine, or slim per runtime. For each choice state the attack-surface reduction, libc compatibility,
healthcheck strategy, and debugging path. Require digest pinning and an automated update cadence.
```

## Review CI for build secrets and supply chain

```text
Review .github/workflows/image.yaml. Trace every credential from CI secret to Dockerfile. Flag any
value that reaches ARG, ENV, docker history, the build cache, or image layers. Then check Trivy/Grype
gating, SBOM generation, digest signing, and admission-time verification. Show corrected runnable
steps.
```

## Triage scanner output

```text
Triage trivy.json for registry.example.com/api@sha256:.... Group findings into reachable,
unreachable, and undetermined. For each reachable finding show the package, vulnerable path, input
source, fixed version, and runtime mitigations. Do not call a CVE critical just because the scanner
does. Be explicit where reachability cannot be established from the repository.
```

## Audit the docker socket in CI

```text
Search all compose files, CI workflows, shell scripts, and task definitions for
/var/run/docker.sock, DOCKER_HOST, privileged containers, and DinD. For each hit say whether forked
pull requests can execute code there. Propose a dedicated builder, rootless BuildKit, or an
endpoint-allowlisted socket proxy. Treat a direct socket mount as host root.
```

## Generate a hardened compose file

```text
Create a production compose.yaml for the existing api and postgres services. Requirements:
digest-pinned images, numeric users, read_only, tmpfs /tmp, cap_drop ALL, no-new-privileges,
memory/CPU/PID limits, healthchecks, depends_on service_healthy, database on an internal network,
and only the API bound to 127.0.0.1. Runtime secrets must be files, never ENV values. Explain any
capability you add back.
```

## Verify before deploy

```text
Run skills/core/docker-security/checklist.md against this release. Mark each item pass, fail, or not
applicable with a reason. Show the exact evidence: Dockerfile line, compose key, CI step, or docker
inspect field. Do not mark daemon-level controls pass unless you inspected the daemon.
```

## Registry review

```text
Review our registry configuration and deploy script for private repository access, short-lived pull
credentials, immutable release tags, digest references, and cosign verification. Show whether a tag
can be repointed after review and whether deployment verifies the signing identity, not only the
presence of a signature.
```

## Anti-patterns

| Prompt | Problem |
|---|---|
| "Make this Dockerfile secure" | No runtime scope. Produces `USER node` and stops |
| "Use Alpine to reduce attack surface" | Picks a base before checking libc compatibility or debugging needs |
| "Fix all Trivy findings" | Treats scanner output as truth and creates an unmaintainable exception file |
| "Add Docker best practices" | Invites a recital instead of findings tied to exploitable paths |
| "Make it CIS compliant" | A repository review cannot verify host or daemon controls. Ask for named sections |
| "Use latest security patches" | Often produces `FROM latest`, which makes the build unreproducible |
| "Run Docker in Docker securely" | Assumes the architecture. Ask whether a dedicated or rootless builder removes the need |
| "Sign the image" | Produces a signature nobody verifies. Ask for admission-time verification and signer identity |
