# Docker Security Skill

Container hardening from `FROM` line to running process.

## Purpose

Give an AI assistant a defensible position on container decisions. Most container advice
circulates as folklore - "use alpine", "don't run as root" - without the reason or the cost. This
skill states the failure first, names the standard, and admits where a control does not help.

Three things it exists to prevent:

- A secret baked into an image layer, shipped to a registry, and considered fixed because a later
  `RUN rm` deleted the file
- `/var/run/docker.sock` mounted into a CI container, which is unrestricted root on the host
- A hardened image running with every default capability, a writable root filesystem, and no
  memory limit

## How It Works

Plain Markdown. Nothing executes. The assistant reads `SKILL.md`, follows the five-step workflow
(trust boundary, image build, runtime config, supply chain, verify), and opens the supporting file
it needs at each step.

```text
SKILL.md                          workflow, severity, entry point
README.md                         this file
checklist.md                      pre-return verification, grouped by layer
best-practices.md                 patterns with vulnerable/fixed pairs
common-mistakes.md                what goes wrong and why the fix works
troubleshooting.md                when hardening breaks the container
prompts.md                        prompts that produce findings, plus anti-patterns
references/
  cis-docker-benchmark.md         control IDs, verified against the bench tool source
  runtime-flags.md                every flag that matters, what it does, what it costs
  owasp-mapping.md                Top 10 2025, ASVS 5.0, CWE mapping
examples/
  README.md                       eight vulnerable/fixed pairs with category + CWE
```

## Standards Covered

| Standard | Version | Verified |
|---|---|---|
| OWASP Top 10 | 2025 - A02 Security Misconfiguration, A03 Software Supply Chain Failures | 2026-07-28 |
| OWASP ASVS | 5.0.0 - V13 Configuration, V15 Secure Coding and Architecture | 2026-07-28 |
| CIS Docker Benchmark | control IDs read from `docker/docker-bench-security` sections 1–5 | 2026-07-28 |
| CWE | CWE-250, CWE-269, CWE-1104, CWE-522, CWE-732, CWE-798 | 2026-07-28 |

CIS control numbers are quoted only where the ID and title were read from source. The benchmark
PDF is behind a CIS account, so the reference file says which implementation the IDs came from
rather than pretending to quote the PDF. Details in
[references/cis-docker-benchmark.md](references/cis-docker-benchmark.md).

## Configuration

None. No build step, no dependency, no environment variable.

To use it in Claude Code, keep this repository in the working directory so
`skills/core/docker-security/SKILL.md` is readable, or copy the `docker-security` directory into
`~/.claude/skills/`. The frontmatter `allowed-tools` restricts it to read, search, and web lookup
plus `ls`/`cat` - it cannot run `docker` or modify the daemon.

## Example Usage

Review a Dockerfile against a named scope:

```text
Review Dockerfile and compose.yaml against skills/core/docker-security. For each finding give
the layer (image, runtime, host), the CIS control or OWASP category, what an attacker gains, and
the fix. Rank by what the attacker gains, not by scanner severity.
```

Ask for the hardened rewrite with the cost stated:

```text
Harden this Dockerfile: digest-pinned base, multi-stage, numeric non-root UID, read-only
filesystem. Tell me what breaks and what operational work the digest pin adds.
```

Triage scanner noise:

```text
Here is Trivy output for our image. Separate findings where our code actually calls the
vulnerable path from findings in binaries we never execute. Say which ones you cannot determine.
```

More in [prompts.md](prompts.md).

## Limitations

- Docker and Podman only. Kubernetes `securityContext`, Pod Security Standards, admission
  controllers, and network policy are out of scope - that belongs to `cloud-security`. The
  container-level reasoning transfers; the field names do not.
- No orchestrator runtime enforcement. This skill can tell you a compose file is wrong. It cannot
  stop someone running `docker run --privileged` by hand.
- Reading a Dockerfile cannot confirm what a base image actually contains. `FROM` a digest you
  have not inspected is still trusting someone. Pair with a scanner and an SBOM.
- Cannot verify reachability of a CVE. The skill says to distinguish reachable from unreachable
  findings, and gives a method, but confirming reachability needs runtime tracing or a
  reachability-aware scanner. Do not claim it from reading a Dockerfile.
- Windows containers are not covered. Process isolation, Hyper-V isolation, and the
  `ContainerAdministrator` account behave differently enough that applying Linux guidance is
  misleading.
- No claim about specific CVE numbers or scanner versions. Tool flags shown are the documented
  ones as of the check date; verify against your installed version.
- The docker socket alternatives listed (rootless, socket proxy, Kaniko, BuildKit) reduce blast
  radius. None of them make build-in-container equivalent in safety to a dedicated build host.

## Security Notes

This skill contains deliberately vulnerable Dockerfiles, compose files, and CI configuration in
`best-practices.md`, `common-mistakes.md`, and `examples/`. Every such block is labelled
`Vulnerable:` and paired with a fixed version. Do not copy a labelled-vulnerable block.

The digests in examples are illustrative placeholders in valid `sha256:` form. They are not real
image digests and will not pull. Resolve real digests with `docker buildx imagetools inspect`.

No real credentials, registry hostnames, or personal data appear anywhere in this skill.

## References

- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>
- OWASP ASVS - <https://owasp.org/www-project-application-security-verification-standard/>
- OWASP Docker Security Cheat Sheet - <https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html>
- CIS Docker Benchmark - <https://www.cisecurity.org/benchmark/docker>
- docker-bench-security - <https://github.com/docker/docker-bench-security>
- Docker build secrets - <https://docs.docker.com/build/building/secrets/>
- Rootless mode - <https://docs.docker.com/engine/security/rootless/>
- Trivy - <https://trivy.dev/> · Grype - <https://github.com/anchore/grype>
- Syft - <https://github.com/anchore/syft> · Sigstore cosign - <https://docs.sigstore.dev/cosign/signing/overview/>
- CWE-250, CWE-269, CWE-1104 - <https://cwe.mitre.org/>
