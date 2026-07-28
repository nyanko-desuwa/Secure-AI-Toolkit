# Prompt Examples

Prompts that get useful output from this skill. Each states the scope, the standard, and the
shape of the answer. Vague prompts produce a recital of best practices that applies to every
repository equally.

## Review a dependency change

```
Review the dependency changes in this diff against OWASP A03:2025. For each added or upgraded
package: is it pinned with a hash, does it declare install scripts, and is it reachable from a
request path? Read the lockfile diff, not just package.json. Skip pure version bumps of
packages already in the tree.
```

Why it works: the lockfile diff is where transitive additions appear, and "skip pure version
bumps" stops the answer being padded with the twelve changes that do not matter.

## Check an AI-suggested package name

```
An assistant suggested `huggingface-cli`. Treat the name as unverified. Find the canonical
install command in the upstream project's documentation, confirm repository and maintainers,
and say whether this could be a typosquat or slopsquat. Do not install it to test the answer.
```

Why it works: slopsquatting relies on the suggestion becoming an install without an independent
source of truth. "Do not install" keeps the check before the attack boundary.

## Audit transitive dependencies

```
Read the manifest and lockfile. Report the number of direct and transitive dependencies, every
new transitive package in this diff, who pulled it in, whether it declares an install hook, and
whether its resolved registry and integrity hash match policy. Do not treat the manifest as the
full tree.
```

Why it works: the direct-dependency audit misses the part of the tree nobody chose. Asking "who
pulled it in" turns a package name into a remediation path.

## Audit an SBOM policy path

```
Find where the release SBOM is generated, what exact artefact digest it describes, where it is
stored, and which gate consumes it. If no gate reads it, report generation as archival rather
than a security control. Compare build-graph and artefact-scan coverage.
```

Why it works: it tests the join and the consumer, not the existence of `sbom.json`.

## Check a name before installing it

```
I am about to add `python-jwt` to this project. Check whether that is the package I want:
what is its real repository, when was it first published, what does it depend on, and is there
a more established package with a similar name?
```

Typosquats install cleanly, so the only defence is checking before. Asking for first-publish
date and the neighbouring name catches most of them.

## Audit a release pipeline against SLSA

```
Read .github/workflows/release.yml and map it to SLSA v1.2 build levels. What level does it
reach today, what is the single change that would raise it, and is there any path by which a
fork PR reaches a secret or a write token? Cite the requirement, not just the level number.
```

Naming the version matters — SLSA renumbered between 0.1 and 1.0. Asking for the single next
change produces a plan instead of a wish list.

## Find the dependency confusion exposure

```
List every package manager configuration in this repo (.npmrc, pip.conf, settings.xml, go env,
Dockerfiles). For each: how many indexes can it resolve from, could an outsider publish a name
we use privately, and are internal packages namespaced? Map findings to ASVS 15.2.4.
```

Configuration is scattered across file types that share no naming convention, which is why
this one is worth asking as an enumeration rather than a review.

## Triage a scanner report honestly

```
We have 47 SCA findings. Group them by reachability from a request path, not by CVSS. For each
group give the remediation window from best-practices.md, and for anything you call unreachable
state how you determined it. Say which ones you could not determine.
```

The last sentence is the one that produces a usable answer. Without it you get 47 findings
sorted by severity, which is the report you already had.

## Design review before adding a build step

```
I want to add a step that downloads a linter binary and runs it in CI. Before I write it, what
controls does it need? Map each to a Top 10 category and an ASVS requirement, and tell me what
this adds to our attack surface that a package-managed tool would not.
```

Design-time prompts are cheaper than review-time ones, and the comparison question surfaces
the `curl | sh` problem without naming it.

## Respond to a malicious package

```
`some-pkg@4.2.1` has been reported as malicious and it is in our lockfile. Give me the response
order: what to revoke, how to find which builds consumed it, and what artefacts are suspect.
Do not start with the dependency fix.
```

The constraint at the end is load-bearing. The default answer is "upgrade the package", which
is the last step, not the first.

## Explain a control you disagree with

```
You said to pin GitHub Actions to a commit SHA. Our team says tags are fine because we trust
the action authors. Which should win, what specifically breaks with tags, and what does the
SHA pin cost us in maintenance?
```

Conflicts between a control and a team norm are normal. Asking for the cost as well as the
benefit produces an argument that survives contact with the team. See
[troubleshooting.md](troubleshooting.md).

## Anti-patterns

| Prompt | Problem |
|---|---|
| "Are our dependencies secure?" | No scope. Produces a generic checklist |
| "Update all packages to the latest version" | Removes the cooldown and merges unreviewed maintainer changes in bulk |
| "Make us SLSA compliant" | SLSA has levels and tracks, not compliance. Ask which level and what blocks the next one |
| "Fix all the CVEs" | Invites version bumps with no reachability analysis and no test budget |
| "Generate an SBOM" | Without saying from what, bound to which digest, and consumed by which policy, you get a file nobody uses |
| "Install whatever package fixes this import" | Turns a typo or LLM hallucination directly into code execution; verify the canonical name first |
| "Review package.json for dependency risk" | Misses most of the resolved tree; review the lockfile and explain transitive paths |
| "Add security to the pipeline" | Produces scanners that warn. Ask for a gate that fails |
