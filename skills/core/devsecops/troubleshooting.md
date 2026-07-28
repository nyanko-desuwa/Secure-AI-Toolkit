# DevSecOps Troubleshooting

What to do when the secure pipeline design does not fit the existing repository.

## The scanner finds thousands of issues

Do not suppress the ruleset or mark the entire job non-blocking forever.

1. Export a stable baseline with fingerprints.
2. Remove obvious duplicates and generated/vendor paths.
3. Triage reachable critical and high findings now.
4. Block only findings introduced relative to the baseline.
5. Assign the baseline to owners with a dated burn-down plan.

If the tool cannot compare baselines reliably, run it on changed files or post-process stable
fingerprints. If neither is possible, keep it advisory while evaluating another tool.

`A03:2025` · ASVS V15 · NIST SSDF RV.1

## A blocking rule has false positives

Take it out of the blocking profile immediately, not out of all scanning. Keep it advisory, collect
examples, narrow source/sink/path conditions, and add safe and unsafe rule tests. Restore blocking
only after the observed false positive rate is near zero.

Do not teach the team to bypass the whole gate for one bad rule. Bypass habits outlive the rule.

`A03:2025` · ASVS V15 · NIST SSDF PW.5

## The security job is too slow

Measure by step. Cache immutable scanner databases where safe. Scope PR analysis to the diff and
lockfile changes. Split independent checks. Move full history, authenticated DAST, base-image
rescans, and deep interfile analysis to nightly.

Do not add `continue-on-error` to meet the timing target. That changes enforcement, not speed.

`A03:2025` · ASVS V15 · NIST SSDF PW.5

## A tool reports a high CVE but the function is unreachable

Keep the upstream severity and attach a contextual assessment. Record how reachability was tested,
which deployed artifact was examined, and what change would invalidate the conclusion. A static
reachability engine can miss reflection, plugins, dynamic imports, native calls, and configuration-
selected paths.

If evidence is weak, downgrade confidence rather than severity. If a fix is low risk, update anyway.

`A03:2025` · ASVS V15 · NIST SSDF RV.1 · CWE-1104

## No lockfile exists

Do not pretend a manifest range is a pin. Introduce the ecosystem's standard lockfile in a focused,
reviewed change, record the resolved dependency delta, and change CI to its frozen install command.
If the ecosystem genuinely has no lockfile, pin exact versions and hashes in its native mechanism
and archive the resolved graph with the build.

`A03:2025` · ASVS V15 · NIST SSDF PS.3 · CWE-829

## A dependency needs install scripts

Do not globally use `--ignore-scripts` and assume success. Identify the required script, inspect its
source and transitive tools, pin all executable inputs, and isolate installation from secrets and
write tokens. If safe, permit the script only in trusted builds; fork PR tests may use a reduced
path that cannot publish.

The remaining limitation is explicit: install scripts execute supplier code. Isolation and least
privilege limit impact; they do not make the code trustworthy.

`A03:2025` · ASVS V15 · CWE-829

## The workflow claims it needs `pull_request_target`

Ask which privileged operation is required. Most tests need none and belong in `pull_request`.
Comments or labels can use a separate privileged workflow that never checks out or executes the PR.
For result handoff, use `workflow_run` and treat the artifact as untrusted data: validate schema,
size, identifiers, and paths; never source a script or execute a binary from it.

If code owners insist on one workflow, do not silently approve it. State that untrusted code and
secrets/write permission cannot safely coexist and propose the split.

`A08:2025` · ASVS V13, V15 · CWE-829

## A privileged third-party action has no immutable release guidance

Resolve the selected release tag to its full commit SHA, inspect the diff and action entry point,
and pin that commit. Prefer a small auditable action or direct CLI invocation from a verified binary
when the action's dependency tree is too large to review. Record the release tag in a comment.

Do not fork an action merely to obtain a SHA; Git commits already have one. A private fork transfers
maintenance and vulnerability response to your team.

`A03:2025` · ASVS V15 · CWE-829, CWE-506

## OIDC is unavailable in the cloud or platform

Use the shortest-lived credential the provider supports. Store it in an environment-scoped secret,
restrict it to the deploy job and protected environment, rotate automatically, alert on use, and
deny access from PR jobs. Open a dated migration item for federation.

Do not expose a long-lived key at workflow scope because "masking" protects the log. It does not
protect the process, action, runner, or artifacts.

`A03:2025` · `A08:2025` · ASVS V13 · CWE-829

## Keyless cosign is unavailable

Keep the private signing key in an HSM or cloud KMS, grant signing only to the release identity,
and keep build steps from reading key material. Verify by key identity and artifact digest at
admission. Rotate and audit the key.

This can provide strong signing, but provenance strength still depends on build platform isolation.
A KMS signature does not make a self-modifying build SLSA Build L3.

`A08:2025` · ASVS V15 · SLSA 1.2

## Reproducible builds are not feasible

Pin every known input, normalize timestamps and locale where possible, and record the remaining
non-deterministic inputs. Generate platform provenance and a digest anyway. Reproducibility is
independent corroboration, not a prerequisite for signing or provenance.

`A08:2025` · ASVS V15 · SLSA 1.2

## DAST cannot authenticate

Create a dedicated least-privilege test account and a scripted login suitable for the isolated
environment. Seed deterministic state. Keep credentials out of the scan plan and logs. If MFA or an
external identity provider prevents automation, cover unauthenticated paths in DAST and exercise
authenticated security assertions in integration tests. State the coverage gap.

Do not disable production MFA to make the scanner work.

`A03:2025` · ASVS V15 · NIST SSDF PW.8

## The licence scanner says `UNKNOWN`

Inspect the package's source distribution, metadata, and licence text. Treat unknown, custom, dual,
and conflicting declarations as review-required. Do not map `UNKNOWN` to allowed. Legal counsel or
the organization's designated owner decides the obligation.

`A03:2025` · ASVS V15 · CWE-1104

## Branch protection cannot be configured from the repository

Provide the exact required job names, required review count, code-owner requirement, conversation
resolution, and administrator bypass policy to the repository administrator. Until it is applied,
state that the workflow is advisory even if jobs are green.

`A08:2025` · ASVS V13 · NIST SSDF PS.1

## A scanner and a standard disagree

A scanner implements a ruleset; the standard states an objective. Verify the rule's actual data
flow and version. If the finding does not establish an exploitation path, report it as a hardening
opportunity or uncertain finding, not a vulnerability. If the standard requires a control the tool
cannot test, add a manual or integration verification rather than marking the scanner green as
compliance.

`A03:2025` · ASVS V15 · NIST SSDF PW.5
