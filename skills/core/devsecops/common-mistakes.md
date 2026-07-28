# Common DevSecOps Mistakes

These failures usually start as reasonable shortcuts. Each one either destroys signal or gives an
untrusted build more authority than it needs.

## Making the new scanner block on day one

`A03:2025` · ASVS V15 · NIST SSDF PW.5, RV.1

A full scan finds 4,000 historical issues and every pull request turns red. The team adds
`continue-on-error: true`, so the job runs forever and nobody opens the report.

Fix: triage critical reachable findings first, save a reviewed baseline, block only new findings,
and put the baseline on an owned burn-down plan.

Why it works: the current change gets a meaningful pass/fail signal. The tempting wrong fix is
raising the severity threshold globally. That hides new medium issues along with historical noise.

## Treating every high-CVSS dependency as a high finding

`A03:2025` · ASVS V15 · NIST SSDF RV.1 · CWE-1104

The vulnerable package is present only in a test tool, the vulnerable function is never called,
and production does not ship it. Calling this critical crowds out a reachable RCE.

Fix: record package presence, deployment context, vulnerable-function reachability, attacker
control, exploit maturity, and blast radius. Preserve the original CVSS; add a contextual severity
rather than rewriting external data.

Why it works: remediation order reflects actual risk without pretending the upstream advisory is
wrong. "Not reachable" must have evidence and a recheck trigger when the call graph changes.

## Running DAST against shared production

`A03:2025` · ASVS V15 · NIST SSDF PW.8

An active ZAP scan modifies data, trips rate limits, and reports another team's transient state as
a vulnerability.

Fix: deploy the exact build to an isolated environment with seeded accounts and disposable data.
Use a tuned baseline scan for regular runs and reserve active/full rules for an approved window.

Why it works: findings are reproducible and the scanner cannot harm customers. `-I` or
`continue-on-error` does not make production scanning safe; it changes only the process exit code.

## Assuming SCA scans source code

`A03:2025` · ASVS V15 · CWE-1104

A clean dependency report is presented as a clean application security report. SCA matched package
versions to advisories; it did not inspect authorization, injection paths, business logic, or
vendored code absent from package metadata.

Fix: state the tool class and coverage with every result. Pair SCA with SAST, tests, review, and
runtime analysis where the failure requires them.

Why it works: the evidence says what was actually tested. Adding a second SCA vendor does not fill
the missing class; it mostly duplicates the same advisory feeds.

## Scanning only the manifest, not the artifact

`A03:2025` · ASVS V15 · CWE-1104

The lockfile is clean, but the container includes OS packages, copied binaries, and build residue
that the lockfile never described.

Fix: scan dependencies at PR time and scan the built image by immutable digest. Generate the SBOM
from that image in the build.

Why it works: source-level feedback stays fast while release evidence covers what actually ships.
A Dockerfile scan is IaC/static configuration analysis; it is not an image inventory.

## Trusting a mutable action tag

`A03:2025` · ASVS V15 · CWE-829, CWE-506

```yaml
- uses: third-party/release@v3
```

The tag owner can move `v3` to different code. That code inherits every secret and permission
available to the step.

Fix: pin the action to a reviewed full commit SHA and keep the semantic version in a comment.
Review proposed SHA updates like dependency code.

Why it works: the workflow continues to execute the reviewed commit after a tag or repository
compromise. A release tag is better for readability, not immutability.

## Giving every job the publisher's token

`A08:2025` · ASVS V13 · CWE-829

```yaml
permissions: write-all
```

A compromised test dependency can alter releases, issues, or repository contents even though the
test job never publishes anything.

Fix: default to `permissions: {}` and grant exact scopes per job. Put publishing in a separate job
that consumes a verified digest and runs only on a protected ref/environment.

Why it works: compromise of the broad, attacker-influenced test surface cannot borrow the small
publisher's authority.

## Believing masked means secret

`A03:2025` · ASVS V13 · CWE-829

```bash
set -x
curl -H "Authorization: Bearer $TOKEN" https://api.example/status
```

GitHub may replace the exact token with `***`. A transformed value, short substring, encoded
value, process argument, stack trace, or uploaded log can still leak. Debug logging widens this
further.

Fix: disable shell tracing around secret use, pass secrets through standard input or a protected
file where supported, scope them to one step, and redact before logging. Rotate any value that may
have appeared.

Why it works: the secret never enters the log stream. Adding `::add-mask::` after printing is too
late, and masking variants is an endless denylist.

## Using `pull_request_target` to "make secrets available"

`A08:2025` · ASVS V13, V15 · CWE-829

The event runs in the trusted base context, but an explicit checkout of the PR head followed by a
build executes the fork's code with secrets and a write token. Install hooks make `npm ci` enough.

Fix: run untrusted code under `pull_request`. Split any privileged follow-up into a
`workflow_run` that consumes only validated passive data.

Why it works: privilege and untrusted execution never share a job. A "safe to test" label is only
a stopgap; the contributor can push a new commit after review unless the workflow binds approval
to an exact SHA.

## Reusing a self-hosted runner after a fork PR

`A08:2025` · ASVS V13 · SLSA Build L3 · CWE-829

Deleting the working directory leaves processes, containers, credentials, caches, host changes,
and network footholds behind.

Fix: never run arbitrary public fork code on a persistent self-hosted runner. Use hosted runners or
single-use VM-level isolation, then destroy the instance.

Why it works: persistence dies with the trust boundary. A cleanup script runs inside the already
compromised host and cannot prove its own success.

## Creating an SBOM after the release

`A03:2025` · ASVS V15 · SLSA 1.2

Re-running dependency resolution from source days later can select different transitive packages
or omit bundled and OS components.

Fix: generate CycloneDX or SPDX during the build from the exact artifact and bind it to the artifact
digest with an attestation.

Why it works: incident response queries the contents that shipped, not a reconstruction of what
might have shipped. Signing a late reconstruction only authenticates the wrong inventory.

## Signing without verification policy

`A08:2025` · ASVS V15 · SLSA 1.2 · CWE-506

The pipeline signs images but the cluster accepts every image. The signature is decorative.

Fix: enforce admission-time verification of digest, trusted OIDC issuer, workflow identity,
provenance predicate, and repository/ref policy. Exercise a known-unsigned image to prove rejection.

Why it works: the control is at the consumption boundary. A successful `cosign sign` job says
nothing about what deployment accepts.

## Permanent risk acceptance

`A03:2025` · ASVS V15 · NIST SSDF RV.2 · CWE-1104

"Accepted risk" has no owner or expiry, so it survives team changes and architecture changes.

Fix: require evidence, compensating control, accountable approver, owner, and date. Reopen
or block automatically at expiry.

Why it works: the decision is re-evaluated when its assumptions age. A ticket in a frozen backlog
is not a control.
