# Troubleshooting

What to do when the guidance cannot be applied cleanly.

## Vendoring is required

Vendoring trades registry availability and substitution risk for patch ownership. It is a
reasonable choice for air-gapped builds, dependencies whose upstream may disappear, or code that
needs a reviewed local patch. It is not "removing the dependency".

Keep four pieces of evidence beside the vendored copy:

1. Upstream URL and exact release tag or commit
2. Hash of the upstream source archive
3. Local changes as reviewable patches, not edits with no baseline
4. Named owner and advisory source for future security releases

Make the component appear in the generated SBOM even though the package manager no longer sees
it. Set a recurring upstream comparison. The operational cost is deliberate: you now own every
security backport and licence obligation. If nobody accepts that ownership, do not vendor.

## A dependency turns out to be malicious

Order matters, and it is counterintuitive. The dependency fix is last.

1. Revoke and rotate every credential the affected builds and developer machines could read.
   Registry tokens, cloud credentials, SSH keys, CI secrets, signing keys. Do this before you
   understand the incident.
2. Identify which builds consumed the version. The lockfile history and the build logs answer
   this; if you cannot answer it, that gap is a second finding.
3. Determine what shipped. Any artefact built from an affected build is suspect, including ones
   already promoted to production.
4. Then remove or pin around the package.

Treat it as a credential incident, not a version bump. Install scripts run with the identity of
whoever ran the install, so a compromised dev dependency is a compromise of the laptop and the
runner, not just of the artefact.

Hand off to `incident-response` for the process; this skill only covers the ordering.

## The ecosystem has no hash-pinning mechanism

Some ecosystems and some sources — a git dependency, a private wheel served from a bucket, an
internal Maven repository without checksum enforcement — will not give you verified bytes.

State that plainly rather than implying the lockfile covers it. Then buy back what you can:

- Mirror the artefact into a repository you control and pin to your copy
- Record the hash yourself at first adoption and check it in CI, even if the package manager
  will not
- Restrict who can write to the mirror, and audit that write log

Report the residual gap. "We verify integrity for PyPI packages and not for the two git
dependencies" is a useful sentence. "Dependencies are pinned" is not.

## Disabling install scripts breaks the build

Expected — a handful of packages genuinely need a native compilation step. Do not respond by
re-enabling scripts globally.

1. Run the install with scripts off and read which package failed
2. Verify that the package legitimately needs a build step, rather than assuming it
3. Allowlist that package by name
4. Prefer the prebuilt artefact where one exists — many packages publish platform wheels or
   prebuilt binaries specifically to avoid this

If the allowlist grows past a handful of entries, the finding is the size of the list, not the
mechanism.

## You cannot reach SLSA Build L3 on the available platform

L3 requires a hardened hosted platform where runs cannot influence each other and the
provenance signing key is out of reach of user-defined build steps. Self-hosted runners, shared
build machines, and most on-premise CI cannot claim it, and no amount of workflow YAML changes
that.

Say which level you reach and what blocks the next one. L2 — hosted platform, platform-signed
provenance, consumer-verified — is a real improvement and often the honest ceiling. Claiming L3
because the workflow looks careful is worse than claiming L1, because a consumer will act on
the claim.

## An SBOM is requested and the build cannot produce one

Usually a monorepo with multiple language ecosystems, or a build that assembles artefacts from
steps that do not share a dependency graph.

Produce one per component and state the boundaries, rather than producing one incomplete
document that reads as complete. A CycloneDX BOM with an explicit note that the Go binaries are
covered by a separate BOM is defensible. A BOM silently missing them is not — a consumer will
assume absence means the component is not present.

If the requester wants a single file, aggregate at delivery time and keep the per-component
sources as the thing you regenerate.

## Two standards disagree about a version window

ASVS asks for documented, risk-based remediation windows. A customer contract asks for 30 days
on everything. A regulator asks for something else.

Meet the strictest applicable requirement and document why, or negotiate the contract. Do not
maintain two sets of windows — the one nobody enforces becomes the one everyone cites.

Where the conflict is between speed and safety, name it: a 24-hour patch mandate is in direct
tension with a release cooldown, and both are real controls. The usual resolution is a fast
path for advisory-driven updates and a cooldown for routine ones.

## An exception is genuinely necessary

Unmaintained package with no replacement, a fix that requires a major version migration nobody
can schedule, a vulnerable transitive dependency the direct dependency has not upgraded.

An exception needs four things, or it is a silent acceptance:

- The specific component and version, not "the reporting library"
- Why remediation is not possible now, and what would make it possible
- The compensating control, if any — network isolation, feature flag off, input constrained
- An expiry date and a named owner

"Until we upgrade" is not an expiry date. ASVS 15.2.5 points at sandboxing, encapsulation,
containerisation, and network isolation as the compensating controls for a component you must
keep — reach for those rather than accepting the risk bare.

## The vulnerability has no patch

Check, in order: a maintained fork, a backport in your distribution's package, a virtual patch
at a WAF or gateway, and configuration that removes the code path. A03 names virtual patching
explicitly as a fallback when patching is impossible, and migration when the component is
unmaintained.

If none apply, the finding becomes an exception with the compensating control named. Record
that the component is a "risky component" in ASVS 15.1.4 terms so it appears in the next
review rather than being rediscovered.

## Provenance verification fails after a legitimate change

The identity in a Sigstore certificate includes the workflow path and the ref. Renaming
`release.yml`, moving to a different branch, or moving the repository changes the identity, and
verification correctly rejects the new artefact.

Update the expected identity deliberately, as a reviewed change. Do not widen the regex to make
the failure go away — that converts a working control into a check that Sigstore is up. Keep
the previous identity accepted for as long as artefacts signed by it are still deployed, then
remove it.

## You cannot determine reachability

Common, and fine to say so. Report the finding with the uncertainty attached and the
precondition you could not confirm.

"`lodash` prototype pollution, reachable only if untrusted input reaches `merge` — I found
three call sites and could not trace the input source for one of them" is actionable. "Not
exploitable in our usage" with no reasoning is a deferral wearing a triage costume.

## The registry is down and the build must ship

Do not add a public fallback index to get past it. That is the dependency confusion
configuration, added under time pressure, and it will outlive the outage.

Use the cached artefacts, or ship the previously built digest. Promotion by digest exists
exactly so a release does not require a working registry.

## The standard has moved on

The versions here were verified on 2026-07-28: OWASP Top 10 2025, ASVS 5.0.0, SLSA v1.2, SSDF
SP 800-218 v1.1, CycloneDX 1.7, SPDX 3.0. Tool flag names move faster than any of them.

Before quoting a flag, a requirement ID, or a level name, re-check the source. See
[references/](references/) for URLs and per-file check dates. Never assume undocumented
behaviour, including in a standard or a package manager. Fetch it.
