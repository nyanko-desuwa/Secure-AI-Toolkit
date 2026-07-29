# OWASP Top 10 2025 - the categories that carry publish findings

Source: <https://owasp.org/Top10/2025/> · verified 2026-07-28

The 2025 edition is not a renumbering of 2021. A03 and A10 are new, and Injection moved from A03
to A05. If a project's tooling still emits 2021 IDs, map them rather than renumbering silently.
The full category list and the 2021 → 2025 mapping live in
[owasp/references/owasp-top10-2025.md](../../owasp/references/owasp-top10-2025.md); this file only
covers the four categories a publish decision lands on.

## A02:2025 - Security Misconfiguration

The packaging and visibility settings that decide what ships. Almost every publish finding starts
here, because the leak is usually a configuration that included more than intended.

Applies when:

- A repository's visibility was changed without a history scan
- `.gitignore`, `.dockerignore`, `.npmignore`, or the host's ignore file is missing an entry, or the
  four are out of sync with each other
- `package.json` has no `files` allowlist, so the tarball defaults to everything
- A Dockerfile does `COPY . .` with no build context exclusions
- A `.git` directory is inside deployed output or a container image
- A build log, plan output, or CI log is published to a PR comment or a public build page
- Secret scanning or push protection is available on the platform and switched off

Ask: what does this configuration include that nobody listed? An allowlist answers that question by
construction; a denylist answers it only for the cases someone thought of.

## A04:2025 - Cryptographic Failures

The credential itself, once it has been exposed. A02 is why it shipped; A04 is what shipping it
costs.

Applies when:

- A credential literal is in published source, a published tarball, a pushed image layer, or a
  deployed bundle
- The exposed credential has no expiry, so the exposure does not decay
- The same credential is used across environments, so a leak from staging reaches production
- Rotation exists on paper but has never run, so the response to exposure is unbounded

The category to cite when you are explaining impact rather than cause. Pair it with the CWE from
[cwe-publishing.md](cwe-publishing.md).

## A03:2025 - Software Supply Chain Failures

New in 2025. It applies in the direction people forget: what you publish becomes someone else's
dependency, and their build trusts it.

Applies when:

- A package is published with no allowlist, so an internal file, a test fixture, or a script ends up
  in a dependency other people install
- A published artifact carries no provenance, so a consumer cannot tell whether it came from your
  build
- A leaked publish token would let someone else push a version under your name
- An image is published by mutable tag only, so what a consumer pulls can change

Depth on signing, provenance, and SLSA belongs to `advanced/supply-chain-security`. This skill stops
at the question of what is inside the artifact.

## A08:2025 - Software or Data Integrity Failures

Applies to the artifact-integrity side of publishing:

- A published artifact is not signed, and the platform offers no way for a consumer to verify it
- A release is built from a mutable reference rather than a pinned commit
- An unpublish-and-republish cycle changes what a version means for anyone who already resolved it

Cite A08 when the finding is about whether a consumer can trust what they received, and A03 when it
is about what the artifact contains.

## Which category to lead with

| The finding is about | Lead with |
|---|---|
| An ignore file, an allowlist, a visibility setting, a platform control | A02 |
| A credential that is now public and what it can do | A04 |
| What downstream consumers install from you | A03 |
| Whether a consumer can verify what they received | A08 |

Give one primary category and add a second only when it changes what someone would do. Three
categories on one finding reads as padding.

## Sources

- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>
