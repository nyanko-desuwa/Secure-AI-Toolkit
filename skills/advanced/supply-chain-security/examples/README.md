# Supply Chain Examples

Vulnerable configuration next to its fix. Each names the Top 10 category, the CWE where one
applies, and why the fix closes the hole rather than just looking safer.

These are defensive examples. Nothing here is a working attack — the malicious side is shown as
the shape of a manifest or workflow you would find during review, not as a payload.

Commit SHAs, digests, hostnames, and identities are placeholders. Resolve the real values before
using any of it; a pin copied out of documentation is a pin nobody reviewed.

## Contents

1. [Version ranges versus a lockfile with hashes](#1-version-ranges-versus-a-lockfile-with-hashes) — A03, CWE-345
2. [A package name that looks right](#2-a-package-name-that-looks-right) — A03, CWE-1357
3. [Public registry fallback versus a scoped private registry](#3-public-registry-fallback-versus-a-scoped-private-registry) — A03, CWE-1357
4. [Install scripts trusted versus disabled and allowlisted](#4-install-scripts-trusted-versus-disabled-and-allowlisted) — A03, CWE-829
5. [Toolchain downloaded without verification](#5-toolchain-downloaded-without-verification) — A08, CWE-494
6. [Unsigned artefact versus cosign-verified](#6-unsigned-artefact-versus-cosign-verified) — A08, CWE-347
7. [SBOM generated but never checked](#7-sbom-generated-but-never-checked) — A03, CWE-1395
8. [Auto-merge meeting a compromised maintainer](#8-auto-merge-meeting-a-compromised-maintainer) — A03, CWE-1357

---

## 1. Version ranges versus a lockfile with hashes

`A03:2025` · `CWE-345` · ASVS 15.1.2

```json
// Vulnerable: package.json with ranges, and the lockfile is not committed
{
  "dependencies": {
    "express": "^5.0.0",
    "pg": "~8.13.0"
  }
}
```

```gitignore
# .gitignore
package-lock.json
```

```text
# requirements.in, installed directly
django>=5.1
psycopg[binary]>=3.2
```

Two builds a minute apart can resolve different code. `^5.0.0` accepts every future minor
release, so the artefact you tested and the artefact you shipped are not the same inputs, and
neither is reproducible after the fact. Nothing records which bytes arrived.

```json
// Fixed: exact versions, lockfile committed, frozen install
{
  "dependencies": {
    "express": "5.1.0",
    "pg": "8.13.1"
  }
}
```

```bash
npm ci --ignore-scripts        # fails if package.json and the lockfile disagree
```

```text
# requirements.txt, compiled with hashes for every requirement including transitive
django==5.1.4 \
  --hash=sha256:<hex-of-wheel> \
  --hash=sha256:<hex-of-sdist>
psycopg==3.2.3 \
  --hash=sha256:<hex-of-wheel>
```

```bash
pip install --require-hashes --only-binary :all: -r requirements.txt
```

Why this works on two levels. The exact version plus a committed lockfile makes resolution
deterministic, so the reviewed graph is the built graph. The hash makes retrieval verifiable, so
a compromised registry, a poisoned mirror, or a republished version fails the install instead of
entering the build. `--require-hashes` is all-or-nothing: if any requirement lacks a hash, pip
errors, which is what stops a partially hashed file smuggling an unpinned dependency through.

The tempting wrong fix is a version pin without hashes. A pin names a release; it does not name
bytes. `ua-parser-js` shipped malicious code under three ordinary-looking version numbers from
the legitimate maintainer account, and every version pin in the world resolved to it happily.

Note what the lockfile does not do: it records what resolved, not whether it was safe. It is the
reviewable artefact, not the verdict.

---

## 2. A package name that looks right

`A03:2025` · `CWE-1357`

Two variants of the same failure. In the first the misspelling comes from a keyboard; in the
second it comes from a model.

```json
// Vulnerable: typosquats. Which of these is the real package?
{
  "dependencies": {
    "crossenv": "7.0.3",
    "python-jwt": "4.0.0",
    "reqeusts": "2.31.0"
  }
}
```

The names are close enough to `cross-env`, `pyjwt`, and `requests` that a reviewer's eye
completes them. Typosquats commonly re-export the real package, so the application works — which
removes the only feedback that would prompt a second look.

```bash
# Vulnerable: slopsquat. The assistant wrote the import and the install line together,
# and they agree with each other, so nothing looks wrong.
pip install huggingface-cli
```

`huggingface-cli` is the command name, not the package. The real install is
`pip install -U "huggingface_hub[cli]"`. An empty package registered under the hallucinated name
was downloaded over 30,000 times in three months. Spracklen et al. (arXiv:2406.10279) measured
19.7% of LLM-recommended packages as nonexistent, with more than 205,000 distinct hallucinated
names — and the same model produces the same plausible name repeatedly, which is what makes
pre-registering them worth an attacker's time.

```bash
# Fixed: the name comes from the upstream project's own install documentation,
# and is confirmed against the registry before it enters the manifest
npm view cross-env repository.url time.created maintainers --json
pip index versions requests

pip install -U "huggingface_hub[cli]"
```

Why checking at adoption is the only place it works: once installed, the package has already run
whatever it wanted to run. The signals are cheap — does the declared repository exist and contain
the published code, is the first-publish date days old, do the maintainers overlap with the
project the package claims to belong to.

The tempting wrong fix is a scanner. SCA matches known-vulnerable versions of known-good
packages; a fresh squat is neither, so it scans clean. Registry reputation gates help and are not
first-line either — download counts are inflatable, and the name has to be wrong before anything
can flag it.

For AI-assisted work specifically: treat every package name in generated code as unverified
input, and never let an agent install a name a human has not read. A hallucinated name is absent
from your lockfile, so a frozen install fails rather than fetching — which is the second reason
example 1 matters.

Honest status: no attack in the wild has been publicly attributed to slopsquatting. The
hallucination rates are measured and the registrations are trivial; the incident has not been
reported. Say that rather than implying a breach.

---

## 3. Public registry fallback versus a scoped private registry

`A03:2025` · `CWE-1357` · ASVS 15.2.4

The oldest supply chain bug that still works, because it lives in configuration nobody reviews.

```ini
# Vulnerable: pip.conf with two indexes and an unnamespaced internal package
[global]
index-url = https://pypi.org/simple
extra-index-url = https://pypi.acme.internal/simple
```

```text
# requirements.in
acme-billing>=1.4
requests>=2.31
```

`acme-billing` exists only on the internal index. pip offers no priority guarantee between
indexes, so anyone who publishes `acme-billing 99.0.0` to PyPI becomes a candidate, and version
resolution prefers it. The attacker needs no access to anything and does not have to guess your
version — they publish an absurd one. PEP 708 was written to address exactly this and is
Rejected, so there is no index-priority feature to wait for.

```ini
# Fixed: one index, which is a proxy that decides what public packages it mirrors
[global]
index-url = https://pypi.acme.internal/simple/
```

```ini
# .npmrc — internal names live in a scope bound to one registry
registry=https://npm.acme.internal/repository/npm-group/
@acme:registry=https://npm.acme.internal/repository/npm-private/
//npm.acme.internal/:_authToken=${NPM_TOKEN}
```

```bash
# Go — keep private module paths off the public proxy and checksum database
go env -w GOPRIVATE='corp.example.com/*'
go env -w GOPROXY='https://goproxy.acme.internal'
```

Why this works: the attacker's package is never a candidate, because the resolver never queries a
registry they can publish to. Scoping the internal name means claiming `acme-billing` publicly
gains nothing. The hashes from example 1 are the second layer — even a poisoned mirror serves
bytes that fail the check.

The tempting wrong fix is defensive publishing: registering `acme-billing` on PyPI as an empty
stub. Worth doing as a second layer, and it is not the control. It does nothing about a resolver
that prefers the highest version across indexes, it does not apply where you cannot claim the
namespace, and it fails silently the first time someone adds a new internal package without
registering the stub.

One cost to state honestly: `GOPRIVATE` also removes those modules from checksum-database
verification. Scope it to the narrowest prefix that works, never `*`.

---

## 4. Install scripts trusted versus disabled and allowlisted

`A03:2025` · `CWE-829`

The attack lands before your code ever runs. The 2025 `Shai-Hulud` worm — which OWASP describes
as the first successful self-propagating npm worm — used post-install scripts to exfiltrate
secrets, then republished itself with the npm tokens it found, reaching more than 500 package
versions.

```yaml
# Vulnerable: dependency code runs before any of your code does, with your secrets in env
- uses: actions/checkout@v6
- run: npm install
  env:
    NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
    AWS_ROLE_ARN: ${{ secrets.AWS_ROLE_ARN }}
- run: npm test
```

```json
// What any package in the tree can declare — no consent required from you
{
  "name": "some-transitive-dep",
  "scripts": {
    "postinstall": "node ./scripts/setup.js"
  }
}
```

Python has the same shape: a source distribution executes `setup.py` at install time, and a Go
build can run `//go:generate` directives that fetch and execute.

```yaml
# Fixed: no dependency code runs at install, and the install job holds no secrets
- uses: actions/checkout@<full-40-char-sha>   # v6.0.0
- run: npm ci --ignore-scripts
- run: npm test
```

```bash
# pip: refuse source distributions, so setup.py is not on the install path
pip install --require-hashes --only-binary :all: -r requirements.txt

# Go: generate is never implicit. Run it deliberately, in review, not in the build
go generate ./...      # a reviewed step, with its output committed
```

Why this works: `ignore-scripts` means `package.json` scripts do not run, so nothing in the
dependency tree executes until your own code imports it. That moves the trust decision from
"install time, all 900 packages, with CI credentials in the environment" to "runtime, the ones
you actually call". `--only-binary :all:` does the same job for pip by removing the code path
rather than sandboxing it.

Where a package genuinely needs a native build, allowlist it by name rather than re-enabling
scripts globally:

```json
{ "allowScripts": { "sharp": true, "esbuild": true } }
```

The allowlist works because you enumerate the few packages you decided to trust with execution. A
denylist would require predicting which transitive dependency adds a `postinstall` in its next
patch release.

Two documented details. `npm start`, `npm test`, and `npm run` still execute their target script
under `ignore-scripts` — it suppresses the pre- and post-scripts around them, so `npm test` still
works. And `strict-allow-scripts` turns the unreviewed-dependency warning into a failure, which
is what you want in CI.

Honest limitation: this stops install-time execution, not malicious runtime code. A backdoor in a
library you import runs when you call it. Egress restriction is the control that still helps
after a script slips through — ASVS 13.2.4 asks for an allowlist of external systems the
application may talk to.

---

## 5. Toolchain downloaded without verification

`A08:2025` · `CWE-494`

A08 is explicit that fetching updates without integrity verification lets an attacker push their
own build to every install. The Codecov Bash Uploader is the canonical shape: an attacker
extracted a storage key from an intermediate layer of a public Docker image, modified the script
in the bucket, and every pipeline that piped it to a shell handed over its environment variables.
It was found by one customer comparing the published SHA256 against one they computed.

```dockerfile
# Vulnerable: mutable base, unverified script, executed as root, no version anywhere
FROM node:22-alpine
RUN apk add --no-cache curl \
 && curl -fsSL https://get.example-tool.io/install.sh | sh
```

Three failures compound. The base image tag moves. The install script is fetched at build time,
so the bytes differ between builds and nobody records which ones ran. And whoever controls that
hostname, or a proxy in front of it, controls what executes as root in your image.

```dockerfile
# Fixed: pinned base by digest, pinned release, verified checksum before execution
FROM node:22-alpine@sha256:<64-hex-digest>

ARG TOOL_VERSION=1.9.2
ARG TOOL_SHA256=<hex-digest-of-the-release-artifact>

RUN apk add --no-cache curl \
 && curl -fsSLo /tmp/tool.tar.gz \
      "https://github.com/example/tool/releases/download/v${TOOL_VERSION}/tool-linux-amd64.tar.gz" \
 && echo "${TOOL_SHA256}  /tmp/tool.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/tool.tar.gz -C /usr/local/bin tool \
 && rm /tmp/tool.tar.gz
```

Why this works: `sha256sum -c` fails the build before the archive is extracted, so a substituted
artefact never executes. The digest is in the Dockerfile, under review, and changing it is a
visible diff.

Preferring the ecosystem's package manager over a download is better still, because it brings a
lockfile and an advisory feed with it. A `curl | sh` step is a dependency that appears in no
manifest, no lockfile, and no SBOM — which is precisely why Codecov reached so many pipelines.

Honest limitation: the checksum protects integrity, not provenance. It confirms you got the bytes
you recorded; it says nothing about whether that release was built from the source it claims. And
a checksum copied from the same page that served the file proves only that the download
completed. Where the tool publishes Sigstore signatures, verify the signature instead — that is
the next example.

---

## 6. Unsigned artefact versus cosign-verified

`A08:2025` · `CWE-347` · SLSA v1.2 Build L2

Signing gets implemented and celebrated. The verify step is the control, and it is the half that
gets skipped, because skipping it breaks nothing.

```yaml
# Vulnerable: signed at build, never checked at deploy
- name: sign
  run: cosign sign "registry.acme.io/api:${{ github.sha }}"

- name: deploy
  run: kubectl set image deploy/api api="registry.acme.io/api:${{ github.sha }}"
```

```bash
# Also vulnerable: a verify step that accepts anything anyone signed
cosign verify "$IMAGE" \
  --certificate-identity-regexp '.*' \
  --certificate-oidc-issuer-regexp '.*'
```

The wildcard version passes for any image signed by any Sigstore user. It verifies that Sigstore
is reachable.

```bash
# Fixed: verify by digest, at the consuming end, with the expected identity pinned
set -euo pipefail

cosign verify "registry.acme.io/api@sha256:${DIGEST}" \
  --certificate-identity \
    "https://github.com/acme/api/.github/workflows/release.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"

kubectl set image deploy/api "api=registry.acme.io/api@sha256:${DIGEST}"
```

```bash
# The npm equivalent, in a gate that fails
npm audit signatures
```

Why this works: the Sigstore certificate binds the signature to an OIDC identity, so pinning
identity and issuer means only that workflow, on that branch, can produce an artefact you accept.
Verifying by digest rather than tag matters independently — a tag can be repointed at a different
image whose own signature is perfectly valid.

Run it where the artefact is consumed. An admission controller is the strongest placement,
because it catches deployments that bypass the pipeline entirely. Verification inside the job
that just signed the image tells you nothing you did not already know.

Two claims worth separating. A signature says who produced the artefact. SLSA provenance says how
it was built, and Build L2 is the level where the platform signs that provenance and the consumer
checks it — see [../references/slsa.md](../references/slsa.md). Neither says the source
was benign: a backdoor committed by a compromised maintainer produces flawless provenance. What
you get is attribution, which is what makes an incident tractable.

---

## 7. SBOM generated but never checked

`A03:2025` · `CWE-1395` · ASVS 15.1.2

An SBOM is an inventory. It earns its keep by answering "which of our builds contains this
component" in minutes. Generated and filed, it answers nothing.

```yaml
# Vulnerable: an SBOM of the source tree, attached to nothing, read by nobody
- name: sbom
  run: syft dir:. -o cyclonedx-json > sbom.json
- uses: actions/upload-artifact@v4
  with:
    name: sbom
    path: sbom.json
```

Three problems. It describes the source tree, not the artefact that shipped, so base-image OS
packages are missing and build-time-only components are guessed at. It is keyed to a workflow run
rather than an artefact digest, so it cannot be matched to what is running. And no step reads it,
so a critical finding inside it changes nothing.

```yaml
# Fixed: generated from the artefact, bound to its digest, gated on policy
- id: build
  run: |
    docker buildx build --push -t registry.acme.io/api:${{ github.sha }} \
      --metadata-file meta.json .
    echo "digest=$(jq -r '."containerimage.digest"' meta.json)" >> "$GITHUB_OUTPUT"

- name: sbom from the image and from the lockfile
  env:
    IMAGE: registry.acme.io/api@${{ steps.build.outputs.digest }}
  run: |
    syft "$IMAGE" -o cyclonedx-json=sbom.image.cdx.json
    npm sbom --sbom-format cyclonedx > sbom.lock.cdx.json

- name: gate
  run: grype "sbom:sbom.image.cdx.json" --fail-on high

- name: bind the SBOM to the digest
  env:
    IMAGE: registry.acme.io/api@${{ steps.build.outputs.digest }}
  run: cosign attest --yes --type cyclonedx --predicate sbom.image.cdx.json "$IMAGE"
```

Why this works: `--fail-on high` sets a non-zero exit status, so the release stops rather than
printing a report into a log nobody opens. `cosign attest` binds the document to the artefact
digest, so an incident query has something to join on — two builds of `v1.4.2` are two artefacts,
and an SBOM keyed by version string cannot tell you which one is deployed.

Running both generators is deliberate. `npm sbom` reads the lockfile and gives the exact resolved
graph including dev scopes; `syft <image>` reads the finished artefact and finds OS packages the
lockfile never mentioned. When the two disagree, that disagreement is the finding — something
entered the artefact outside the declared graph.

What people wrongly expect from an SBOM: that it is a vulnerability report (it is the input to
one), that presence implies reachability (it does not), and that it is trustworthy unsigned (it
inherits the credibility of whoever handed it over). Format details and the build-time versus
scan-time tradeoff are in [../references/sbom-formats.md](../references/sbom-formats.md).

Honest limitation: component identity is the weak joint. `purl` works well inside an ecosystem;
matching an OS package or a statically linked C library to an advisory identifier is lossy, and
both false positives and misses come from there. A gate at `--fail-on high` will need an
exception process, and an exception without an expiry date is a silent acceptance.

---

## 8. Auto-merge meeting a compromised maintainer

`A03:2025` · `CWE-1357`

`ua-parser-js` shipped malicious code under three ordinary version numbers from the legitimate
account, and was fixed within hours. The question is not whether it happens; it is what your
repository does during those hours.

```json
// Vulnerable: newest version wins, automatically, on everything
{
  "extends": ["config:recommended"],
  "automerge": true,
  "automergeType": "branch",
  "minimumReleaseAge": null,
  "schedule": ["at any time"]
}
```

A malicious release published at 02:00 is merged at 02:10 and running in CI — with CI's
credentials — before anyone is awake. The configuration is not careless; it is what "keep
dependencies current" looks like when nobody asked what happens on a bad release.

```json
// Fixed: a cooldown, and automerge only where execution does not reach CI secrets or production
{
  "extends": ["config:recommended"],
  "minimumReleaseAge": "5 days",
  "packageRules": [
    { "matchDepTypes": ["devDependencies"], "automerge": true },
    { "matchDepTypes": ["dependencies"], "automerge": false },
    { "matchManagers": ["github-actions", "dockerfile"],
      "automerge": false, "pinDigests": true },
    { "matchUpdateTypes": ["major"], "automerge": false },
    { "matchPackageNames": ["/^@acme//"], "minimumReleaseAge": "0 days" }
  ],
  "vulnerabilityAlerts": { "minimumReleaseAge": "0 days", "automerge": false }
}
```

```yaml
# The Dependabot equivalent: a cooldown per update type, and no blanket allow
version: 2
updates:
  - package-ecosystem: npm
    directory: "/"
    schedule:
      interval: weekly
    cooldown:
      default-days: 5
      semver-major-days: 14
    open-pull-requests-limit: 5
    allow:
      - dependency-type: direct
```

Why the cooldown works: malicious releases are usually detected and yanked within days, often
hours. Waiting converts "we were patient zero" into "the registry pulled it before we resolved
it". The cost is a few days of exposure to already-published CVEs, which is why the delay is
short and why the `vulnerabilityAlerts` override exists — advisory-driven updates skip the queue.
Dependabot applies a three-day cooldown by default and does not apply it to security updates.

Two details that carry weight. `pinDigests` on Actions and Dockerfiles closes the mutable-tag gap
in the same config. And leaving `automerge: false` on production dependencies is not about
distrusting the bot; it is about a human reading the lockfile diff of a package that will run in
a request path.

Honest limitation: a cooldown is a probability play, not a guarantee. A patient attacker waits out
the window, and `event-stream` sat in the tree for weeks. It is worth having because most
attackers are not patient and it costs one configuration line — but it is not a substitute for
`--ignore-scripts` and least privilege in CI, which hold regardless of timing.

---

## Sources

- <https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/>
- <https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/>
- <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x24-V15-Secure-Coding-and-Architecture.md>
- <https://slsa.dev/spec/v1.2/>
- <https://docs.npmjs.com/cli/v11/using-npm/config>
- <https://pip.pypa.io/en/stable/topics/secure-installs/>
- <https://peps.python.org/pep-0708/>
- <https://docs.sigstore.dev/cosign/verifying/verify/>
- <https://docs.renovatebot.com/configuration-options/>
- <https://docs.github.com/en/code-security/dependabot/working-with-dependabot/dependabot-options-reference>
- <https://arxiv.org/abs/2406.10279>
