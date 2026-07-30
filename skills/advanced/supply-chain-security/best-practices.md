# Supply Chain Best Practices

Patterns that hold up under review. Each names the Top 10 category, the ASVS requirement or
chapter, and a CWE where one applies.

Order matters here more than in most security work. Signing an artefact built from a confused
dependency proves you faithfully shipped someone else's code.

CI pipeline mechanics - which scanner runs at which stage, what blocks a merge, how token
permissions are scoped - belong to `devsecops`. This file covers what you depend on and what you
ship.

## Decide Whether to Add It At All

`A03:2025` · ASVS 15.1.2, 15.1.4 · `CWE-1357`, `CWE-1104`

The cheapest supply chain control is the dependency you did not add. A03's prevention text asks
you to remove unused dependencies and to choose versions deliberately; both start at adoption.

Four questions, in order of how often they catch something:

1. Is this in the standard library or an existing dependency? A left-pad-shaped package adds a
   maintainer, a publish token, and a lifecycle-script slot in exchange for eight lines.
2. Is this the name I think it is? Check the project's own documentation, not registry search.
3. Who maintains it, and how? Last release date, open issue response, number of maintainers,
   whether the declared repository actually contains the published code.
4. What does it pull in? A package with 40 transitive dependencies is 41 trust decisions.

Maintenance signals worth reading, and what each one actually tells you:

| Signal | Reads as | Caveat |
|---|---|---|
| Last release date | Active maintenance | A stable, finished library legitimately looks abandoned |
| Single maintainer | One account compromise is total | Most of the ecosystem looks like this |
| Declared repository missing or empty | Strong negative - published code has no reviewable source | |
| First publish within days | Strong negative for a name resembling an established package | |
| Download count | Popularity | Trivially inflated, and popularity is what attackers target |
| OpenSSF Scorecard `Signed-Releases`, `Pinned-Dependencies` | Process maturity | A score is an input to a decision, not a gate |

ASVS 15.1.4 (L3) asks documentation to highlight "risky components" - its own examples are
poorly maintained, unsupported, end-of-life, or a history of significant vulnerabilities. Write
that list at adoption, when you have just done the research, not during an incident.

### Typosquatting

`crossenv` for `cross-env`, `python-jwt` for `pyjwt`, `reqeusts` for `requests`. The attack
works because reading is pattern-matching: the eye completes a familiar name. Typosquats
commonly re-export the real package, so the application works and the only feedback you would
have had is gone.

```bash
# Vulnerable: the name came from a blog post, an error message, or an autocomplete
npm install crossenv
```

```bash
# Fixed: confirm the name resolves to the project you mean, before it enters the manifest
npm view cross-env repository.url time.created maintainers versions --json
pip index versions requests        # and read the project page, not search results
```

Why checking first is the only control: by the time the package is installed it has already run
whatever it wanted to run. An SCA scanner cannot help here - it matches known-vulnerable
versions of known-good packages, and a fresh typosquat is neither.

### Slopsquatting

Named by Seth Larson in April 2025 for the case where the misspelling comes from a model rather
than a keyboard. An LLM suggests a package that does not exist; normally the install fails, but
an attacker who registered that name in advance turns a hallucination into a live install path.

The measurement everyone cites is Spracklen et al., "We Have a Package for You! A Comprehensive
Analysis of Package Hallucinations by Code Generating LLMs" (arXiv:2406.10279): 19.7% of
recommended packages did not exist across the models tested, averaging 21.7% for open-weight
models against 5.2% for commercial ones, with more than 205,000 distinct hallucinated names
observed. Hallucinated names repeat across runs, which is what makes registering them
worthwhile.

The demonstrated case predates the name. In 2023 Bar Lanyado found models recommending
`huggingface-cli` - plausible, because that is the command name, while the real install is
`pip install -U "huggingface_hub[cli]"`. He published an empty package under the hallucinated
name and it was downloaded more than 30,000 times in three months, and the fake name appeared
in the README of an Alibaba research repository.

```bash
# Vulnerable: the assistant wrote the import and the install line, and both look fine
pip install huggingface-cli
```

```bash
# Fixed: the package name comes from the project's own install documentation
pip install -U "huggingface_hub[cli]"
```

Why this matters more than ordinary typosquatting: an agent that can run shell commands closes
the loop without a human ever reading the name. The install and the code that imports it are
generated together and are internally consistent, so nothing looks wrong.

Practical rules for AI-assisted work, which is the only new part of the mitigation:

- Every package name in generated code is unverified input until checked against the upstream
  project's documentation
- Never let an agent install a package a human has not seen the name of
- An import of a package absent from the lockfile is a review stop, not an install prompt
- Lockfile plus hashes plus one index still applies, and still helps: a hallucinated name is not
  in your lockfile, so a frozen install fails rather than fetching

Honest limitation: as of this writing there is no publicly reported attack that has been
attributed to slopsquatting. The registrations and the hallucination rates are documented; the
exploitation is anticipated. Treat it as a cheap control against a well-evidenced exposure, and
do not inflate it into an incident that has not happened.

## Resolve From One Place You Control

`A03:2025` · ASVS 15.2.4 · `CWE-1357`

Dependency confusion is a resolution bug, not a coding bug. If your resolver consults a public
index for a name you use privately, whoever publishes that name publicly and picks a higher
version wins.

```ini
# Vulnerable: pip has no priority guarantee between index-url and extra-index-url.
# A public "acme-billing 99.0.0" can win over the internal 1.4.2.
[global]
index-url = https://pypi.org/simple
extra-index-url = https://pypi.acme.internal/simple
```

```ini
# Fixed: one index. The internal proxy is the only resolver, and it decides what
# public packages it will mirror.
[global]
index-url = https://pypi.acme.internal/simple/
```

For npm the equivalent is a scope bound to a registry, with no unscoped internal names at all:

```ini
# .npmrc
@acme:registry=https://npm.acme.internal/
//npm.acme.internal/:_authToken=${NPM_TOKEN}
```

Why this closes it: the attacker's package is never a candidate, because the resolver never
asks a registry they can publish to. The private name is namespaced, so claiming
`acme-billing` publicly gains nothing.

The tempting wrong fix is defensive publishing - registering your internal names on the public
registry as empty stubs. It helps on npm and it is worth doing as a second layer, but it is
not the control. It does nothing about a resolver that prefers the highest version across
indexes, nothing for ecosystems where you cannot squat the whole namespace, and it fails the
day someone adds a new internal package and forgets the stub.

Verifying this is ASVS 15.2.4, which asks that third-party components and all transitive
dependencies come from the expected repository with no risk of a dependency confusion attack.
It is a Level 3 requirement, which understates it: the attack is cheap and fully automated.

## Put a Proxy Between You and the Public Registry

`A03:2025` · ASVS 15.1.2 · `CWE-1357`

A03's prevention text asks you to obtain components from official sources over secure links,
and A08 goes further: restrict npm, Maven, and similar to trusted repositories, with a vetted
internal mirror for higher-risk organisations.

A pull-through proxy - Artifactory, Nexus, Verdaccio, Athens, a cloud artifact registry - is
where three controls become possible at once that are awkward anywhere else:

- One resolution endpoint, which is what closes dependency confusion for every ecosystem in one
  configuration change instead of per-project
- A quarantine window, so a version is not servable until it has existed publicly for N days
- A cached copy, so a yanked upstream version does not break your builds and a deleted one is
  still analysable after an incident

```ini
# Vulnerable: every developer and runner talks to the public registry directly.
# There is no chokepoint, so policy has to be re-applied in every repository.
registry=https://registry.npmjs.org/
```

```ini
# Fixed: one endpoint. Upstream selection and quarantine are the proxy's job.
registry=https://npm.acme.internal/repository/npm-group/
@acme:registry=https://npm.acme.internal/repository/npm-private/
//npm.acme.internal/:_authToken=${NPM_TOKEN}
audit=false                      # the proxy's own advisory feed replaces this
```

Why this works: policy moves from N repositories to one server. A new internal package is
namespaced by default, and a malicious version published upstream is not servable during the
quarantine window even if a manifest asks for it.

What a proxy does not do, and this is where teams overestimate it. A cache serves whatever
upstream served, so a compromised upstream release is faithfully mirrored. The proxy is a
control point, not a verdict. Keep hashes in the lockfile - they are what detects a poisoned
mirror, including your own.

Two configuration details that decide whether it holds:

- Write access to the private repository is the new crown jewel. Publish tokens scoped per
  project, not one shared account. ASVS 13.2.1 asks for individual service accounts and
  short-term tokens rather than unchanging credentials, and a registry publish token is exactly
  the unchanging credential it means
- Remote repositories should be allowlisted upstreams, not "proxy anything". A proxy that
  fetches from an arbitrary URL on request has recreated the problem with an internal hostname

## Pin and Verify, Not Just Pin

`A03:2025` · `A08:2025` · ASVS 15.1.2 · `CWE-1104`, `CWE-345`

A pinned version says which release you want. A hash says which bytes you got. Registries can
be compromised, mirrors can be poisoned, and some ecosystems permit republishing.

```dockerfile
# Vulnerable: mutable tag, and install resolves fresh at build time
FROM node:22-alpine
COPY package.json .
RUN npm install
```

```dockerfile
# Fixed: base image by digest, install from the lockfile only
FROM node:22-alpine@sha256:<64-hex-digest>
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
```

`npm ci` is the load-bearing change. It requires an existing `package-lock.json` or
`npm-shrinkwrap.json`, exits with an error when the lockfile and `package.json` disagree
instead of updating the lock, and never writes to either file. `npm install` silently
resolves and rewrites - which means the build you tested and the build you shipped can differ.

Python needs hashes explicitly:

```text
# requirements.txt - hash-checking mode is all-or-nothing and requires pinned versions
requests==2.32.3 \
  --hash=sha256:<hex> \
  --hash=sha256:<hex-of-sdist>
```

```bash
pip install --require-hashes --only-binary :all: -r requirements.txt
```

Why this works: `--require-hashes` fails the install if any requirement, including transitive
ones, lacks a hash, so a partially hashed file cannot slip an unpinned dependency through.
`--only-binary :all:` refuses source distributions, which is what removes `setup.py`
execution from the install path.

Digest, not tag, everywhere a reference can be mutated: base images, deployed images, CI
actions, Terraform modules, Helm charts.

## Audit the Tree, Not the Manifest

`A03:2025` · ASVS 15.1.2, 15.2.4 · `CWE-1395`

Your `package.json` has 12 entries. Your `node_modules` has 900 packages. The 888 you did not
choose have the same execution rights as the 12 you did, and they are where the incidents
happen - `event-stream` was compromised through `flatmap-stream`, a dependency nobody added on
purpose.

ASVS 15.1.2 asks for an inventory of all third-party libraries, and 15.2.4 says "all transitive
dependencies" come from the expected repository. Both are unsatisfiable from the manifest.

```bash
# Vulnerable: reviews the 12 names a human typed
git diff package.json
```

```bash
# Fixed: read the resolved graph, which is where additions actually appear
git diff package-lock.json                 # the review artefact
npm ls --all --json > tree.json            # the full resolved tree
npm ls some-package                        # who pulled this in, and why
pip install --dry-run --report - -r requirements.in   # resolution without installing
go mod graph                               # every edge, direct and transitive
go mod why -m some/module                  # the shortest path to a module
mvn dependency:tree -Dverbose              # includes omitted-for-conflict edges
```

Why the lockfile diff is the review artefact: a one-line manifest change can add fifty packages
and change the resolved version of thirty more. The manifest records intent, the lockfile records
what will execute. A PR that changes only the lockfile is not noise; it is the diff that matters.

Three properties of transitive dependencies that change how you triage them:

- You cannot patch one directly. Fixing a vulnerable transitive dependency means the direct
  dependency upgrades, or you override the resolution yourself - `overrides` in npm, `resolutions`
  in Yarn and pnpm, `dependencyManagement` in Maven, a `replace` directive in Go. An override
  pins a version its parent was never tested against, so it buys time, not correctness.
- Depth does not reduce privilege. A dependency six levels down runs its `postinstall` with the
  same credentials as a direct one.
- Duplicate versions are normal and defeat naive counting. Two copies of `lodash` at different
  versions means "is `lodash` patched" has two answers, and the vulnerable one may be the copy
  that is actually imported.

The tempting wrong fix is a policy of "fewer dependencies" applied only to direct ones. Replacing
one direct dependency with another that has a deeper tree makes the number look better and the
exposure worse. Count the resolved graph.

## Stop Install-Time Code Execution

`A03:2025` · `CWE-829`

`postinstall` runs with the credentials of whoever ran the install: a developer's SSH agent
and cloud session, or a CI runner's tokens. The 2025 `Shai-Hulud` npm worm - described by
OWASP as the first successful self-propagating npm worm - used post-install scripts to
exfiltrate secrets and then republished itself with the npm tokens it found, reaching more
than 500 package versions.

```bash
# Vulnerable: every dependency in the tree may run code, right now, as you
npm ci
```

```bash
# Fixed: no scripts by default
npm ci --ignore-scripts
```

`ignore-scripts` stops `package.json` scripts from running. Note the documented exception:
`npm start`, `npm test`, and `npm run` still execute their target script, but not the pre- or
post-scripts around it.

Node is not unique here. A Python source distribution runs its build backend and historically
`setup.py` during installation; refuse source distributions with
`pip install --only-binary :all:` where wheels exist. Go does not run `go generate` during
`go build` - that is the safety property. Keep generation as an explicit, reviewed step, commit
its output where practical, and never add an implicit `go generate ./...` to the release build.
A generator named in a `//go:generate` directive is arbitrary code.

Blanket blocking breaks the handful of packages that genuinely need a native build. Allowlist
those by name rather than re-enabling everything:

```json
{
  "allowScripts": {
    "sharp": true,
    "esbuild": true,
    "some-analytics-sdk": false
  }
}
```

npm also offers `allow-scripts` for one-off and global contexts (`npm exec`, `npx`,
`npm install -g`), `strict-allow-scripts` to turn the policy warning into a hard failure for
unreviewed entries, and `dangerously-allow-all-scripts`, which the documentation calls a
migration escape hatch whose use is strongly discouraged. Matching is against the resolved
dependency identity, not the name a package claims for itself.

Why the allowlist works and a denylist does not: you are enumerating the small set of
packages you decided to trust with code execution, instead of trying to predict which of your
900 transitive dependencies will add a `postinstall` in its next patch release.

## Isolate the Build

`A03:2025` · ASVS V13 · SLSA Build L2 => L3

Two properties define a trustworthy build: the provenance is produced by the platform rather
than the build script, and one build cannot reach another or reach the signing key.

```yaml
# Vulnerable: a fork's PR runs with the base repo's secrets and a write token
name: ci
on: pull_request_target
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          ref: ${{ github.event.pull_request.head.sha }}   # attacker's code
      - run: npm install && npm test                       # with your secrets
      - run: ./scripts/publish.sh
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
```

```yaml
# Fixed: untrusted code runs without secrets; publishing is a separate, trusted job
name: ci
on: [pull_request]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@d632683dd7b4114ad314bca15554477dd762a938  # v6.0.0
      - run: npm ci --ignore-scripts
      - run: npm test

  publish:
    if: github.event_name == 'release'
    needs: test
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write        # OIDC, no long-lived registry token
    steps:
      - uses: actions/checkout@d632683dd7b4114ad314bca15554477dd762a938  # v6.0.0
      - uses: actions/setup-node@<pinned-sha>
        with:
          node-version: '24.x'
          registry-url: 'https://registry.npmjs.org'
          package-manager-cache: false     # never cache in a release build
      - run: npm ci --ignore-scripts
      - run: npm publish --provenance --access public
```

Why the split works: `pull_request_target` runs in the context of the base repository, so it
has secrets and, with `write-all`, a token that can push. Checking out the PR head under that
context hands both to the submitter. `pull_request` runs without them. Nothing else in the
workflow needs to change.

Two details in the fixed version that are easy to drop. Actions are pinned to a commit SHA
with the version in a comment, because a tag is a mutable pointer the action's owner can move.
And publishing uses OIDC (`id-token: write`) rather than a stored registry token - npm
generates provenance attestations automatically under trusted publishing, without the
`--provenance` flag and without a token to steal.

## Build Reproducibly Enough to Compare

`A03:2025` · ASVS V15 · SLSA v1.2 · `CWE-506`

The xz backdoor was not in the git repository. It was in the release tarball - extra autotools
files that the repository never contained, which extracted a prebuilt object during the build
and patched liblzma. Reviewing the source found nothing, because the source was clean.

A hermetic build declares every input and fetches nothing at build time. A reproducible build
produces identical bytes from identical inputs, so a second party can rebuild and compare. The
first makes the second possible.

```dockerfile
# Vulnerable: resolves at build time, so no two builds share inputs
FROM golang:1.25
RUN go install github.com/acme/tool@latest
COPY . .
RUN go build -o /out/app ./cmd/app
```

```dockerfile
# Fixed: inputs pinned, network off during compile, timestamps and paths normalised
FROM golang:1.25-alpine@sha256:<64-hex-digest> AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download            # only step allowed to reach the network
COPY . .

ENV CGO_ENABLED=0 GOFLAGS=-mod=readonly SOURCE_DATE_EPOCH=1
RUN go build -trimpath -buildvcs=false \
      -ldflags='-s -w -buildid=' \
      -o /out/app ./cmd/app
```

Why each flag matters. `-mod=readonly` fails rather than silently editing `go.mod`, so the
declared graph is the built graph. `go mod download` verifies every module against `go.sum`
before anything compiles. `-trimpath` removes absolute build paths, and `-buildid=` removes a
value that varies by build, both of which otherwise make byte comparison useless. Separating
`go mod download` from `COPY . .` is what lets you drop the network for the compile step.

What reproducibility buys, precisely: an independent rebuild that produces different bytes tells
you an undeclared input entered the build. That is the only control in this file that would have
caught xz. What it does not buy: a reproducible build of backdoored source reproduces the
backdoor perfectly.

Honest limitation: full bit-for-bit reproducibility is out of reach in several ecosystems, and
chasing it is not a prerequisite for provenance. Pin what you can, record the nondeterminism you
cannot remove, and do not delay signing while you work on it.

## Generate an SBOM Something Consumes

`A03:2025` · ASVS 15.1.2 · SSDF PS.3.2

An SBOM is an inventory. Its whole value is answering "which of our builds contains this
component" in minutes rather than days. Generated and filed, it answers nothing.

```bash
# Vulnerable: an SBOM of the source tree, attached to nothing, read by nobody
syft dir:. -o cyclonedx-json > sbom.json
```

```bash
# Fixed: generated from the artefact, bound to its digest, and gated on policy
DIGEST=$(crane digest registry.acme.io/api:"$GIT_SHA")
IMAGE="registry.acme.io/api@${DIGEST}"

syft "$IMAGE" -o cyclonedx-json=sbom.cdx.json
cosign attest --yes --type cyclonedx --predicate sbom.cdx.json "$IMAGE"

# the gate: fail the release on a policy breach, do not print and continue
grype "sbom:sbom.cdx.json" --fail-on high
```

Two generators, two purposes. `npm sbom --sbom-format cyclonedx` reads the lockfile and gives
you the exact resolved graph the build used, including dev scopes. `syft <image>` reads the
finished artefact and finds base-image OS packages the lockfile never mentioned. Run both. When
they disagree, that disagreement is the finding: something entered the artefact outside the
declared graph.

Why the digest binding matters: two builds of `v1.4.2` are two artefacts. An SBOM keyed by
version string cannot tell you which one is running, which is exactly the question incident
response asks.

What people wrongly expect from an SBOM, and it is worth saying out loud:

- It is not a vulnerability report. It is the input to one
- It is not proof of reachability. Presence of a vulnerable version says nothing about whether
  the vulnerable function is called
- It is not trustworthy on its own. Unsigned, it inherits the credibility of whoever handed it
  to you - which is why the `cosign attest` line is not optional
- It is not a licence compliance verdict, though it is the evidence a lawyer needs

Format details, current versions, and the build-time versus scan-time tradeoff are in
[references/sbom-formats.md](references/sbom-formats.md).

## Sign and Actually Verify

`A08:2025` · `CWE-347`, `CWE-494`

Signing is the easy half. The control is the verify step at the consuming end, with the
expected identity named.

```bash
# Vulnerable: accepts anything anyone signed
cosign verify "$IMAGE" --certificate-identity-regexp '.*' \
                       --certificate-oidc-issuer-regexp '.*'
```

```bash
# Fixed: only this workflow, in this repository, via this issuer
cosign verify "registry.acme.io/api@sha256:$DIGEST" \
  --certificate-identity "https://github.com/acme/api/.github/workflows/release.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  || { echo "signature verification failed"; exit 1; }
```

Why this works: the certificate binds the signature to an OIDC identity, so pinning identity
and issuer means only that workflow on that branch can produce an artefact you will accept. A
wildcard identity verifies that Sigstore is reachable and nothing more.

Verify by digest, not by tag - a tag can be repointed at an image whose own signature is
perfectly valid. And run the verification where the artefact is consumed: an admission
controller or the deploy job, not the build job that just signed it.

For npm packages the equivalent consumer-side check is `npm audit signatures`; for GitHub
artefact attestations it is `gh attestation verify`. Both need to run in a gate that fails the
pipeline, or they are logging.

## Promote by Digest

`A08:2025` · `CWE-345`

Rebuilding per environment produces a different artefact with none of the testing.

```yaml
# Vulnerable: staging and production are different builds of the same commit
- name: deploy staging
  run: docker build -t acme/api:staging . && docker push acme/api:staging
- name: deploy production
  run: docker build -t acme/api:prod . && docker push acme/api:prod
```

```yaml
# Fixed: build once, promote the digest that passed
- id: build
  run: |
    digest=$(docker buildx build --push -t acme/api:${{ github.sha }} \
             --metadata-file meta.json . && jq -r '."containerimage.digest"' meta.json)
    echo "digest=$digest" >> "$GITHUB_OUTPUT"
- name: promote to production
  run: |
    cosign verify "acme/api@${{ steps.build.outputs.digest }}" \
      --certificate-identity "$EXPECTED_IDENTITY" \
      --certificate-oidc-issuer "$EXPECTED_ISSUER"
    crane tag "acme/api@${{ steps.build.outputs.digest }}" production
```

Why this works: promotion moves a label, so the bytes in production are provably the bytes
that passed staging, and the signature and SBOM attached to that digest still describe what is
running. Two builds of one commit differ in base image contents, resolved dependencies, and
build timestamps - so a clean staging run says nothing about production.

A03 lists promotion over rebuilds among its artefact hardening recommendations, alongside
provenance, signing, timestamping, and immutability.

## Guard the Update Path

`A03:2025` · `CWE-1357`

The dangerous update is not the outdated dependency. It is the one that arrives within hours
of a maintainer account compromise and gets merged by a bot at 03:00.

```json
// Vulnerable: newest wins, automatically, on everything
{
  "extends": ["config:recommended"],
  "automerge": true,
  "automergeType": "branch",
  "minimumReleaseAge": null
}
```

```json
// Fixed: a cooldown, and no automerge where execution reaches CI or production
{
  "extends": ["config:recommended"],
  "minimumReleaseAge": "5 days",
  "packageRules": [
    { "matchDepTypes": ["devDependencies"], "automerge": true },
    { "matchDepTypes": ["dependencies"], "automerge": false },
    { "matchManagers": ["github-actions", "dockerfile"], "automerge": false,
      "pinDigests": true },
    { "matchUpdateTypes": ["major"], "automerge": false }
  ]
}
```

Why the cooldown works: malicious releases are usually found and yanked in days, often hours.
Waiting turns "we were patient zero" into "the registry pulled it before we resolved it". The
cost is a few days of exposure to known CVEs, which is why the delay is short and why security
advisories should override it - most tools support a separate, faster path for vulnerability
fixes.

Staged rollouts and canary deployments belong here too, and A03 names them: updating
everything at once turns a bad release into a total outage.

## Triage and Remediation Windows

`A03:2025` · ASVS 15.1.1, 15.2.1 · `CWE-1395`

Write the clock down, then hold to it. ASVS 15.1.1 asks for documented, risk-based remediation
time frames; 15.2.1 asks that the application contain no component that has breached them.
Without the first, the second is unmeasurable and every triage becomes an argument.

| Situation | Window | Reasoning |
|---|---|---|
| Malicious package confirmed in the tree | Immediate | Assume credential theft, not just a vulnerability |
| Reachable critical, production path | 72 hours | Exploitable now |
| Reachable high | 14 days |  |
| Not reachable, any severity | Next scheduled upgrade | Record the reachability judgement |
| Dev or test only | Next scheduled upgrade | Still reachable from CI, so not "no risk" |
| Unmaintained, no fix available | Migration plan within a quarter | ASVS 15.1.4 "risky component" |

Reachability is the judgement that makes triage honest, and the one people fake. State how you
determined it: the vulnerable function is not called, the code path requires a config you do
not set, the package is imported only by a test fixture. "Not exploitable in our usage"
without a reason is a deferral, not a triage.

Two corrections to the usual instinct:

- Dev-only is not zero risk. A dev dependency executes on developer machines and in CI, where
  the deploy credentials live. Downgrade the severity, do not dismiss it.
- A malicious package is a credential incident, not a version bump. Rotate every secret the
  affected builds could see before you think about the diff. See
  [troubleshooting.md](troubleshooting.md#a-dependency-turns-out-to-be-malicious).

## Sources

- <https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/>
- <https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/>
- <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x24-V15-Secure-Coding-and-Architecture.md>
- <https://slsa.dev/spec/v1.2/>
- <https://docs.npmjs.com/cli/v11/using-npm/config>
- <https://pip.pypa.io/en/stable/topics/secure-installs/>
- <https://docs.sigstore.dev/cosign/verifying/verify/>
