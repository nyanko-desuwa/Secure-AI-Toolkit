# Ecosystem Controls

> Flags and file names verified 2026-07-28 against each tool's own documentation, linked per
> section. These change far faster than the standards do - re-check before quoting one in a
> report, and prefer `--help` on the installed version over this table.

The six trust links from `SKILL.md` in each ecosystem's own vocabulary. Where a control does
not exist, this file says so instead of inventing one.

## npm

Source: <https://docs.npmjs.com/cli/v11/using-npm/config> ·
<https://docs.npmjs.com/generating-provenance-statements>

| Concern | Control |
|---|---|
| Retrieval from lockfile only | `npm ci`. Requires an existing `package-lock.json` or `npm-shrinkwrap.json`, exits with an error if it disagrees with `package.json`, never writes to either, and removes `node_modules` first |
| Install-time execution | `ignore-scripts=true`. npm then does not run scripts declared in `package.json` files |
| Selective allowance | `allow-scripts` (one-off/global contexts: `npm exec`, `npx`, `npm install -g`), or `allowScripts` in `package.json` for project-wide policy. `strict-allow-scripts=true` turns the unreviewed-dependency warning into a failure |
| Escape hatch to avoid | `dangerously-allow-all-scripts`. The docs call it a migration escape hatch and strongly discourage it |
| Provenance | `npm publish --provenance` from a GitHub-hosted runner with `permissions: id-token: write`. Equivalent: `NPM_CONFIG_PROVENANCE=true`, `publishConfig.provenance` in `package.json`, or `provenance=true` in `.npmrc`. Trusted publishing generates provenance without the flag |

Two gotchas the docs call out. `ignore-scripts` still lets `npm start`, `npm test`, and
`npm run` execute their target script - it suppresses pre- and post-scripts. And if the
lockfile was generated with tree-shaping flags such as `--legacy-peer-deps`, `npm ci` needs the
same flags or it errors; commit them via a project `.npmrc`.

## pip

Source: <https://pip.pypa.io/en/stable/topics/secure-installs/>

Hash-checking mode, added in pip 8.0, is the control that matters:

```bash
pip install --require-hashes --only-binary :all: -r requirements.txt
```

- Hash-checking is all-or-nothing. A `--hash` on any requirement activates it globally, and
  then hashes are required for every requirement and every dependency
- Requirements must be pinned - `==`, a URL, or a filesystem path. Unpinned plus hashed is a
  contradiction and pip treats it as an error
- sha256 is the recommended algorithm. md5, sha1, and sha224 are excluded deliberately
- Multiple hashes per package are allowed, which is how you cover several wheels plus the sdist
- `--only-binary :all:` matters as much as the hashes: it refuses source distributions, and a
  source distribution executes `setup.py` at install time
- `pip hash` generates the values. `--no-require-hashes` (added in pip 26.2) disables the
  automatic global enforcement - reach for it only for local paths and VCS URLs

On dependency confusion specifically: `--extra-index-url` gives no priority guarantee between
indexes, and PEP 708 ("Extending the Repository API to Mitigate Dependency Confusion Attacks")
was **Rejected**. There is no index-priority mechanism to wait for. Use one index.

## Go

Source: <https://go.dev/ref/mod>

| Variable | Effect |
|---|---|
| `GOPROXY` | Ordered list of proxy URLs. The keyword `direct` fetches from the version control repository instead |
| `GOPRIVATE` | Glob patterns of module prefixes treated as private. Default for the two below |
| `GONOPROXY` | Prefixes never fetched through a proxy |
| `GONOSUMDB` | Prefixes not checked against the public checksum database `sum.golang.org` |
| `GOINSECURE` | Prefixes allowed over HTTP and other insecure protocols. Justify every entry |

`go.sum` gives you hash verification by default, which is the strongest out-of-the-box position
of any ecosystem here. The documented pattern for private modules is a central private proxy
serving everything:

```bash
GOPROXY=https://proxy.corp.example.com
GONOSUMDB=corp.example.com
```

Note what `GONOSUMDB` costs: those modules lose checksum-database verification. Scope it to the
narrowest prefix that works, never `*`.

## Maven and Gradle

Source: <https://docs.gradle.org/current/userguide/dependency_verification.html>

Gradle writes verification metadata to `gradle/verification-metadata.xml`, and verification
turns on automatically once that file exists:

```bash
./gradlew --write-verification-metadata sha256,pgp --export-keys
./gradlew --write-verification-metadata sha256 help --dry-run   # preview only
```

- Checksums prove integrity, signatures prove provenance. Record both - the docs are explicit
  that "checksums alone verify integrity but not authenticity"
- Trusted keys use the full 40-character fingerprint. A group-level `<trusted-key>` trusts
  every artefact in that group, so prefer per-artefact `<pgp>` entries
- Bootstrapping trusts whatever is in your repositories right now, and marks entries
  `origin="Generated by Gradle"`. Review before promoting them to `"Verified"`
- `SNAPSHOT` and locally built artefacts are skipped, because their hashes move

Maven's equivalent is the `maven-artifact-plugin` for reproducible builds plus a repository
manager that enforces the policy centrally. Maven has no single-file verification metadata
equivalent to Gradle's.

## Containers

| Concern | Control |
|---|---|
| Base image identity | Reference by digest: `FROM registry/image@sha256:...`. A tag is mutable |
| Signing | `cosign sign <image>`, keyless via OIDC (Google, GitHub, Microsoft), or `--key` with a KMS URI (`awskms://`, `gcpkms://`, `azurekms://`, `hashivault://`, `k8s://`) |
| Verification | `cosign verify <image> --certificate-identity=... --certificate-oidc-issuer=...` |
| Attestations | `cosign attest --type custom --predicate p.json <image>`, checked with `cosign verify-attestation --policy` |
| Inspection | `cosign tree <image>` lists attached signatures. They use the OCI 1.1 referrers specification |

Identity values for CI-produced signatures, from the Sigstore documentation:

| Producer | `--certificate-oidc-issuer` | `--certificate-identity` |
|---|---|---|
| GitHub Actions | `https://token.actions.githubusercontent.com` | `https://github.com/ORG/REPO/.github/workflows/FILE@refs/heads/BRANCH` |
| GitLab CI | `https://gitlab.com` | `https://gitlab.com/PROJECT_PATH//CI_CONFIG_PATH@REF_PATH` |
| Human, GitHub login | `https://github.com/login/oauth` | the email address |
| Human, Google | `https://accounts.google.com` | the email address |

`cosign verify` without both identity flags accepts a signature from any identity in the
transparency log. That is the single most common way signing gets adopted without buying
anything - see [../examples/README.md](../examples/README.md#deploying-an-image-nobody-verified).

## GitHub Actions attestations

Source: <https://github.com/actions/attest>

```yaml
permissions:
  id-token: write          # mint the OIDC token for the Sigstore certificate
  attestations: write      # persist the attestation
  artifact-metadata: write # create the artifact storage record

steps:
  - uses: actions/attest@v4
    with:
      subject-path: dist/app.tar.gz
```

Verify with `gh attestation verify`. `actions/attest-build-provenance` at v4 is a wrapper over
`actions/attest`; new work should use `actions/attest` directly. With no `sbom-path` or
predicate inputs it generates SLSA build provenance; `sbom-path` produces an SBOM attestation
from SPDX or CycloneDX.

Availability constraint worth knowing before you design around it: attestations are available
in public repositories on current plans, but private and internal repositories require GitHub
Enterprise Cloud, and they are not supported on GitHub Enterprise Server.

## OpenSSF Scorecard

Source: <https://github.com/ossf/scorecard>

Three checks carry most of the signal for this skill:

| Check | Question | Risk |
|---|---|---|
| `Pinned-Dependencies` | Are dependencies declared and pinned? | Medium |
| `Signed-Releases` | Are releases cryptographically signed? | High |
| `Dependency-Update-Tool` | Is there tooling to help update dependencies? | High |

Use it as an input to a dependency-adoption decision, not as a gate. `Dependency-Update-Tool`
is omitted from the weekly scan behind the REST API for cost reasons, so an API-sourced score
is not the same as a CLI-sourced one.

## Sources

- <https://docs.npmjs.com/cli/v11/using-npm/config>
- <https://docs.npmjs.com/generating-provenance-statements>
- <https://pip.pypa.io/en/stable/topics/secure-installs/>
- <https://peps.python.org/pep-0708/>
- <https://go.dev/ref/mod>
- <https://docs.gradle.org/current/userguide/dependency_verification.html>
- <https://docs.sigstore.dev/cosign/signing/signing_with_containers/>
- <https://docs.sigstore.dev/cosign/verifying/verify/>
- <https://github.com/actions/attest>
- <https://github.com/ossf/scorecard>
