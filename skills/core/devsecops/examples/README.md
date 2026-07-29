# DevSecOps Examples

These examples deliberately show common pipeline mistakes beside hardened alternatives. They are
patterns, not copy-paste production policy. Every vulnerable example is labelled. Test fixtures use
placeholders only.

## Contents

1. [Fork PR secret exposure](#1-fork-pr-secret-exposure) - A08, CWE-829
2. [Mutable third-party action](#2-mutable-third-party-action) - A03, CWE-829
3. [Over-permissioned token](#3-over-permissioned-token) - A08, CWE-829
4. [Long-lived cloud key](#4-long-lived-cloud-key) - A03/A08, CWE-829
5. [No baseline](#5-no-baseline) - A03, ASVS V15
6. [Late SBOM](#6-late-sbom) - A03, ASVS V15
7. [Unverified artifact](#7-unverified-artifact) - A08, CWE-506
8. [Auto-merge scope](#8-auto-merge-scope) - A03, CWE-1104

Runnable files in this directory:

- `vulnerable-pr-target.yml` - do not enable; fork secret exposure fixture
- `hardened-pr.yml` - PR gate with minimal permissions and pinned actions
- `release-signed.yml` - image, SBOM, cosign, and provenance release skeleton
- `pre-commit-config.yaml` - fast local secret and syntax checks
- `semgrep-rule.yml` - custom rule for a dangerous workflow pattern

## 1. Fork PR Secret Exposure

`A08:2025` · ASVS V13, V15 · CWE-829

```yaml
# Vulnerable: a fork can change package scripts and run with secrets/write token
on: pull_request_target
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { ref: "${{ github.event.pull_request.head.sha }}" }
      - run: npm ci && npm test
        env: { DEPLOY_TOKEN: "${{ secrets.DEPLOY_TOKEN }}" }
```

```yaml
# Fixed: fork code is isolated from secrets and write authority
on: pull_request
permissions: {}
jobs:
  test:
    permissions: { contents: read }
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with: { persist-credentials: false }
      - run: npm ci --ignore-scripts
      - run: npm test
```

Why the fix works: the event context does not grant fork PR jobs repository secrets, and the token
is read-only. `ignore-scripts` narrows install-time execution but is not a substitute for the trust
boundary. A privileged follow-up must never execute the PR artifact.

## 2. Mutable Third-Party Action

`A03:2025` · ASVS V15 · CWE-829, CWE-506

```yaml
# Vulnerable: a moved tag changes the code that receives this job's authority
- uses: third-party/upload@v3
```

```yaml
# Fixed: full SHA is immutable; comment retains release readability
- uses: third-party/upload@4f44c9dd0a71c4ed34c76e64925b51b07cf1f434 # v3.2.0
```

Why the fix works: a tag owner cannot silently change the referenced commit. Replace the example
SHA only after reviewing the real action release and dependency diff.

## 3. Over-Permissioned Token

`A08:2025` · ASVS V13 · CWE-829

```yaml
# Vulnerable: tests, linters, and actions all inherit every write scope
permissions: write-all
```

```yaml
# Fixed: each job receives only the API scope it needs
permissions: {}
jobs:
  scan:
    permissions:
      contents: read
      security-events: write
```

Why the fix works: compromise of a scan step cannot write releases, workflows, issues, or package
contents. Set permissions at job scope, not just workflow scope.

## 4. Long-Lived Cloud Key

`A03:2025` · `A08:2025` · ASVS V13 · CWE-829

```yaml
# Vulnerable: stored credentials remain useful until manually rotated
- uses: aws-actions/configure-aws-credentials@v4
  with:
    aws-access-key-id: "${{ secrets.AWS_ACCESS_KEY_ID }}"
    aws-secret-access-key: "${{ secrets.AWS_SECRET_ACCESS_KEY }}"
    aws-region: us-east-1
```

```yaml
# Fixed: short-lived role session from GitHub's OIDC token
permissions: {}
jobs:
  deploy:
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: aws-actions/configure-aws-credentials@ececac1a45f3b08a01d2dd070d28d111c5fe6722 # v4.1.0
        with:
          role-to-assume: arn:aws:iam::123456789012:role/github-deploy
          aws-region: us-east-1
```

Why the fix works: no long-lived key is stored in GitHub. The cloud trust policy must still bind the
role to the exact repository and protected environment/ref; an unrestricted OIDC role is not safe.

## 5. No Baseline

`A03:2025` · ASVS V15 · NIST SSDF RV.1

```yaml
# Vulnerable: historical debt makes every change fail
- run: semgrep scan --config auto --error
```

```yaml
# Fixed: compare the change to the base and burn down old debt separately
- run: semgrep scan --config .semgrep --error --baseline-commit "${BASE_SHA}"
```

Why the fix works: historical findings remain tracked but do not drown out regressions. Store stable
fingerprints, owner, evidence, and review date. Do not replace the baseline with line-level ignores.

## 6. Late SBOM

`A03:2025` · ASVS V15 · SLSA 1.2

```yaml
# Vulnerable: this can resolve a different graph after the release was built
- run: syft dir:. -o cyclonedx-json=sbom.json
  # run days after the image was published
```

```yaml
# Fixed: build-time SBOM is generated from the exact immutable image
- run: syft "registry.example/app@${IMAGE_DIGEST}" -o cyclonedx-json=sbom.cdx.json
- run: cosign attest --yes --type cyclonedx --predicate sbom.cdx.json "registry.example/app@${IMAGE_DIGEST}"
```

Why the fix works: the inventory describes bundled, transitive, and OS components that shipped.
The SBOM is useful for exposure queries and licence review; it is not itself a vulnerability scan.

## 7. Unverified Artifact

`A08:2025` · ASVS V15 · SLSA 1.2 · CWE-506

```yaml
# Vulnerable: deployment trusts whatever an artifact name resolves to
- uses: actions/download-artifact@v4
  with: { name: app }
- run: ./app/deploy.sh
```

```yaml
# Fixed: consume the expected run and verify a trusted digest before deployment
- uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4.3.0
  with: { name: app, run-id: "${{ needs.build.outputs.run_id }}" }
- run: sha256sum --check app.sha256
```

Why the fix works: the artifact identity is bound to the intended build. The checksum must come
from a trusted build output or attestation; hashing a file and checksum supplied by the same
untrusted producer proves nothing.

## 8. Auto-Merge Scope

`A03:2025` · ASVS V15 · CWE-1104

```json
// Vulnerable: any production or major dependency can merge without review
{ "packageRules": [{ "matchUpdateTypes": ["major", "minor", "patch"], "automerge": true }] }
```

```json
// Fixed: only dev dependency patches, after a release-age delay and required checks
{
  "packageRules": [{
    "matchDepTypes": ["devDependencies"],
    "matchUpdateTypes": ["patch"],
    "minimumReleaseAge": "3 days",
    "automerge": true,
    "platformAutomerge": true
  }]
}
```

Why the fix works: the automatic trust boundary is narrow. Patch updates can still be malicious,
so lockfile diff review, registry monitoring, required tests, and branch protection remain required.

## Sources

- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>
- OWASP ASVS 5.0 - <https://owasp.org/www-project-application-security-verification-standard/>
- NIST SSDF - <https://csrc.nist.gov/pubs/sp/800/218/final>
- SLSA v1.2 - <https://slsa.dev/spec/>
- GitHub Actions security - <https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions>
- CWE-1104 - <https://cwe.mitre.org/data/definitions/1104.html>
- CWE-506 - <https://cwe.mitre.org/data/definitions/506.html>
- CWE-829 - <https://cwe.mitre.org/data/definitions/829.html>
