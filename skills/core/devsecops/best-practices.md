# DevSecOps Best Practices

A security control that regularly blocks correct work will be bypassed. These patterns keep the
high-signal checks close to the change and move slower or noisier analysis off the merge path.

## Place Checks by Cost and Signal

`A03:2025` · ASVS V15 · NIST SSDF PW.5

Running every scanner on every commit gives slow feedback without better coverage.

```yaml
# Vulnerable: a slow, noisy DAST scan blocks every pull request
name: Security
on: [pull_request]
jobs:
  zap:
    runs-on: ubuntu-latest
    steps:
      - run: zap-full-scan.py -t https://shared-staging.example -I
```

`-I` softens the exit status while the job still looks authoritative. The shared target also lets
one PR affect another.

```yaml
# Fixed: precise checks gate the PR; DAST gets an isolated scheduled target
name: Security
on:
  pull_request:
  schedule:
    - cron: "17 2 * * *"
permissions: {}
jobs:
  pr-gate:
    if: github.event_name == 'pull_request'
    permissions:
      contents: read
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - run: semgrep scan --config .semgrep --error --baseline-commit "${{ github.event.pull_request.base.sha }}"

  nightly-dast:
    if: github.event_name == 'schedule'
    runs-on: ubuntu-latest
    steps:
      - run: ./ci/deploy-isolated-target.sh
      - run: docker run --rm --network host ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://127.0.0.1:8080
```

Why this works: the PR gate analyses changed code and uses only rules proven precise enough to
block. DAST sees a real running application, but its slower crawl and authentication/setup noise
cannot hold every merge. Pin the ZAP image by digest in a real repository.

## Baselining an Existing Codebase

`A03:2025` · ASVS V15 · NIST SSDF RV.1 · CWE-1104

Turning on a tool with four thousand existing findings makes "red" the normal state.

```yaml
# Vulnerable: day one fails on every historical finding
- run: semgrep scan --config auto --error
```

```yaml
# Fixed: PRs fail on new findings while existing debt is tracked separately
- name: Semgrep changed-code gate
  run: >-
    semgrep scan
    --config .semgrep
    --error
    --baseline-commit "${{ github.event.pull_request.base.sha }}"
```

The baseline is not `# nosemgrep` on every line. Record a machine-readable snapshot with rule ID,
fingerprint, path, owner, and review date. Triage critical reachable items before rollout. Create a
separate burn-down queue and delete entries when fixed. Regenerate only through a reviewed change.

Why this works: new code cannot deepen the debt, while old findings remain visible and owned.
Blind suppression would hide both old and future instances of the same flaw.

## CI/CD Pipeline Security

`A03:2025` · `A08:2025` · ASVS V13, V15 · CWE-829

A workflow with repository write access executes a fork's code. The attacker changes
`package.json` so `npm ci` exfiltrates the token in an install hook.

```yaml
# Vulnerable: pull_request_target has secrets and a write token
on: pull_request_target
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci && npm test
        env:
          RELEASE_TOKEN: ${{ secrets.RELEASE_TOKEN }}
```

```yaml
# Fixed: untrusted PR code receives neither secrets nor write permission
on: pull_request
permissions: {}
jobs:
  test:
    permissions:
      contents: read
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false
      - run: npm ci --ignore-scripts
      - run: npm test
```

Why this works: `pull_request` from a fork receives a read-only token and no repository secrets by
default. The action is immutable and does not leave credentials in the checkout. `--ignore-scripts`
is defence in depth, not the primary fix; tests still execute attacker-controlled code.

If a privileged follow-up is required, pass passive data such as a PR number through an artifact to
a `workflow_run` job. Never execute a binary, script, HTML report, or archive path supplied by the
untrusted job in that privileged context.

### Third-Party Actions

`A03:2025` · ASVS V15 · CWE-829

```yaml
# Vulnerable: a maintainer compromise can move the tag
- uses: vendor/publish-action@v2
```

```yaml
# Fixed: reviewed code is immutable
- uses: vendor/publish-action@4f44c9dd0a71c4ed34c76e64925b51b07cf1f434 # v2.4.1
```

The SHA above is illustrative; use the real reviewed commit for the chosen action. A tag comment
preserves readability. Dependabot/Renovate may propose SHA updates, but a human reviews actions
that get secrets or write access.

### Token Permissions

`A08:2025` · ASVS V13 · CWE-829

```yaml
# Vulnerable: every step can modify repository content and workflows
permissions: write-all
```

```yaml
# Fixed: deny by default, grant one job the exact scopes it needs
permissions: {}
jobs:
  scan:
    permissions:
      contents: read
      security-events: write
```

When any permission is specified, unspecified scopes become `none`. Set permissions per job so a
test dependency cannot borrow the publisher's authority.

## OIDC Instead of Long-Lived Cloud Keys

`A03:2025` · `A08:2025` · ASVS V13 · CWE-829

```yaml
# Vulnerable: durable credentials are available to the whole job
- uses: aws-actions/configure-aws-credentials@v4
  with:
    aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
    aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
    aws-region: us-east-1
```

```yaml
# Fixed: GitHub exchanges a short-lived OIDC token for a scoped role
permissions: {}
jobs:
  deploy:
    environment: production
    permissions:
      contents: read
      id-token: write
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@ececac1a45f3b08a01d2dd070d28d111c5fe6722 # v4.1.0
        with:
          role-to-assume: arn:aws:iam::123456789012:role/github-production-deployer
          aws-region: us-east-1
```

The AWS ARN is a placeholder. The role trust policy must constrain `sub` to the exact repository
and environment or protected ref, plus the expected `aud`. OIDC removes a stored long-lived key;
it does not make an over-broad cloud role safe.

## Dependency Management

`A03:2025` · ASVS V15 · NIST SSDF PS.3, PW.4 · CWE-1104, CWE-829

```json
// Vulnerable: broad ranges, no lockfile, all updates auto-merge
{
  "packageRules": [{ "matchUpdateTypes": ["major", "minor", "patch"], "automerge": true }]
}
```

```json
// Fixed: only patch updates of development dependencies auto-merge
{
  "packageRules": [
    {
      "description": "Auto-merge dev dependency patches after required checks",
      "matchDepTypes": ["devDependencies"],
      "matchUpdateTypes": ["patch"],
      "minimumReleaseAge": "3 days",
      "automerge": true,
      "platformAutomerge": true
    }
  ]
}
```

Commit the package manager's lockfile and use its frozen install command. Configure branch
protection with named required checks; automation must not be able to merge around them. Keep
production dependencies, minor/major updates, action SHAs, images, and digests review-only.

Why this works: the trusted automatic set is narrow and low-blast-radius. A patch can still be
malicious, so release age, registry signals, required tests, and lockfile diff review remain
important. `--ignore-scripts` may reduce install-time execution but can break packages and does
not stop malicious runtime code. Review the update as code.

Dependabot can be used instead, but its update file does not safely express "auto-merge only this
class" by itself. Implement that policy in a separate, tightly permissioned workflow or use the
platform's merge rules. Never auto-approve with a broadly writable bot token.

## SBOM at Build Time

`A03:2025` · ASVS V15 · NIST SSDF PS.3 · SLSA 1.2

```yaml
# Vulnerable: inventory reconstructed later from a mutable source checkout
- name: Make SBOM after release
  run: syft dir:. -o cyclonedx-json=sbom.json
```

```yaml
# Fixed: inventory the exact artifact that will ship
- name: Build image
  run: docker build --tag "${IMAGE}:${GITHUB_SHA}" .
- name: Generate CycloneDX SBOM from the image
  run: syft "${IMAGE}:${GITHUB_SHA}" -o cyclonedx-json=sbom.cdx.json
- name: Bind SBOM to image digest
  run: cosign attest --yes --type cyclonedx --predicate sbom.cdx.json "${IMAGE_DIGEST}"
```

Why this works: the SBOM reflects resolved, bundled components in the artifact rather than what a
manifest claims should be present. Generate CycloneDX or SPDX during the build, store it beside the
artifact, and bind both to the same digest.

Use the SBOM to answer exposure questions during a new CVE, supply customers or regulators with a
component inventory, enforce licence policy, and compare expected to observed release contents.
It is not proof that components are vulnerability-free or correctly licensed.

## Provenance, Signing, and Admission

`A08:2025` · ASVS V15 · SLSA 1.2 Build L1-L3 · CWE-506

Signing whatever a mutable deployment script points at authenticates the wrong object.

```bash
# Vulnerable: tag can move between approval and deployment
cosign verify registry.example/app:latest
kubectl set image deployment/app app=registry.example/app:latest
```

```bash
# Fixed: verify identity and immutable digest, then deploy that digest
cosign verify \
  --certificate-identity-regexp '^https://github.com/acme/app/.github/workflows/release.yml@refs/tags/v[0-9].*$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "registry.example/app@sha256:${DIGEST}"
kubectl set image deployment/app "app=registry.example/app@sha256:${DIGEST}"
```

Admission policy should perform this verification again inside the cluster and reject an image
whose digest, signature identity, issuer, or required SLSA provenance does not match policy.
Cosign signing proves who signed a digest. SLSA provenance records how it was built. Neither says
the source code is benign.

Aim for SLSA Build L2 as a practical first release target: hosted build platform, platform-signed
provenance, consumer verification. L3 adds build isolation and keeps signing material inaccessible
to user build steps. Reproducible builds add independent evidence where the toolchain can produce
bit-identical output; do not delay provenance while pursuing perfect reproducibility.

## Self-Hosted Runner Isolation

`A08:2025` · ASVS V13 · SLSA Build L3 · CWE-829

```yaml
# Vulnerable: public fork code lands on a persistent runner inside the production network
on: pull_request
jobs:
  test:
    runs-on: [self-hosted, production]
```

```yaml
# Fixed: untrusted PRs use an ephemeral hosted runner; deployment is separate and protected
on: pull_request
permissions: {}
jobs:
  test:
    runs-on: ubuntu-latest
    permissions:
      contents: read
```

A workspace cleanup cannot erase persistence elsewhere on the host or network. Privileged
self-hosted runners should be single-use, isolated by VM or equivalent boundary, denied internet
or internal routes they do not need, and restricted through runner groups to approved workflows.

## Artifact Integrity Between Jobs

`A08:2025` · ASVS V15 · SLSA 1.2 · CWE-829

```yaml
# Vulnerable: deploys a named artifact without checking what was downloaded
- uses: actions/download-artifact@v4
  with:
    name: app
- run: ./app/deploy.sh
```

```yaml
# Fixed: download by run, verify the expected digest, then consume as data
- uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4.3.0
  with:
    name: app
    run-id: ${{ needs.build.outputs.run_id }}
- run: sha256sum --check app.sha256
```

The digest itself must cross a trusted channel: job output from the same run, signed attestation,
or release metadata protected from the untrusted producer. Hashing an attacker-controlled file and
checking it against an attacker-controlled checksum proves nothing.

## Vulnerability Management

`A03:2025` · ASVS V15 · NIST SSDF RV.1-RV.3 · CWE-1104

Triage answers four questions: is the component shipped, is the vulnerable function reachable, is
there attacker-controlled input, and what privilege or blast radius follows? Record evidence, not
only the scanner severity.

Set organizational SLAs rather than copying a universal table. A typical policy might require an
actively exploited internet-facing critical issue within 24 hours and a reachable high issue
within seven days, but the owner must approve the actual numbers. Exceptions include finding,
reason, compensating controls, approver, owner, and expiry. Expiry reopens the finding; "accepted"
without a date means "forgotten".

## Security Champions

`A03:2025` · ASVS V15 · NIST SSDF PO.2

One developer per team keeps the baseline honest, helps tune a noisy rule, and knows whom to call
when reachability is unclear. Do not turn the role into unpaid gatekeeping. Give champions time,
training, a short escalation path, and no expectation that they replace the security team.
