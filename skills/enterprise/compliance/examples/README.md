# Compliance Control Mapping Examples

These examples start with an enforced technical control, identify its build or runtime evidence,
and then map that evidence to framework requirements. They are not legal advice and do not make
an organisation compliant. An auditor determines whether the control and evidence are sufficient
for the engagement scope.

All names and data are synthetic. Vulnerable blocks are intentionally unsafe.

## 1. Audit logging that the application cannot erase

`A09:2025 Security Logging and Alerting Failures` · ASVS V16 · CWE-778

Vulnerable:

```typescript
app.post("/roles/:userId", requireAdmin, async (req, res) => {
  await roles.set(req.params.userId, req.body.role);
  console.log(`role changed for ${req.params.userId}`);
  res.sendStatus(204);
});
```

The event lacks actor, old/new role, outcome, time, and request ID. It shares the application's
mutable log stream. A compromised runtime can erase it.

Fixed:

```typescript
app.post("/roles/:userId", requireAdmin, async (req, res) => {
  const targetId = UserId.parse(req.params.userId);
  const role = Role.parse(req.body.role);
  const previous = await roles.set(targetId, role);
  await securityEvents.append({
    actorId: req.auth.subject,
    action: "access.role_changed",
    targetId,
    outcome: "success",
    previousRole: previous,
    newRole: role,
    requestId: req.id,
    occurredAt: new Date().toISOString(),
  });
  res.sendStatus(204);
});
```

Evidence: schema test; negative update/delete IAM test; append-only store policy; redacted event
sample; sequence-gap alert test; runtime access export. The fix closes the hole because the event
is structured and accepted by a separately controlled append-only sink.

Supports: ISO/IEC 27001:2022 A.8.15 Logging, A.8.16 Monitoring activities, A.5.28 Collection of
evidence; HIPAA 45 CFR 164.312(b) Audit controls; PCI DSS v4.0.1 Requirement 10; SOC 2 CC7 System
Operations. Framework scope still decides applicability.

## 2. Per-object access control

`A01:2025 Broken Access Control` · ASVS V8 · CWE-200

Vulnerable:

```python
@app.get("/exports/<int:export_id>")
@login_required
def download_export(export_id: int):
    export = db.session.get(Export, export_id)
    return send_file(export.path)
```

Any logged-in user can enumerate another user's export.

Fixed:

```python
@app.get("/exports/<int:export_id>")
@login_required
def download_export(export_id: int):
    export = db.session.execute(
        select(Export).where(
            Export.id == export_id,
            Export.owner_id == current_user.id,
        )
    ).scalar_one_or_none()
    if export is None:
        abort(404)
    return send_file(export.path)
```

Evidence: negative cross-user test; policy/code digest tied to deployment; identity-provider role
export; access-review decision and completed-removal report. The ownership predicate prevents the
unauthorized object from being returned rather than detecting it after fetch.

Supports: ISO A.5.15 Access control, A.5.18 Access rights, A.8.3 Information access restriction;
HIPAA 164.312(a)(1) Access control and 164.312(d) Person or entity authentication; PCI
Requirements 7 and 8; SOC 2 CC6 Logical and Physical Access Controls.

## 3. Encryption at rest and in transit

`A04:2025 Cryptographic Failures` · ASVS V11/V12/V14 · CWE-311 · CWE-312

Vulnerable:

```hcl
resource "example_database" "records" {
  name = "records"
}
```

Encryption and network transport depend on console defaults that can drift.

Fixed:

```hcl
resource "example_database" "records" {
  name               = "records"
  storage_encryption = true
  kms_key_id         = example_kms_key.records.id
  require_tls        = true
  public_access      = false
}
```

Evidence: IaC policy test; plan tied to commit; deployed-resource configuration export; key-policy
least-privilege test; TLS scan and invalid-certificate negative test; drift report. Explicit IaC
makes the property reviewable and blockable. Runtime collection is still needed because a plan is
not proof of deployed state.

Supports: ISO A.8.24 Use of cryptography; GDPR Art 32 Security of processing; PCI Requirement 3
for stored account data and Requirement 4 for transmission; HIPAA 164.312(a)(2)(iv) Encryption and
decryption and 164.312(e)(2)(ii) Encryption, both addressable specifications.

## 4. Secret rotation with revocation

`A04:2025 Cryptographic Failures` · ASVS V13/V14 · CWE-922

Vulnerable:

```python
PARTNER_TOKEN = os.environ["PARTNER_TOKEN"]  # static, no expiry or revocation test
```

A written 90-day policy does not rotate this credential.

Fixed:

```python
from datetime import timedelta

def partner_credential(identity):
    return identity.issue(
        audience="partner-api",
        lifetime=timedelta(minutes=15),
    )
```

Evidence: credential identifier and version, issued/expiry time, workload subject, audience,
rotation job result, bounded overlap, and a test showing the previous version is rejected. No
secret value enters evidence. Short-lived workload identity removes manual rotation from normal
operation and proves old access ends.

Supports: ISO A.5.17 Authentication information and A.8.5 Secure authentication; PCI Requirements
7 and 8; SOC 2 CC6. Granular SOC 2 criterion IDs are deliberately omitted because they were not
verified from fetched source text.

## 5. Change management enforced before deployment

`A08:2025 Software or Data Integrity Failures` · ASVS V15

Vulnerable:

```yaml
jobs:
  deploy:
    steps:
      - run: security-scan . || true
      - run: deploy production
```

The scan creates paperwork but cannot stop a vulnerable release.

Fixed:

```yaml
jobs:
  verify:
    steps:
      - run: security-scan . --output evidence/scan.json
      - run: verify-independent-approval "$GIT_SHA" production
      - uses: actions/upload-artifact@v4
        with:
          name: evidence-${{ github.sha }}
          path: evidence/
  deploy:
    needs: verify
    environment: production
    steps:
      - run: deploy-digest "$ARTIFACT_DIGEST"
```

Evidence: branch-protection export, review metadata, blocking scan result, source commit, immutable
artifact digest, approval bound to commit/environment, and deployment event. The fixed dependency
makes successful verification a deployment precondition.

Supports: ISO A.8.32 Change management; PCI Requirement 6; SOC 2 CC8 Change Management. Workflow
hardening, provenance, and pinning patterns live in [`../../../core/devsecops/`](../../../core/devsecops/).

## 6. Vulnerability management as a build control

`A03:2025 Software Supply Chain Failures` · ASVS V15

Vulnerable:

```bash
scanner filesystem . > scan.txt
```

The report omits input digest, tool/rules/database versions, policy, and enforcement result.

Fixed:

```bash
set -eu
scanner sbom --locked --output evidence/sbom.cdx.json .
scanner vulnerabilities \
  --input evidence/sbom.cdx.json \
  --policy security/vulnerability-policy.yml \
  --output evidence/vulnerabilities.json \
  --fail-on-policy-violation
sha256sum evidence/* > evidence/SHA256SUMS
```

Evidence: SBOM, lockfile and build digests, scan output, scanner/rules/database metadata, expiring
exception register, and linked remediation. The fixed command turns the assessment into a
reproducible gate rather than an ignored report.

Supports: ISO A.8.8 Management of technical vulnerabilities; PCI Requirements 6 and 11; SOC 2
CC7 System Operations. The mapping covers only ecosystems and assets included in the scan.

## 7. Backup plus verified recovery

`A04:2025 Cryptographic Failures` · ASVS V14 · CWE-312

Vulnerable:

```bash
backup create production-db
```

Exit zero shows only that a job accepted the request. It does not show decryptability, integrity,
or recovery time.

Fixed:

```bash
set -eu
snapshot_id="$(backup create production-db --encrypted)"
restore_id="$(backup restore "$snapshot_id" --isolated-network)"
backup wait-restored "$restore_id"
./verify-schema --target "$restore_id"
./verify-manifest --target "$restore_id" --expected evidence/expected-manifest.json
backup destroy-restored-copy "$restore_id"
```

Evidence: backup policy and job result, encryption/access settings, isolated restore transcript,
integrity and application checks, measured recovery point/time, and restored-copy destruction.
The control closes the gap because restoration and usable data are tested, not inferred.

Supports: ISO A.8.13 Information backup; GDPR Art 32(1)(c)-(d); SOC 2 Availability category. HIPAA
contingency-plan intent may also apply, but this example omits an exact administrative safeguard
subparagraph because that source text was not successfully fetched.

## Evidence manifest shape

Each example can emit one manifest:

```json
{
  "control": "app.audit.admin-actions",
  "commit": "0123456789abcdef0123456789abcdef01234567",
  "artifactDigest": "sha256:synthetic-example-digest",
  "environment": "production",
  "population": "privileged role changes",
  "periodStart": "2026-07-01T00:00:00Z",
  "periodEnd": "2026-07-28T00:00:00Z",
  "collector": "ci-evidence-readonly",
  "tools": [{ "name": "policy-test", "version": "pinned-by-lockfile" }],
  "results": [{ "name": "append-only-policy", "status": "pass" }],
  "limitations": ["identity-provider administration collected separately"]
}
```

Use real hashes produced by the build, not this synthetic placeholder. Sign the manifest, restrict
access, and retain it for the applicable observation period. A manifest makes artifacts traceable;
it does not transform incomplete coverage into compliance.
