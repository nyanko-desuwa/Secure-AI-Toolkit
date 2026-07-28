# Compliance Best Practices

This skill maps controls that already exist in code, configuration, and operations to the
framework requirements they can evidence. It does not provide legal advice, create compliance,
or certify an organisation. The auditor's interpretation and the applicable scope govern.

Use this direction:

```text
implemented technical control -> operating evidence -> framework requirement -> scope caveat
```

Never start with a framework checklist and infer that a control exists.

## Build a control evidence record

For each control, keep a machine-readable record beside the implementation:

```yaml
control_id: app.audit.admin-actions
implementation:
  - src/audit/admin.ts
  - infra/audit-store.tf
owner: platform-security
test: test/audit/admin-actions.spec.ts
evidence_job: .github/workflows/control-evidence.yml
scope: production admin actions
limitations:
  - identity-provider administration is evidenced separately
```

This record is a pointer, not proof. The CI run, test result, deployment digest, and runtime
export prove that the implemented control operated. A quarterly screenshot proves only that a
screen looked a certain way once.

## Audit logging

`A09:2025` · ASVS V16 · CWE-778 · CWE-532

| Implemented control | Evidence artifact | Framework mapping |
|---|---|---|
| Append-only privileged-action events with actor, action, target, outcome, time, request ID | Schema test, immutability policy result, sampled redacted export, gap alert test | ISO/IEC 27001:2022 A.8.15 Logging; A.8.16 Monitoring activities; A.5.28 Collection of evidence |
| Access to the audit store is separately logged | IAM policy test and access-event export | HIPAA 45 CFR 164.312(b) Audit controls; PCI DSS v4.0.1 Requirement 10; SOC 2 CC7 System Operations |

```typescript
// Vulnerable: mutable application log; the actor can omit fields.
logger.info(`admin changed ${req.body.userId}`);

// Fixed: typed event goes to a separately controlled append-only sink.
await audit.write({
  actorId: req.auth.subject,
  action: "role.changed",
  targetId: validated.userId,
  outcome: "success",
  requestId: req.id,
  occurredAt: new Date().toISOString(),
});
```

The fixed version closes the evidence gap because required fields are structural and the
application cannot update or delete accepted events. It still needs a runtime IAM export and a
tamper/gap test. Do not log secrets or sensitive request bodies.

## Access control

`A01:2025` · ASVS V8 · CWE-200

| Implemented control | Evidence artifact | Framework mapping |
|---|---|---|
| Server-side, deny-by-default, per-object authorization | Negative authorization tests, policy bundle digest, production role export | ISO A.5.15 Access control; A.5.18 Access rights; A.8.2 Privileged access rights; A.8.3 Information access restriction |
| Unique identity plus authenticated privileged access | Identity-provider export, MFA policy-as-code result, dormant-account report | HIPAA 164.312(a)(1) Access control and 164.312(d) Person or entity authentication; PCI Requirements 7 and 8; SOC 2 CC6 Logical and Physical Access Controls |

```python
# Vulnerable: login is mistaken for authorization.
invoice = db.session.get(Invoice, request.view_args["invoice_id"])

# Fixed: ownership is enforced by the query.
invoice = db.session.execute(
    select(Invoice).where(
        Invoice.id == request.view_args["invoice_id"],
        Invoice.owner_id == current_user.id,
    )
).scalar_one_or_none()
```

The fixed query cannot return another subject's row. A policy document or UI-hidden button is
not evidence of this control.

## Encryption at rest and in transit

`A04:2025` · ASVS V11, V12, V14 · CWE-311 · CWE-312

| Implemented control | Evidence artifact | Framework mapping |
|---|---|---|
| Storage encryption configured in IaC, with controlled key use | IaC policy result, deployed-resource export, key-policy test | ISO A.8.24 Use of cryptography; GDPR Art 32(1)(a); PCI Requirement 3; HIPAA 164.312(a)(2)(iv), addressable |
| TLS with certificate validation between trust boundaries | TLS scanner output, service-mesh policy result, negative certificate test | GDPR Art 32; PCI Requirement 4; HIPAA 164.312(e)(1) Transmission security and (e)(2)(ii) Encryption, addressable |

```hcl
# Vulnerable: encryption depends on a console default.
resource "example_bucket" "evidence" { name = "control-evidence" }

# Fixed: the deployable resource states the control.
resource "example_bucket" "evidence" {
  name       = "control-evidence"
  encryption = "customer-managed-key"
  tls_only   = true
}
```

The fixed state can be policy-tested before deployment. It does not prove the production
resource matches IaC; add drift detection and a runtime export.

## Secrets rotation

`A04:2025` · ASVS V13, V14 · CWE-922

| Implemented control | Evidence artifact | Framework mapping |
|---|---|---|
| Workload identity or automatically rotated secret with bounded overlap | Secret metadata export without values, rotation integration test, failed-old-version test | ISO A.5.17 Authentication information; A.8.5 Secure authentication; PCI Requirements 7 and 8; SOC 2 CC6 |

```python
# Vulnerable: a policy says 90 days, but this static secret never expires.
token = os.environ["PARTNER_TOKEN"]

# Fixed: fetch a short-lived credential for this workload and audience.
token = identity.issue(audience="partner-api", ttl_seconds=900)
```

The fixed control removes manual rotation from the steady state. Do not publish secret values as
evidence. Evidence records metadata: secret identifier, version, creation/expiry time, workload,
and rotation result.

## Change management

`A02:2025` · `A08:2025` · ASVS V15

| Implemented control | Evidence artifact | Framework mapping |
|---|---|---|
| Protected branch, independent review, tested immutable build, approved deployment | Repository rules export, review metadata, CI result, artifact digest, deployment record | ISO A.8.32 Change management; PCI Requirement 6; SOC 2 CC8 Change Management |

```yaml
# Vulnerable: scanner failure does not block release.
- run: dependency-scan . || true

# Fixed: failure stops the job and evidence is retained.
- run: dependency-scan . --format sarif --output evidence/dependencies.sarif
- uses: actions/upload-artifact@v4
  with:
    name: control-evidence-${{ github.sha }}
    path: evidence/
```

The fixed gate binds evidence to a commit and makes failure observable. Pin third-party actions
by immutable digest in production workflows; a mutable tag weakens provenance.

## Vulnerability management

`A03:2025` · ASVS V15

| Implemented control | Evidence artifact | Framework mapping |
|---|---|---|
| SCA, SAST, image and IaC scanning with a blocking severity policy and tracked exceptions | SARIF/JSON outputs, scanner/version metadata, exception expiry report, remediation issue link | ISO A.8.8 Management of technical vulnerabilities; PCI Requirements 6 and 11; SOC 2 CC7 System Operations |

Generate an SBOM and scan it in CI. Retain the lockfile hash, source commit, build digest, scanner
version, database timestamp, policy version, and result. A clean result without tool/database
metadata cannot be reproduced. Detailed CI patterns live in
[`../../core/devsecops/`](../../core/devsecops/).

## Backup and recovery

`A04:2025` · ASVS V14 · CWE-312

| Implemented control | Evidence artifact | Framework mapping |
|---|---|---|
| Encrypted, access-controlled, versioned backups | Backup policy as code, backup job result, key/access policy test | ISO A.8.13 Information backup; GDPR Art 32(1)(c); SOC 2 Availability category |
| Restore is performed and verified against recovery objectives | Restore-job transcript, integrity check, measured recovery time and recovery point | GDPR Art 32(1)(c)-(d); HIPAA contingency requirements in 164.308(a)(7), cited in prose here because exact subparagraph titles were not fetched |

```bash
# Vulnerable: success means only that an archive command exited zero.
tar -czf backup.tgz data/

# Fixed: create, restore in isolation, and verify expected content.
tar -czf "$ARTIFACT" data/
mkdir "$RESTORE_DIR"
tar -xzf "$ARTIFACT" -C "$RESTORE_DIR"
sha256sum --check "$EXPECTED_MANIFEST"
```

A backup is not a recovery control until a restore succeeds. Never restore sensitive production
data into an uncontrolled test environment.

## Evidence generated by CI

The evidence job should produce, at minimum:

1. SBOM tied to source commit and artifact digest.
2. Dependency, source, container, and IaC policy scan outputs.
3. Authorization and audit-schema negative test results.
4. Deployment manifest and provenance.
5. Runtime exports that CI can safely obtain: identity access review, backup status, encryption
   settings, log retention, and drift status.
6. A signed manifest hashing every artifact, with timestamps and tool versions.

Access-review exports need subject ID, role, grant source, last use, reviewer decision, and review
time. Minimise personal data and never export credentials. Store evidence with read-only access,
retention, and deletion rules of its own.

## Mapping discipline

- Map only an implemented and tested control. Design intent is not implementation.
- Record which system, environment, data class, and period the artifact covers.
- Separate control design evidence from operating-effectiveness evidence.
- State framework fit as `supports` or `evidences`; never say one artifact `proves compliance`.
- Preserve one-to-many mappings. TLS may support several requirements, but each has different
  scope and expected evidence.
- Re-verify editions before quoting IDs. SOC 2 granular criteria and HIPAA administrative
  safeguard subparagraphs are deliberately omitted here where source text was not fetched.
