# Microservices Architecture Skill

## Purpose

A service boundary is useful only when ownership, authorization, and operations remain explicit. The common failure is a gateway that authenticates a caller once while downstream services trust a service name, mTLS peer, tenant field, or object ID supplied by that caller. This skill keeps the authorization boundary at the object owner and costs every network indirection.

## How it works

Read `SKILL.md` first. It gives a boundary-first workflow, a runtime cost ledger, and a hard “when NOT to use this” section. Use `best-practices.md` for implementation shapes, `checklist.md` before returning a design, and `troubleshooting.md` when the split conflicts with latency, data ownership, or operations. Code blocks labelled Vulnerable are intentionally unsafe.

## File layout

```text
SKILL.md
README.md
checklist.md
best-practices.md
common-mistakes.md
troubleshooting.md
prompts.md
references/
  owasp-mapping.md
  cwe-microservices.md
  service-identity.md
  migration-and-observability.md
examples/
  README.md
```

## Configuration

This is Markdown guidance. It has no package, build step, environment variable, or live-system access. Replace placeholders such as `SERVICE_IDENTITY`, `OBJECT_ID`, and `https://service.invalid` with deployment-specific values. Do not treat example limits as production sizing.

## Example usage

```text
Read skills/architecture/microservices/SKILL.md. Review services/orders and services/billing.
Inventory every API and outbound call. For each object operation, show where authorization is
performed, whether mTLS is being mistaken for authorization, and the cost at three replicas.
Report missing live configuration as unverified.
```

```text
Using skills/architecture/microservices, plan a reversible strangler migration for the invoice
module. Include data ownership, dual-read reconciliation, traffic percentage gates, rollback, API
inventory updates, deadlines, retry budgets, queue limits, and alerts for authorization failures.
```

## Standards

| Standard | Coverage | Verification |
|---|---|---|
| OWASP Top 10 2025 | A01, A02, A06, A07, A08, A09, A10 | Pinned by brief; 2026-07-28 |
| OWASP ASVS 5.0.0 | V2, V4, V6, V8, V9, V12, V13, V14, V15, V16 | Pinned by brief; chapter-level only |
| CWE | 290, 441, 602, 653, 918, 1220, 400, 770, 772, 799 | Titles verified 2026-07-28; see references |

## Limitations

- The files cannot prove that a mesh verifies certificates, that a policy engine is fail-closed, or that an API is reachable. Verify deployment and runtime configuration separately.
- Cost formulas are planning bounds. Actual connection, trace, queue, and cache behaviour depends on client libraries, limits, and traffic; measure it.
- Service ownership does not automatically solve distributed consistency, privacy retention, or incident response.
- CWE mappings are mechanism-level guidance, not severity scores. Use one precise mapping where possible.
- Examples are complete small programs, not production service frameworks. They use synthetic identifiers and no credentials.

## Security notes

mTLS authenticates the peer on a transport channel. It does not authorize a caller to read or mutate a particular object. A service that accepts `tenantId`, `role`, or `objectId` as authority from an upstream service creates a confused deputy. Shared database credentials erase the intended compartment. Service discovery can turn a user-controlled URL into SSRF. Events remain untrusted at the consumer boundary.

Use OWASP Top 10 2025 A01 Broken Access Control, A02 Security Misconfiguration, A06 Insecure Design, A07 Authentication Failures, A08 Software or Data Integrity Failures, A09 Security Logging and Alerting Failures, and A10 Mishandling of Exceptional Conditions. Use ASVS chapters V4 API and Web Service, V6 Authentication, V8 Authorization, V12 Secure Communication, V13 Configuration, V14 Data Protection, V15 Secure Coding and Architecture, and V16 Security Logging and Error Handling.

## References

- [OWASP mapping](references/owasp-mapping.md)
- [Verified CWE entries](references/cwe-microservices.md)
- [Service identity and transport](references/service-identity.md)
- [Migration and observability](references/migration-and-observability.md)
