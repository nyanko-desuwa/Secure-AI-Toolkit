---
name: cloud-security
description: 'Secure AWS, Azure, and GCP infrastructure: IAM least privilege, workload identity, object storage exposure, network boundaries, instance metadata, encryption, logging, secrets, serverless, and Terraform review. Triggers: "AWS", "Azure", "GCP", "IAM", "S3 bucket", "Terraform", "cloud misconfiguration", "IMDS", "bảo mật đám mây", "quyền truy cập".'
allowed-tools: Read, Glob, Grep, WebSearch, WebFetch
---

# Cloud Security

Cloud breaches are almost never exploits. They are a permission that was wider than the job
needed, a bucket that answered an unauthenticated request, or a credential that lived long
enough to be found. This skill is organised by concern rather than by provider, because the
concern is the same on all three and only the service name changes.

## When to Use

- Writing or reviewing Terraform, CloudFormation, Bicep, or Pulumi
- Granting a permission, writing a trust policy, or creating an access key
- Exposing storage, a database, or a load balancer to a network
- Wiring a workload to a cloud identity (EKS, GKE, AKS, Lambda, Cloud Run, Functions)
- Deciding what to log and what to alert on
- Investigating an unexpected bill, an unexpected region, or an unexpected principal

## The Three Questions

Ask these before writing any resource block:

1. Which identity performs this action, and how long do its credentials live?
2. Who else can reach this resource, and from what network?
3. If this identity is compromised, what is the largest thing it can do?

Question three is blast radius. It is the one that decides whether an incident is a page or a
company event.

## Workflow

### 1. Identify the trust boundaries

Draw the edges the change crosses: account or subscription or project, VPC, and identity.
A resource inside a VPC is not protected by the VPC. Anything with a public endpoint or a
resource-based policy is reachable from outside it.

### 2. Grant the identity

Start from zero and add the specific actions the code calls. If you cannot name the actions,
read the code — do not paste a managed admin policy as a placeholder. See
[best-practices.md](best-practices.md#iam-least-privilege) and
[references/iam-antipatterns.md](references/iam-antipatterns.md).

No long-lived keys. Roles, workload identity, or federation. Every access key in a
non-human workload is a finding.

### 3. Close the network

Default deny inbound. Then close egress, which is the direction people leave open and the
direction data leaves by. Prefer private endpoints over public endpoints with an IP allowlist.

### 4. Encrypt and log

Encryption at rest with a customer-managed key where the data is regulated or shared across
accounts. TLS in transit, terminated where you can still see the traffic you need to inspect.
An organisation-wide audit trail with log file validation, in an account the workload cannot
write to.

### 5. Verify

Run [checklist.md](checklist.md). Then run policy-as-code against the plan, not against the
deployed state — the plan is the last point where a change is free to reject.

### 6. Report

Per finding: the resource address, the identity or network path that makes it exploitable,
the blast radius, and the fix as a diff. A finding without a reachable path is a hardening
suggestion. Label it as one.

## Severity

Rank by reachability and blast radius, not by service name.

- **Critical** — unauthenticated access to data from the internet, or a path to credentials
  that can escalate to account administrator
- **High** — an authenticated principal can escalate privileges, read another tenant's data,
  or reach the metadata service from an application input
- **Medium** — needs an existing foothold, or exposes non-sensitive configuration
- **Low** — missing defence in depth with no current path

"S3 bucket not encrypted" is not critical if it is also not public and holds build artefacts.
"IAM role with `AdministratorAccess`" is critical if a public Lambda assumes it, and medium
if only a break-glass human can.

## Standards

| Standard | Version | Use for |
|---|---|---|
| OWASP Top 10 2025 | 2025 | A01 access control, A02 misconfiguration, A04 crypto, A09 logging |
| OWASP ASVS | 5.0.0 | V13 Configuration, V14 Data Protection, V12 Secure Communication |
| CIS AWS Foundations | 7.0.0 | AWS account baseline |
| CIS Microsoft Azure Foundations | 6.0.0 | Azure subscription baseline |
| CIS GCP Foundation | 5.0.0 | GCP project and organisation baseline |
| Provider well-architected security pillars | current | Design-time trade-offs |

Details and source URLs in [references/](references/). Cite CIS by section title, not by a
control number you have not read — the numbering shifts between major versions.

## Related Skills

- `owasp` — the general security baseline, and the entry point when this skill does not fit
- `secrets-management` — vault patterns, rotation mechanics
- `docker-security` — container image and runtime hardening under the cloud layer
- `devsecops` — wiring policy-as-code into CI
- `logging-audit` — SIEM pipelines downstream of the audit trail
- `redis-security` — managed Redis/Valkey access, ACLs, TLS, persistence, eviction, and service telemetry

## Supporting Files

- [README.md](README.md) — purpose, layout, limitations, security notes
- [checklist.md](checklist.md) — pre-return verification, grouped by concern
- [best-practices.md](best-practices.md) — patterns with vulnerable and fixed Terraform
- [common-mistakes.md](common-mistakes.md) — what goes wrong and why the fix works
- [troubleshooting.md](troubleshooting.md) — when the control cannot be applied
- [prompts.md](prompts.md) — prompts that produce findings
- [references/provider-mapping.md](references/provider-mapping.md) — concern to service table
- [references/iam-antipatterns.md](references/iam-antipatterns.md) — policy shapes to reject
- [references/cis-benchmarks.md](references/cis-benchmarks.md) — versions and scope
- [references/owasp-cloud-mapping.md](references/owasp-cloud-mapping.md) — Top 10 and ASVS
- [references/well-architected.md](references/well-architected.md) — provider design guidance
- [examples/README.md](examples/README.md) — eight vulnerable and fixed pairs
