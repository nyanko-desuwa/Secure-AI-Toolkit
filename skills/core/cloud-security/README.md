# Cloud Security Skill

## Purpose

Turn AWS, Azure, and GCP configuration into reviewable security decisions. The skill treats
identity, storage, network, metadata, encryption, logging, secrets, serverless, and
infrastructure-as-code as one system. A secure setting in one layer does not repair an open
setting in another.

## How It Works

Read `SKILL.md` first. Identify trust boundaries, grant the smallest identity, close inbound
and outbound network paths, encrypt and audit, then run `checklist.md`. Use `best-practices.md`
for Terraform patterns and `examples/README.md` for pairs. Use the provider mapping table when
translating between AWS, Azure, and GCP.

```text
SKILL.md                         workflow and severity
README.md                        purpose, scope, limitations
checklist.md                     pre-return verification
best-practices.md                concrete vulnerable/fixed patterns
common-mistakes.md               tempting fixes that fail
troubleshooting.md               conflicts and unverifiable settings
prompts.md                       review prompts and anti-patterns
references/provider-mapping.md   concern-to-provider service map
references/iam-antipatterns.md  wildcard and escalation policy shapes
references/                         benchmark and standards references
examples/README.md               eight vulnerable/fixed pairs
```

## Standards

| Standard | Version | How this skill uses it |
|---|---|---|
| OWASP Top 10 | 2025 | A01 access control, A02 misconfiguration, A04 cryptography, A06 design, A08 integrity, A09 logging |
| OWASP ASVS | 5.0.0 | V8 authorization, V11 cryptography, V12 communication, V13 configuration, V14 data protection, V16 logging |
| CIS AWS Foundations | 7.0.0 | Account baseline; cite section title and version |
| CIS Microsoft Azure Foundations | 6.0.0 | Subscription baseline; cite section title and version |
| CIS GCP Foundation | 5.0.0 | Project and organisation baseline; cite section title and version |
| Provider Well-Architected security pillars | Current guidance | Design trade-offs and shared responsibility |

Version sources and dates are in `references/cis-benchmarks.md`,
`references/owasp-cloud-mapping.md`, and `references/well-architected.md`. Do not invent CIS
control numbers: major editions renumber controls.

## Configuration

None. The skill is Markdown and has no runtime dependency. Terraform snippets require the
corresponding provider and a normal `terraform init` in the consuming project. Replace sample
account IDs, subscription IDs, project IDs, names, and CIDRs before use.

Useful checks after a plan:

```bash
terraform fmt -check -recursive
terraform validate
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
conftest test tfplan.json --policy policy/
```

Provider CLI checks should run with a read-only audit identity:

```bash
aws s3api get-public-access-block --bucket example-bucket
az storage account show --name examplestorage --query "{https:enableHttpsTrafficOnly,public:allowBlobPublicAccess}"
gcloud storage buckets describe gs://example-bucket --format="yaml(iamConfiguration,versioning,logging)"
```

## Example Usage

```text
Review the Terraform plan in tfplan.json with skills/core/cloud-security/checklist.md.
Report each finding as resource address, Top 10 2025 category, ASVS chapter, CWE, exploitation
path, fix, severity, and whether the claim was verified from the plan or needs a live check.
```

```text
Compare this EKS service account, GKE workload identity binding, and Azure managed identity.
Reject every long-lived credential and every wildcard action. Show the fixed Terraform or CLI.
```

## Limitations

- Markdown guidance is not a cloud scanner. It cannot prove a live resource is private, a key
  is rotated, or a route is reachable. Pair it with provider APIs and posture tooling.
- Terraform examples cover AWS most deeply because IAM policy and S3 examples are concise. The
  concern-to-service mapping and CLI snippets cover Azure and GCP; adapt provider syntax rather
  than assuming flags are interchangeable.
- A WAF is a compensating control. It can block common signatures and abusive request patterns,
  but it does not fix a vulnerable application, an over-broad identity, or a public bucket.
- Default encryption does not protect data from an identity that is already authorised to read
  it. Customer-managed keys add control and audit, not a replacement for least privilege.
- Private endpoints reduce exposure but do not create a security boundary by themselves. A
  compromised workload with network access and a permissive identity can still exfiltrate.
- Metadata header requirements reduce simple SSRF. They do not make an application safe from
  SSRF, and AWS IMDSv2 hop limits are a network defence rather than an input validation fix.
- Versioning is recovery material, not ransomware prevention. A principal able to delete object
  versions can still erase recovery data; use Object Lock, immutable blob policy, or retention
  locks for that threat.
- Cost anomalies are a detection signal, not proof of compromise. Legitimate load tests and
  growth also cost money; correlate spend with regions, principals, and API events.

## Security Notes

The examples deliberately contain vulnerable Terraform and CLI. Every unsafe block is labelled
`Vulnerable:`. Do not apply it. Sample secrets are placeholders, but Terraform state can still
contain secret values even when the configuration uses a secret manager. Protect remote state
with private storage, encryption, versioning, restricted access, and state locking.

Use separate AWS accounts, Azure subscriptions, or GCP projects for production, security, and
experimentation. A boundary that only exists in a variable or a naming convention is not a
blast-radius boundary.

## References

- Provider mapping - [references/provider-mapping.md](references/provider-mapping.md)
- IAM anti-patterns - [references/iam-antipatterns.md](references/iam-antipatterns.md)
- CIS benchmarks - [references/cis-benchmarks.md](references/cis-benchmarks.md)
- OWASP cloud mapping - [references/owasp-cloud-mapping.md](references/owasp-cloud-mapping.md)
- Well-Architected pillars - [references/well-architected.md](references/well-architected.md)
