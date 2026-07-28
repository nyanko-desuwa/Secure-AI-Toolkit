# OWASP Mapping for Cloud Findings

Cloud misconfiguration findings need a category a non-specialist can read. This maps the
concerns in this skill to OWASP Top 10 2025 categories, ASVS 5.0 chapters, and a CWE where one
fits.

Verified 2026-07-28 against <https://owasp.org/Top10/2025/> and
<https://owasp.org/www-project-application-security-verification-standard/>.

## Top 10 2025 categories used here

Only four of the ten carry most cloud findings.

| Category | Cloud reading |
|---|---|
| A01 Broken Access Control | An IAM policy, bucket policy, or network rule grants more than the actor should have. Includes privilege escalation through `iam:PassRole` and role chaining |
| A02 Security Misconfiguration | Default-open settings left as shipped: public buckets, IMDSv1 optional, default VPC security group, public database endpoints, disabled public-access prevention |
| A04 Cryptographic Failures | Missing encryption at rest, provider-managed keys where a customer-managed key is required, TLS not enforced, keys never rotated |
| A09 Security Logging and Alerting Failures | No organisation trail, no log integrity validation, no detection rule for privileged API calls, logs writable by the account they audit |

Two more appear less often but matter:

| Category | Cloud reading |
|---|---|
| A06 Insecure Design | A single account holding production and development. A serverless function with one role for every path. Structure decisions that cannot be fixed by a setting |
| A08 Software or Data Integrity Failures | Unsigned or unverified IaC modules, a Terraform state file anyone can write, a container image pulled by mutable tag |

Note the 2025 numbering. Injection is A05, not A03. A03 is Software Supply Chain Failures and
A10 is Mishandling of Exceptional Conditions — both new in this edition. Guidance recalled
from the 2021 list will mis-map.

## ASVS 5.0 chapters used here

| Chapter | Cloud reading |
|---|---|
| V13 Configuration | The main one. Secrets management, dependency and platform configuration, hardening of deployed components |
| V14 Data Protection | Encryption at rest, data classification, retention, and preventing unintended data exposure |
| V12 Secure Communication | TLS configuration and enforcement, certificate validation, internal service-to-service transport |
| V11 Cryptography | Key management, algorithm choice, key rotation |
| V16 Security Logging and Error Handling | What to log, what to mask, and how failures behave |
| V8 Authorization | The access-control model itself, including least privilege for machine identities |

ASVS mapping here is at chapter level. This skill does not quote individual requirement IDs —
for formal verification, work from the official ASVS 5.0.0 CSV.

## CWE identifiers that fit cloud findings

| CWE | Title | Typical cloud finding |
|---|---|---|
| CWE-284 | Improper Access Control | Broad catch-all when nothing more specific fits |
| CWE-732 | Incorrect Permission Assignment for Critical Resource | Bucket or object readable by `*` / `allUsers` |
| CWE-269 | Improper Privilege Management | Role with `AdministratorAccess`, `Owner`, or `roles/editor` |
| CWE-266 | Incorrect Privilege Assignment | Wildcard `iam:PassRole` enabling escalation |
| CWE-918 | Server-Side Request Forgery | The application-side hole that reaches the metadata service |
| CWE-441 | Unintended Proxy or Intermediary (Confused Deputy) | Cross-account trust policy without an external ID |
| CWE-311 | Missing Encryption of Sensitive Data | Unencrypted volume, snapshot, or database |
| CWE-312 | Cleartext Storage of Sensitive Information | Secret in a Terraform variable, user data script, or Lambda environment variable |
| CWE-319 | Cleartext Transmission of Sensitive Information | TLS not enforced on a storage account or database |
| CWE-798 | Use of Hard-coded Credentials | Access key committed to a repository or baked into an image |
| CWE-1188 | Insecure Default Initialization of Resource | Public-access prevention off, IMDSv1 optional, default network in use |
| CWE-778 | Insufficient Logging | Audit trail missing, disabled, or single-region |
| CWE-117 | Improper Output Neutralization for Logs | Forged audit entries from unsanitised input |
| CWE-668 | Exposure of Resource to Wrong Sphere | Snapshot or AMI shared publicly, resource reachable from an unintended VPC |

CWE-284 is the honest answer when the finding is "this permission is too wide" and nothing
narrower applies. Do not stretch a specific CWE to fit.

## Worked mappings

| Finding | Top 10 | ASVS | CWE |
|---|---|---|---|
| S3 bucket policy allows `s3:GetObject` to `*` | A01, A02 | V13, V14 | CWE-732 |
| IAM policy with `Action: "*"` on `Resource: "*"` | A01 | V8, V13 | CWE-269 |
| Wildcard `iam:PassRole` on a CI role | A01 | V8 | CWE-266 |
| IMDSv1 optional and SSRF in the app | A01, A02 | V13 | CWE-918 |
| RDS instance publicly accessible, unencrypted | A02, A04 | V13, V14 | CWE-311 |
| Security group `0.0.0.0/0` on port 22 | A02 | V13 | CWE-284 |
| Unrestricted egress from a private subnet | A01 | V13 | CWE-668 |
| Cross-account role with no external ID | A01 | V8 | CWE-441 |
| Long-lived access key in a Kubernetes secret | A02, A04 | V13 | CWE-798 |
| CloudTrail single-region, no log validation | A09 | V16 | CWE-778 |
| Terraform state in a bucket readable by developers | A02, A04 | V13 | CWE-312 |
| Storage account allowing HTTP | A04 | V12 | CWE-319 |

## Sources

- OWASP Top 10 2025 — <https://owasp.org/Top10/2025/>
- OWASP ASVS — <https://owasp.org/www-project-application-security-verification-standard/>
- CWE list — <https://cwe.mitre.org/data/index.html>

Checked 2026-07-28.
