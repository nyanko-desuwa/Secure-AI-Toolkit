# CIS Benchmarks

Prescriptive account baselines, one per provider. Use them for "is this account configured
correctly", not for "is this application secure". They cover the control plane; they say
nothing about your code.

## Versions

Checked 2026-07-28 against <https://www.cisecurity.org/cis-benchmarks>.

| Benchmark | Current version |
|---|---|
| CIS Amazon Web Services Foundations | 7.0.0 |
| CIS AWS Compute Services | 2.0.0 |
| CIS AWS Database Services | 2.0.0 |
| CIS AWS Storage Services | 1.0.0 |
| CIS Microsoft Azure Foundations | 6.0.0 |
| CIS Microsoft Azure Compute Services | 2.0.0 |
| CIS Microsoft Azure Database Services | 2.0.0 |
| CIS Microsoft Azure Storage Services | 2.0.0 |
| CIS Google Cloud Platform Foundation | 5.0.0 |

CIS also publishes Kubernetes benchmarks (including EKS and GKE variants) and OS-level
benchmarks such as Google Container-Optimized OS 1.2.0. Those apply below the cloud layer;
see the `docker-security` skill for the container side.

## How to cite one

Do not quote a control number from memory. Section numbering changes between major versions —
a control that was 2.1.5 in one edition is renumbered in the next, and citing the wrong number
makes the whole finding suspect.

Cite by section title and benchmark version:

> CIS AWS Foundations Benchmark v7.0.0, the S3 section: ensure S3 buckets block public access
> at the bucket level.

If a project needs exact numbering for an audit, download the PDF from CIS (free with
registration) and quote from it. The benchmark text is the authority, not this file.

## What each Foundations benchmark covers

The section structure is stable across editions even when numbering is not. Expect these
areas:

| Area | AWS | Azure | GCP |
|---|---|---|---|
| Identity | Root account use, MFA, key age, password policy | Entra ID, guest accounts, MFA, PIM | Service account keys, corporate login, admin separation |
| Logging | CloudTrail in all regions, log validation, KMS encryption, Config | Activity Log retention, diagnostic settings, log alerts | Audit log sinks, log retention, sink filters |
| Monitoring | Metric filters and alarms for privileged API calls | Activity Log alerts for policy and NSG changes | Log-based metrics and alerting policies |
| Networking | Default security group, unrestricted ports, flow logs | NSG rules from any source, Network Watcher | Default network, firewall rules from 0.0.0.0/0, flow logs |
| Storage | Public access, encryption, MFA delete | Secure transfer, public blob access, soft delete | Uniform bucket-level access, public access prevention |
| Database | Public accessibility, encryption at rest, backups | Firewall rules, TDE, auditing | Authorized networks, SSL enforcement, backups |
| Encryption | KMS rotation | Key Vault, purge protection | CMEK, KMS rotation period |

The overlap with this skill is deliberate. CIS gives you the account baseline; the rest of
this skill covers the parts CIS cannot see, such as whether a role's permissions match what
the code actually calls.

## Profile levels

Each benchmark splits recommendations into Level 1 and Level 2.

- Level 1 — expected to be safe to apply broadly, low functional impact.
- Level 2 — defence in depth for environments where security outweighs convenience. Some
  Level 2 items will break things. Read them before enabling.

State the level when you recommend an item. "CIS Level 2" is a useful signal that a change
needs a conversation rather than a merge.

## Automated assessment

CIS scoring is available through provider and third-party tooling:

- AWS Security Hub ships a CIS AWS Foundations standard. Check which benchmark version the
  standard maps to before reporting a score; Security Hub lags new CIS releases.
- Microsoft Defender for Cloud includes CIS regulatory compliance dashboards per subscription.
- GCP Security Command Center reports CIS Benchmark findings at Premium and Enterprise tiers.
- Open source: `prowler` (AWS, Azure, GCP), `scoutsuite`, `cloudsploit`, `kube-bench` for the
  Kubernetes benchmarks.

A passing score is not a secure account. Every one of these tools checks configuration state
and none of them evaluates whether a permission is wider than the workload needs.

## Limitations

- Point-in-time configuration only. A benchmark pass at 09:00 says nothing about 09:05.
- No application layer. Injection, broken authorization, and business logic flaws are entirely
  out of scope. That is what the `owasp` skill is for.
- No data classification. CIS cannot tell you a bucket that legitimately allows public read
  is serving customer records.
- Multi-account structure, workload identity design, and blast radius are architecture
  decisions the benchmark does not make for you.

## Sources

- CIS Benchmarks list — <https://www.cisecurity.org/cis-benchmarks>
- AWS benchmarks — <https://www.cisecurity.org/benchmark/amazon_web_services>
- Azure benchmarks — <https://www.cisecurity.org/benchmark/azure>
- GCP benchmarks — <https://www.cisecurity.org/benchmark/google_cloud_computing_platform>

Checked 2026-07-28.
