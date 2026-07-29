# Secret Manager Comparison

Vault, AWS Secrets Manager, Azure Key Vault, and GCP Secret Manager, compared on the things
that change a design decision. Behaviour checked against vendor documentation on 2026-07-28.
Pricing and quotas move; re-check before quoting a number to anyone.

Code for each is in [../best-practices.md](../best-practices.md#secret-managers).

## The decision, briefly

Use the manager your platform already authenticates to. The integration is the value; the
feature list is mostly the same. Vault earns a separate deployment when you need dynamic
credentials across more than one cloud, or a credential type the cloud managers do not issue.

## Side by side

| | HashiCorp Vault | AWS Secrets Manager | Azure Key Vault | GCP Secret Manager |
|---|---|---|---|---|
| You run it | Yes, unless HCP Vault | No | No | No |
| Workload auth | Kubernetes, JWT/OIDC, AWS/Azure/GCP IAM, AppRole | IAM role, IRSA, instance profile | Managed identity, workload identity | Service account, workload identity |
| Dynamic credentials | Yes - databases, cloud IAM, SSH, PKI | Only via a rotation function you write or a supported managed rotation | No | No |
| Built-in rotation | Yes, per secrets engine | Yes, Lambda-based; managed for RDS and some AWS services | No - bring your own automation | No - bring your own automation |
| Versioning | KV v2 keeps versions | Version IDs plus staging labels | Versioned secrets | Versioned, addressed by number or `latest` |
| Rotation labels | Lease, renew, revoke | `AWSCURRENT`, `AWSPENDING`, `AWSPREVIOUS` | Enabled/disabled per version | Enabled/disabled/destroyed per version |
| Encryption key control | Vault's own barrier, or auto-unseal via cloud KMS | KMS key, customer-managed available | Software or HSM-backed, managed HSM tier | Google-managed or CMEK |
| Audit | Audit devices, request-level | CloudTrail | Azure Monitor diagnostic logs | Cloud Audit Logs |
| Also stores keys/certs | Yes - PKI, transit, SSH engines | Secrets only; KMS is separate | Yes - keys, secrets, certificates in one service | Secrets only; Cloud KMS is separate |

## What actually differs in practice

Dynamic secrets are Vault's distinguishing feature. The database secrets engine creates a
per-lease database user and drops it at expiry, so no shared password exists to rotate. The
cloud managers store a value you rotate; Vault can issue a value nobody stores. That changes the
threat model, not just the workflow.

Rotation automation is AWS's distinguishing feature. Managed rotation for RDS, Redshift, and
DocumentDB is real and works with the alternating-user strategy. Azure and GCP give you
versioning and expect you to drive rotation yourself with a function or a pipeline. Do not read
"supports rotation" in an Azure or GCP feature list as "rotates for you".

Certificates matter more than they look. Key Vault handling keys, secrets, and certificates in
one service is genuinely simpler than pairing Secrets Manager with KMS and ACM. If your estate
is Azure and you need certificate lifecycle, that is a real reason to prefer it.

## Version pinning: `latest` versus a number

This is the design decision people make by accident.

| | `latest` / `AWSCURRENT` | Pinned version |
|---|---|---|
| Rotation propagates | Without a deploy | Needs a deploy |
| Bad rotation blast radius | Whole fleet, at once, as caches expire | Bounded to whatever you deploy next |
| Rollback | Rotate again | Change the pin |

`latest` is right for a credential your rotation automation tests before promoting. A pin is
right when a bad value must not reach every replica simultaneously. Pick one on purpose and say
which in a comment - the default is `latest` and the failure mode is a fleet-wide outage from a
single bad rotation.

## Caching and TTL

Every manager charges per API call and rate limits. Every one of them also means an unavailable
manager becomes an unavailable application if you read per request with no cache.

Rules that hold regardless of vendor:

- Cache in memory. Never to disk, never to a temp file, never to a shared cache other workloads
  can read.
- TTL shorter than the rotation interval. A TTL of one hour against hourly rotation guarantees a
  window where the process holds a retired credential.
- Treat an authentication failure as a signal to invalidate the cache and refetch once, then
  fail. That handles the window between rotation and TTL expiry without turning into a retry
  storm.
- Do not extend the TTL to fix a throttling problem. Fix the call pattern.
- Fetch failure fails the request. No fallback to a hardcoded default, no serving a value past
  its TTL indefinitely.

AWS publishes language-specific caching clients (Java, Python, .NET, Go) that implement this;
using one is preferable to hand-rolling the cache if you are on AWS.

## Sidecar and CSI alternatives

Application-level SDK calls are not the only delivery path.

| Approach | Value arrives as | Tradeoff |
|---|---|---|
| SDK call in the app | In-process memory | Most control, most code, per-language |
| Vault Agent / injector sidecar | Rendered file or templated config | No app code changes; the file is on a shared volume |
| Secrets Store CSI driver | Mounted tmpfs file | No Kubernetes Secret object; needs the driver installed |
| External Secrets Operator | A synced Kubernetes Secret | Simple, but recreates the base64-not-encrypted problem |

Note the last row. Syncing an external secret into a Kubernetes Secret is convenient and puts
the value back in etcd. That is acceptable with encryption at rest and tight RBAC, and it is not
equivalent to the CSI driver's tmpfs mount. Say which one a design uses.

## Things that are true of all four

- The bootstrap identity is the real boundary. A perfect manager reached with a static key stored
  in a Kubernetes Secret has moved the problem, not solved it.
- Read scope is where over-permissioning hides. `secretsmanager:GetSecretValue` on `*`, a Vault
  policy on `secret/*`, or Key Vault "Secrets User" at subscription scope all mean one compromised
  workload reads everything.
- Audit logs are off, sampled, or unread by default in most deployments. A manager whose access
  log nobody looks at gives you revocation, not detection.
- The value still lands in process memory, and can still be logged by the application that
  fetched it. The manager does not fix CWE-532.

## Sources

- Vault documentation - <https://developer.hashicorp.com/vault/docs>
- Vault database secrets engine - <https://developer.hashicorp.com/vault/docs/secrets/databases>
- AWS Secrets Manager user guide - <https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html>
- AWS Secrets Manager rotation - <https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html>
- Azure Key Vault documentation - <https://learn.microsoft.com/en-us/azure/key-vault/>
- GCP Secret Manager documentation - <https://cloud.google.com/secret-manager/docs>
- Secrets Store CSI Driver - <https://secrets-store-csi-driver.sigs.k8s.io/>
- OWASP Secrets Management Cheat Sheet - <https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html>
