# Provider Mapping

Concern to service, across AWS, Azure, and GCP. Use this to read guidance written for one
provider on another. Verified 2026-07-28 against the provider documentation linked at the
bottom.

The mapping is by role, not by feature parity. Services in the same row solve the same
problem and differ in detail - read the provider doc before assuming a flag exists.

## Identity

| Concern | AWS | Azure | GCP |
|---|---|---|---|
| Identity service | IAM | Microsoft Entra ID | Cloud IAM |
| Human identity | IAM Identity Center (SSO) | Entra ID users and groups | Cloud Identity |
| Workload identity, generic | IAM role | Managed identity | Service account |
| Permission grant | Identity policy, resource policy | Role assignment | IAM policy binding |
| Reusable permission set | Managed policy | Role definition | Predefined or custom role |
| Upper bound on permissions | Permissions boundary, SCP | Entra PIM, Azure Policy deny | Deny policy, org policy |
| Org-wide guardrail | Service Control Policy | Management group + Azure Policy | Organization policy constraints |
| Short-lived credentials | `sts:AssumeRole` | Managed identity token endpoint | Service account impersonation |
| External federation | OIDC / SAML identity provider | Workload identity federation | Workload Identity Federation |
| Cross-tenant confused deputy control | External ID in trust policy | Multi-tenant app + tenant check | Audience and subject conditions |

## Workload identity in Kubernetes and serverless

| Concern | AWS | Azure | GCP |
|---|---|---|---|
| Kubernetes pod identity | EKS Pod Identity, or IRSA | Entra Workload ID (OIDC) | GKE Workload Identity Federation |
| VM identity | Instance profile | System- or user-assigned managed identity | Attached service account |
| Function identity | Lambda execution role | Function managed identity | Cloud Run / Functions service account |
| Container platform identity | ECS task role | Container Apps managed identity | Cloud Run service account |

Note the AWS distinction: the task role is what your code uses; the task execution role is
what the agent uses to pull the image and write logs. Conflating them hands your application
ECR and CloudWatch permissions it does not need.

## Object storage

| Concern | AWS | Azure | GCP |
|---|---|---|---|
| Service | S3 | Blob Storage | Cloud Storage |
| Container | Bucket | Storage account + container | Bucket |
| Blanket public-access block | S3 Block Public Access | `allowBlobPublicAccess = false` | Public access prevention |
| Resource policy | Bucket policy | Stored access policy + RBAC | Bucket IAM policy |
| Legacy per-object ACL | Object ACL (disable via Object Ownership) | Container public access level | Legacy ACL (disable via uniform bucket-level access) |
| Time-limited URL | Presigned URL | SAS token | Signed URL |
| Default encryption | SSE-S3, SSE-KMS, DSSE-KMS | Microsoft-managed or customer-managed key | Google-managed or CMEK |
| Version history | Versioning + MFA delete | Blob versioning + soft delete | Object versioning |
| Immutability | Object Lock | Immutable blob policy | Bucket Lock / retention policy |
| Data-plane access log | S3 server access logging, CloudTrail data events | Storage Analytics / diagnostic settings | Data access audit logs |

## Network

| Concern | AWS | Azure | GCP |
|---|---|---|---|
| Virtual network | VPC | VNet | VPC network |
| Instance-level filter | Security group (stateful) | NSG (stateful) | VPC firewall rule (stateful) |
| Subnet-level filter | Network ACL (stateless) | NSG applied to subnet | Firewall rule with target tags |
| Egress default | All allowed | AllowInternetOutbound default rule | Implied allow-egress rule |
| Private service access | VPC endpoint / PrivateLink | Private Endpoint / Service Endpoint | Private Service Connect / Private Google Access |
| Managed WAF | AWS WAF | Azure WAF on App Gateway or Front Door | Cloud Armor |
| DDoS | Shield | DDoS Protection | Cloud Armor |
| Flow logging | VPC Flow Logs | NSG flow logs | VPC Flow Logs |

## Instance metadata service

| Concern | AWS | Azure | GCP |
|---|---|---|---|
| Endpoint | `169.254.169.254` | `169.254.169.254` | `169.254.169.254` / `metadata.google.internal` |
| Anti-SSRF mechanism | IMDSv2 PUT token, `X-aws-ec2-metadata-token` | Required `Metadata: true` header | Required `Metadata-Flavor: Google` header |
| Hop limit control | `http_put_response_hop_limit` | Not configurable | Not applicable |
| Hard disable | `http_endpoint = "disabled"` | No supported disable | Not supported per instance |
| Terraform / config key | `metadata_options` block | n/a | n/a |

Azure and GCP require a non-forwardable header on every metadata request, so a plain SSRF
that only controls a URL cannot read them. AWS IMDSv1 needs no header at all, which is why
IMDSv2 exists and why leaving v1 optional is the finding.

## Keys and secrets

| Concern | AWS | Azure | GCP |
|---|---|---|---|
| Key management | KMS | Key Vault, Managed HSM | Cloud KMS |
| Customer-managed key | KMS CMK | Customer-managed key in Key Vault | CMEK |
| Automatic rotation | KMS key rotation | Key Vault auto-rotation policy | Cloud KMS rotation period |
| Secret store | Secrets Manager, SSM Parameter Store (SecureString) | Key Vault secrets | Secret Manager |
| Managed rotation | Secrets Manager rotation Lambda | Event Grid + function | Rotation schedule + topic |
| Envelope encryption | Data key from KMS, ciphertext stored with data | Key Vault key wraps DEK | KMS key wraps DEK |

## Audit and detection

| Concern | AWS | Azure | GCP |
|---|---|---|---|
| Control-plane audit log | CloudTrail management events | Azure Activity Log | Cloud Audit Logs, Admin Activity |
| Data-plane audit log | CloudTrail data events | Resource diagnostic settings | Cloud Audit Logs, Data Access |
| Org-wide trail | Organization trail | Management group diagnostic setting | Organization-level log sink |
| Log integrity | CloudTrail log file validation | Immutable storage on the archive | Bucket Lock on the sink destination |
| Threat detection | GuardDuty | Microsoft Defender for Cloud | Security Command Center |
| Posture management | Security Hub, Config | Defender for Cloud, Azure Policy | Security Command Center, Org Policy |
| Config drift | AWS Config rules | Azure Policy compliance | Config Validator / SCC posture |

## Structure and cost

| Concern | AWS | Azure | GCP |
|---|---|---|---|
| Isolation unit | Account | Subscription | Project |
| Grouping | Organizations OU | Management group | Folder |
| Landing zone tooling | Control Tower | Azure Landing Zones | Cloud Foundation Toolkit |
| Cost anomaly signal | Cost Anomaly Detection, Budgets | Cost Management alerts | Budget alerts, anomaly detection |

## Sources

- AWS IAM - <https://docs.aws.amazon.com/IAM/latest/UserGuide/>
- AWS IMDS - <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html>
- Azure managed identities - <https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/>
- Azure IMDS - <https://learn.microsoft.com/azure/virtual-machines/instance-metadata-service>
- GCP IAM - <https://cloud.google.com/iam/docs>
- GCP metadata server - <https://cloud.google.com/compute/docs/metadata/overview>

Checked 2026-07-28.
