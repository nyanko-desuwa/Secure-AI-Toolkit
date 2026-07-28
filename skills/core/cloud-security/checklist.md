# Cloud Security Verification Checklist

Mark every item pass, fail, or not applicable with a reason. A live configuration claim needs
a live check; a Terraform-only review must say it is unverified.

## Identity and workload credentials (A01 · ASVS V8, V13 · CWE-269, CWE-798)

- [ ] Every identity has only the actions and resources its code needs; `*` is justified or removed
- [ ] No workload uses an IAM access key, GCP service-account JSON key, or Azure client secret
- [ ] EKS uses Pod Identity or IRSA, GKE uses Workload Identity Federation, and Azure uses managed identity
- [ ] Human access uses SSO/federation and short-lived sessions, not shared users
- [ ] `iam:PassRole`, `sts:AssumeRole`, GCP `iam.serviceAccounts.actAs`, and Azure role-assignment writes are resource-scoped
- [ ] Cross-account or cross-tenant trust pins the principal and uses external ID, source conditions, audience, or tenant checks
- [ ] Permission boundaries, SCPs, Azure Policy, or GCP organisation constraints limit delegated administration
- [ ] Access keys, service-account keys, and app secrets have age alerts and a tested rotation path

## Object storage (A01, A02, A04 · ASVS V13, V14 · CWE-732, CWE-311)

- [ ] S3 Block Public Access, Azure public blob access prevention, or GCP public access prevention is enabled
- [ ] Legacy ACLs are disabled where possible: S3 Bucket Owner Enforced and GCS uniform bucket-level access
- [ ] No bucket, container, or object policy grants anonymous read or write unless explicitly documented
- [ ] Presigned URLs or SAS tokens use the narrowest object, method, and expiry; they are not permanent download links
- [ ] Default encryption is enabled; customer-managed keys are used when ownership, separation, or audit requires it
- [ ] Versioning and a recovery path are enabled; immutable retention is used for ransomware recovery where required
- [ ] Data-plane access logging is enabled for sensitive storage and sent to a separate protected destination
- [ ] Public access, policy, ACL, and encryption settings were checked live, not assumed from Terraform

## Network and exposure (A01, A02, A06 · ASVS V13 · CWE-284, CWE-668)

- [ ] Inbound rules deny by default and expose only required ports from named ranges or security groups
- [ ] NACLs, NSGs, or firewall rules are not mistaken for application authorization
- [ ] Egress is restricted to required destinations or an egress proxy; default-open egress is reviewed
- [ ] Databases, metadata endpoints, control planes, and administrative ports have no public path
- [ ] Private endpoints are used for provider services where feasible and their endpoint policies are scoped
- [ ] VPC/VNet/VPC-network segmentation is documented; a VPC is not treated as a complete boundary
- [ ] Flow logs are enabled and sent to a destination the workload cannot alter
- [ ] WAF rules are present where useful, but the underlying validation and authorization fix still exists

## Metadata and SSRF (A01, A02, A06 · ASVS V2, V13 · CWE-918)

- [ ] AWS instances require IMDSv2 and use a hop limit appropriate to the workload
- [ ] IMDSv1 is disabled, or an explicit compatibility exception has an owner and removal date
- [ ] Azure and GCP application SSRF controls account for required metadata headers
- [ ] User-controlled URLs use scheme/host allowlists, private-range rejection, timeouts, and redirect controls
- [ ] Egress controls prevent application paths from reaching metadata and control-plane endpoints
- [ ] DNS rebinding and connection-time-of-check/time-of-use gaps are acknowledged or handled by an egress proxy

## Encryption and transport (A04 · ASVS V11, V12, V14 · CWE-311, CWE-319)

- [ ] Sensitive databases, disks, snapshots, queues, and storage use encryption at rest
- [ ] Customer-managed key use has a key policy, separation of duties, rotation, backup, and deletion recovery plan
- [ ] Envelope encryption keeps a data-encryption key separate from the key-encryption key
- [ ] Key rotation is enabled or an equivalent documented rotation process exists
- [ ] TLS is enforced for public and private service paths; certificate verification is not disabled
- [ ] TLS termination is deliberate: the boundary has access controls, logging, and re-encryption where needed
- [ ] Encryption is not treated as a substitute for identity authorization

## Logging and detection (A09, A10 · ASVS V16 · CWE-778)

- [ ] AWS CloudTrail, Azure Activity Log, and GCP Audit Logs cover all accounts/subscriptions/projects
- [ ] Organisation-wide trails or sinks include the regions and data events that matter
- [ ] Logs are encrypted, retained for the required period, and written to a separate protected destination
- [ ] CloudTrail log file validation or an equivalent integrity control is enabled
- [ ] Alerts cover root use, MFA changes, new keys, policy changes, public exposure, logging changes, and role assumption anomalies
- [ ] Detection covers new regions, unusual service-account impersonation, metadata access, and mass object deletion
- [ ] Logs contain actor, action, target, outcome, time, and source without secrets or tokens
- [ ] A failed security control denies or raises an actionable alert; it does not silently allow

## Secrets, serverless, and data lifecycle (A01, A02, A04 · ASVS V13, V14 · CWE-312, CWE-798)

- [ ] Secrets come from Secrets Manager/SSM, Key Vault, or Secret Manager, not source or Terraform literals
- [ ] Cross-account secret access is explicit, resource-scoped, and protected against confused deputy access
- [ ] Rotation is tested against consumers; cold-start caches have a bounded lifetime and refresh path
- [ ] Functions have separate execution roles per function or trust boundary, not one oversized role
- [ ] Event source policies validate the producer, account/project, source ARN, and intended event type
- [ ] Function URLs and triggers do not accidentally permit anonymous invocation
- [ ] Database public access is disabled and encryption, backups, and network ACLs are checked together

## IaC, structure, and cost (A01, A02, A08, A09 · ASVS V13, V14 · CWE-312, CWE-1188)

- [ ] Terraform state is remote, encrypted, versioned, locked, private, and access-controlled
- [ ] Sensitive outputs and variables are marked sensitive; state exposure is still assumed possible
- [ ] Every plan receives security review before apply; destructive and public changes are called out
- [ ] Policy-as-code runs on plan JSON using OPA/Conftest, Sentinel, Azure Policy, or GCP Policy Validator
- [ ] Drift detection runs and unexplained live changes are investigated
- [ ] Production, security logging, and development are separate accounts/subscriptions/projects
- [ ] SCPs, management-group policies, or organisation policies constrain the blast radius
- [ ] Budgets and cost anomaly alerts cover every isolation unit; unexpected GPU/compute spend is investigated as a possible credential compromise

## Before returning

- [ ] Relevant Terraform formatting, validation, plan, and policy checks ran; output is reported honestly
- [ ] Provider CLI checks were run where the finding depends on live state
- [ ] Every skipped item has a reason
- [ ] No sample secret, account ID, subscription ID, or project ID is real
- [ ] WAF, encryption, private endpoints, and versioning are described as controls with limits, not complete fixes
