# Troubleshooting

What to do when a control in this skill cannot be applied, or when two sources disagree.

## The least-privilege policy denies something and you cannot tell what

Do not widen the policy to find out. Read the denial.

```bash
# AWS: the denied action and the principal are both in the event
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --max-results 20

# AWS: ask what a principal can actually do, before deploying
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::111122223333:role/app \
  --action-names s3:PutObject kms:Decrypt \
  --resource-arns arn:aws:s3:::example-app-data/uploads/x

# GCP: which binding grants or fails to grant a permission
gcloud policy-troubleshoot iam //cloudresourcemanager.googleapis.com/projects/PROJECT \
  --principal-email app@PROJECT.iam.gserviceaccount.com \
  --permission storage.objects.create
```

Azure has no direct simulator. `az role assignment list --assignee <id> --all` plus the
Activity Log entry for the failed operation gets you there.

If the error is a KMS denial rather than a service denial, the gap is usually the key policy,
not the identity policy. Both must allow.

## The provider requires a wildcard resource

Some APIs are account-scoped and reject a specific ARN — `cloudwatch:PutMetricData`,
`ec2:DescribeInstances`, `logs:DescribeLogGroups`, most `List*` operations. `Resource: "*"` is
correct there.

Constrain with a condition instead, and say in a comment which API forced it:

```hcl
statement {
  # PutMetricData is account-scoped; no ARN form exists
  actions   = ["cloudwatch:PutMetricData"]
  resources = ["*"]
  condition {
    test     = "StringEquals"
    variable = "cloudwatch:namespace"
    values   = ["MyApp/Orders"]
  }
}
```

A commented, condition-constrained wildcard passes review. An uncommented one does not, because
the reviewer cannot distinguish it from laziness.

## Egress cannot be closed because the dependency list is unknown

Run it open in staging with flow logs on, collect the destinations, then close it with that list
as the allowlist. Do not close production egress from a guess — you will cause an outage and the
control will be reverted permanently.

If a dependency resolves to a rotating set of IPs (most SaaS APIs, package registries), the
allowlist has to be at the hostname layer, which means an explicit proxy or a firewall with FQDN
support rather than a security group. Say that in the design rather than pretending a CIDR list
will hold.

## An old SDK breaks under IMDSv2

Check whether the SDK is actually too old before accepting the claim. Support for IMDSv2 landed
in the AWS SDKs years ago; the usual culprit is a vendored binary, a shell script using `curl`
against the v1 path, or a pinned SDK from a container image nobody rebuilds.

Order of preference:

1. Upgrade the SDK or fix the `curl` call to fetch a token first.
2. Keep `http_tokens = "required"` and give the one broken workload its own instance without a
   role, reading what it needs from a secret store instead.
3. Leave v1 on for that instance only, with a comment, an expiry date, and an alarm on
   `MetadataNoToken` in CloudWatch.

Never resolve this by setting `optional` across a module that many instances share.

## The database must accept connections from the internet

Sometimes true — a legacy client, a partner integration, an analyst's laptop with no VPN.

Ranked alternatives, best first:

1. Private endpoint plus a client-side VPN or a bastion with session recording (SSM Session
   Manager, Azure Bastion, GCP IAP TCP forwarding). No public listener at all.
2. Public listener with TLS required, an IP allowlist that names specific addresses, IAM or
   Entra authentication instead of a password, and audit logging on.
3. Public listener with a password. State that this is the weakest option and why it was chosen.

Option 2 is not equivalent to option 1. An IP allowlist is a filter, not authentication, and
office IPs change.

## Customer-managed keys are more operational risk than the team can carry

CMEK is not free. A deleted or unavailable key means unrecoverable data, and cross-account access
needs the key policy and the identity policy to agree.

If the team cannot yet run key rotation and key access reviews, provider-managed keys with
encryption enabled are better than a CMEK nobody understands. Say which you chose and why. What
is not acceptable is unencrypted storage — that is a default nobody has to manage.

Where CMEK is worth the cost: regulated data, data shared across accounts, and anywhere you need
the ability to revoke access by disabling a key.

## Terraform reports drift that someone made deliberately

Someone fixed an incident in the console. Two failure modes: reverting the fix breaks
production, and keeping it means the code no longer describes reality.

1. Find the change: CloudTrail, Activity Log, or Cloud Audit Logs for the resource.
2. Decide whether it was correct. An emergency security-group narrowing usually was.
3. If correct, port it into the code and apply. If not, apply the code and tell the person.
4. Either way, note whether console write access should exist for that role at all.

Unexplained drift on a security-relevant field — a bucket policy, a security group, a key
policy, a role trust policy — is an incident until proven otherwise. Do not silently `terraform
apply` over it; you may be destroying evidence.

## The policy-as-code rule fires on something legitimate

Add an exception with a reason and an owner, in the code, next to the resource. Never disable the
rule globally.

```hcl
# conftest: allow-public-read
# Reason: static marketing site, no non-public objects in this bucket.
# Owner: web-platform. Reviewed: 2026-07-28.
```

A global suppression removes the control for every future resource. A local exception with a
review date is a decision.

## A CIS recommendation conflicts with how the workload has to work

CIS benchmarks are a baseline for a general account, not a specification for your workload. When
a recommendation does not fit, document the deviation: which recommendation, why it does not
apply, and what compensates for it.

Do not cite a CIS control number you have not read. The numbering changes between major versions
and a wrong number is worse than none — it sends the reader to unrelated guidance. Cite the
recommendation by its title.

## The finding is in a managed service you cannot configure

Some settings are not exposed. A managed service may not support a private endpoint in your
region, or may not allow disabling a public port.

Report it as accepted risk with the compensating controls: authentication strength, audit
logging, network filtering where available, and a detection rule for anomalous access. Then check
whether the provider has shipped support since the last time anyone looked — this changes often.

## Two providers give conflicting advice for the same concern

They usually differ in mechanism, not intent. AWS solves the confused deputy with an external ID;
Azure solves it with a tenant-ID claim check. Implement the mechanism the provider offers and
name the concern it addresses, so a reader on the other cloud can map it.

Where a provider genuinely offers less — no way to disable IMDS on Azure, no per-instance
metadata disable on GCP — say so plainly instead of inventing an equivalent setting.

## You cannot verify the deployed state from the code

Terraform describes intent. It does not prove what is running, and it says nothing about
resources created outside it.

State that limit in the report. "The code sets `block_public_acls = true`; I could not confirm
the deployed bucket matches, and there may be buckets outside this module" is honest and
actionable. Reading a repository and claiming the account is compliant is not.
