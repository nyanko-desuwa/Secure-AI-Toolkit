# IAM Anti-Patterns

Policy shapes to reject in review, with the reason and the replacement. Every entry maps to
`A01:2025` (Broken Access Control) and ASVS V13 (Configuration). Checked 2026-07-28 against
the AWS IAM, Azure RBAC, and GCP IAM documentation linked at the bottom.

## The two wildcards

A policy statement has an action side and a resource side. `*` on either is a finding, and
they fail differently.

| Shape | What it means | Why it is worse than it looks |
|---|---|---|
| `Action: "*"` | Every API in every service | Includes `iam:*`, so the principal can grant itself anything else |
| `Action: "s3:*"` | Every S3 API | Includes `s3:PutBucketPolicy` and `s3:DeleteBucket`, not just read and write |
| `Resource: "*"` | Every resource of that type in the account | A per-tenant role now reads every tenant |
| `Action: "s3:Get*"` | Looks read-only | Includes `s3:GetBucketPolicy`, which discloses your access model |
| `NotAction` | Everything except a list | Silently grows every time the provider ships a new service |

`Action: "*"` with `Resource: "*"` is account administrator regardless of what the policy is
named.

The GCP equivalents are `roles/owner`, `roles/editor`, and any `*.admin` role bound at the
project or folder level. The Azure equivalents are `Owner` and `Contributor` at subscription
scope. All three providers ship a broad default role that is convenient in a sandbox and a
breach in production.

## Wildcard `iam:PassRole`

The single most reliable privilege escalation path in AWS.

```json
{
  "Effect": "Allow",
  "Action": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
  "Resource": "*"
}
```

`iam:PassRole` decides which roles a principal may hand to a service. With `Resource: "*"`,
the holder creates a Lambda function, passes the account's most privileged role to it, invokes
it, and runs code as that role. The same works with EC2 instance profiles, CodeBuild projects,
Glue jobs, SageMaker notebooks, and ECS task definitions.

Nothing in the policy above mentions administrator access. The escalation comes from combining
two ordinary-looking grants.

Fixed:

```json
{
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": "arn:aws:iam::111122223333:role/app-lambda-exec",
  "Condition": {
    "StringEquals": { "iam:PassedToService": "lambda.amazonaws.com" }
  }
}
```

Two constraints. The role ARN is named, and `iam:PassedToService` stops the same role from
being passed to EC2 or CodeBuild where a shell is easier to get.

The GCP equivalent is `iam.serviceAccounts.actAs`. Grant it on the specific service account
resource, never at project level. `iam.serviceAccountTokenCreator` and
`iam.serviceAccountKeys.create` are the impersonation and key-minting equivalents — treat both
as privilege escalation primitives.

## Other escalation primitives worth naming

These are grants that look narrow and are not. Check for them by name.

| AWS | Effect |
|---|---|
| `iam:CreatePolicyVersion` | Rewrite an attached policy to allow everything |
| `iam:AttachUserPolicy` / `AttachRolePolicy` | Attach `AdministratorAccess` to yourself |
| `iam:UpdateAssumeRolePolicy` | Add yourself to a privileged role's trust policy |
| `iam:CreateAccessKey` on another user | Take over a more privileged identity |
| `lambda:UpdateFunctionCode` | Run code as an existing function's role |
| `ssm:SendCommand` | Run commands on instances, inheriting their instance profile |
| `sts:AssumeRole` with `Resource: "*"` | Assume every role that trusts the account |

| GCP | Effect |
|---|---|
| `iam.roles.update` | Widen a custom role already bound to you |
| `iam.serviceAccountKeys.create` | Mint a long-lived key for a privileged service account |
| `cloudfunctions.functions.update` | Run code as the function's service account |
| `deploymentmanager.deployments.create` | Deploy as the Google APIs service agent |

| Azure | Effect |
|---|---|
| `Microsoft.Authorization/roleAssignments/write` | Assign yourself Owner |
| `Microsoft.Compute/virtualMachines/runCommand/action` | Run as the VM's managed identity |
| `Microsoft.Web/sites/config/list/action` | Read app settings, which usually hold secrets |
| Automation Account contributor | Run a runbook under its identity |

A role that can grant roles is an administrator with extra steps. `User Access Administrator`
in Azure and `roles/iam.securityAdmin` in GCP both belong in this category.

## Long-lived access keys

An `aws_iam_access_key` attached to a user for a workload is a credential with no expiry,
which will end up in a `.env`, a CI variable, a container image layer, or a Slack message. The
same applies to a GCP service account JSON key and an Azure app registration client secret.

Replacements, in order of preference:

1. The platform's ambient identity — instance profile, managed identity, attached service
   account. No credential exists to leak.
2. Workload identity federation from an external OIDC issuer — GitHub Actions, GitLab,
   another cloud. The exchanged token lives minutes.
3. `sts:AssumeRole` or impersonation from an identity that itself came from step 1 or 2.
4. An access key with a documented rotation job, only where the provider offers nothing else.

If step 4 is genuinely required, say why in a comment next to the resource and set an alarm on
its age. GCP lets you block key creation entirely with the
`iam.disableServiceAccountKeyCreation` organization policy constraint; use it.

## Trust policies that trust too much

```json
{
  "Effect": "Allow",
  "Principal": { "AWS": "*" },
  "Action": "sts:AssumeRole"
}
```

Any principal in any AWS account can assume this role. This is not theoretical — it is a
one-line typo away from `"Principal": {"AWS": "arn:aws:iam::111122223333:root"}`, and account
IDs are not secrets.

Also over-broad, more subtly:

- `"Principal": {"Service": "ec2.amazonaws.com"}` with no `aws:SourceAccount` condition
- An OIDC trust for GitHub Actions whose `sub` condition ends in `:*`, which trusts every
  branch and every pull request in the repository, including a fork's PR in some workflows
- `"Principal": {"Federated": "..."}` with `token.actions.githubusercontent.com:aud` checked
  but `sub` not checked at all — that trusts every repository on GitHub

Pin the subject. For GitHub Actions, `repo:org/name:ref:refs/heads/main` or
`repo:org/name:environment:production`. For GCP workload identity federation, set both
`attribute.repository` and a subject or branch attribute in the principal set.

## The confused deputy

You grant a third-party SaaS vendor a role in your account so it can read your metrics. The
vendor's trust policy names the vendor's account. Every one of the vendor's customers has the
same arrangement.

Another customer of that vendor tells it "read the role in account 111122223333" — your
account. The vendor's code has the permission, so the request succeeds. The vendor was the
deputy; it was confused about whose behalf it acted on.

```json
{
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::VENDOR-ACCOUNT:root" },
  "Action": "sts:AssumeRole",
  "Condition": {
    "StringEquals": { "sts:ExternalId": "a-value-the-vendor-generated-for-you" }
  }
}
```

The external ID is not a secret and does not need to be. It is a correlation value: the vendor
must present the ID it associated with your account, and it cannot present yours while acting
for someone else. Generating the external ID yourself weakens it — the vendor should generate
it, because the vendor is the one who must not mix customers up.

For services rather than vendors, the AWS conditions are `aws:SourceAccount` and
`aws:SourceArn`. Azure's equivalent is validating the `tid` claim in a multi-tenant app; GCP's
is constraining `audience` and `subject` on the workload identity pool provider.

## Conditions that do nothing

```json
{ "Condition": { "StringLike": { "aws:userid": "*" } } }
```

Reviewers see a `Condition` block and stop reading. Check that the condition actually
constrains something. Common no-ops:

- A `StringLike` whose value is `*`
- `aws:SourceIp` on a request that arrives through a VPC endpoint, where the source IP is
  private and the condition never matches the intended public range
- `aws:PrincipalTag` where nothing sets the tag
- `Deny` with `NotPrincipal`, which is notoriously hard to reason about and usually does not
  do what the author expected

Write the condition, then test it with `aws iam simulate-principal-policy` or the GCP Policy
Troubleshooter. An untested condition is a comment.

## Permissions boundaries and SCPs

A boundary limits what an identity can do even if a policy grants more. An SCP limits what an
entire account can do, including its root user. They are different tools and neither is a
grant.

Use a boundary when you delegate IAM to a team: they can create roles, but nothing they create
can exceed the boundary. Without one, "let developers create their own roles" is "let
developers create administrator".

Use an SCP for statements that should be true of every principal in the account: no leaving
the organisation, no disabling CloudTrail, no using regions you do not operate in, no
deleting the security tooling's role. Region restriction is the cheapest one and shrinks the
crypto-mining surface immediately.

Azure achieves the same with management groups plus Azure Policy `deny` effects. GCP uses
organization policy constraints and IAM deny policies. All three evaluate before the grant,
which is why they hold when a policy is wrong.

## Review order

When reading a policy, check in this order. Stop at the first failure and report it.

1. Is there a `*` in `Action` or `Resource`?
2. Does it include `iam:PassRole`, `iam:*`, `sts:AssumeRole`, or a role-assignment write?
3. Who is in `Principal`, and is the subject pinned?
4. Do the conditions constrain anything, and have they been tested?
5. Is there a boundary or SCP above this, and does it hold if the policy is wrong?

## Sources

- AWS IAM policy evaluation — <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html>
- AWS PassRole — <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html>
- AWS confused deputy and external ID — <https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html>
- AWS permissions boundaries — <https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html>
- AWS SCPs — <https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html>
- GCP service account impersonation — <https://cloud.google.com/iam/docs/service-account-impersonation>
- GCP deny policies — <https://cloud.google.com/iam/docs/deny-overview>
- Azure RBAC best practices — <https://learn.microsoft.com/azure/role-based-access-control/best-practices>

Checked 2026-07-28.
