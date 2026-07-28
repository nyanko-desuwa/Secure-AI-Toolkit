# Prompt Examples

Prompts that produce findings rather than a recital of cloud security principles. Each names the
scope, the concern, and the output shape.

## Review Terraform before apply

```
Review the Terraform in infra/ against this skill. For each finding give the resource address,
the identity or network path that makes it reachable, the blast radius, and the fix as a diff.
Skip anything with no reachable path, or label it hardening.
```

Why it works: bounds the input to a directory, asks for the path rather than the label. "S3
bucket unencrypted" and "S3 bucket readable by anyone on the internet" are both misconfigurations
and only one of them is an incident.

## Audit one IAM policy for escalation

```
Read this IAM policy document. Can the principal holding it reach AdministratorAccess by any
combination of the actions it grants? Check iam:PassRole, policy-version writes, trust-policy
writes, and lambda:UpdateFunctionCode specifically. Show the exact sequence of API calls.
```

Asking for the call sequence is what forces the analysis. Without it you get "this policy is
overly permissive", which the author already suspected.

## Find the long-lived credentials

```
Search this repo for cloud credentials that never expire: aws_iam_access_key resources, service
account JSON keys, Azure client secrets, and any hardcoded key IDs in code or CI config. For
each, say what should replace it — instance identity, workload identity federation, or
impersonation — and what breaks in the migration.
```

The migration question matters. A finding the team cannot act on gets closed as won't-fix.

## Trace an SSRF to credentials

```
This service fetches a URL from user input at src/preview.py. Trace what an attacker reaches on
the instance it runs on: check the metadata_options block for the ASG, whether the role has
credentials worth stealing, and what those credentials can do. End with the blast radius.
```

Cross-layer prompts find the real severity. Application SSRF is medium on its own and critical
when IMDSv1 is reachable and the instance role is wide.

## Check storage exposure end to end

```
For every bucket in this project: is Block Public Access on at the account and bucket level, are
ACLs disabled, does the bucket policy allow a wildcard principal, is default encryption set, is
versioning on, and is access logging going somewhere the workload cannot write? Table of bucket
against those seven, then the fixes.
```

Naming all seven checks prevents the answer stopping at "public access is blocked" — the common
failure is a bucket policy with `"Principal": "*"` on an account where Block Public Access is on
but was scoped per-bucket and missed one.

## Review egress specifically

```
List every security group, NSG, and firewall rule in this codebase that allows outbound traffic
to 0.0.0.0/0. For each, name what the workload actually needs to reach and give the narrowed
rule or the VPC-endpoint replacement.
```

Egress is the rule people never write, so asking for inbound problems finds nothing new. This
prompt finds the exfiltration path.

## Detection rules from an audit trail

```
Given CloudTrail is enabled org-wide, write the detection rules I am missing for: root account
use, CloudTrail being disabled or its trail deleted, IAM policy changes, access key creation,
console login without MFA, and API calls from a region we do not operate in. Give me each as a
CloudWatch metric filter or an EventBridge pattern.
```

Asking for the artefact rather than the concept gets something deployable. "Monitor for
suspicious activity" is not a rule.

## Blast radius of one compromised identity

```
Assume the role at aws/roles/etl-worker.tf is compromised — the attacker has its credentials and
nothing else. What can they read, write, delete, and escalate to? Include what it can reach
cross-account. Then tell me the smallest change that most reduces that.
```

Starting from an assumed compromise produces prioritisation, because the answer naturally ranks
by what the attacker gets.

## Cost as a signal

```
Which resources in this account could an attacker create at scale with the permissions granted in
iam/, and would a budget alert catch it? Look for ec2:RunInstances, sagemaker, and any *:Create
on GPU-capable instance types with no instance-type condition.
```

## Anti-patterns

| Prompt | Problem |
|---|---|
| "Is my AWS account secure?" | No scope, no artefact. Produces the CIS table of contents |
| "Make this Terraform secure" | Invites rewriting working infrastructure. Ask for findings first |
| "Add IAM permissions until it works" | This is how `Action: "*"` gets written. Ask which API calls the code makes |
| "Is this CIS compliant?" | CIS has no pass mark for a repository. Ask about specific recommendations |
| "Apply security best practices" | Adds defensive resources instead of closing the one open path |
| "Give me the CIS control number for this" | It will be guessed. Ask for the recommendation title and verify it yourself |
