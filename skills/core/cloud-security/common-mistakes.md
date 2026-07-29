# Common Mistakes

What goes wrong in cloud configuration, why it goes wrong, and why the fix holds. Ordered
roughly by how often it turns up in a real account.

## A managed admin policy attached "temporarily"

```hcl
resource "aws_iam_role_policy_attachment" "temp" {
  role       = aws_iam_role.deploy.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
```

It goes in because the deploy failed with an access-denied error and nobody wanted to read the
error to find the missing action. It stays because nothing breaks afterwards.

Fix: read the denied action out of CloudTrail and grant that action on that resource. Run the
deploy again and repeat. Two or three iterations produce a policy that is both minimal and
documented by the errors that shaped it.

Why the fix works: the policy now describes what the code does, so the next reviewer can tell
whether a new grant is legitimate. `AdministratorAccess` carries no information.

The same mistake on Azure is `Contributor` at subscription scope, and on GCP it is
`roles/editor` at project level. Both are handed out by tutorials.

## `Resource: "*"` because the ARN was not known yet

Written during development when the bucket name was still changing, then never narrowed. A
per-tenant role with `Resource: "*"` reads every tenant, and the code will never notice because
it only ever asks for its own prefix.

Fix: interpolate the resource from the Terraform reference rather than hardcoding or
wildcarding. `resources = ["${aws_s3_bucket.data.arn}/tenant/${var.tenant_id}/*"]` cannot drift
from the bucket it refers to.

Some APIs genuinely require `Resource: "*"` - `cloudwatch:PutMetricData`, `ec2:DescribeInstances`,
most list operations. Constrain those with a condition key instead and leave a comment saying
which API forced it.

## Blocking public access while leaving the public policy in place

```hcl
resource "aws_s3_bucket_public_access_block" "data" {
  bucket              = aws_s3_bucket.data.id
  block_public_policy = true
  # ... but the aws_s3_bucket_policy with Principal "*" is still in the module
}
```

Two problems. The apply order can leave a window where the policy exists and the block does
not, and the next engineer who needs a legitimate cross-account grant will turn the block off
rather than untangle the policy.

Fix: delete the public statement. Then set the block as a backstop against the next accident.

Why the fix works: the block is a guardrail, not a control. A guardrail that is the only thing
standing between a bucket and the internet will eventually be removed by someone who has a
reason.

## Treating a presigned URL as an authenticated request

```python
url = s3.generate_presigned_url(
    "get_object",
    Params={"Bucket": "example-private-data", "Key": key},
    ExpiresIn=604800,   # seven days
)
```

The URL is a bearer capability. Seven days in a browser history, a referrer header, a CDN log,
or a shared Slack message is seven days of access with no identity attached and no way to
revoke short of deleting the object.

Fix: minutes, not days. One object, one method. Generate on demand behind an endpoint that
performs the ownership check, so the authorization decision happens at request time.

Why the fix works: the capability's lifetime is short enough that leaking it after use is
uninteresting, and the ownership check is enforced by your code rather than by the URL's
existence.

Signing with a role that can read the whole bucket does not widen the URL - the URL is scoped
to its key. But it does mean a bug in key construction can sign a URL for someone else's
object, so validate the key against the actor before signing.

## Assuming the VPC makes it private

An RDS instance in a private subnet with `publicly_accessible = true` gets a public DNS name and
a public IP. The subnet's route table does not undo that. Similarly, an S3 bucket, a Key Vault,
or a Cloud SQL instance reached from inside a VPC is still reachable from outside it unless the
resource-level policy or firewall says otherwise.

Fix: check the resource's own exposure setting and its resource-based policy, not just where it
sits on the network diagram. Use private endpoints so the traffic path and the identity path
agree.

Why the fix works: managed services are multi-tenant control planes with their own front doors.
Network placement describes one path in; it does not close the others.

## Egress left open because closing it broke a build

Default-open egress is the exfiltration path. It is also how a compromised container reaches a
crypto-mining pool, a C2 host, and `raw.githubusercontent.com` for the next stage.

The reason it stays open is that the first attempt to close it broke `apt-get`, `npm install`, or
an SDK call to a regional endpoint nobody had inventoried.

Fix: route egress through a proxy or NAT with an allowlist, log the denies, and use the deny log
to build the allowlist. Do this in staging where breakage is cheap.

Why the fix works: you end up with an inventory of every external dependency the workload has,
which is useful well beyond this control.

## IMDSv1 left optional because "nothing uses v1"

```hcl
metadata_options {
  http_tokens = "optional"   # backwards compatible
}
```

`optional` means v1 still answers. An SSRF that only controls a URL - no headers, no method -
reads the instance role's credentials from
`http://169.254.169.254/latest/meta-data/iam/security-credentials/`. This is the exact shape of
several well-known cloud breaches.

Fix: `http_tokens = "required"`, and set `http_put_response_hop_limit = 1` unless a container
network genuinely needs 2. Old SDKs are the usual blocker; upgrading the SDK is less work than
the incident.

Why the fix works: v2 requires a PUT to obtain a token and a custom header to use it. A
URL-only SSRF can do neither.

Do not treat this as a substitute for fixing the SSRF. The metadata service is one target among
many - internal admin panels and other services on the private network are still reachable.

## Secrets in Terraform variables, then in state

```hcl
variable "db_password" { type = string }

resource "aws_db_instance" "orders" {
  password = var.db_password
}
```

`sensitive = true` hides the value from CLI output. It does not remove it from the state file.
Anyone with read access to the state bucket has the password, and state is often readable by the
whole platform team.

Fix: let the provider generate and store the secret - `manage_master_user_password = true` on RDS
puts it in Secrets Manager - or create an empty secret in Terraform and populate the value out
of band. Encrypt the state backend with a customer-managed key and restrict it as production
data.

Why the fix works: the value never passes through Terraform, so no amount of state access
discloses it.

## An oversized Lambda execution role

The execution role is often the account's most over-permissioned identity, because functions
accumulate integrations and nobody removes the grants for the integration that was dropped.

Fix: one role per function, granted the actions that function calls. Review the role when the
function changes, not on a schedule.

Why the fix works: a function is the easiest thing in the account to invoke - sometimes from an
unauthenticated URL, an API Gateway route, or an S3 event that a user can trigger by uploading.
Its role is the blast radius of any bug in its handler.

Related: the event source is a trust boundary. `aws_lambda_permission` with a principal of
`s3.amazonaws.com` and no `source_account` lets any account's bucket invoke your function.

## Caching a secret for the life of the container

```python
SECRET = get_secret("db-password")   # module scope, cached until the sandbox dies
```

Cold-start caching is the right instinct - calling the secret manager on every invocation costs
latency and money. The failure is caching with no expiry, so a rotated secret is not picked up
until the execution environment is recycled, which can be hours.

Fix: cache with a TTL shorter than the rotation interval, and handle an authentication failure by
invalidating the cache and retrying once.

Why the fix works: rotation only reduces the value of a stolen secret if the old one stops being
used. A cache with no TTL quietly extends the credential's life.

## Logging enabled per account, by hand

Each new account gets CloudTrail switched on during setup, which means the account created on a
Friday does not have it. Coverage that depends on a human step is not coverage.

Fix: an organisation trail, an Azure Policy at management-group scope, or a GCP organisation-level
sink. Enable log file validation so tampering is detectable, and send the logs to an account the
workload cannot write to.

Why the fix works: new accounts inherit the trail. The attacker's first move after gaining
admin - disabling the trail - now requires access to a different account, and an SCP can deny it
outright.

## Alerting on everything, so alerting on nothing

A rule per CIS recommendation produces hundreds of alerts, all of which get muted within a month.

Fix: start with the small set that indicates compromise rather than untidiness - root account
use, CloudTrail or Activity Log disabled, IAM policy or role-assignment change, storage made
public, new region activity, unusual `AssumeRole` or service-account impersonation, mass object
deletion, cost anomaly. Add rules only when someone owns the response.

Why the fix works: an alert nobody acts on is worse than no alert, because it creates the
impression of monitoring.

## Reading the plan for correctness but not for exposure

Plan review catches "this destroys the database". It routinely misses "this adds
`0.0.0.0/0` on 3306" because the diff is one line among two hundred.

Fix: run policy-as-code against `terraform show -json tfplan` in CI so the exposure checks are
mechanical. Keep the human review for design questions the policy cannot express.

Why the fix works: humans are good at intent and bad at scanning. Conftest is the reverse.

## Ignoring the bill as a security signal

An unexpected several-hundred-dollar spike in a region you do not operate in is usually
crypto-mining on stolen credentials, and it often shows up in billing before it shows up in
detection.

Fix: a budget alert per account with an owner, an anomaly-detection subscription, and an SCP or
organisation policy restricting regions so the mining has nowhere convenient to run.

Why the fix works: region restriction removes most of the capacity an attacker wants, and the
budget alert catches what remains within hours rather than at the end of the month.
