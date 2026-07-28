# Common Mistakes

What it looks like, why it fails, the fix, and why the fix holds. These are the failures that
show up in AI-generated code and in hand-written code under deadline.

## Deleting the commit instead of rotating

```bash
git rm --cached .env && git commit -m "remove secrets"
```

The file is gone from the tip and still in history, in every clone, in every fork, in the
pull request diff, and in the CI log from the build that ran before the removal. Rewriting
history with `filter-repo` or BFG does not reach forks, mirrors, or anyone's local copy, and
GitHub keeps unreferenced objects reachable by SHA until garbage collection.

Fix: revoke the credential at the provider, then rotate. Treat the git cleanup as tidiness,
not remediation. Why it works: revocation invalidates the value everywhere at once, which is
the only operation that does not depend on tracking down copies.

## Env var treated as the finish line

```yaml
environment:
  - DATABASE_PASSWORD=hunter2-placeholder
```

Moving a secret out of source into a compose file, a systemd unit, or a Helm `values.yaml`
moves it from one file in git to another file in git. Even injected correctly at runtime, the
value is readable in `/proc/<pid>/environ`, inherited by every child process, and attached to
crash reports by several error-tracker SDKs.

Fix: fetch from a secret manager, or mount a file and read it. See
[best-practices.md](best-practices.md#environment-variables-are-a-waypoint-not-a-destination).
Why it works: a mounted file has file permissions, is not part of the inherited environment
block, and does not appear in process listings.

## Kubernetes Secret assumed to be encrypted

```bash
kubectl create secret generic db --from-literal=password=placeholder-value
```

`data` fields are base64, which is an encoding. Anyone with `get secrets` in the namespace
reads the value with one command, and by default etcd stores it unencrypted on the control
plane disk.

Fix: enable encryption at rest with a KMS provider, restrict `get`/`list` on secrets through
RBAC, and prefer an external store projected in through the Secrets Store CSI driver or an
operator so the value never becomes a long-lived Kubernetes object. Why it works: the value
is no longer at rest in etcd, and RBAC stops namespace read from being credential read.

## Secret passed as a Docker build arg

```dockerfile
ARG NPM_TOKEN
RUN echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > .npmrc \
 && npm ci \
 && rm .npmrc
```

The `rm` deletes the file in a later layer. The layer that created it is still in the image
and `docker history` shows the `ARG` value. Deleting a file never removes it from the layer
that added it.

Fix: BuildKit secret mounts. The value is present during the `RUN` and never written to a
layer.

```dockerfile
# syntax=docker/dockerfile:1
RUN --mount=type=secret,id=npmtoken \
    NPM_TOKEN="$(cat /run/secrets/npmtoken)" npm ci
```

Why it works: the mount is a tmpfs available only for that instruction, and it is excluded
from the layer's filesystem diff.

## Terraform state left unmanaged

```hcl
resource "aws_db_instance" "orders" {
  password = var.db_password
}
```

Every secret Terraform touches is stored in plaintext in state, regardless of `sensitive =
true`. That flag only suppresses console output. A state file in a repository or an
unencrypted bucket is a credential dump with a `.tfstate` extension.

Fix: remote backend with encryption and access control, and generate the value inside the
managed system rather than passing it in:

```hcl
resource "aws_db_instance" "orders" {
  manage_master_user_password = true    # AWS generates and rotates, value never enters state
}
```

Why it works: the credential is never a Terraform input or output, so there is nothing for
state to record.

## Logging the whole object

```python
logger.info("outbound request", extra={"headers": dict(request.headers)})
```

`Authorization` is a header. The bearer token is now in the log, replicated to whatever
aggregator receives it, retained under that system's policy, and visible to everyone with log
read — which is usually a much larger group than those with production credential access.
CWE-532.

Fix: log an allowlist of fields, and add a redaction filter as a backstop.

```python
REDACT = {"authorization", "cookie", "x-api-key", "proxy-authorization"}

def safe_headers(headers) -> dict:
    return {k: ("[redacted]" if k.lower() in REDACT else v) for k, v in headers.items()}
```

Why it works: the default becomes exclusion. A denylist alone fails the first time someone
adds `X-Session-Token`; combining an explicit allowlist at the call site with the filter at
the pipeline means one miss is not an exposure.

## Secret compared with `==`

```python
if request.headers.get("X-Api-Key") == API_KEY:
```

`==` returns at the first differing byte. Given enough requests, an attacker recovers the key
one byte at a time from response timing. It also crashes or silently mis-compares when one
side is `None`.

Fix: `hmac.compare_digest`. Why it works: the comparison time does not depend on where the
values diverge, so the response carries no information about the correct prefix.

## Secret manager wrapped in a per-request call with no cache

```python
def handler(event, context):
    password = get_secret_value(SecretId="prod/db")   # every invocation
```

A network round trip on every request adds latency, costs per call, and hits the provider's
rate limit under load. The usual reaction is to move the call to module scope with no expiry,
which then means the process keeps using a credential that rotation has already retired.

Fix: cache with a TTL shorter than the rotation interval, and treat an authentication failure
as a signal to refetch rather than to widen the TTL. Why it works: the TTL bounds how long a
retired credential can be in use, and the retry-on-auth-failure path handles the window
between rotation and expiry.

## Rotation designed as a swap

Change the password in the manager, restart the service. Between those two events every
replica is using a credential that no longer exists. If the restart fails, the outage is
total and the rollback is a second rotation.

Fix: two credentials, an overlap window, and a verifier that accepts both. For databases,
alternate between two users rather than resetting one password. Why it works: producer and
consumer move independently, so no instant exists where a valid configuration is impossible.

## Long-lived cloud access key where a role would do

```python
session = boto3.Session(
    aws_access_key_id="AKIAEXAMPLEPLACEHOLDER",
    aws_secret_access_key="placeholder-not-a-real-key",
)
```

A static key never expires, so it must be stored, delivered, rotated, and revoked — four
processes that all have to work. It also survives leaving the environment it was created for.

Fix: attach a role. IRSA on EKS, an instance profile on EC2, workload identity on GKE, managed
identity on Azure. `boto3.Session()` with no arguments picks up the projected token. Why it
works: credentials are minted per-session with a short expiry and never exist at rest, so
there is nothing to leak and nothing to rotate.

## Secret sent to a model or a tool call

```python
prompt = f"Debug this request:\n{json.dumps(request_body)}"   # body carries an api_key field
```

The value leaves your trust boundary, may be retained by the provider, and can surface in a
later completion or a trace UI. The same applies to tool arguments in an agent loop, where the
full argument object is usually logged verbatim.

Fix: redact before the prompt is built, and pass a reference instead of a value — a secret
name or a handle the tool resolves server-side. Why it works: the model never receives
material it could echo, and the resolution happens inside a boundary you control.

## CI variable not marked secret, or exposed to forks

An unmasked pipeline variable appears in job output the first time someone runs `env` or a
verbose curl. Worse, a workflow triggered by `pull_request_target` on a fork's branch runs with
access to repository secrets while executing code the fork author controls.

Fix: mark variables as secret/masked, scope them to protected branches and environments, use
`pull_request` rather than `pull_request_target` for untrusted contributions, and prefer OIDC
federation so there is no stored value. Why it works: masking is best-effort against accidental
printing; removing the stored value removes the target entirely.

## `.gitignore` treated as the control

`.gitignore` stops accidental staging of files not yet tracked. It does nothing for a file
already tracked, nothing for `git add -f`, and nothing about history. It is a convenience.

Fix: keep it, and add a pre-commit hook plus CI scanning. Why it works: three layers with
different failure modes. The hook blocks before the write, the scan catches the bypass, and
`.gitignore` handles the everyday case.
