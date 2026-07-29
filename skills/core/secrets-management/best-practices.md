# Secrets Management Best Practices

Each pattern names the Top 10 2025 category, the ASVS 5.0 chapter, and a CWE where one
applies. Code is real and runnable. Every credential below is an obvious placeholder.

## Never in Source

`A04:2025` · ASVS V13 (Configuration), V14 (Data Protection) · CWE-798, CWE-259

```python
# Vulnerable: the credential is the source code
STRIPE_KEY = "sk_live_PLACEHOLDER_DO_NOT_USE"     # TODO: move to env
DB_PASSWORD = "changeme-in-prod"
```

```python
# Fixed: required at startup, absent means the process does not run
import os

def required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"missing required configuration: {name}")
    return value

STRIPE_KEY = required("STRIPE_KEY")
DB_PASSWORD = required("DB_PASSWORD")
```

Why this works: there is no value in the repository to leak, and the failure is at boot
rather than at first request. A default value is worse than no value - `os.environ.get("DB_PASSWORD", "changeme")`
means a misconfigured production deploy starts and quietly uses the placeholder.

The tempting wrong fix is to keep the constant and add the file to `.gitignore`. That does
nothing for history. Once committed, treat the value as public and rotate it.

## Environment Variables Are a Waypoint, Not a Destination

`A02:2025` · ASVS V13 · CWE-214

Env vars fix "in the repo". They do not fix "readable from outside the intended code path".
Four concrete leaks:

- Process listings. `ps eww <pid>` and `/proc/<pid>/environ` expose the whole environment to
  any process running as the same user, and to root in any container sharing the PID namespace.
- Crash dumps and core files capture the environment block verbatim.
- Child processes inherit the full environment. A shell-out to `curl` or an image converter
  now carries your database password.
- Error reporters. Sentry, Rollbar, and Bugsnag SDKs attach environment context by default in
  several languages. The secret ships to a third party with the next stack trace.

```javascript
// Vulnerable: every subprocess and the crash handler see everything
const { execFile } = require("node:child_process");
execFile("/usr/bin/convert", [input, output]);   // inherits process.env
```

```javascript
// Fixed: the child gets only what it needs
execFile("/usr/bin/convert", [input, output], {
  env: { PATH: process.env.PATH, HOME: process.env.HOME, LANG: "C.UTF-8" },
});
```

Where the runtime allows it, read the secret once at boot and unset it, so later leaks find
nothing:

```python
import os
DB_PASSWORD = os.environ.pop("DB_PASSWORD")   # removed from the inherited environment
```

This is a partial control. The value is still in process memory and still in whatever the
supervisor used to inject it. It closes the child-process and late-crash-dump paths, not the
memory-disclosure path.

Prefer a file over an env var where the platform supports it - a mounted file has
permissions, is not inherited, and does not appear in `environ`:

```python
from pathlib import Path
DB_PASSWORD = Path(os.environ["DB_PASSWORD_FILE"]).read_text().strip()
```

## Secret Managers

`A04:2025` · ASVS V13, V14 · CWE-522

The manager is not the point. The point is a credential you can revoke centrally, audit, and
issue with a short lifetime. Comparison and tradeoffs:
[references/secret-manager-comparison.md](references/secret-manager-comparison.md).

### HashiCorp Vault

Authenticate with the platform identity, not a token in a file. On Kubernetes, Vault verifies
the pod's projected service account token against the cluster's token review API.

```python
# Vault KV v2 via Kubernetes auth, with a TTL-bounded cache
import time
import hvac
from pathlib import Path

TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"

class VaultSecrets:
    def __init__(self, addr: str, role: str, mount: str = "secret", ttl: int = 300):
        self._client = hvac.Client(url=addr)
        self._role = role
        self._mount = mount
        self._ttl = ttl
        self._cache: dict[str, tuple[float, dict]] = {}
        self._login()

    def _login(self) -> None:
        jwt = Path(TOKEN_PATH).read_text()
        self._client.auth.kubernetes.login(role=self._role, jwt=jwt)

    def get(self, path: str) -> dict:
        hit = self._cache.get(path)
        if hit and hit[0] > time.monotonic():
            return hit[1]

        if not self._client.is_authenticated():
            self._login()

        resp = self._client.secrets.kv.v2.read_secret_version(
            path=path, mount_point=self._mount, raise_on_deleted_version=True
        )
        data = resp["data"]["data"]
        self._cache[path] = (time.monotonic() + self._ttl, data)
        return data
```

Vault's real advantage is dynamic secrets. The database secrets engine issues a fresh
credential per lease instead of handing out a shared password:

```bash
# The application never learns a long-lived database password
vault write database/roles/orders-ro \
    db_name=orders \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
    default_ttl=1h max_ttl=24h
```

Leases must be renewed or the credential stops working mid-flight. Handle the authentication
error by re-reading the lease, not by widening the TTL to a year.

### AWS Secrets Manager

```python
# Cache the value, not the client call. Respect staging labels for rotation.
import json
import time
import boto3
from botocore.exceptions import ClientError

_client = boto3.client("secretsmanager")
_cache: dict[str, tuple[float, dict]] = {}
TTL_SECONDS = 300

def get_secret(secret_id: str, stage: str = "AWSCURRENT") -> dict:
    key = f"{secret_id}:{stage}"
    hit = _cache.get(key)
    if hit and hit[0] > time.monotonic():
        return hit[1]

    try:
        resp = _client.get_secret_value(SecretId=secret_id, VersionStage=stage)
    except ClientError as exc:
        # Do not fall back to a hardcoded default. Fail the request.
        raise RuntimeError(f"secret unavailable: {secret_id}") from exc

    value = json.loads(resp["SecretString"])
    _cache[key] = (time.monotonic() + TTL_SECONDS, value)
    return value
```

`get_secret_value` is a network call billed per request and rate limited. Without the cache a
busy service throttles itself. With a TTL longer than the rotation interval it authenticates
with a revoked credential. Keep the TTL well under the rotation period.

### Azure Key Vault

```python
# Managed identity: no client secret anywhere in the deployment
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

credential = DefaultAzureCredential()   # managed identity in Azure, dev login locally
client = SecretClient(
    vault_url="https://kv-orders-prod.vault.azure.net/", credential=credential
)

def get_secret(name: str) -> str:
    return client.get_secret(name).value
```

`DefaultAzureCredential` walks a chain: environment variables, workload identity, managed
identity, Azure CLI. That is convenient and it is also a footgun - a stray `AZURE_CLIENT_SECRET`
in the environment silently wins over managed identity. In production, construct the specific
credential type you intend:

```python
from azure.identity import ManagedIdentityCredential
credential = ManagedIdentityCredential(client_id="<user-assigned-mi-client-id>")
```

The Azure SDK caches tokens, not secret values. Add your own TTL cache around
`get_secret` if you call it per request.

### GCP Secret Manager

```python
# Pin a version in production. "latest" changes under you.
from google.cloud import secretmanager

_client = secretmanager.SecretManagerServiceClient()

def get_secret(project: str, name: str, version: str = "latest") -> str:
    path = f"projects/{project}/secrets/{name}/versions/{version}"
    resp = _client.access_secret_version(request={"name": path})
    return resp.payload.data.decode("utf-8")
```

`latest` is right when rotation should propagate without a deploy. A pinned version number is
right when a bad rotation must not take down every replica at once. Choose deliberately; the
default is `latest` and the failure mode is a simultaneous fleet-wide outage.

## Workload Identity: Prefer a Role Over a Key

`A02:2025` · ASVS V13 · CWE-798

A static access key is a secret you must store, rotate, and revoke. A role is an identity the
platform proves on your behalf, with credentials that expire in minutes and are never written
down.

```yaml
# Vulnerable: long-lived cloud keys in a Kubernetes Secret
apiVersion: v1
kind: Secret
metadata:
  name: aws-creds
stringData:
  AWS_ACCESS_KEY_ID: AKIAEXAMPLEPLACEHOLDER
  AWS_SECRET_ACCESS_KEY: placeholder-not-a-real-secret-key
```

```yaml
# Fixed: IRSA on EKS. No key material in the cluster at all.
apiVersion: v1
kind: ServiceAccount
metadata:
  name: orders-api
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::111122223333:role/orders-api
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: orders-api
spec:
  template:
    spec:
      serviceAccountName: orders-api
      containers:
        - name: api
          image: registry.example.com/orders-api:1.4.2
          # No AWS_* env vars. The SDK finds the projected token itself.
```

The IAM role's trust policy is the actual security boundary. Scope it to one service account,
not to the whole cluster:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::111122223333:oidc-provider/oidc.eks.eu-west-1.amazonaws.com/id/EXAMPLEDOC"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "oidc.eks.eu-west-1.amazonaws.com/id/EXAMPLEDOC:sub": "system:serviceaccount:orders:orders-api",
        "oidc.eks.eu-west-1.amazonaws.com/id/EXAMPLEDOC:aud": "sts.amazonaws.com"
      }
    }
  }]
}
```

Using `StringLike` with a wildcard on `:sub`, or omitting the `:sub` condition entirely, lets
any pod in the cluster assume the role. That is the most common IRSA misconfiguration and it
converts a namespace boundary into nothing.

Equivalents:

| Platform | Mechanism | Binding |
|---|---|---|
| EKS | IRSA / EKS Pod Identity | Service account annotation plus OIDC trust policy conditioned on `:sub` |
| GKE | Workload Identity Federation for GKE | Kubernetes SA mapped to an IAM principal, `roles/iam.workloadIdentityUser` |
| AKS | Microsoft Entra Workload ID | SA annotated `azure.workload.identity/client-id`, federated credential on the identity |
| Non-cloud CI to AWS | OIDC from the CI provider | Trust policy conditioned on repository and ref, not just the issuer |

For CI, the trust condition must include the repository and the branch or environment.
Trusting the issuer alone means anyone's pipeline on that provider can assume your role.

## Rotation

`A04:2025` · ASVS V13, V14

Rotation fails as an outage when the system assumes exactly one valid secret exists. Design
for two.

### Dual-secret window on the verifier

```python
# Vulnerable: rotating the signing secret invalidates every in-flight webhook
def verify_webhook(body: bytes, signature: str) -> bool:
    expected = hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
```

```python
# Fixed: accept current and previous during the overlap window
import hmac, hashlib

def verify_webhook(body: bytes, signature: str, secrets: list[str]) -> bool:
    # secrets = [current, previous] during rotation; [current] otherwise
    for secret in secrets:
        expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected, signature):
            return True
    return False
```

Why this works: the producer can move to the new secret at its own pace while the verifier
accepts both. Rotation becomes two independent deploys instead of one synchronised cutover.
The overlap must be bounded and enforced - an overlap left open forever is just two live
secrets.

Sign with the newest, verify against the set. Never verify with a loop that has no end date.

### The four-step rotation contract

AWS Secrets Manager formalises what every rotation needs, whoever runs it:

1. `createSecret` - generate the new value, store it labelled `AWSPENDING`
2. `setSecret` - configure the upstream system to accept the new value, alongside the old
3. `testSecret` - authenticate with `AWSPENDING` and confirm it actually works
4. `finishSecret` - move `AWSCURRENT` to the new version; the old becomes `AWSPREVIOUS`

Step 3 is the one people skip, and skipping it is how rotation promotes a broken credential.
Step 2 is where the dual window comes from: for databases, that means alternating between two
users rather than resetting one password.

### Rotation on exposure

Scheduled rotation and exposure rotation are different operations. Scheduled rotation is
gradual and safe. Exposure rotation is immediate and accepts breakage. Do not run an exposure
event through the scheduled path - the overlap window that makes scheduled rotation safe keeps
the leaked credential valid.

Revoke first, then rotate. See [references/exposure-response.md](references/exposure-response.md).

## Constant-Time Comparison

`A04:2025` · ASVS V11 (Cryptography), V14 · CWE-208

`==` on secrets returns as soon as bytes differ. The timing difference is small but
measurable over many requests, and it leaks a prefix one byte at a time.

```python
# Vulnerable: early return leaks how much of the token was correct
if provided_token == stored_token:
    grant()
```

```python
# Fixed
import hmac
if hmac.compare_digest(provided_token, stored_token):
    grant()
```

Node needs equal lengths, or `timingSafeEqual` throws - which itself leaks length. Hash both
sides first so lengths always match:

```javascript
const crypto = require("node:crypto");

function secretEquals(a, b) {
  const ha = crypto.createHash("sha256").update(a, "utf8").digest();
  const hb = crypto.createHash("sha256").update(b, "utf8").digest();
  return crypto.timingSafeEqual(ha, hb);
}
```

Go: `hmac.Equal(a, b)` from `crypto/hmac`. PHP: `hash_equals($known, $user)` - argument order
matters, the known value goes first. Java: `MessageDigest.isEqual`.

Honest scope: this matters most for values an attacker can guess byte by byte with unlimited
attempts - API keys, HMAC signatures, password reset tokens. It matters less for a
high-entropy session ID behind rate limiting. Use it anyway; it costs nothing.

## Detection

`A02:2025` · ASVS V13 · CWE-798

Two layers, and neither is sufficient alone.

Pre-commit blocks the write:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.30.1        # verified against the gitleaks releases page, 2026-07-28
    hooks:
      - id: gitleaks
```

CI catches what bypassed the hook - `--no-verify`, a different clone, a web edit, a machine
without hooks installed:

```yaml
# .github/workflows/secret-scan.yml
name: secret-scan
on: [push, pull_request]
permissions:
  contents: read
jobs:
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      # SHAs verified against the GitHub tag refs API, 2026-07-28
      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8  # v5.0.0
        with:
          fetch-depth: 0        # scan history, not just the tip
      - uses: gitleaks/gitleaks-action@ff98106e4c7b2bc287b24eaf42907196329070c7  # v2.3.9
```

Why scanning alone is insufficient: CI runs after the push. By the time the job is red, the
value is in the remote repository, in every fork and mirror, in the CI log, and possibly in a
notification webhook. A red build tells you to start the exposure response, not that you are
protected. Scanners are also pattern-based - they catch `AKIA...` and `sk_live_...` reliably
and miss a bare 32-character database password entirely.

Verify the `rev`/version pin against the tool's release page before committing it; do not
carry a version forward from memory.

## Local Development Without Real Secrets

`A02:2025` · ASVS V13

The reason people paste production credentials into `.env` is that nothing else works
locally. Fix the cause.

- Commit `.env.example` with keys and empty or clearly fake values. Commit the loader, never
  the values.
- Run real dependencies locally in containers with throwaway passwords. A local Postgres with
  `POSTGRES_PASSWORD=localdev` is not a secret and does not need managing.
- Point third-party integrations at sandbox tenants with their own keys. Keep sandbox and
  production keys in separate managers or separate paths so a copy-paste cannot cross over.
- Where a real secret is unavoidable, fetch it per-session from the manager with a short TTL
  rather than storing it: `export DB_PASSWORD=$(vault kv get -field=password secret/dev/db)`.
- Make failure obvious. If `STRIPE_KEY` is missing, refuse to start with a message naming the
  variable. Do not fall back to a stub silently, or you will ship the stub.

```gitignore
.env
.env.*
!.env.example
*.pem
*.key
*.p12
*-credentials.json
```

## Sources

- <https://owasp.org/Top10/2025/>
- <https://owasp.org/www-project-application-security-verification-standard/>
- <https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html>
- <https://cwe.mitre.org/data/definitions/798.html>
