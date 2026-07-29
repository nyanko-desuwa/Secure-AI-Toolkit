# Secrets Management Examples

Vulnerable code next to its fix. Each one names the Top 10 2025 category, the CWE, and the ASVS
chapter, then says why the fix closes the hole instead of just looking safer.

Every credential, key, account ID, and hostname below is an obvious placeholder. Nothing here is
formatted to pass as live key material.

## Contents

- [Hardcoded credential with a TODO](#hardcoded-credential-with-a-todo) - A04, CWE-798
- [Dockerfile baking a token into a layer](#dockerfile-baking-a-token-into-a-layer) - A02, CWE-798
- [Kubernetes Secret assumed to be encrypted](#kubernetes-secret-assumed-to-be-encrypted) - A02, CWE-522
- [Log line that leaks a bearer token](#log-line-that-leaks-a-bearer-token) - A09, CWE-532
- [API key compared with `==`](#api-key-compared-with-) - A04, CWE-208
- [Long-lived cloud key where a role would do](#long-lived-cloud-key-where-a-role-would-do) - A02, CWE-798
- [Rotation designed as a swap](#rotation-designed-as-a-swap) - A04, CWE-522
- [Secret on a CI command line](#secret-on-a-ci-command-line) - A02, CWE-214

---

## Hardcoded credential with a TODO

`A04:2025` · `CWE-798`, `CWE-259` · ASVS V13, V14

```python
# Vulnerable: the credential ships with the code
class Settings:
    STRIPE_KEY = "sk_live_PLACEHOLDER_NOT_A_REAL_KEY"   # TODO: move to env before launch
    DB_PASSWORD = os.environ.get("DB_PASSWORD", "changeme")
```

Two failures in three lines. The literal is readable by everyone with repo access, every fork,
every CI checkout, and every AI assistant that indexes the tree. The default on the second line
is worse than nothing: a production deploy with `DB_PASSWORD` unset starts successfully and
connects with `changeme`, so the misconfiguration is silent until someone else finds it.

```python
# Fixed: no value in the repo, and no default to hide a misconfiguration
import os


def required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"missing required configuration: {name}")
    return value


class Settings:
    STRIPE_KEY = required("STRIPE_KEY")
    DB_PASSWORD = required("DB_PASSWORD")
```

Why this works: the repository contains no secret to leak, and a missing value stops the process
at boot rather than at the first request that needs it. Failing loudly at startup is the control;
the environment lookup is just plumbing.

The tempting wrong fix is to keep the literal and add the file to `.gitignore`. `.gitignore` does
nothing for a file already tracked and nothing for history. Once the value has been committed,
the only remediation is revoke-then-rotate - see
[../references/exposure-response.md](../references/exposure-response.md).

---

## Dockerfile baking a token into a layer

`A02:2025` · `CWE-798`, `CWE-522` · ASVS V13

```dockerfile
# Vulnerable: three different ways to persist a secret in the image
FROM node:22-alpine

ARG NPM_TOKEN
ENV SENTRY_AUTH_TOKEN="placeholder-sentry-token"

COPY .npmrc /app/.npmrc
WORKDIR /app
COPY package*.json ./
RUN npm ci && rm -f /app/.npmrc

COPY . .
CMD ["node", "server.js"]
```

`docker history` prints the `ARG` and `ENV` values. `docker inspect` shows `SENTRY_AUTH_TOKEN` in
the image config for anyone who pulls the tag. And `rm -f /app/.npmrc` runs in a later layer, so
the layer created by `COPY .npmrc` still contains the file - extract the tarball and read it:

```bash
docker save myimage:1.0 -o img.tar   # unpack, find the layer, the .npmrc is intact
```

If `.dockerignore` is missing, `COPY . .` also drags in `.env` and the entire `.git` directory,
which carries every secret ever committed.

```dockerfile
# Fixed: BuildKit secret mounts, nothing in ARG or ENV, nothing copied
# syntax=docker/dockerfile:1.7
FROM node:22-alpine AS build

WORKDIR /app
COPY package*.json ./

RUN --mount=type=secret,id=npmrc,target=/root/.npmrc,mode=0400 \
    npm ci --omit=dev

COPY . .
RUN --mount=type=secret,id=sentry_token \
    SENTRY_AUTH_TOKEN="$(cat /run/secrets/sentry_token)" npm run build:sourcemaps

FROM node:22-alpine
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
USER node
CMD ["node", "dist/server.js"]
```

```bash
docker build \
  --secret id=npmrc,src="$HOME/.npmrc" \
  --secret id=sentry_token,env=SENTRY_AUTH_TOKEN \
  -t orders-api:1.4.2 .
```

```gitignore
# .dockerignore
.git
.env
.env.*
*.pem
*.key
node_modules
```

Why this works: a secret mount is a tmpfs visible only during that one `RUN` instruction, and it
is excluded from the layer's filesystem diff - there is no layer to extract it from and no image
metadata recording it. The multi-stage split means the build stage, where the secret was present
in memory, is not part of the published image at all.

The tempting wrong fix is `RUN ... && rm secret` in a single instruction, or `docker build
--squash`. Squashing collapses layers in the final image but the build cache still holds them,
and `--squash` does nothing about `ARG` values in metadata. Verify with `docker history --no-trunc`
and a layer extraction rather than assuming.

---

## Kubernetes Secret assumed to be encrypted

`A02:2025` · `CWE-522` · ASVS V13

```yaml
# Vulnerable: base64 is an encoding, and this manifest is in git
apiVersion: v1
kind: Secret
metadata:
  name: orders-db
  namespace: orders
type: Opaque
data:
  password: cGxhY2Vob2xkZXItcGFzc3dvcmQ=      # base64("placeholder-password")
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: orders-app
  namespace: orders
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["*"]                               # every secret in the namespace, every verb
```

`data` being base64 fools people into thinking the value is protected. It is not:

```bash
kubectl get secret orders-db -n orders -o jsonpath='{.data.password}' | base64 -d
```

Three separate problems. The manifest is committed, so the value is in git history. The wildcard
verb lets the app read every secret in the namespace, including ones belonging to other
workloads. And unless the API server was configured otherwise, etcd stores the value unencrypted
on the control plane disk, so a node backup or a disk snapshot is a credential dump.

```yaml
# Fixed: the value is never a Kubernetes object, and RBAC names one secret
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata:
  name: aws-sm
  namespace: orders
spec:
  provider:
    aws:
      service: SecretsManager
      region: eu-west-1
      auth:
        jwt:
          serviceAccountRef:
            name: orders-api          # IRSA, no stored cloud key
---
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: orders-db
  namespace: orders
spec:
  refreshInterval: 15m                # picks up rotation without a redeploy
  secretStoreRef:
    name: aws-sm
    kind: SecretStore
  target:
    name: orders-db
  data:
    - secretKey: password
      remoteRef:
        key: prod/orders/db
        property: password
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: orders-app
  namespace: orders
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["orders-db"]      # one secret, named
    verbs: ["get"]
```

Also required, and not visible in any manifest - encryption at rest on the API server:

```yaml
# EncryptionConfiguration on the control plane
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources: ["secrets"]
    providers:
      - kms:
          apiVersion: v2
          name: cluster-kms
          endpoint: unix:///var/run/kmsplugin/socket.sock
      - identity: {}        # last, so existing plaintext values can still be read and rewritten
```

Why this works: git holds a pointer, not a value. RBAC scoped by `resourceNames` means a
compromised pod cannot enumerate its neighbours' credentials. Encryption at rest removes the disk
snapshot path. `refreshInterval` means rotation in the upstream manager propagates without a
deploy.

Worth being honest about: with external-secrets the value still materialises as a Kubernetes
Secret, so RBAC and encryption at rest still matter. The Secrets Store CSI driver goes further by
projecting into the pod's filesystem without creating the object - at the cost of a
`volumeMount` and no `envFrom`. If manifests must carry values, SOPS or sealed-secrets encrypt
them for git, which solves the repository problem and not the etcd or RBAC problems.

---

## Log line that leaks a bearer token

`A09:2025` · `CWE-532` · ASVS V16, V14

```python
# Vulnerable: the middleware logs the whole request
@app.middleware("http")
async def log_requests(request: Request, call_next):
    logger.info(
        "request",
        extra={
            "url": str(request.url),          # ?api_key=... lives here
            "headers": dict(request.headers),  # Authorization lives here
        },
    )
    return await call_next(request)
```

What lands in the log:

```text
2026-07-28T09:14:02Z INFO request url=https://api.example.com/v1/sync?api_key=PLACEHOLDER_KEY_123
  headers={'authorization': 'Bearer PLACEHOLDER.TOKEN.VALUE', 'cookie': 'session=placeholder'}
```

That token now sits wherever logs ship: a third-party aggregator, an APM trace, a long-retention
S3 bucket. Log read is granted far more liberally than production credential access, so this
usually widens the audience from a handful of engineers to everyone with dashboard access. It is
also a compliance problem the moment retention exceeds the token's lifetime.

```python
# Fixed: allowlist the fields, redact the rest, strip the query string
REDACTED = "[redacted]"
SAFE_HEADERS = ("content-type", "content-length", "user-agent", "x-request-id")
SENSITIVE_QUERY = {"api_key", "token", "access_token", "code", "signature"}


def safe_url(url) -> str:
    params = [
        (k, REDACTED if k.lower() in SENSITIVE_QUERY else v)
        for k, v in url.query_params.multi_items()
    ]
    return str(url.replace_query_params(**dict(params)))


@app.middleware("http")
async def log_requests(request: Request, call_next):
    logger.info(
        "request",
        extra={
            "method": request.method,
            "path": request.url.path,
            "url": safe_url(request.url),
            "headers": {k: v for k, v in request.headers.items() if k.lower() in SAFE_HEADERS},
            "actor": getattr(request.state, "user_id", None),
        },
    )
    return await call_next(request)
```

A backstop filter on the logger catches what the call site misses:

```python
import re

TOKEN_PATTERN = re.compile(
    r"(?i)\b(bearer\s+[\w\-.=]+|sk_(?:live|test)_[\w]+|eyJ[\w\-]+\.[\w\-]+\.[\w\-]+)"
)


class RedactFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = TOKEN_PATTERN.sub(REDACTED, record.msg)
        return True
```

Why this works: the header allowlist means a new sensitive header - `X-Session-Token` next
sprint - is excluded by default rather than needing to be added to a denylist. Redaction happens
before the log call, so the value never enters the pipeline and cannot be recovered from a buffer
or a sink that ignores your filter.

The tempting wrong fix is the regex alone. It is a backstop, not the control: it only catches
shapes you predicted, it cannot recognise a bare 32-character database password, and it runs
after the string has already been assembled. Two layers because they fail differently.

One more path people miss: exception handlers.
`logger.exception("auth failed", extra={"args": locals()})` re-leaks everything the allowlist
just excluded.

---

## API key compared with `==`

`A04:2025` · `CWE-208` · ASVS V11, V14

```python
# Vulnerable: early return leaks how much of the key was correct
def authorize(request) -> bool:
    provided = request.headers.get("X-Api-Key")
    return provided == settings.API_KEY
```

`==` returns at the first differing byte. Response time grows with the length of the correct
prefix, so with enough samples an attacker recovers the key one byte at a time. On this endpoint
there is no rate limit to make that expensive. It also fails oddly when the header is absent:
`None == str` is `False`, which is right by accident, and `secrets.compare_digest(None, s)`
raises - so handle the missing case explicitly.

```python
# Fixed: constant-time comparison, explicit missing-header path
import hmac


def authorize(request) -> bool:
    provided = request.headers.get("X-Api-Key")
    if not provided:
        return False
    return hmac.compare_digest(provided.encode(), settings.API_KEY.encode())
```

Node's `timingSafeEqual` throws when lengths differ, which leaks length by itself. Hash both
sides so they always match:

```javascript
const crypto = require("node:crypto");

function secretEquals(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const ha = crypto.createHash("sha256").update(a, "utf8").digest();
  const hb = crypto.createHash("sha256").update(b, "utf8").digest();
  return crypto.timingSafeEqual(ha, hb);
}
```

Why this works: comparison time no longer depends on where the two values diverge, so the
response carries no information about the correct prefix. Hashing first equalises length, which
is why the Node version does not leak what `timingSafeEqual` alone would.

Honest severity: on its own this is low. The attack needs many samples over a low-noise path. It
matters when the compared value is guessable byte by byte with unlimited attempts. Report it as a
defence-in-depth gap unless you can show the sampling is practical - and fix it anyway, because
it costs one function call.

Equivalents: Go `hmac.Equal`, PHP `hash_equals($known, $user)` with the known value first, Java
`MessageDigest.isEqual`.

---

## Long-lived cloud key where a role would do

`A02:2025` · `CWE-798` · ASVS V13

```python
# Vulnerable: a static key that must be stored, delivered, rotated, and revoked
import boto3

session = boto3.Session(
    aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
    aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
)
s3 = session.client("s3")
```

```yaml
# Vulnerable: and here is where the key lives
apiVersion: v1
kind: Secret
metadata:
  name: aws-creds
  namespace: orders
stringData:
  AWS_ACCESS_KEY_ID: AKIAEXAMPLEPLACEHOLDER
  AWS_SECRET_ACCESS_KEY: placeholder-not-a-real-secret-access-key
```

A static key never expires. It works from anywhere, so it keeps working after it leaves the
cluster in a log, a laptop, or a screenshot. Four separate processes - storage, delivery,
rotation, revocation - all have to work, and rotation usually has not been tested.

```python
# Fixed: no credentials in code. The SDK finds the projected token.
import boto3

s3 = boto3.client("s3")
```

```yaml
# Fixed: IRSA. No key material anywhere in the cluster.
apiVersion: v1
kind: ServiceAccount
metadata:
  name: orders-api
  namespace: orders
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::111122223333:role/orders-api
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: orders-api
  namespace: orders
spec:
  template:
    spec:
      serviceAccountName: orders-api
      containers:
        - name: api
          image: registry.example.com/orders-api:1.4.2
          # no AWS_* environment variables at all
```

The trust policy is the actual boundary:

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

Why this works: credentials are minted per session with a short expiry and never exist at rest.
There is nothing to store, nothing to rotate, and nothing a leaked file can contain.

The failure mode to watch for is the trust policy. `StringLike` with `system:serviceaccount:*:*`
on `:sub`, or omitting `:sub` entirely, lets any pod in the cluster assume the role - which turns
a namespace boundary into nothing and is the most common IRSA misconfiguration. Condition on
`:aud` as well; without it the policy accepts tokens minted for other audiences.

Same shape elsewhere: Workload Identity Federation on GKE, Microsoft Entra Workload ID on AKS,
instance profiles on EC2, and OIDC federation from a CI provider. For CI, condition on the
repository and the branch or environment - trusting the issuer alone means anyone's pipeline on
that provider can assume your role.

---

## Rotation designed as a swap

`A04:2025` · `CWE-522` · ASVS V13, V14

```python
# Vulnerable: exactly one secret can be valid at any instant
WEBHOOK_SECRET = os.environ["WEBHOOK_SECRET"]


def verify(body: bytes, signature: str) -> bool:
    expected = hmac.new(WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
```

Rotating means changing the value in two systems at once. Between the two changes every request
fails: the sender is signing with the new secret and the verifier still holds the old one. If the
deploy is slow or partial, some replicas hold each. The rollback is a second rotation. In
practice teams discover this mid-incident and decide not to rotate at all, which is how a
five-year-old webhook secret happens.

```python
# Fixed: verify against a set, sign with the newest, bound the overlap
import hashlib
import hmac
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class SigningSecret:
    value: str
    not_after: float | None = None       # epoch seconds; None means current


def active(secrets: list[SigningSecret], now: float | None = None) -> list[SigningSecret]:
    now = time.time() if now is None else now
    return [s for s in secrets if s.not_after is None or s.not_after > now]


def verify(body: bytes, signature: str, secrets: list[SigningSecret]) -> bool:
    matched = False
    for secret in active(secrets):
        expected = hmac.new(secret.value.encode(), body, hashlib.sha256).hexdigest()
        # no early break: keep the work constant across candidates
        matched |= hmac.compare_digest(expected, signature)
    return matched


def sign(body: bytes, secrets: list[SigningSecret]) -> str:
    current = next(s for s in secrets if s.not_after is None)
    return hmac.new(current.value.encode(), body, hashlib.sha256).hexdigest()
```

Rotation becomes four ordered steps, each independently deployable:

1. Add the new secret as current, keep the old with `not_after = now + 24h`. Verifier accepts both.
2. Authenticate with the new value and confirm it works - before anything depends on it only.
3. Move senders to the new secret.
4. Let `not_after` pass. The old secret stops being accepted with no deploy.

Why this works: no instant exists where a valid configuration is impossible, so rotation is a
sequence of safe changes rather than a synchronised cutover. Step 2 is the one people skip, and
skipping it is how rotation promotes a credential that was never tested.

Two things to keep honest. The overlap must expire on its own - an overlap window enforced only
by a calendar reminder is just two live secrets. And this is the scheduled path: an exposure
event must not run through it, because the overlap keeps the leaked value working. Revoke first,
then rotate. See [../references/exposure-response.md](../references/exposure-response.md).

For database credentials the same idea is two users alternating (`app_a`, `app_b`) rather than one
password being reset, because a password reset has no overlap window by construction.

---

## Secret on a CI command line

`A02:2025` · `CWE-214`, `CWE-798` · ASVS V13

```yaml
# Vulnerable: a plaintext value in the workflow, and a secret in argv
name: deploy
on:
  pull_request_target:            # runs fork code with access to repository secrets
    types: [opened, synchronize]

env:
  DEPLOY_TOKEN: "placeholder-deploy-token-in-plaintext"

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main         # mutable ref
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci && npm run build
      - run: ./deploy.sh --token="$DEPLOY_TOKEN" --verbose
      - run: aws s3 sync dist/ s3://example-assets/
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
```

Four independent failures. The literal in `env:` is in git, and because it was never a
repository secret it gets no masking - it prints in full the first time a step runs `env` or
fails with a verbose stack. `--token=...` on the command line is visible in the process table to
anything else on the runner and lands in the step log; `--verbose` makes that near-certain.
`pull_request_target` runs code from the fork's branch with access to secrets, so a pull request
can print them. And `actions/checkout@main` is a mutable ref: whoever controls that branch
controls what runs next to your credentials.

```yaml
# Fixed: OIDC instead of stored keys, no secret in argv, actions pinned
name: deploy
on:
  push:
    branches: [main]

permissions:
  contents: read
  id-token: write               # required for OIDC, and nothing more

jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production      # required reviewers, environment-scoped secrets
    steps:
      # SHAs verified against the GitHub tag refs API, 2026-07-28
      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8  # v5.0.0
      - uses: aws-actions/configure-aws-credentials@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
        with:
          role-to-assume: arn:aws:iam::111122223333:role/gha-deploy-orders
          aws-region: eu-west-1
      - run: npm ci && npm run build
      - name: Deploy
        env:
          DEPLOY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}   # read from env, never in argv
        run: ./deploy.sh
      - run: aws s3 sync dist/ s3://example-assets/
```

The IAM trust policy scopes to the repository and the ref, not just the provider:

```json
{
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub": "repo:example-org/orders-api:ref:refs/heads/main"
    }
  }
}
```

Why this works: the AWS credentials no longer exist - the job exchanges a short-lived OIDC token
for session credentials that expire in minutes, so there is nothing to steal from the repository
settings and nothing to rotate. `DEPLOY_TOKEN` reaches the script through the environment instead
of `argv`, so it is not in the process table or the command echo. `permissions:` caps what a
compromised step can reach with the workflow token. Pinning by SHA means a tag being moved does
not change what executes.

The tempting wrong fix is relying on masking. Masking is best-effort string replacement on stdout:
it misses the value once it is base64-encoded, split across lines, or written to an artifact, and
it does nothing about a process listing. Treat it as a safety net, not a control.

If a fork-triggered workflow genuinely needs to run, use `pull_request` (no secret access) and
split any privileged step into a separate `workflow_run` job that does not check out fork code.

---

## Sources

- <https://owasp.org/Top10/2025/>
- <https://owasp.org/www-project-application-security-verification-standard/>
- <https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html>
- <https://cwe.mitre.org/data/definitions/798.html>
- <https://cwe.mitre.org/data/definitions/532.html>
- <https://cwe.mitre.org/data/definitions/214.html>
- <https://cwe.mitre.org/data/definitions/208.html>
