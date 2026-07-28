# Secrets Verification Checklist

Run before returning code. Mark each item pass, fail, or not applicable. "Not applicable"
needs a one-line reason — an unexplained skip is a gap.

Only the sections the change touches need running. A CSS fix does not need the Kubernetes
section.

## Source and Repository (A04 · ASVS V13 · CWE-798, CWE-259)

- [ ] No credential literal in application code, config, tests, fixtures, seeds, or comments
- [ ] No credential in a commented-out line or a `TODO: move to env`
- [ ] `.env` and `*.key`, `*.pem`, `*.p12`, `*-credentials.json` are gitignored
- [ ] `.env.example` exists, lists every required key, and holds no real values
- [ ] No secret in a README, docstring, OpenAPI example, or Postman collection
- [ ] No secret in a git submodule, vendored directory, or `node_modules` patch
- [ ] Missing secret fails at boot with a message naming the variable, no silent default

## Runtime Delivery (A02 · ASVS V13 · CWE-214)

- [ ] Secret read once at startup, not re-read from the environment per request
- [ ] Subprocesses get an explicit minimal `env`, not the inherited one
- [ ] Error reporter (Sentry/Rollbar/Bugsnag) configured to strip environment and request
      headers, or the secret is not in the environment at all
- [ ] Where the platform supports it, the secret arrives as a mounted file with restrictive
      permissions rather than an env var
- [ ] Core dumps disabled, or the process does not hold the secret in the environment block

## Secret Manager (A04 · ASVS V13, V14 · CWE-522)

- [ ] Access authenticated by platform identity, not a bootstrap token or static key
- [ ] Read is scoped to the specific secret path, not the whole vault or namespace
- [ ] Cache present, with a TTL shorter than the rotation interval
- [ ] Cache is in memory only, never written to disk or a temp file
- [ ] Fetch failure fails the request. No fallback to a default or a stale value past TTL
- [ ] GCP: `latest` versus a pinned version chosen deliberately, with the reason stated
- [ ] Azure: the specific credential type constructed in production, not
      `DefaultAzureCredential`'s ambient chain
- [ ] Audit logging enabled on the manager, and someone reads it

## Workload Identity (A02 · ASVS V13)

- [ ] No long-lived cloud access key anywhere in the deployment
- [ ] EKS: trust policy conditions on `:sub` with the exact
      `system:serviceaccount:<ns>:<name>`, using `StringEquals` not a wildcard
- [ ] EKS: trust policy conditions on `:aud` as well as `:sub`
- [ ] GKE: Kubernetes SA bound to one IAM principal, not a project-wide binding
- [ ] AKS: federated credential subject matches the exact service account
- [ ] CI OIDC trust conditions include repository and branch or environment, not just the
      issuer
- [ ] The attached role grants the minimum actions on the minimum resources

## Rotation (A04 · ASVS V13, V14)

- [ ] Every credential has a named owner and a rotation interval
- [ ] Verifier accepts current and previous during a bounded overlap window
- [ ] Overlap window has an expiry that is enforced, not just documented
- [ ] Rotation is tested: the new value is authenticated with before it is promoted
- [ ] Rotation does not require a synchronised deploy of producer and consumer
- [ ] Database rotation alternates between two users rather than resetting one password
- [ ] Exposure rotation path exists and is separate from the scheduled path
- [ ] Rotation has been executed at least once, not merely designed

## Comparison and Handling (A04 · ASVS V11, V14 · CWE-208)

- [ ] Secret equality uses a constant-time comparison, not `==`
- [ ] Node `timingSafeEqual` inputs are equalised by hashing, so length is not leaked
- [ ] PHP `hash_equals` argument order is known value first
- [ ] Secret not concatenated into a URL, query string, or redirect target
- [ ] Secret not placed in a client-readable location: cookie without `HttpOnly`,
      `localStorage`, HTML, or a bundled frontend build

## CI/CD (A02, A03 · ASVS V13)

- [ ] Pipeline secrets stored as masked/protected variables, not in the workflow file
- [ ] Masking verified: the value does not appear when echoed or in a failing assertion
- [ ] Secrets not exposed to workflows triggered by forks (`pull_request_target` reviewed)
- [ ] `permissions:` block present and minimal on GitHub Actions workflows
- [ ] Third-party actions pinned to a commit SHA, not a mutable tag
- [ ] No secret passed as a command-line argument — it lands in the process listing and log
- [ ] Debug/verbose modes off, or confirmed not to print the environment
- [ ] Build logs reviewed for the secret after the first run on a new pipeline

## Container Images (A02, A03 · ASVS V13)

- [ ] No `COPY` of a credential file, even if a later layer deletes it
- [ ] No secret in `ARG` — build args are visible in `docker history` and image metadata
- [ ] No secret in `ENV` in the Dockerfile
- [ ] Build-time secrets use `RUN --mount=type=secret`, not a copied file or an arg
- [ ] `.dockerignore` excludes `.env`, `.git`, and key files from the build context
- [ ] Final image inspected: `docker history` and a layer extraction show no credential
- [ ] Base image and installed packages pinned by digest or exact version

## Kubernetes (A02 · ASVS V13)

- [ ] Understood that a Secret is base64-encoded, not encrypted — `data` is not protection
- [ ] etcd encryption at rest enabled for `secrets` resources
- [ ] RBAC restricts `get`/`list`/`watch` on Secrets to the specific service accounts
      that need them, with no wildcard verb on `secrets`
- [ ] Secret not mounted into a pod that does not use it
- [ ] Secret manifests not committed in plaintext; sealed-secrets, SOPS, or an external
      operator used if they live in git
- [ ] Preferred: CSI Secrets Store or an external-secrets operator, so the value is not a
      Kubernetes object at all
- [ ] No secret in a ConfigMap, in pod annotations, or in a container `command`/`args`

## Infrastructure as Code (A02 · ASVS V13)

- [ ] No credential literal in `.tf`, `.tfvars`, Helm `values.yaml`, or a CloudFormation
      parameter default
- [ ] Terraform state treated as a secret store: remote backend, encrypted, access-controlled
- [ ] Understood that `sensitive = true` hides output from the plan and not from state
- [ ] Plan output not published to a PR comment or a public build log
- [ ] Generated credentials sourced from a data block or the provider, not a variable a human
      types

## Logging and Telemetry (A09 · ASVS V16 · CWE-532)

- [ ] No log line contains a token, key, password, cookie, or `Authorization` header value
- [ ] Whole request, response, headers, or config objects are never logged
- [ ] Redaction happens before the log call, not in a downstream filter
- [ ] Exception handlers do not log the arguments that carried the credential
- [ ] Query strings are not logged where a token could appear in one
- [ ] Redaction verified against the actual sink, not just locally

## AI and Tooling (A02 · ASVS V13, V14)

- [ ] No secret in a system prompt, a few-shot example, or a tool description
- [ ] No secret in a tool call argument — those are logged by the model provider
- [ ] Retrieved documents and tool output scrubbed of credentials before entering the prompt
- [ ] Agent runs with its own scoped, short-lived credential, not the operator's
- [ ] Any secret pasted into a prompt during development treated as exposed and rotated

## Detection (A02 · ASVS V13)

- [ ] Pre-commit secret scanning installed, with tool version pinned and verified
- [ ] CI secret scanning on push and pull request, with full history fetched
- [ ] Understood that CI scanning is detection after the fact, not prevention
- [ ] Provider-side push protection enabled where available
- [ ] A red scan triggers the exposure response, not just a force-push

## Before Returning

- [ ] Build or compile step run
- [ ] Relevant tests run, with output reported honestly
- [ ] Temporary files, dumped configs, and scratch `.env` files removed
- [ ] Any secret touched during the work accounted for: still unexposed, or rotated
- [ ] Anything unverifiable stated plainly, not implied to be fine
