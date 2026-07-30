# Secrets Verification Checklist

Run before returning code. Mark each item pass, fail, or not applicable. "Not applicable"
needs a one-line reason - an unexplained skip is a gap.

Only the sections the change touches need running. A CSS fix does not need the Kubernetes
section.

## Source and Repository (A04 · ASVS V13 · CWE-798, CWE-259)

- [ ] [critical] No credential literal in application code, config, tests, fixtures, seeds, or comments
- [ ] [critical] No credential in a commented-out line or a `TODO: move to env`
- [ ] [critical] `.env` and `*.key`, `*.pem`, `*.p12`, `*-credentials.json` are gitignored
- [ ] [recommended] `.env.example` exists, lists every required key, and holds no real values
- [ ] [critical] No secret in a README, docstring, OpenAPI example, or Postman collection
- [ ] [critical] No secret in a git submodule, vendored directory, or `node_modules` patch
- [ ] [recommended] Missing secret fails at boot with a message naming the variable, no silent default

## Runtime Delivery (A02 · ASVS V13 · CWE-214)

- [ ] [recommended] Secret read once at startup, not re-read from the environment per request
- [ ] [recommended] Subprocesses get an explicit minimal `env`, not the inherited one
- [ ] [critical] Error reporter (Sentry/Rollbar/Bugsnag) configured to strip environment and request
      headers, or the secret is not in the environment at all
- [ ] [recommended] Where the platform supports it, the secret arrives as a mounted file with restrictive
      permissions rather than an env var
- [ ] [recommended] Core dumps disabled, or the process does not hold the secret in the environment block

## Secret Manager (A04 · ASVS V13, V14 · CWE-522)

- [ ] [critical] Access authenticated by platform identity, not a bootstrap token or static key
- [ ] [recommended] Read is scoped to the specific secret path, not the whole vault or namespace
- [ ] [recommended] Cache present, with a TTL shorter than the rotation interval
- [ ] [critical] Cache is in memory only, never written to disk or a temp file
- [ ] [recommended] Fetch failure fails the request. No fallback to a default or a stale value past TTL
- [ ] [optional] GCP: `latest` versus a pinned version chosen deliberately, with the reason stated
- [ ] [recommended] Azure: the specific credential type constructed in production, not
      `DefaultAzureCredential`'s ambient chain
- [ ] [recommended] Audit logging enabled on the manager, and someone reads it

## Workload Identity (A02 · ASVS V13)

- [ ] [critical] No long-lived cloud access key anywhere in the deployment
- [ ] [critical] EKS: trust policy conditions on `:sub` with the exact
      `system:serviceaccount:<ns>:<name>`, using `StringEquals` not a wildcard
- [ ] [critical] EKS: trust policy conditions on `:aud` as well as `:sub`
- [ ] [critical] GKE: Kubernetes SA bound to one IAM principal, not a project-wide binding
- [ ] [critical] AKS: federated credential subject matches the exact service account
- [ ] [critical] CI OIDC trust conditions include repository and branch or environment, not just the
      issuer
- [ ] [recommended] The attached role grants the minimum actions on the minimum resources

## Rotation (A04 · ASVS V13, V14)

- [ ] [recommended] Every credential has a named owner and a rotation interval
- [ ] [recommended] Verifier accepts current and previous during a bounded overlap window
- [ ] [recommended] Overlap window has an expiry that is enforced, not just documented
- [ ] [recommended] Rotation is tested: the new value is authenticated with before it is promoted
- [ ] [optional] Rotation does not require a synchronised deploy of producer and consumer
- [ ] [recommended] Database rotation alternates between two users rather than resetting one password
- [ ] [recommended] Exposure rotation path exists and is separate from the scheduled path
- [ ] [recommended] Rotation has been executed at least once, not merely designed

## Comparison and Handling (A04 · ASVS V11, V14 · CWE-208)

- [ ] [critical] Secret equality uses a constant-time comparison, not `==`
- [ ] [critical] Node `timingSafeEqual` inputs are equalised by hashing, so length is not leaked
- [ ] [recommended] PHP `hash_equals` argument order is known value first
- [ ] [critical] Secret not concatenated into a URL, query string, or redirect target
- [ ] [critical] Secret not placed in a client-readable location: cookie without `HttpOnly`,
      `localStorage`, HTML, or a bundled frontend build

## CI/CD (A02, A03 · ASVS V13)

- [ ] [critical] Pipeline secrets stored as masked/protected variables, not in the workflow file
- [ ] [recommended] Masking verified: the value does not appear when echoed or in a failing assertion
- [ ] [critical] Secrets not exposed to workflows triggered by forks (`pull_request_target` reviewed)
- [ ] [recommended] `permissions:` block present and minimal on GitHub Actions workflows
- [ ] [recommended] Third-party actions pinned to a commit SHA, not a mutable tag
- [ ] [critical] No secret passed as a command-line argument - it lands in the process listing and log
- [ ] [recommended] Debug/verbose modes off, or confirmed not to print the environment
- [ ] [recommended] Build logs reviewed for the secret after the first run on a new pipeline

## Container Images (A02, A03 · ASVS V13)

- [ ] [critical] No `COPY` of a credential file, even if a later layer deletes it
- [ ] [critical] No secret in `ARG` - build args are visible in `docker history` and image metadata
- [ ] [critical] No secret in `ENV` in the Dockerfile
- [ ] [recommended] Build-time secrets use `RUN --mount=type=secret`, not a copied file or an arg
- [ ] [recommended] `.dockerignore` excludes `.env`, `.git`, and key files from the build context
- [ ] [recommended] Final image inspected: `docker history` and a layer extraction show no credential
- [ ] [recommended] Base image and installed packages pinned by digest or exact version

## Kubernetes (A02 · ASVS V13)

- [ ] [recommended] Understood that a Secret is base64-encoded, not encrypted - `data` is not protection
- [ ] [recommended] etcd encryption at rest enabled for `secrets` resources
- [ ] [critical] RBAC restricts `get`/`list`/`watch` on Secrets to the specific service accounts
      that need them, with no wildcard verb on `secrets`
- [ ] [recommended] Secret not mounted into a pod that does not use it
- [ ] [critical] Secret manifests not committed in plaintext; sealed-secrets, SOPS, or an external
      operator used if they live in git
- [ ] [optional] Preferred: CSI Secrets Store or an external-secrets operator, so the value is not a
      Kubernetes object at all
- [ ] [critical] No secret in a ConfigMap, in pod annotations, or in a container `command`/`args`

## Infrastructure as Code (A02 · ASVS V13)

- [ ] [critical] No credential literal in `.tf`, `.tfvars`, Helm `values.yaml`, or a CloudFormation
      parameter default
- [ ] [critical] Terraform state treated as a secret store: remote backend, encrypted, access-controlled
- [ ] [recommended] Understood that `sensitive = true` hides output from the plan and not from state
- [ ] [critical] Plan output not published to a PR comment or a public build log
- [ ] [recommended] Generated credentials sourced from a data block or the provider, not a variable a human
      types

## Logging and Telemetry (A09 · ASVS V16 · CWE-532)

- [ ] [critical] No log line contains a token, key, password, cookie, or `Authorization` header value
- [ ] [critical] Whole request, response, headers, or config objects are never logged
- [ ] [recommended] Redaction happens before the log call, not in a downstream filter
- [ ] [recommended] Exception handlers do not log the arguments that carried the credential
- [ ] [recommended] Query strings are not logged where a token could appear in one
- [ ] [recommended] Redaction verified against the actual sink, not just locally

## AI and Tooling (A02 · ASVS V13, V14)

- [ ] [critical] No secret in a system prompt, a few-shot example, or a tool description
- [ ] [critical] No secret in a tool call argument - those are logged by the model provider
- [ ] [recommended] Retrieved documents and tool output scrubbed of credentials before entering the prompt
- [ ] [recommended] Agent runs with its own scoped, short-lived credential, not the operator's
- [ ] [critical] Any secret pasted into a prompt during development treated as exposed and rotated

## Detection (A02 · ASVS V13)

- [ ] [recommended] Pre-commit secret scanning installed, with tool version pinned and verified
- [ ] [recommended] CI secret scanning on push and pull request, with full history fetched
- [ ] [optional] Understood that CI scanning is detection after the fact, not prevention
- [ ] [recommended] Provider-side push protection enabled where available
- [ ] [recommended] A red scan triggers the exposure response, not just a force-push

## Before Returning

- [ ] [critical] Build or compile step run
- [ ] [critical] Relevant tests run, with output reported honestly
- [ ] [recommended] Temporary files, dumped configs, and scratch `.env` files removed
- [ ] [critical] Any secret touched during the work accounted for: still unexposed, or rotated
- [ ] [critical] Anything unverifiable stated plainly, not implied to be fine
