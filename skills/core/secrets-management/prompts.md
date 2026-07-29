# Prompt Examples

Prompts that produce findings instead of a lecture on secret hygiene. Each names the scope, the
artefact, and the shape of the answer.

## Inventory what exists

```
Inventory every credential this repo uses. For each: the name, where the value comes from at
runtime (hardcoded / committed file / gitignored file / env var / manager), what it can do, and
whether it can be revoked in one action. Rank by severity and say what makes each one that
severity.
```

Why it works: the third column is the one nobody has an answer for, and asking for it surfaces
the credentials with no owner and no rotation path. Asking for the severity reasoning stops
"hardcoded, therefore critical" for a sandbox test key.

## Audit the delivery path, not just the code

```
Check the Dockerfile, .dockerignore, the CI workflow, and the k8s manifests in this repo
against skills/core/secrets-management/checklist.md. I care specifically about secrets that
survive in image layers, build args, or CI logs. Quote the exact line for each finding.
```

Application code is where people look. Layers, build args, and pipeline variables are where
secrets actually persist. Naming the artefacts stops the answer drifting back to `config.py`.

## Grade a single credential's position

```
Our Stripe key is read from an env var set by the Helm chart. Place that on the storage
hierarchy in skills/core/secrets-management/SKILL.md, tell me exactly what still leaks, and
give me the next reachable rung with the tradeoff.
```

Asking for what still leaks is the point. "Env var, that is fine" is the answer this prompt is
designed to prevent.

## Design a rotation that is not an outage

```
Our webhook signing secret has never been rotated. Design the rotation with a dual-secret
window. Give me the sequence of deploys, what is valid at each step, how long the overlap stays
open, and what breaks if a step fails halfway.
```

The failure-halfway question forces a design that survives a partial rollout rather than a
happy-path runbook.

## Respond to a leak

```
An AWS access key was pushed to a public repo 40 minutes ago and CI has already run twice.
Give me the ordered response. Be explicit about what happens first and why deleting the commit
is not it. Then tell me what to check in CloudTrail and over what window.
```

Stating the elapsed time and the public visibility changes the answer - it moves the assumption
from "seen" to "used". Asking for the order explicitly is what stops the git-cleanup reflex.

## Review a secret manager integration

```
Read src/config/secrets.py. Check: how it authenticates to the manager, whether the cache TTL
is shorter than the rotation interval, what happens when the fetch fails, and whether the
fetched value can reach a log or an error tracker.
```

Four specific questions produce four specific answers. "Review this secrets code" produces a
summary of what the code does.

## Check the workload identity trust boundary

```
Review this IAM trust policy and the ServiceAccount annotation together. Can any pod other than
orders/orders-api assume this role? Check the :sub and :aud conditions and the match operator.
```

The trust policy is the actual boundary and a `StringLike` wildcard on `:sub` silently removes
it. Asking about the operator is what catches it.

## Find secrets on the paths that reach a model

```
This service builds prompts and calls tools in an agent loop. Trace every value that reaches a
prompt, a tool argument, or a tool description. Flag anything that is or contains a credential,
including values pulled from retrieved documents.
```

Model providers log requests and traces. A credential in a tool argument is exposed to a third
party, and it is the leak path least likely to be in an existing review checklist.

## Verify before returning

```
Run skills/core/secrets-management/checklist.md against the change we just made. Mark each item
pass, fail, or not applicable with a reason. Do not mark anything pass that you have not
actually read the file for, and list what you could not verify.
```

The last clause matters. Runtime state - etcd encryption, whether rotation has ever run - is
not verifiable from the repo, and a wall of checkmarks hides that.

## Anti-patterns

| Prompt | Problem |
|---|---|
| "Are our secrets secure?" | No scope, no artefact. Produces the hierarchy read back at you |
| "Move the secrets to environment variables" | Treats rung four as the destination. Ask for the next rung and the remaining leaks |
| "Scan for hardcoded secrets" | An LLM is a bad entropy scanner. Run `gitleaks`, then ask what to do with the hits |
| "Remove the secret from git history" | Wrong first action. Revoke first. History cleanup is tidiness |
| "Add secret rotation" | Rotation is a system property, not a function. Ask for the dual-secret window and the deploy sequence |
| "Is this key still valid?" | The skill cannot check. Only the provider's API can |
| Pasting a real credential to ask about it | The paste is now an exposure. Describe the shape instead |
