# Exposure Response

What to do in the hour after a credential leaks. Order matters, and the intuitive order is
wrong.

Checked against OWASP Top 10 2025 (A02, A04), ASVS 5.0 V13/V14, and the OWASP Secrets
Management Cheat Sheet on 2026-07-28. This is the credential-specific slice of incident
response, not the whole process — see the `incident-response` skill for the wider loop.

## The order

1. Revoke
2. Rotate
3. Investigate

Revoke first, before you know how bad it is. Every minute spent working out who pushed the
commit is a minute the credential still works.

### 1. Revoke

Make the old value useless at the provider. Not "remove it from the repo" — invalidate it at
the system that honours it.

| Credential | Revocation |
|---|---|
| AWS access key | Deactivate then delete the key on the IAM user, `iam update-access-key --status Inactive` |
| Cloud service account key | Delete the key resource, not just the local file |
| Database password | Change it, or drop the role if it was per-service |
| API key from a SaaS provider | Delete or roll it in the provider console; most have a one-click roll |
| OAuth client secret | Add a new secret, remove the old — most providers allow two |
| Signing key (JWT, webhook) | Remove from the verifier's accepted set. Existing signed artefacts remain valid until expiry |
| SSH key | Remove from `authorized_keys` on every host and from the provider's deploy keys |
| Vault token or lease | `vault token revoke` / `vault lease revoke` — this also invalidates dynamic credentials issued under it |

Two things that are not revocation: deleting the file, and rotating without disabling the old
value. A rotation that leaves the previous secret in the accepted set has changed nothing about
the leaked credential.

If revoking immediately breaks production, revoke anyway for anything with write or admin scope.
For a read-scoped credential you may have room to sequence revoke-after-deploy — decide that
explicitly and write down the window, do not let it become "later".

### 2. Rotate

Issue the replacement and deploy it. This is the scheduled-rotation machinery run at speed, with
one difference: the overlap window is zero. Exposure rotation must not accept the old value
during a grace period, which is exactly what the safe scheduled path does. If your rotation
automation always opens an overlap window, do not use it here.

If there is no rotation path, this step is where you discover it. Build the minimum viable one
now and open a follow-up to do it properly.

### 3. Investigate

Now find out what happened. The credential is already dead, so there is no clock pressure.

- Read the provider's audit log for use of the credential between first exposure and revocation.
  First exposure is the commit timestamp, the image push, or the log write — not when you noticed.
- Look for use from unfamiliar IPs, user agents, regions, or at unusual times.
- Check for durable artefacts the credential could have created: new IAM users, new keys, new
  OAuth grants, forwarding rules, scheduled jobs, webhooks. An attacker who used a key for two
  minutes may have left something that outlives it.
- Establish the exposure surface: was the repository public, was the image pushed to a public
  registry, did the CI log go to a third party, was the value in a notification webhook or a
  chat message.
- Decide on disclosure. If customer data was reachable, notification obligations may apply. That
  is a decision for whoever owns that call, not an engineering judgement.
- Write down how the value got there. The fix is a control, not a reminder to be careful.

## Why deleting the commit does not help

Rewriting history feels like remediation because the value disappears from what you can see. It
is not, for reasons that are all independent of each other:

- History. Removing a line in a new commit leaves the old commit intact. Every clone has it.
- Reflogs and unreferenced objects. After a force-push, the old commit is often still fetchable
  by SHA until the host garbage-collects. On GitHub, objects in a repository network can remain
  reachable from forks indefinitely.
- Forks and mirrors. You cannot rewrite someone else's clone, a CI cache, a backup, or an
  internal mirror.
- Pull request views. The diff and the patch endpoint retain the content independently of the
  branch.
- CI logs and artefacts. A build that ran before the removal may have printed the value or baked
  it into an artefact that is still stored.
- Container images. If it shipped in a layer, the layer is in the registry and in every pulled
  copy.
- Third-party ingestion. Code search indexes, secret-scanning bots, IDE telemetry, and AI
  assistant context windows may all have seen it. Public-repo commits are scraped within
  minutes.

Do the history cleanup for hygiene, after revocation, and do not report it as the fix.

## Timeline template

Fill this in as you go. It is the input to both the investigation and the post-incident change.

```text
T0   exposure created        commit / push / image / log write, with the actual timestamp
T1   exposure detected       scanner alert, provider notification, human report
T2   revoked                 what action, by whom, confirmed how
T3   rotated                 new value issued and deployed
T4   audit reviewed          window checked, findings
T5   artefacts checked       IAM, grants, jobs, webhooks
T6   control added           what stops the next one
```

The gap between T0 and T1 is the number that matters. If it is days, the problem is detection,
not the developer who pushed the commit.

## When the leak is somewhere unusual

| Leak location | Extra step beyond revoke/rotate |
|---|---|
| Container image layer | Delete the tag and the digest from every registry, and check for pulled copies. Rebuild without the layer |
| CI log | Purge the log if the provider allows it. Assume anyone with build read has seen it |
| Kubernetes Secret in git | Rotate, then treat the manifest history as public. Move to sealed secrets or an operator |
| Terraform state | Rotate everything in that state file, not just the one you noticed. State is a bundle |
| Error tracker | Purge the event, then fix the SDK config so environment and headers are stripped |
| LLM prompt or tool call | Assume retained by the provider. Rotate. There is no purge path you control |
| Public code-search hit | Assume automated use within minutes. Revoke first, ask questions after |

## What to change afterwards

An exposure without a control change will recur. Pick from:

- Pre-commit secret scanning, installed by default in the repo template so nobody opts in
- CI secret scanning on push and pull request, with full history fetched
- Provider push protection where available
- Removing the stored value entirely: workload identity or OIDC federation instead of a key
- Shortening credential lifetime so the next exposure expires on its own
- Narrowing scope so the next leaked credential can do less

Ranked by effect: removing the stored value beats detecting the stored value.

## Sources

- OWASP Secrets Management Cheat Sheet — <https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html>
- OWASP Top 10 2025 — <https://owasp.org/Top10/2025/>
- CWE-798 Use of Hard-coded Credentials — <https://cwe.mitre.org/data/definitions/798.html>
- CWE-522 Insufficiently Protected Credentials — <https://cwe.mitre.org/data/definitions/522.html>
- GitHub, removing sensitive data from a repository — <https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository>
