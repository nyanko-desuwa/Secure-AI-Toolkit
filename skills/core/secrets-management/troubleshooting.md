# Troubleshooting

What to do when the guidance does not resolve cleanly, or cannot be applied at all.

## There is no secret manager and there will not be one this quarter

Do not stall on the ideal. Move up one rung and say so.

Order of preference when a manager is off the table:

1. Platform-native injection with no repository footprint — systemd `LoadCredential`, a
   Docker/Swarm secret, an ECS task definition pulling from Parameter Store.
2. A mounted file with `0400` permissions, path supplied by an env var.
3. An env var set by the orchestrator, never by a committed file.

Report the residual risk in one line: which leak paths from
[best-practices.md](best-practices.md#environment-variables-are-a-waypoint-not-a-destination)
remain open. "Moved to env vars; still readable via `/proc` and inherited by subprocesses" is a
complete and honest statement.

## The secret is already in git history and rewriting is not possible

Rewriting history is often blocked: shared branches, signed tags, a mirror you do not control,
compliance retention. That does not change the response.

Revoke and rotate. The old value being visible in history stops mattering the moment it stops
working. Then decide about the cleanup separately, on its own merits. Never let a debate about
`filter-repo` delay revocation — that ordering mistake is the one that turns an exposure into
an incident.

If the repository is public, assume automated collection happened within minutes and treat the
credential as used, not just seen. Check the provider's audit log for activity.

## You cannot revoke without breaking production

This is the situation rotation design exists to prevent, and you are past that point. Options,
best first:

- If the credential supports multiple concurrent values (API keys with a key ID, database users,
  webhook secrets with a key set) create the replacement first, deploy it, then revoke the old.
  Minutes of overlap, no downtime.
- If the provider supports scope reduction, narrow the leaked credential's permissions
  immediately. A key that can no longer write is a smaller incident while you prepare the swap.
- If neither is possible, take the outage. A short planned outage costs less than an
  indefinite window with a live leaked credential. Say this plainly to whoever decides.

Record which option you took. The reason a credential could not be revoked cleanly is a design
finding worth its own ticket.

## Rotation is not supported by the upstream provider

Some third-party APIs issue one key per account with no second slot and no programmatic
rotation. You cannot build a dual window on top of that.

What you can do: put the value behind your own indirection. Your services talk to an internal
proxy or a single egress service that holds the one key; that service is the only thing that
needs a coordinated restart. Rotation becomes one deploy of one component instead of a
fleet-wide cutover.

State the limitation. "Provider supports a single key; rotation requires a brief restart of
`payments-egress`, scoped to that service" is a real answer.

## The credential must be shared across services

Sharing a credential means an incident in the noisiest service revokes the credential for all
of them, and the audit log cannot tell you which service acted.

If the provider issues multiple credentials, issue one per service. If it does not, treat the
shared credential as a single trust zone and document that: one exposure means rotating for
everyone, and attribution requires application-level logging because provider-side logs will
not distinguish the callers.

Do not solve this by copying the value into more places. Fewer copies, one owner.

## The scanner flags a value that is not a secret

Test fixtures, example keys from documentation, and public identifiers all trip pattern
matchers. Suppress narrowly:

- Prefer changing the value so it does not look real — insert `PLACEHOLDER` or `EXAMPLE` into
  the string. This fixes it for every scanner at once and for humans reading the diff.
- If the value must keep its shape, use the tool's inline allow directive on that specific
  line with a comment explaining why, not a path-wide or rule-wide exclusion.
- Never disable the rule globally to clear a build. The next real hit is then invisible.

A baseline file is acceptable for adopting scanning on an existing repository, but every entry
in it is unreviewed debt. Note the count and shrink it.

## The framework already handles redaction, allegedly

Verify it. Logging libraries and error trackers vary by version and by configuration, and
"sensitive fields are scrubbed" usually means a default denylist of field names that does not
include yours.

Check the actual sink: send a request with a marker value in the header or field, then search
the log aggregator and the error tracker UI for the marker. If you cannot run that test, say
the redaction is unverified rather than reporting it as a control that is in place.

## Two guidance items conflict

Common collisions and how they resolve:

- Cache TTL versus rotation propagation. Rotation interval wins. Make the TTL a fraction of
  the rotation period and handle authentication failure by refetching.
- Pinned secret version versus automatic rotation pickup. Blast radius wins for anything that
  can take down the fleet simultaneously. Pin the version and roll the deploy.
- Fail closed versus availability. Fail closed wins for a credential that gates authorization.
  For a non-security dependency, a bounded stale-cache fallback is defensible if you log it and
  cap the staleness. Say which you chose.
- Least privilege versus operational urgency during an incident. Grant broadly, log it, and
  file the narrowing ticket in the same hour. An undocumented emergency grant becomes
  permanent.

State that you made the call and why. Silent resolution is the problem, not the choice.

## The exposure window cannot be determined

You will often not know when a secret was first readable. Do not guess a date to make the
report tidy.

Bound it instead: earliest possible exposure is the commit date, the image push date, or the
log retention start, whichever is earliest. Latest is revocation. Report the range and the
audit evidence you actually have. "Exposed between 2026-03-04 (commit) and 2026-07-28
(revocation); provider audit log only retains 90 days, so use before 2026-04-29 is
unverifiable" is far more useful than a confident single date.

## Local development still needs a real credential

Sometimes the third party has no sandbox. Narrow the exposure:

- One shared development credential with the smallest possible scope, held in the manager and
  fetched per session. Never per-developer copies in files.
- A short TTL, so a laptop compromise expires on its own.
- If the credential can reach production data, it is a production credential. Treat it as one
  and stop calling it a dev secret.

See [best-practices.md](best-practices.md#local-development-without-real-secrets) for the cases
where this can be avoided entirely.

## A checklist item genuinely does not apply

Write the reason. "No Kubernetes section: this service runs on ECS" is a complete answer. An
unexplained skip is indistinguishable from an oversight.

## The standard or the SDK has moved on

The Top 10 2025, ASVS 5.0.0, and CWE entries here were verified on 2026-07-28. Provider SDK
signatures and tool versions change faster than standards do. If a project depends on a
precise category ID, requirement number, or API call, re-check the source before quoting it.
See [references/](references/) for the URLs.

Never assume undocumented behaviour, including which fields a secret manager encrypts or which
metadata a build tool records. Fetch it.
