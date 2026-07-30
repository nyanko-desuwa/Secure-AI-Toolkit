# Review Verification Checklist

Run this before returning a review. It checks the review, not the code - the code checklist
lives in `core/owasp/checklist.md`.

Mark each item pass, fail, or not applicable. "Not applicable" needs a one-line reason.

## Scope Was Established

- [ ] [recommended] The reviewed boundary is written down: diff range, directory, or weakness class
- [ ] [recommended] Deployment context stated: internet-facing, internal, or local CLI
- [ ] [critical] Every changed line was read, not just the ones matching a grep
- [ ] [recommended] Called functions outside the diff were opened one level out
- [ ] [recommended] What was not reviewed is named explicitly

## Trust Boundaries Were Mapped

- [ ] [critical] Every request entry point in scope is listed: routes, consumers, cron, webhooks
- [ ] [critical] Where actor identity is established is identified
- [ ] [critical] Where each authorization decision is made is identified - route, service, or query
- [ ] [recommended] Egress points listed: outbound HTTP, DB writes, file writes, shell, logs
- [ ] [recommended] Source → sink pairs written down before findings were drafted

## Sinks Were Hunted, Not Guessed

- [ ] [critical] The sink table in `SKILL.md` was walked, not sampled
- [ ] [critical] Injection sinks checked: SQL, dynamic identifiers, shell, eval, template
- [ ] [critical] Rendering sinks checked for encoding at the sink, not just validation at the boundary
- [ ] [critical] Object lookups checked for actor scoping, including update and delete
- [ ] [critical] Handlers checked for a missing policy, not only a wrong one
- [ ] [critical] File path and archive extraction sinks checked
- [ ] [critical] Outbound request sinks checked for user-controlled destinations
- [ ] [critical] Deserializers checked against their input source
- [ ] [critical] Error handlers checked for fail-open behaviour
- [ ] [critical] Authentication and token verification code read, not assumed correct

## Each Finding Was Verified Adversarially

For every finding in the list:

- [ ] [critical] The source is confirmed attacker-controlled by reading the caller, not inferred
- [ ] [critical] Intervening controls were checked in the pinned version and its config, not assumed
- [ ] [critical] The sink's actual behaviour was confirmed (parameterization, auto-escaping, safe API)
- [ ] [recommended] A concrete triggering input or request is written out
- [ ] [recommended] Preconditions for exploitation are stated
- [ ] [recommended] The finding survived one deliberate attempt to disprove it

## Findings and Observations Are Separated

- [ ] [recommended] Nothing without an exploitation path is in the findings list
- [ ] [recommended] Items with no path are in an observations list with one line each
- [ ] [optional] No item is listed twice under two CWEs
- [ ] [recommended] Chained findings are rated once, as the chain

## Each Finding Is Cited and Rated

- [ ] [recommended] Specific CWE assigned, with its name, not a parent class used as a catch-all
- [ ] [recommended] OWASP Top 10 2025 category assigned, using 2025 numbering not 2021
- [ ] [recommended] API Security Top 10 2023 category assigned where the surface is an API
- [ ] [recommended] ASVS 5.0 chapter named
- [ ] [recommended] Severity derived from exploitability and blast radius, with reasoning
- [ ] [optional] Any CVSS vector labelled `CVSS-B` if only Base metrics were scored
- [ ] [recommended] Assumptions that could not be verified from the code are stated in the finding

## Fixes Are Minimal and Provable

- [ ] [recommended] The fix changes the vulnerable behaviour and nothing else
- [ ] [recommended] No refactor, rename, or dependency bump bundled into a security fix
- [ ] [critical] The fix is at the right layer: encoding at the sink, authorization at the data layer
- [ ] [recommended] A regression test is written that fails before the fix and passes after
- [ ] [recommended] The test asserts the security property, not the absence of a crash
- [ ] [recommended] Known residual gaps in the fix are named

## AI-Generated Code Was Checked Specifically

Applies when the code under review was generated.

- [ ] [critical] Client-side guards confirmed to have a server-side counterpart
- [ ] [critical] Boundary validation confirmed not to be substituting for sink encoding
- [ ] [critical] `try`/`catch` around security decisions confirmed to fail closed
- [ ] [recommended] Library calls and config options confirmed to exist in the pinned version
- [ ] [recommended] Copied patterns checked for the framework version actually in the lockfile

## Before Returning

- [ ] [critical] Every claim about behaviour was either verified or labelled unverified
- [ ] [recommended] Line numbers checked against the current file, not a stale read
- [ ] [critical] No secret values echoed into the review output
- [ ] [recommended] Findings ordered by severity, highest first
- [ ] [recommended] Temporary files and scratch scripts removed
