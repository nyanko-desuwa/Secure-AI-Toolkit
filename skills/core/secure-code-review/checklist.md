# Review Verification Checklist

Run this before returning a review. It checks the review, not the code - the code checklist
lives in `core/owasp/checklist.md`.

Mark each item pass, fail, or not applicable. "Not applicable" needs a one-line reason.

## Scope Was Established

- [ ] The reviewed boundary is written down: diff range, directory, or weakness class
- [ ] Deployment context stated: internet-facing, internal, or local CLI
- [ ] Every changed line was read, not just the ones matching a grep
- [ ] Called functions outside the diff were opened one level out
- [ ] What was not reviewed is named explicitly

## Trust Boundaries Were Mapped

- [ ] Every request entry point in scope is listed: routes, consumers, cron, webhooks
- [ ] Where actor identity is established is identified
- [ ] Where each authorization decision is made is identified - route, service, or query
- [ ] Egress points listed: outbound HTTP, DB writes, file writes, shell, logs
- [ ] Source → sink pairs written down before findings were drafted

## Sinks Were Hunted, Not Guessed

- [ ] The sink table in `SKILL.md` was walked, not sampled
- [ ] Injection sinks checked: SQL, dynamic identifiers, shell, eval, template
- [ ] Rendering sinks checked for encoding at the sink, not just validation at the boundary
- [ ] Object lookups checked for actor scoping, including update and delete
- [ ] Handlers checked for a missing policy, not only a wrong one
- [ ] File path and archive extraction sinks checked
- [ ] Outbound request sinks checked for user-controlled destinations
- [ ] Deserializers checked against their input source
- [ ] Error handlers checked for fail-open behaviour
- [ ] Authentication and token verification code read, not assumed correct

## Each Finding Was Verified Adversarially

For every finding in the list:

- [ ] The source is confirmed attacker-controlled by reading the caller, not inferred
- [ ] Intervening controls were checked in the pinned version and its config, not assumed
- [ ] The sink's actual behaviour was confirmed (parameterization, auto-escaping, safe API)
- [ ] A concrete triggering input or request is written out
- [ ] Preconditions for exploitation are stated
- [ ] The finding survived one deliberate attempt to disprove it

## Findings and Observations Are Separated

- [ ] Nothing without an exploitation path is in the findings list
- [ ] Items with no path are in an observations list with one line each
- [ ] No item is listed twice under two CWEs
- [ ] Chained findings are rated once, as the chain

## Each Finding Is Cited and Rated

- [ ] Specific CWE assigned, with its name, not a parent class used as a catch-all
- [ ] OWASP Top 10 2025 category assigned, using 2025 numbering not 2021
- [ ] API Security Top 10 2023 category assigned where the surface is an API
- [ ] ASVS 5.0 chapter named
- [ ] Severity derived from exploitability and blast radius, with reasoning
- [ ] Any CVSS vector labelled `CVSS-B` if only Base metrics were scored
- [ ] Assumptions that could not be verified from the code are stated in the finding

## Fixes Are Minimal and Provable

- [ ] The fix changes the vulnerable behaviour and nothing else
- [ ] No refactor, rename, or dependency bump bundled into a security fix
- [ ] The fix is at the right layer: encoding at the sink, authorization at the data layer
- [ ] A regression test is written that fails before the fix and passes after
- [ ] The test asserts the security property, not the absence of a crash
- [ ] Known residual gaps in the fix are named

## AI-Generated Code Was Checked Specifically

Applies when the code under review was generated.

- [ ] Client-side guards confirmed to have a server-side counterpart
- [ ] Boundary validation confirmed not to be substituting for sink encoding
- [ ] `try`/`catch` around security decisions confirmed to fail closed
- [ ] Library calls and config options confirmed to exist in the pinned version
- [ ] Copied patterns checked for the framework version actually in the lockfile

## Before Returning

- [ ] Every claim about behaviour was either verified or labelled unverified
- [ ] Line numbers checked against the current file, not a stale read
- [ ] No secret values echoed into the review output
- [ ] Findings ordered by severity, highest first
- [ ] Temporary files and scratch scripts removed
