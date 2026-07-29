# Prompt Examples

Architecture prompts fail differently from code prompts. Ask "review this architecture" and you get
the seven headings of a generic security whitepaper. The prompts below constrain the output shape,
because that is what forces an actual read of the design.

## Map the trust boundaries

```
Read infra/ and the service manifests in deploy/. List every trust boundary. For each one give a
table row: what crosses it, what authenticates the caller, what authorizes the operation, and what
happens when that check fails. Mark rows you inferred from config versus read explicitly.
```

Why it works: the four columns are the finding. An empty authorization cell or an unknown failure
cell is the answer, and the format makes the gap visible instead of letting it be skipped.

## Find only architectural findings

```
Review this codebase for design-level security problems. Report a finding only if fixing it in one
file leaves the same problem reachable by another path. Skip anything a linter or SAST rule would
catch.
```

The exclusion is what does the work. Without it the answer fills up with missing input validation
and you never get to the missing boundary.

## Threat model one crossing, with the attacker's starting position

```
STRIDE the crossing between the public API gateway and the internal orders service. Assume the
attacker has a valid low-privilege account on the public API and can read our OpenAPI spec. For each
of the six categories, either name a concrete threat with the request path, or say it does not apply
here and why. End with the controls you would add, not a list of concerns.
```

Naming what the attacker already knows is what turns generic STRIDE into a finding. "Assume nothing"
produces spoofing threats about physical datacentre access. The last sentence blocks the Admiration
for the Problem anti-pattern.

## Design review before code exists

```
Here is the design for a new payment reconciliation service. Before we build it: what trust
boundaries does it introduce, what is the blast radius if it is fully compromised, and what controls
does it need? Map each control to a Top 10 2025 category and an ASVS 5.0 chapter.
```

Design-time review is the cheapest kind, and the mapping requirement stops the answer becoming a
wish list.

## Locate the boundaries in an unfamiliar repo

```
I do not know this codebase. Find the trust boundaries without assuming a layering convention.
Start from: every network listener, every database connection string, every credential read from the
environment, and every outbound HTTP client. For each, tell me what calls it and whether the caller
is inside or outside our control. Say which answers you could not determine from the code.
```

Naming the four anchors works when the code has no layers to read. Listeners, credentials, and
clients exist regardless of how the code is organised, and the boundary is wherever two of them meet
different callers.

## Tenant isolation specifically

```
This is a multi-tenant app on a shared PostgreSQL schema. Trace every path that reads the orders
table: HTTP handlers, background jobs, the analytics export, and any migration or admin script.
For each one, show where tenant_id is applied and what happens if it is missing.
```

Naming the non-HTTP paths matters. Background jobs, exports, and admin scripts are where the tenant
predicate is missing, precisely because nobody reviews them as request handlers.

## Blast radius of one service

```
Assume the payments-worker service is fully compromised - the attacker runs arbitrary code in that
container with its real credentials. List what it can read, what it can write, and where it can send
data, using its IAM role, its database grants, its egress policy, and its mounted secrets. Do not
list what it is supposed to do, and do not list what would stop them.
```

The last sentence is load-bearing. Asked neutrally, the answer describes the intended function and
then inventories defences, and the reachable set never gets enumerated. Blast radius is an
attacker-side question.

## Does the proposed split actually reduce blast radius

```
The proposal is to extract billing from the monolith into its own service. Both will keep using the
same PostgreSQL instance and the same application database role. Compare the reachable set from a
compromise of each side, before and after the split. Count shared credentials, shared database
grants, and shared network paths. If all three stay shared, say the split does not reduce blast
radius, and say what would have to change for it to.
```

Splits get proposed for team velocity and then justified as security. Two processes sharing one
database role and one secret are one failure domain wearing two names. Asking for the before and
after reachable set is what settles it; asking "is this a good split" gets an opinion about coupling.

## Choose between two designs, with the tradeoff named

```
Option A: per-tenant database with a connection pool per tenant. Option B: shared schema with
PostgreSQL row-level security. Same application. For each: what an application-level SQL injection
reaches, what a leaked database credential reaches, what a missing predicate reaches, and the
operational cost. Recommend one and name the risk we accept by picking it.
```

Naming the attacker positions up front makes the comparison decidable. Ask which option is "more
secure" and you get adjectives with no accepted risk attached. "Name the risk we accept" forces the
tradeoff into the answer; every architecture choice has one, and the version without it is marketing.

## Failure modes

```
For each external dependency in this design - auth service, policy service, database, cache, message
broker - tell me what breaks when it is unavailable, what the caller sees, and whether the security
posture degrades. Flag any dependency where the outage makes the system more permissive.
```

The last sentence is the one that finds fail-open. Ask about availability alone and you get a
resilience review with no security content.

## Abuse cases from a feature description

```
We are adding "share a report by public link". Write the abuse cases, not the use cases. Cover: link
guessing, link forwarding after the sharer loses access, indexing by crawlers, and what a departing
employee can take. For each, say whether the current design stops it.
```

Naming three or four concrete abuses seeds the pattern. Asking for abuse cases with no examples
usually returns the use cases with "unauthorized" prefixed.

## Least privilege on a specific identity

```
Read infra/iam/ci.tf. List every action this CI role can perform and every resource it can reach.
Then tell me which of those the pipeline actually uses, based on .github/workflows/. Propose the
narrowed policy.
```

Two-sided prompts beat one-sided ones. Reading only the policy gets you "avoid wildcards"; reading
the policy against the workflow gets you the specific actions to delete.

## Secure defaults audit

```
Find every place in this config where an absent, empty, or unparseable value results in permissive
behaviour. Include feature flags, env var reads with defaults, and any try/except around a config
load. Show the current default and the fail-closed version.
```

Naming the three shapes - flags, env defaults, exception handlers - covers where fail-open actually
lives. A general question about defaults returns advice about default passwords.

## Write the ADR

```
We decided to keep tenants in a shared schema with PostgreSQL RLS instead of a database per tenant.
Write the security ADR: context, threat with the assumed attacker, the options we rejected and why,
the decision, consequences, residual risk, and the trigger to revisit.
```

Asking for the residual risk and the review trigger by name is what stops the ADR reading as a
justification. Those two sections are the ones that get left out.

## Privacy pass

```
Run LINDDUN over this design. For Linking, Identifying, and Data Disclosure specifically, trace where
personal data flows outside the primary datastore: logs, analytics events, error reports, backups,
and any third-party SDK. Say which of those inherit the access controls of the primary store.
```

Personal data leaks through the exhaust, not the front door. Naming the five destinations is what
finds it.

## Anti-patterns

| Prompt | Problem |
|---|---|
| "Is this architecture secure?" | No scope and no attacker. Produces a lecture with the headings of a whitepaper |
| "Make it zero trust" | A marketing phrase as posed. Ask for the specific control: per-request authorization, audience-scoped service tokens, no network-position trust |
| "Should we use microservices?" | Not a security question as posed. It becomes one when you ask which trust boundary the split creates and whether it shrinks a named reachable set |
| "Make this architecture secure" | Invites a rewrite proposal nobody will implement. Ask for the smallest change that removes one attack path |
| "What are the best practices for microservices security?" | Generic. Nothing gets read, nothing gets found |
| "Add defense in depth" | Produces layers with no threat behind them, which is cost without risk reduction |
| "Threat model our system" | Too large. One boundary crossing per prompt, with the attacker's position stated |
| "Which of these is more secure?" | Underspecified. Name the attacker positions to compare against, or the answer is adjectives |
