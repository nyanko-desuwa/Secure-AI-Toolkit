# Prompt Examples

Prompts that produce structure instead of a pattern lecture. Each one names the scope, the level
of CQRS in play, and the shape of the answer wanted.

## Decide whether to split at all

```
I have a settings page: list, edit, save, one table, about 200 rows per tenant. Someone
proposed CQRS with a read model and a projector. Using skills/architecture/cqrs, tell me
which level this needs and what the split would cost. If level 0 or 1 is right, say so.
```

Why it works: it gives the shape of the data and the volume, which is what the decision turns on.
Without those numbers you get "it depends" or, worse, an enthusiastic yes.

## Review a projection schema

```
Read db/migrations/*_create_order_summary_view.sql. Does the projection carry tenant and
owner? For every consumer of order_summary_view, tell me whether an unscoped query is
possible. Cite A01 / API1:2023 / CWE-1220 where it applies.
```

Asking for "is an unscoped query possible" is stronger than "is it scoped". The first forces a
search for callers; the second gets answered from the one query in front of it.

## Find the second path to the data

```
The Invoice aggregate enforces that only a manager can see the fraud_score field. Find every
other path that reads that column - projections, views, reporting queries, exports, admin
tools. List each and say whether the same rule is enforced there.
```

This is the core question of this skill, phrased so it cannot be answered by reading the
aggregate.

## Check authorization against consistency

```
Grep for authorization checks that read from a *_view or *_projection table. For each one,
state the projection lag under load and what a revoked user can still do during that window.
```

## Review a command handler for idempotency

```
This handler is invoked from an SQS consumer. Show me what happens on redelivery. If dedup
exists, confirm the claim and the state change share one transaction. Do not accept a
SELECT-then-INSERT as a fix - explain the race if that is what you find.
```

The last sentence pre-empts the most common wrong answer. `CWE-367`.

## Audit the projector for retained state

```
Read src/projections/*.ts. For every module-level Map, Set, array, or cache, tell me what
grows per event and what bounds it. Classify each finding against
skills/architecture/performance leak shapes and give me the bounded rewrite.
```

## Cost a projection rebuild before running it

```
We need to add owner_id to order_summary_view, which has ~40M rows. Give me the rebuild plan:
new table plus swap, throttling, how readers switch over, how long a rollback takes, and what
breaks if the replay is still running at peak.
```

Asking for the rollback path is what separates a plan from an intention.

## Check the write-then-publish path

```
Search for places that call SaveChanges/commit and then publish to a broker. For each, tell
me what state the system is in if the process dies between the two calls, and whether the
failure is visible. Then show the outbox version.
```

## Event store erasure review

```
We store CustomerRegistered and ProfileUpdated events containing email and address. A
customer requested erasure. Walk me through what crypto-shredding does and does not solve
here, including backups, projections built before the request, and replay after the key is
gone. Flag the parts that are legal questions, not engineering ones.
```

## Anti-patterns

| Prompt | Problem |
|---|---|
| "Implement CQRS in this project" | No bounded context, no level. Produces folders and interfaces, not a decision |
| "Add event sourcing" | Conflates two patterns. Ask for the split first, and only then whether the log is the source of truth |
| "Make this scalable with CQRS" | Skips the measurement that decides whether reads and writes are actually asymmetric |
| "Create a read model for the dashboard" | Will produce a view joined from everything, with no tenant in the key |
| "Set up a projector for these events" | Gets an in-memory accumulator and an unbounded queue unless bounds are asked for |
| "Is my CQRS correct?" | No scope. Ask about one projection, one handler, or one query path |
| "Denormalise these tables for reads" | Denormalise is not a goal. Name the screen and the columns it needs |
| "Why is my read model out of date?" | Fine as a symptom, but pair it with the lag metric and the outbox state, or you get guesses |
