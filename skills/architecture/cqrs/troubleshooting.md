# CQRS Troubleshooting

What to do when the split does not fit, conflicts with a constraint, or has already been applied
badly.

## The codebase already has CQRS everywhere and it is unusable

Do not rewrite it in one change. Work per bounded context:

1. Find the contexts where the read shape equals the write shape. Those are the collapse
   candidates.
2. Collapse the query side first - replace the projection with a query against the write tables
   with an explicit column list. The command side can stay as it is.
3. Delete the projector, then the broker topic, then the read table. In that order, so nothing is
   reading a table you removed.
4. Leave the contexts where the asymmetry is real.

Report it as a reduction, not a rewrite. "Six of nine contexts do not need a read model" is a
reviewable claim.

## Nobody can say where authorization is enforced

This is the state that must be resolved before any structural change. Answer it empirically:

- Grep for the tenant column and for the owner column across the whole repository. Every
  occurrence and every absence is data.
- List every path that reaches the read tables: query handlers, reporting jobs, exports, admin
  tools, migrations, ad-hoc scripts, BI connections.
- For each, name what scopes it. If nothing does, that is the finding.

If the count of paths is large, add row-level security first. It is the only control that covers
paths you have not found yet. Then fix the repository signatures.

## A stale read is causing a support ticket

Establish the size of the lag before choosing a fix. Without the number you cannot tell a design
problem from a load problem.

- Emit `now() - max(event_occurred_at)` per projection as a gauge. If that metric does not exist,
  that is the first fix.
- If lag is normally milliseconds and spikes to minutes under load, the problem is projector
  throughput or an unbounded queue, not the pattern.
- If lag is normally seconds, the design assumed something that is not true, and the affected read
  needs one of the read-your-own-write options in
  [best-practices.md](best-practices.md#reading-your-own-write).

Do not make the projector synchronous. That is covered in
[common-mistakes.md](common-mistakes.md#making-the-projector-synchronous-to-fix-stale-reads).

## An invariant needs data from two aggregates

The projection is the tempting place to check it, and the projection is the wrong place - it is
eventually consistent, so the check is a race.

Options, in order:

1. Reconsider the aggregate boundary. If two things must be consistent at the same instant, they
   may be one aggregate.
2. Enforce it in the authoritative store with a constraint or a conditional `UPDATE`.
3. Accept the race and add a compensating action - detect the violation from events and correct it.
   This is only acceptable when the business can tolerate a temporary violation. Overselling a
   seat sometimes can be; granting a permission cannot.

Say which one you chose and why. A check against a projection presented as an invariant is the
failure mode this skill exists to catch.

## The read model must be consistent for a specific screen

Route that screen to the write store. There is no rule that every read goes through the projection.
A tuned query with an explicit column list against the authoritative tables is a normal answer for
the small number of screens that need immediate consistency.

If most screens need it, you are at level 1 or 2 and the async projection is not earning its cost.

## Two standards or two guides disagree

Prefer the more security-focused option and say you made the call. Specifically:

- Performance guidance may say to cache permissions in the read model. This skill says do not.
  Security wins: use a short explicit TTL against the authoritative store instead.
- Some CQRS material presents the aggregate as the only authorization point. This skill treats the
  query side as a second enforcement point that needs its own control. Follow this skill; a
  read-only path still reads data.

## Row-level security is not available

Managed databases without RLS, or a store like DynamoDB or a document database, change the tooling
not the requirement. Compensate:

- Make the tenant the partition key so a query without it cannot be issued.
- Wrap all read access in one module and forbid raw client access by review and by dependency
  direction.
- Add a test that asserts a cross-tenant read returns nothing, seeded with two tenants.

State the residual gap plainly: without a database-level control, a new code path can still bypass
the wrapper. That is a real limitation, not a formality.

## The projector cannot keep up

Diagnose before scaling. Ordering constraints are what usually bite.

- Partition by aggregate or tenant so multiple projector instances can run without reordering
  events for the same entity. Global ordering plus parallelism cannot both hold.
- Batch the upserts. One statement per event into a remote database is usually the bottleneck.
- Check for an N+1 in the projector - an event handler that reads a related row per event.
  `skills/architecture/performance/` covers this.
- Confirm the queue is bounded. An unbounded queue hides the problem until the process is killed.

## A replay has to run in production

Treat it as a planned operation. Estimate rows times per-row cost first; if the answer is hours,
it needs a runbook and a window, not a deploy step.

Build into a versioned new table, throttle it, verify counts and a sample against the old table,
then switch readers. Keep the old table until the new one has served traffic for a full business
cycle. Details in [best-practices.md](best-practices.md#replay-cost).

If the replay is needed because the projection is missing a column that carries authorization data,
add the column with a nullable default and backfill in place instead. A full replay to add
`owner_id` is a large operation for a small change.

## An erasure request arrives and events hold personal data

The order matters:

1. Identify every event stream and every projection holding data for that subject.
2. Delete the per-subject key if crypto-shredding is in place. If it is not, you have a design
   problem, not an operations problem - say so rather than improvising a targeted delete.
3. Purge or rebuild the affected projections. A projection built before erasure may still hold
   plaintext.
4. Record what remains: structural residue in the stream, and the backup retention window during
   which the key still exists.

Whether this satisfies GDPR Article 17 in your jurisdiction is a legal question. Provide the
technical facts and let counsel decide. Do not assert compliance.

## You cannot verify the claim from source

Common cases, and what to say:

- Projection lag: invisible in source. It depends on broker throughput, projector deployment, and
  load. Report the missing bound or the missing metric, not a lag figure.
- Whether the outbox relay is actually running: deployment state. A correct outbox table with no
  relay deployed is worse than no outbox, because it looks right.
- Whether RLS is enabled in the live database: a migration in the repository is not proof it ran.
- Whether replay is side-effect free: requires reading every handler. If you read three of eleven,
  say three of eleven.

Report the precondition you could not check. An unverified claim stated confidently is the thing
that makes a review worthless.
