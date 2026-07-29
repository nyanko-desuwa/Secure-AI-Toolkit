# CQRS Common Mistakes

What goes wrong, why it goes wrong, the fix, and why the fix holds. Several of these are the
wrong fix somebody reached for after hitting an earlier one.

## Applying it to everything

The mistake: a repository where every entity has a `Commands` folder, a `Queries` folder, a
handler per operation, and a projection - including the `Country` lookup table.

Why it happens: the pattern reads as a code layout, so it gets applied as one. An AI asked for
"CQRS" produces the folders because the folders are the visible part.

The fix: apply it to one bounded context, chosen because reads and writes there actually differ.
Everything else stays CRUD. Deleting the ceremony from twelve entities is a bigger and better
change than adding it to a thirteenth.

Why that works: the cost of CQRS is paid per bounded context, and so is the benefit. A context
with no read/write asymmetry pays and receives nothing.

## The read model is the write model with a different name

The mistake: `InvoiceDto` has the same fields as `Invoice`, and the projection is a row-for-row
copy of the table.

Why it happens: the split was adopted for its own sake, so there was never a read shape to
discover.

The fix: either delete the read model and query the table with an explicit column list, or find
the actual read shape - usually a join already done, a count already computed, a status already
translated. If neither, you are at level 0 and that is fine.

Why that works: the projection now earns the write amplification it costs. A copy costs the same
and buys nothing.

## Queries that write

The mistake: the query handler lazily builds a missing projection row, or bumps a `last_viewed_at`
column, or caches its own result in the read table.

Why it happens: it is convenient, and the read handler already has a database connection.

The fix: queries do not write. Build the row in the projector. Record view events as commands. If
a query needs a row that does not exist, return not found and let the projector catch up.

Why that works: once a query can write, the read path needs the write path's authorization rules,
and now the guard is in two places. It also means a read replica cannot serve it, which quietly
removes the scaling the split was for.

## Fixing missing tenant scoping with a code-review rule

The mistake: the projection has no tenant column, so the team adds "always filter by tenant" to
the review guidelines and a `// remember to filter` comment.

Why it happens: adding a column to a large projection means a backfill, and the deadline is
Friday.

The fix: tenant in the primary key, tenant as a required repository parameter, row-level security
underneath. `A01:2025`, `CWE-1220`.

Why that works: a guideline is checked by a human who is tired. A required parameter is checked by
the compiler on every build. The three layers fail independently, so forgetting one is survivable.

## Authorization in the query handler instead of the schema

The mistake: the query handler fetches rows and then filters them in application code.

```csharp
// Vulnerable: correct today, and correct only as long as every future caller copies it
var rows = await _db.QueryAsync<InvoiceRow>("SELECT ... FROM invoice_list_view");
return rows.Where(r => r.TenantId == actor.TenantId).ToList();
```

Why it happens: it reads naturally and the tests pass.

The fix: the predicate goes into the SQL and the tenant goes into the key.

Why that works: the filtered-in-memory version has already loaded every tenant's rows into the
process. A logging statement, an exception message, a debugger, or a `LIMIT` applied before the
filter all expose them. The database-side predicate never materialises the other rows.

## Trusting the tenant ID from the request

The mistake: `GET /invoices?tenantId=...`, and the handler uses it.

Why it happens: the read model needs a tenant, and the parameter is right there.

The fix: derive the tenant from the authenticated session. If a user legitimately belongs to
several tenants, the request may name which one, and the handler must then verify membership
against the authoritative store before using it.

Why that works: an identifier from the client is an input, not an identity. The membership check
is the difference between a selector and a grant.

## Making the projector synchronous to fix stale reads

The mistake: a user complained about a stale read, so the projector now runs inline in the command
transaction.

Why it happens: it works immediately and the bug closes.

The fix: return what the command knows so the client can render optimistically, or route that
user's reads to the write store briefly, or return a version the client can wait for.

Why that works: the synchronous projector has recoupled the two sides. A projector failure now
fails the command, projection count now multiplies command latency, and you kept the complexity of
the split while losing its independence. If synchronous projection is genuinely acceptable, you
wanted level 2 - same transaction, same database, no broker - and should say so.

## Ignoring eventual consistency in an authorization check

The mistake: a permission read model, because permission checks are hot.

Why it happens: reading permissions from the write store on every request looks expensive.

The fix: read the authoritative store, with a short explicit TTL cache in front if measurement
justifies it.

Why that works: a TTL is a number you chose and can defend. Projection lag is a number the queue
chooses for you, and under exactly the load where an incident is happening it is at its worst.
Revocation that takes effect "eventually" is not revocation. `A01:2025`, `A06:2025`.

## Duplicate events treated as a broker bug

The mistake: a projection double-counts, and the response is a support ticket with the broker
vendor.

Why it happens: "exactly-once delivery" appears in a lot of marketing.

The fix: a sequence or version guard in the projector upsert, so applying an event twice is a
no-op.

```sql
-- Fixed: the guard is in the statement, not in the consumer's discipline
ON CONFLICT (tenant_id, order_id) DO UPDATE
  SET total = order_total_view.total + EXCLUDED.total,
      last_event_seq = EXCLUDED.last_event_seq
WHERE order_total_view.last_event_seq < EXCLUDED.last_event_seq;
```

Why that works: at-least-once is the guarantee any outbox relay or broker actually provides.
Idempotent handlers make that guarantee sufficient. Waiting for exactly-once means waiting
forever.

## Unbounded projector state

The mistake: a map, a dictionary, or a list on the projector, keyed by entity, that grows with the
business rather than with concurrency.

Why it happens: the aggregation is easier to express in memory, and in development the dataset is
small.

The fix: keep the running state in the projection row and let the upsert do the arithmetic. If
in-memory state is needed for throughput, cap it with a size and a TTL and make correctness
independent of it.

Why that works: memory now scales with the cap instead of with total entities. Detail on bounds
and diagnosis is in `skills/architecture/performance/` - L1, unbounded cache, `CWE-401`.

## Dual write treated as good enough because it usually works

The mistake: commit, then publish. It works in testing and in most of production.

Why it happens: the failure is invisible. There is no error, no exception, no alert - just a
projection row that never updated.

The fix: outbox table, written in the same transaction, published by a relay.

Why that works: there is no window between the two writes because there is only one write. The
remaining failure mode - a duplicate publish - is one the projector's sequence guard already
handles. `A08:2025`.

## Rebuilding a projection by truncating it

The mistake: `TRUNCATE invoice_list_view;` then replay.

Why it happens: it is the shortest path and works fine on a laptop.

The fix: build `invoice_list_view_v4` alongside the live one, verify row counts and a sample, then
switch the reader.

Why that works: readers never see an empty table. The rollback is a config change rather than
another replay. In production the truncate version is a read outage lasting exactly as long as the
replay, and you will not know how long that is until you are in it.

## Projector with side effects

The mistake: the projector that updates the read model also sends the confirmation email.

Why it happens: the projector already has the event, and the email needs the same data.

The fix: separate the process that maintains state from the process that acts on events. The
projector is replayable; the notifier is not.

Why that works: a rebuild resends every email ever sent. That is not a hypothetical - it is the
classic event-sourcing production incident.

## Event store holding plaintext personal data

The mistake: `CustomerRegistered { email, fullName, dateOfBirth }` in an append-only log, then an
erasure request arrives.

Why it happens: events are supposed to be immutable, and immutability was treated as a licence to
store anything.

The fix: encrypt per-subject payloads with a key held outside the event store, and delete the key
on erasure. Do not put personal data in an event you cannot re-key.

Why that works: erasure becomes a key deletion, which is a single mutable operation on a mutable
store. Limitations to state, not hide: backups hold the key until retention expires, structural
residue remains, replay must tolerate undecryptable payloads, and whether this satisfies GDPR
Article 17 in your jurisdiction is a legal question. `A04:2025`, ASVS V11, V14.

## Denormalising by joining everything

The mistake: one wide view with every column from every joined table, on the theory that the read
model should be denormalised.

Why it happens: "denormalised read model" is heard as "one big view".

The fix: one projection per read shape, with the columns that shape needs.

Why that works: the wide view ships internal fields to whoever queries it, and a new column on any
source table silently joins the API contract. `API3:2023`, `CWE-213`. The narrow projection cannot
leak a column it does not have.

## Command IDs generated server-side

The mistake: the handler generates the command ID, then deduplicates on it.

Why it happens: it looks tidy, and validation of a client-supplied ID feels like extra work.

The fix: the client generates the ID and reuses it on retry. Validate it as a UUID.

Why that works: a server-generated ID is different on every retry, so it deduplicates nothing. The
whole point is that the retry carries the same identity as the original. `CWE-837`.

## Sources

- <https://martinfowler.com/bliki/CQRS.html>
- <https://microservices.io/patterns/data/transactional-outbox.html>
- <https://owasp.org/Top10/2025/>
- <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
