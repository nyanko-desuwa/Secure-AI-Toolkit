# Troubleshooting

Use this when ports and adapters conflict with the framework, the existing codebase, or the
measured cost. Do not resolve a mismatch by adding a port whose purpose nobody can name.

## The codebase has no ports at all

Do not restructure the repository in one pass. Take one use case that has, or is about to have,
a second entry point and convert only that slice.

1. Extract a driving port interface with the actor as the first parameter.
2. Move the authorization decision from the handler into the implementation behind the port.
3. Replace the handler's direct database calls with one driven port.
4. Write the denial test against the port with a fake driven adapter.
5. Add an import-direction check before converting the next slice.

Both shapes are now present. Say so in the pull request, and forbid new code on the old path.
A repository-wide folder move produces a diff where every import changed and no reviewer can
tell whether a check moved or disappeared.

## The framework owns the entry point and wants to own the core

Web frameworks want to inject their request type, their DI container, and their annotations. You
have three options, in descending order of boundary strength.

- Keep a hand-written adapter that maps the framework request to a command. Strongest, one file
  per endpoint, and the framework can be replaced.
- Let the framework bind directly to a request DTO defined in the adapter package, then map that
  DTO to a core command. Slightly cheaper, still no framework type in the core.
- Annotate core commands with the framework's binding attributes. The core now has a compile-time
  framework dependency and its wire schema is its domain schema, which is how mass assignment
  gets in. Only acceptable when you are not claiming a boundary.

Never accept the framework's request type in a port signature. That single decision ends the
pattern, because every future adapter has to fabricate a request object.

## A port has one adapter and always will

Delete the interface unless one of these is true.

- The port exists to hold a security check that every entry point must pass. Comment it as such.
- The dependency cannot be run in a test: a payment provider, an SMTP server, the wall clock, a
  random source, a secret manager.
- The core package otherwise cannot compile without importing infrastructure.
- A second adapter exists or is scheduled, not merely imaginable.

Otherwise you have added a file, a mock, and one indirection between a reader and the code. Call
the concrete type. See `SKILL.md` for the honest test.

## The second adapter is a test harness and nothing else

That is a legitimate reason for the port, and it is also where the pattern quietly fails. A fake
that is more permissive than the real adapter turns a green suite into false confidence.

Write one contract test suite and run it twice: once against the fake, once against the real
adapter with a container-backed dependency in CI. If the real adapter cannot run in CI, say so
and treat every assertion that depends on it as unverified. Do not claim the port is tested when
only the fake is.

## Authorization needs data the port does not return

Do not move the decision to the adapter because the query is inconvenient. Add a driven port
method that returns the policy inputs, or widen the existing one to return the facts the decision
needs.

Watch the cost. Fetching policy facts inside a loop over N entities is N+1 round trips before any
work happens. Batch the facts into one call, or add a read port that returns the decision inputs
for a page in a single query. The read port must still scope by tenant. Query-count diagnosis is
`skills/architecture/performance/`.

## Two driving ports need the same check

Extract a domain policy object that both use cases call with the actor and intent-specific facts.
Do not create `Authorizer.can(actor, action, resource)` with string actions — reviewers lose the
ability to see what a use case requires, and granularity drifts until "document:*" is somebody's
role. `CWE-1220`.

Keep the default deny. An action the policy does not recognise is denied, not allowed.

## The job has no human actor

Authorization is still required. Pick one and record which.

- A delegated actor captured when the work was scheduled, if staleness is acceptable and the
  permission is re-checked at execution time.
- A narrow service principal with the exact permissions the job needs, and no others.
- A tenant-scoped system actor whose construction is restricted to the job package and audited.

Never reuse the last request's actor from ambient state, and never invent a superuser to get past
the check. A "system" role that can do everything is the hole the port was supposed to close.

## The driven port returns a stream and nobody closes it

The port hides the handle, so the core has no idea a resource is open. Three fixes, in order of
preference.

1. Invert it. The core passes a callback; the adapter owns the loop and closes the handle in a
   `defer`, `finally`, or `with`. The lifetime never leaves the adapter.
2. Return a type that carries an explicit release, and make the core's use of it lexically
   scoped. Reviewable, but relies on discipline.
3. Return a bounded page. If the result fits in a page with a server-side maximum, there is no
   stream to leak.

Hiding a resource behind a port does not remove the obligation to release it. It removes the
reminder. `CWE-772`.

## The DI container rejects the adapter registration

Believe it. A captive dependency — a singleton adapter holding something request-scoped — is
usually a cross-tenant correctness bug before it is a leak.

- Make the adapter scoped if it holds an actor, a tenant, a connection, or a cursor.
- Keep the adapter singleton and pass the request-scoped value as a method parameter.
- For a singleton worker, inject a scope factory and open one scope per message.

Do not disable scope validation. If your container does not detect captive dependencies, draw the
graph by hand: search adapter constructors for actor, tenant, request, session, connection, and
cursor types. Then add a test that resolves two scopes with different tenants and asserts the
instances and results differ.

## Mapping shows up in the profile

Prove it first, with representative payload sizes. Then, in this order: replace reflection or
convention mapping with hand-written or generated mapping; project read queries straight into the
response DTO instead of building a domain object; skip the domain object entirely on read-only
paths; page the result.

Do not delete the mapping to save an allocation. That trades a measured CPU cost for an unbounded
response schema and a transport type in the core.

## The repository port hides an N+1

Count before fixing. A page of 100 documents plus one author lookup per document is 101 queries;
add one tag lookup and it is 201. The port did not cause this, but it made it invisible.

Options: batch the child IDs into one call, eager-load one bounded relation, or add a read port
that returns a projection in a single query. Assert the count in a test. Returning a query builder
from the port is not a fix — it moves query construction past the boundary and makes the tenant
predicate optional. `A01:2025`, `CWE-653`.

## The core needs the current time, a random value, or an ID

These are driven ports, not utilities. `Clock`, `IDs`, `Random`. A core that calls
`time.Now()` directly cannot be tested at a boundary condition, and a core that generates its own
token cannot have that generation audited or swapped for a vetted source.

Keep them tiny and keep them one-way. A `Clock` port that also formats for display has become a
presentation dependency.

## Hexagonal is wrong for this feature

Say it and simplify. A CRUD endpoint with no invariant can be a handler plus a tenant-scoped
query with explicit response fields. A report can be SQL to a DTO. A one-shot script can have one
visible check.

The security requirements survive the simplification: identity from a verified credential, tenant
from that identity, explicit writable and readable fields, bounded queries, a timeout, and a
released connection. Folders are not the control.

## Runtime behaviour cannot be verified from source

State the unknown and the test that would settle it.

- "The port passes a deadline; whether the vendor client honours it is unverified."
- "The adapter checks resolved addresses, but the client re-resolves at connect time, so a
  rebinding window may remain."
- "Registration looks singleton-safe; I did not boot the container to confirm."
- "The fake enforces tenant scoping; the SQL adapter was not run against a database here."

Unverified is neither safe nor unsafe. It is unverified, and saying so is part of the report.
