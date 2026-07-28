# Prompt Examples

Prompts that produce ports and adapters rather than folders named after them. A good prompt names
the driving adapters, the actor, the driven dependencies, the resource lifetime, and the cost to
report.

## Design One Use Case With Two Driving Adapters

```text
Design a CancelSubscription use case in Go. Driving adapters: an HTTP handler and a queue
consumer that handles a dunning failure. Driven ports: a subscription repository and a payment
provider. Requirements: the driving port takes an Actor as a required parameter, credential
verification and payload parsing happen in each adapter, the authorization decision happens in
the use case, and the payment client is created once at composition time with a bounded pool and
a Close. Report query count and who closes what on shutdown.
```

Why it works: two adapters force the check behind the port, and asking for the client lifetime
stops the adapter from constructing an HTTP client per call.

## Inventory the Ports That Actually Exist

```text
Read src/core and src/adapters. List every driving port with each adapter that calls it, and
every driven port with each adapter that implements it. Do not use folder names — use the import
graph. Flag any port with exactly one adapter and no security or testability reason to exist, and
any core file that imports a transport, ORM, or broker package.
```

Ask for the real graph. Otherwise the answer restates the intended architecture.

## Find the Second-Adapter Bypass

```text
For every mutating use case, list every caller: HTTP handler, queue consumer, CLI, scheduled job,
admin script, test. For each, show where the identity comes from and where actor plus intent are
authorized. Flag any check that exists in only one adapter as A01:2025 / CWE-602. Treat a
verified credential as authentication, not authorization.
```

## Move Validation to the Inbound Adapter

```text
For each inbound adapter, show where the transport payload is parsed into a core command. Require
a schema that rejects unknown fields, a body size limit, and a mapping that never copies a
client-supplied tenant or role. Flag any validation that lives in the core and would therefore be
duplicated or skipped by a new adapter. Map missing input constraints to ASVS V2.
```

## Audit an Outbound Adapter That Takes a User URL

```text
Review the link-preview adapter. Show scheme allowlisting, resolution of every returned address
against private and link-local ranges, redirect handling, connect and read timeouts, a byte cap
on the response, and schema validation before the response becomes a domain value. State whether
a DNS rebinding window remains and what would close it. Map to A06:2025 / API7:2023 / CWE-918.
```

## Audit Adapter Resource Lifetime

```text
For every adapter: where is the client, connection, or subscription created; is it per call or
per process; what bounds it; and who releases it on shutdown. List every subscribe call and its
matching unsubscribe. List any queue, channel, or buffer between an inbound adapter and the core
and give its capacity and its behaviour when full. Map unbounded cases to CWE-770 and unreleased
ones to CWE-772.
```

## Check Error Translation at the Boundary

```text
Trace every error path from a driven adapter through the core to each inbound adapter's response.
Show where a driver error, stack trace, SQL fragment, or upstream body could reach a client. The
core must return typed domain errors; each adapter maps them to a transport status and a stable
code, with the detail logged and correlated instead of returned. Map leakage to A10:2025 /
CWE-209.
```

## Write the Abuse Test

```text
For the DocumentService driving port, write table-driven tests using a fake repository: a
different user in the same tenant, the same user id in a different tenant, an empty actor, and an
actor claiming an admin role it was not granted. Assert both the returned error and that no state
changed. Then state which assertions depend on the fake and would need the real adapter to be
trustworthy.
```

## Review DI Registration for Captive State

```text
List every adapter registration with its lifetime. For each singleton, list what it captures and
flag any actor, tenant, request, session, connection, or cursor. Show the cross-tenant path that
results, the corrected registration, and how a worker opens one scope per message. Do not disable
scope validation.
```

## Decide Whether to Use the Pattern

```text
This service has one HTTP entry point, one Postgres table, no third-party calls, and no scheduled
work. Compare ports and adapters against the framework's own idioms. Count files, interfaces with
one implementation, and enforcement points for each option. Recommend the simpler one unless a
concrete second entry point or an untestable dependency exists. Name the trigger that would
justify migrating later.
```

## Verify Before Returning

```text
Run skills/architecture/hexagonal/checklist.md against this change. Mark each applicable item
pass or fail with file:line evidence, and give one sentence for anything not applicable. Report
unverified runtime behaviour — client timeouts, container scope validation, query counts, real
adapter tests — as unverified rather than pass.
```

## Anti-Pattern Table

| Prompt | What it produces | Better constraint |
|---|---|---|
| "Make this hexagonal" | Folders named ports and adapters, one interface per class | Name the driving adapters, the actor, and the driven dependencies |
| "Add a repository interface" | Generic CRUD, or a query builder returned to the caller | Ask for intent-revealing methods with tenant scope and a materialized result |
| "Extract an interface for testability" | An interface with one implementation and a mock | Ask which untestable dependency or security check it isolates |
| "Secure the endpoint" | A guard on one adapter, bypassed by the next one | Require the actor in the port signature and the decision in the use case |
| "Add validation to the domain" | Rules the next adapter skips before reaching them | Format and shape at the inbound adapter; invariants in the domain |
| "Pass the request into the service" | A transport type in the core, permanently | Map to a command in the adapter; no framework type crosses the port |
| "Use context to carry the current user" | Ambient identity that compiles when empty | Actor as a required parameter; context carries deadlines only |
| "Make the adapter a singleton for performance" | A captured tenant or connection, shared | Inventory what it holds and prove process lifetime |
| "Wrap the HTTP client" | A wrapper with no bound, no timeout, no Close | Specify pool caps, timeouts, and shutdown ownership |
| "Fetch the URL the user gave us" | SSRF through a driven port | Require address checks, no redirects, byte cap, and schema validation |
| "Return the repository's stream" | An open cursor the core cannot close | Callback-style port, or a bounded page |
| "Add a queue so it responds faster" | Unbounded buffer an anonymous caller can grow | Bounded capacity, explicit full behaviour, actor carried with the job |
| "Mock the repository" | A permissive fake that proves nothing | One contract suite the fake and the real adapter both pass |
| "Show the error to help debugging" | Driver text and stack traces in the response | Typed domain errors, translated per adapter, detail logged |

## Prompt Review Rule

Reject a generated design that cannot answer all six.

1. Which driving ports exist, and which adapters call each one?
2. Where does the Actor come from in every adapter, and is it a required parameter?
3. Where is the authorization decision, and does it hold for an adapter added next year?
4. What does each inbound adapter reject, and what does each outbound adapter refuse to return?
5. What does each adapter acquire, what bounds it, and who releases it?
6. What does each new interface cost, and what is its second implementation?

If the answer is a folder tree and no numbers, the prompt produced a diagram.
