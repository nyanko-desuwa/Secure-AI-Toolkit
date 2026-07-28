# Common Mistakes

Every failure here passes review, because the folders are named correctly and the interfaces
exist. The fix counts only when it removes an option, not when it adds a comment.

## The first adapter carries the check, the second one does not

```typescript
// adapters/http/documents.ts
router.post("/documents/:id/publish", requireOwner, async (req, res) => {
  await publish(req.params.id);          // check lives in the middleware
  res.sendStatus(204);
});

// adapters/queue/retry-consumer.ts — added later
export async function onMessage(m: Message) {
  await publish(m.documentId);           // no owner, no tenant, no audit subject
}
```

The middleware knows one transport. `publish` is a public function that takes exactly what it
asks for, so the consumer author omitted nothing. `A01:2025`, `CWE-602`, `CWE-653`.

Fix: `publish(actor, cmd)` as a driving port, decision inside the use case. The consumer cannot
compile until it produces an actor from its own verified envelope. Residual gap: whatever factory
mints a system actor. Restrict it to the composition root and alert on its use.

## Validation lives in the domain, so every new adapter is an unvalidated entry point

```python
# core/document.py
class Document:
    def __init__(self, title: str) -> None:
        if len(title) > 200:            # the only length check in the system
            raise ValueError("title too long")
        self.title = title
```

The check is real but late and thin. The adapter already decoded a 40 MB body, allocated the
string, and passed unknown fields through. A CLI adapter that constructs `Document` from a CSV
row gets no schema, no unknown-field rejection, and no size bound. ASVS V2, `A06:2025`.

Fix: two layers with different jobs. The adapter bounds the request, parses to a schema, rejects
unknown keys, and produces a core command. The domain enforces business invariants on the way
in. Write the adapter test that sends an oversized body and asserts rejection before any parse.

Why the fix works: the adapter is where untrusted bytes stop being bytes. Putting shape checks
there means each new adapter has an obvious, reviewable place they must appear, and the domain
constructor stays a second line of defence rather than the only one.

## The actor is pulled from ambient state inside the core

```typescript
// core/use-cases/publish.ts
import { currentUser } from "../../adapters/http/request-context"; // arrow points outward

export async function publish(documentId: string) {
  const actor = currentUser();          // undefined in a worker, silently
  // ...
}
```

Two failures in one line. The core now imports an adapter, and the value is empty on any path
that is not an HTTP request — so a cron run either crashes or, worse, gets a partially filled
object and passes the check. `A01:2025`, `CWE-488`, `CWE-653`.

Fix: the actor is a parameter.

```typescript
// core/ports.ts
export interface DocumentService {
  publish(actor: Actor, cmd: PublishCommand): Promise<void>;
}
```

Why the fix works: a parameter cannot be omitted, and a compiler error is a better reviewer than
a convention. Go's `context.Value` and Node's `AsyncLocalStorage` both compile when empty, which
is exactly the property you do not want on an authorization input.

## The port accepts a query fragment

```python
class DocumentRepository(Protocol):
    def search(self, tenant_id: int, where: str) -> list[Document]: ...

# core, later
docs = repo.search(actor.tenant_id, f"title LIKE '%{query}%'")
```

The port promised a repository and delivered a SQL console. The injection surface now sits in the
core, where nobody looks for it, and the tenant argument is trivially escaped with an `OR 1=1`.
`A05:2025`, `CWE-89`.

Fix: intention-revealing methods with typed criteria.

```python
@dataclass(frozen=True)
class DocumentQuery:
    title_contains: str | None = None
    published: bool | None = None
    limit: int = 50

class DocumentRepository(Protocol):
    def search(self, tenant_id: int, q: DocumentQuery) -> list[Document]: ...
```

The adapter builds the statement with bound parameters and clamps `limit`. Why it works: there is
no string the core can hand over that the adapter will treat as syntax. See
`skills/core/database-security/`.

## The repository port hides an N+1

```typescript
const docs = await documents.listForTenant(actor.tenantId);
for (const d of docs) {
  d.author = await users.byId(d.authorId);      // one query per row
}
```

The ports are correct in isolation. Together they are 1 + N round trips, and the port abstraction
is precisely why nobody notices — the call site looks like a property access. `API4:2023`.

Fix: a port method that states the shape the core actually needs, `listForTenantWithAuthors`, or a
batch `byIds` call. Keep the tenant argument on both. Assert the query count in a test; a count
assertion is the only thing that survives a refactor. Detail in
`skills/architecture/performance/`.

## An interface per class, one implementation each

```
core/ports/DocumentRepositoryPort.java
core/ports/DocumentMapperPort.java
core/ports/DocumentValidatorPort.java
core/ports/DocumentIdGeneratorPort.java
```

Four interfaces, four implementations, four mocks, and not one of them is a boundary. The reader
opens eight files to follow one call. No security property was gained, and the navigation cost is
paid on every future change.

Fix: delete the interface unless it satisfies one of these — a second implementation exists or is
scheduled, the dependency cannot run in a test, the signature pins a security predicate such as
tenant plus actor, or the core would otherwise have to import infrastructure to compile. A port
that exists only to hold a check is legitimate; say so in a comment so the next person does not
"simplify" it away.

## A driving adapter is registered as a singleton while holding request state

```csharp
public sealed class HttpDocumentAdapter
{
    private Actor _actor = default!;            // set per request, read per request

    public void Bind(Actor actor) => _actor = actor;
    public Task Publish(Guid id, CancellationToken ct) => _svc.PublishAsync(_actor, id, ct);
}

builder.Services.AddSingleton<HttpDocumentAdapter>();
```

Under concurrency, request B overwrites `_actor` between A's `Bind` and A's `Publish`. Tenant A
publishes as tenant B. This is a correctness bug and a cross-tenant authorization failure, not a
leak. `A01:2025`, `CWE-488`.

The same shape appears with a captured connection or an ORM context: a singleton holding a scoped
`DbContext` pins the connection and the change tracker for the process lifetime, so a per-request
result set is retained forever. `CWE-772`.

Fix: register anything that touches request state at request scope, or keep the state out of
fields and pass it as a parameter. For a singleton worker, open one scope per message and dispose
it. Turn on the container's captive-dependency validation in CI. Residual gap: validation sees
constructor injection, not a factory delegate or a static — draw those by hand.

## A client is created inside the adapter method

```go
func (a *WebhookAdapter) Notify(ctx context.Context, e app.Event) error {
    client := &http.Client{Timeout: 5 * time.Second} // new pool per call
    // ...
}
```

Each client owns a transport, each transport owns a pool, and dropping the client strands sockets.
Under load the process exhausts file descriptors, and every unit test passes. `CWE-772`.

The inverse fails too: one `&http.Client{}` with no `Timeout` and no `IdleConnTimeout` accumulates
half-open connections and hangs a handler forever when the dependency stalls.

Fix: construct the client once at composition time with a bounded pool, idle recycling, and both a
handshake and a response timeout. Expose `Close`. Call it from the shutdown path. Why it works:
lifetime becomes a decision made once, in a place a reviewer can find, instead of an implicit
consequence of call frequency.

## A port returns a lazy stream nobody closes

```python
class DocumentRepository(Protocol):
    def stream_all(self, tenant_id: int) -> Iterator[Document]: ...

# core
for doc in repo.stream_all(actor.tenant_id):
    reindex(doc)
```

The iterator is backed by a server-side cursor and an open connection. If `reindex` raises, the
loop exits, the generator is never exhausted, and the cursor and connection stay checked out until
GC or never. The core cannot release what it does not know exists. `CWE-772`.

Fix: make the lifetime part of the contract. Either the port hands the core a context manager,

```python
class DocumentRepository(Protocol):
    def batches(self, tenant_id: int, size: int) -> AbstractContextManager[Iterator[list[Document]]]: ...
```

or it inverts control and the adapter owns the loop:

```python
class DocumentRepository(Protocol):
    def for_each(self, tenant_id: int, fn: Callable[[Document], None]) -> None: ...
```

Why it works: with a context manager the release is syntactically visible at the call site; with
inversion the resource never leaves the adapter that opened it. Hiding a resource behind a port
does not remove the obligation to release it. It removes the reminder.

## An in-memory adapter becomes the cache

```typescript
export class InMemoryPreviewStore implements PreviewStore {
  private readonly items = new Map<string, Preview>();   // no cap, no TTL, no eviction
  async put(k: string, v: Preview) { this.items.set(k, v); }
  async get(k: string) { return this.items.get(k) ?? null; }
}
```

Written as a test double, promoted to production because it was fast. Keys are derived from user
input, so the growth rate is attacker-controlled. `CWE-770`, `CWE-400`.

Fix: bound it. A maximum entry count, an eviction policy, a TTL, and the tenant in the key if the
values are tenant-specific. If a real cache is warranted, use one and keep the in-memory version
labelled for tests only. A map with no maximum is not a cache, it is a queue that never drains.

## The subscription is registered and never removed

```typescript
export class EventBridge {
  start() {
    this.bus.on("document.published", (e) => this.svc.reindex(e)); // no off()
  }
}
```

Each `start` adds a handler that captures the service and its whole dependency graph. Reconnects,
hot reloads, and per-request registration all multiply handlers, so one event triggers N calls and
the retained graph grows linearly. `CWE-401`, `CWE-400`.

Fix: the adapter returns its own teardown and the composition root owns it — subscribe in `start`,
unsubscribe in `stop`, drain in-flight work after unsubscribing, and wire `stop` to SIGTERM. Why
it works: registration and removal are the same object's responsibility, so the pair is reviewable
in one file.

## The test double bypasses what the real adapter enforces

```go
func (f *fakeDocs) FindOwned(_ context.Context, tenant, id, owner string) (*app.Document, error) {
    return f.byID[id], nil        // ignores tenant and owner entirely
}
```

The cross-tenant test passes because the fake returns the document, the use case's own check is
never exercised on realistic data, and the SQL adapter's predicate is never tested at all. Green
suite, zero evidence. `A06:2025`.

Fix: one contract test suite that both the fake and the real adapter must pass, including a case
where a document belongs to another tenant and the port must return nothing. Run the real adapter
against a container in CI. Treat the fake as a fast approximation, never as proof.

## A domain exception is rendered raw to the client

```typescript
try {
  await service.publish(actor, cmd);
} catch (e) {
  res.status(500).json({ error: String(e), stack: (e as Error).stack });
}
```

The response now carries the table name, the failing SQL, an internal document id from another
tenant, or the connection string from a driver error. `A10:2025`, `CWE-209`, ASVS V16.

Fix: translate at the adapter boundary, per adapter.

```typescript
const STATUS: Record<string, number> = {
  unauthenticated: 401, forbidden: 403, not_found: 404, invalid_request: 400, overloaded: 503,
};

function respond(res: Response, e: unknown, correlationId: string) {
  const code = e instanceof DomainError ? e.code : "internal_error";
  logger.error({ correlationId, err: e });          // detail stays server-side
  res.status(STATUS[code] ?? 500).json({ error: code, correlationId });
}
```

Why it works: the client receives a closed set of codes chosen deliberately, and the default for
anything unmapped is the least informative answer rather than the most. The correlation id keeps
support workable without exporting internals. Do not let a mapping table become an oracle either:
`not_found` and `forbidden` must be the same code where existence is sensitive.

## The async path drops the actor

```go
var work = make(chan app.PublishCommand, 100)

go func() {
    for cmd := range work {
        _ = svc.Publish(ctx, systemActor, cmd)   // whose request was this?
    }
}()
```

The handler accepted the request as a user and the worker performs it as the system. Every
authorization decision in the use case now evaluates against a principal the caller never had.
`A01:2025`, `CWE-1220`.

Fix: the queued value carries the actor alongside the command, and the worker passes it through.
If the work genuinely outlives the credential, capture a narrow delegated principal explicitly and
record that the delegation happened. Why it works: there is no path to the use case that does not
name a principal, so "process asynchronously" cannot quietly mean "process as root".

## Folders were renamed and nothing changed

```
src/
  core/         imports express, prisma, and the broker client
  adapters/     imports core internals and reaches around the ports
```

The hexagon is a directory listing. Nothing is enforced, so the second adapter will bypass
whatever the first one did. `A06:2025`, `CWE-653`.

Fix: enforce direction mechanically — project references, `import-linter` contracts, ESLint
`no-restricted-imports`, Go package boundaries, or a build target that compiles the core with no
framework on the path. Then add one test that fails when a forbidden import returns. A diagram
without an enforcement mechanism is a wish.

## Sources

- <https://alistair.cockburn.us/hexagonal-architecture/>
- <https://owasp.org/Top10/2025/>
- <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- <https://cwe.mitre.org/>
