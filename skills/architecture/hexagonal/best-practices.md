# Ports and Adapters: Patterns

Each pattern names the security boundary it creates and the runtime cost it adds. Code is Go
and TypeScript, with Java where the ceremony is instructive.

## Driving Ports Take the Actor

`A01:2025` · `CWE-602`, `CWE-653` · ASVS V8

A driving port method that does not take an actor cannot enforce ownership. The core has to
trust that somebody upstream checked, and "somebody upstream" is a different somebody per
adapter.

```go
// Vulnerable: the port cannot express who is asking, so the HTTP adapter
// is the only place ownership can be checked — and it is the only adapter that does.
package app

type DocumentService interface {
    Publish(ctx context.Context, docID string) error
}
```

```go
// Fixed: identity is a required parameter. No adapter can call this without one.
package app

// Actor is a core type. It is built by an adapter from a verified credential
// and never carries transport data.
type Actor struct {
    UserID   string
    TenantID string
    Roles    []string
}

type DocumentService interface {
    Publish(ctx context.Context, actor Actor, cmd PublishCommand) error
}

type service struct {
    docs  DocumentRepository // driven port
    clock Clock              // driven port
    log   AuditLog           // driven port
}

func (s *service) Publish(ctx context.Context, actor Actor, cmd PublishCommand) error {
    if actor.UserID == "" || actor.TenantID == "" {
        return ErrUnauthenticated // fail closed: an empty actor is not an anonymous one
    }

    doc, err := s.docs.FindOwned(ctx, actor.TenantID, cmd.DocumentID, actor.UserID)
    if err != nil {
        return err
    }
    if doc == nil {
        return ErrNotFound // same answer for missing and not-yours
    }

    if err := doc.Publish(s.clock.Now()); err != nil {
        return err
    }
    if err := s.docs.Save(ctx, actor.TenantID, doc); err != nil {
        return err
    }
    s.log.Record(ctx, actor, "document.publish", doc.ID, "allowed")
    return nil
}
```

Why the signature matters more than the check: a check can be forgotten, a parameter cannot
be omitted. Every new adapter — a queue consumer written next quarter, a CLI written for a
migration — has to produce an `Actor` before it can compile. That is the difference between a
boundary and a convention.

Do not reach for `context.Value` to carry the actor. It compiles when empty, so the compiler
stops helping and you are back to a convention. Context carries cancellation and deadlines.

Cost: one struct copy per call. Nothing measurable. The `FindOwned` variant costs an extra
predicate in the WHERE clause, which is cheaper than fetch-then-compare because the row never
enters memory unauthorized.

## Every Adapter Is a Trust Boundary

`A01:2025` · ASVS V4, V8

The same use case, three driving adapters. Notice that not one of them makes an authorization
decision — they each construct an `Actor` from whatever credential their transport carries,
and hand it over.

```go
// Driving adapter 1: HTTP. Credential is a bearer token.
func (h *HTTPHandler) publish(w http.ResponseWriter, r *http.Request) {
    claims, err := h.tokens.Verify(r.Header.Get("Authorization"))
    if err != nil {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }

    var body struct{ DocumentID string `json:"documentId"` }
    dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
    dec.DisallowUnknownFields()
    if err := dec.Decode(&body); err != nil {
        http.Error(w, "invalid_request", http.StatusBadRequest)
        return
    }

    actor := app.Actor{UserID: claims.Subject, TenantID: claims.Tenant, Roles: claims.Roles}
    err = h.svc.Publish(r.Context(), actor, app.PublishCommand{DocumentID: body.DocumentID})
    writeErr(w, err) // maps core errors to status codes, ErrNotFound -> 404
}
```

```go
// Driving adapter 2: queue consumer. Credential is a signed message envelope.
// This is the adapter that bypassed authorization when the check lived in the HTTP handler.
func (c *Consumer) handle(ctx context.Context, msg Message) error {
    env, err := c.verifier.Open(msg.Body) // reject unsigned or expired envelopes
    if err != nil {
        return c.deadLetter(ctx, msg, err) // do not retry a forgery
    }

    actor := app.Actor{UserID: env.OnBehalfOf, TenantID: env.Tenant, Roles: env.Roles}
    return c.svc.Publish(ctx, actor, app.PublishCommand{DocumentID: env.DocumentID})
}
```

```go
// Driving adapter 3: scheduled job. There is no human, so the actor is explicit and narrow.
func (j *ScheduledPublisher) run(ctx context.Context) error {
    for _, task := range j.due(ctx) {
        actor := app.Actor{
            UserID:   task.RequestedBy, // the human who scheduled it, not "system"
            TenantID: task.Tenant,
            Roles:    []string{"scheduler"},
        }
        if err := j.svc.Publish(ctx, actor, app.PublishCommand{DocumentID: task.DocumentID}); err != nil {
            j.log.Error("scheduled_publish_failed", "doc", task.DocumentID, "err", err)
        }
    }
    return nil
}
```

A job that invents a superuser actor to get past the check has reintroduced the hole with
extra steps. If the job legitimately acts without a user, give it a distinct role and let the
core policy decide what that role may do — `CWE-1220` is what you get when "system" means
everything.

Cost: none structurally. Three adapters is three files that must each be reviewed for
credential verification, which is real work — but it is work you were doing anyway, now
visible.

## Mapping Belongs in the Adapter

`A01:2025`, `A06:2025` · ASVS V2

The moment a transport type crosses into the core, the boundary is gone. The core starts
reading headers, and every future adapter must fake an HTTP request to call it.

```typescript
// Vulnerable: the core takes a framework request. It now trusts a header
// that only one adapter can set, and only one adapter can ever call it.
export async function publishDocument(req: Request): Promise<void> {
  const tenant = req.headers["x-tenant-id"] as string; // client-controlled
  const doc = await repo.find(req.params.id, tenant);
  // ...
}
```

```typescript
// Fixed: the port speaks in core types only.
// core/ports.ts
export interface Actor {
  readonly userId: string;
  readonly tenantId: string;
  readonly roles: readonly string[];
}

export interface PublishCommand {
  readonly documentId: string;
}

export interface DocumentService {
  publish(actor: Actor, cmd: PublishCommand): Promise<void>;
}

// adapters/http/documents.ts — mapping and rejection live here
import { z } from "zod";

const Body = z.object({ documentId: z.string().uuid() }).strict();

router.post("/documents/publish", async (req, res) => {
  const session = await verifySession(req); // throws -> 401
  const parsed = Body.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "invalid_request" });

  const actor: Actor = {
    userId: session.userId,
    tenantId: session.tenantId, // from the verified session, never from a header
    roles: session.roles,
  };

  try {
    await service.publish(actor, parsed.data);
    res.status(204).end();
  } catch (e) {
    res.status(statusFor(e)).json({ error: codeFor(e) });
  }
});
```

The tenant comes from the verified session because a header is an input. This is the same
mistake as `CWE-602` in a different costume: the server delegates a security decision to
something the client controls.

Cost: one mapping per direction per adapter, and a DTO type that duplicates some fields of a
core type. That duplication is the price of the boundary. Reusing the core type as the wire
type is how mass-assignment bugs get in — the wire schema must be explicit about what a
client may set.

## Driven Ports Define What the Core Expects

`A06:2025` · `CWE-918`, `CWE-502` · ASVS V2, V12

A driven port is a promise stated by the core. The adapter is where the outside world is
forced to keep it, including by refusing it.

```typescript
// core/ports.ts — the core asks for a document, not for an HTTP response
export interface LinkPreview {
  readonly title: string;
  readonly contentType: string;
  readonly bytes: number;
}

export interface LinkPreviewFetcher {
  /** Rejects with UnreachableTarget for anything not publicly routable. */
  fetch(url: string): Promise<LinkPreview>;
}
```

```typescript
// adapters/outbound/link-preview.ts
import { Agent, request } from "undici";
import { lookup } from "node:dns/promises";
import { isIP, BlockList } from "node:net";
import { z } from "zod";

const blocked = new BlockList();
blocked.addSubnet("10.0.0.0", 8);
blocked.addSubnet("172.16.0.0", 12);
blocked.addSubnet("192.168.0.0", 16);
blocked.addSubnet("127.0.0.0", 8);
blocked.addSubnet("169.254.0.0", 16); // cloud metadata
blocked.addSubnet("::1", 128, "ipv6");
blocked.addSubnet("fc00::", 7, "ipv6");

// One agent per process. Bounded, with idle recycling.
const agent = new Agent({
  connections: 32,
  keepAliveTimeout: 10_000,
  keepAliveMaxTimeout: 60_000,
  connect: { timeout: 2_000 },
});

const Meta = z.object({ title: z.string().min(1).max(300) }).strict();

export class EgressGuardedFetcher implements LinkPreviewFetcher {
  async fetch(rawUrl: string): Promise<LinkPreview> {
    const url = new URL(rawUrl);
    if (url.protocol !== "https:") throw new UnreachableTarget("scheme");

    // Resolve and check every address, not just the first.
    const addrs = isIP(url.hostname)
      ? [{ address: url.hostname, family: isIP(url.hostname) }]
      : await lookup(url.hostname, { all: true });
    for (const a of addrs) {
      if (blocked.check(a.address, a.family === 6 ? "ipv6" : "ipv4")) {
        throw new UnreachableTarget("private_address");
      }
    }

    const res = await request(url, {
      dispatcher: agent,
      maxRedirections: 0,          // a permitted host must not forward us inward
      headersTimeout: 2_000,
      bodyTimeout: 3_000,
    });
    if (res.statusCode !== 200) throw new UnreachableTarget("status");

    // Bound the read. A 10 GB response must not become a 10 GB string.
    const cap = 64 * 1024;
    let size = 0;
    const chunks: Buffer[] = [];
    for await (const chunk of res.body) {
      size += chunk.length;
      if (size > cap) { res.body.destroy(); throw new UnreachableTarget("too_large"); }
      chunks.push(chunk as Buffer);
    }

    // Validate before it becomes a domain value.
    const meta = Meta.safeParse(extractMeta(Buffer.concat(chunks).toString("utf8")));
    if (!meta.success) throw new UnreachableTarget("unparseable");

    return {
      title: meta.data.title,
      contentType: String(res.headers["content-type"] ?? "application/octet-stream"),
      bytes: size,
    };
  }
}
```

Why this belongs in the adapter and not the core: the core has no concept of an IP address or
a redirect. If SSRF defence lived in the use case, every driven adapter would need to repeat
it, and a new adapter would silently skip it. One adapter, one place to audit.

Honest limitation: resolve-then-connect leaves a DNS rebinding window, because `undici`
resolves again for the connection. Closing it means pinning the checked address into the
connection, or putting an allowlisting egress proxy in front. Say which one you did.

Never deserialize a third-party response with a format that can instantiate types —
`pickle`, Java native serialization, `yaml.load` without a safe loader. `CWE-502`. Parse into
a schema, then construct the domain object yourself.

Cost: one agent per process, `connections: 32` sockets at steady state, a 64 KB peak buffer
per in-flight fetch. Bound the number of concurrent fetches too or that peak multiplies.

## Adapter Resource Lifecycle

`A06:2025` · `CWE-772`, `CWE-401`, `CWE-400`

Adapters own every handle in the system. The core owns none. That is convenient for testing
and dangerous for lifetime, because the two failure modes look opposite and are equally fatal.

```go
// Vulnerable A: client per call. Each Transport keeps its own connection pool,
// and dropping it strands sockets in TIME_WAIT. Under load: FD exhaustion.
func (a *PaymentAdapter) Charge(ctx context.Context, c app.Charge) error {
    client := &http.Client{Timeout: 5 * time.Second} // new pool, every call
    // ...
}

// Vulnerable B: one client forever, no idle recycling and no timeout.
// Half-open connections accumulate behind a load balancer that silently drops
// idle sockets, and every request through a dead one hangs until the OS gives up.
var client = &http.Client{} // no Timeout: a hung dependency hangs your handler forever
```

```go
// Fixed: one client per process, built at composition time, bounded and recycled.
func NewPaymentAdapter(baseURL string, secret app.SecretRef) *PaymentAdapter {
    transport := &http.Transport{
        MaxIdleConns:          64,
        MaxIdleConnsPerHost:   16,
        MaxConnsPerHost:       32,              // cap, so a slow dependency cannot fan out
        IdleConnTimeout:       30 * time.Second, // recycle before the LB kills them
        TLSHandshakeTimeout:   3 * time.Second,
        ResponseHeaderTimeout: 5 * time.Second,
        ForceAttemptHTTP2:     true,
    }
    return &PaymentAdapter{
        base:   baseURL,
        secret: secret,
        client: &http.Client{Transport: transport, Timeout: 10 * time.Second},
    }
}

// Close is called by the composition root on shutdown.
func (a *PaymentAdapter) Close() {
    a.client.CloseIdleConnections()
}
```

Both failures are invisible in tests. A per-call client passes every unit test and dies at
p99 traffic; a forever client with no `IdleConnTimeout` passes every test and starts failing
after a load balancer config change. Neither is caught by reading the happy path. Heap-level
detail is in `skills/architecture/performance/`.

Subscriptions are worse, because the adapter registers a closure that captures the core.

```typescript
// Vulnerable: subscribes on start, never unsubscribes. On a hot reload or a
// reconnect, handlers accumulate — each retaining the service and its dependencies.
export class BrokerConsumer {
  start(): void {
    this.broker.subscribe("documents.publish", (m) => this.handle(m));
  }
}
```

```typescript
// Fixed: the adapter returns its own teardown, and the composition root owns it.
export class BrokerConsumer {
  #sub?: Subscription;
  #inflight = new Set<Promise<void>>();

  async start(): Promise<void> {
    this.#sub = await this.broker.subscribe("documents.publish", (m) => {
      const p = this.handle(m).finally(() => this.#inflight.delete(p));
      this.#inflight.add(p);
    });
  }

  async stop(): Promise<void> {
    await this.#sub?.unsubscribe();        // stop new work first
    this.#sub = undefined;
    await Promise.allSettled(this.#inflight); // then drain what is running
    this.#inflight.clear();
  }
}

// composition root
const consumer = new BrokerConsumer(broker, service);
await consumer.start();

for (const sig of ["SIGTERM", "SIGINT"] as const) {
  process.once(sig, async () => {
    await Promise.allSettled([
      httpServer.close(),   // stop accepting
      consumer.stop(),      // unsubscribe, drain
    ]);
    await pool.end();       // release the DB last, drain needs it
    process.exit(0);
  });
}
```

Order matters: stop accepting, drain, then release. Releasing the pool first turns an orderly
shutdown into a burst of errors on in-flight work.

## Bound the Queue Between Adapter and Core

`A06:2025` · `CWE-400`, `CWE-770`

The tempting shortcut is to have the driving adapter accept fast and hand work to the core
asynchronously. An unbounded channel makes that a memory bomb an anonymous caller can drive.

```go
// Vulnerable: accept everything, buffer without limit.
var work = make(chan app.PublishCommand) // or a slice appended under a mutex
go func() { for c := range work { svc.Publish(ctx, systemActor, c) } }()
```

```go
// Fixed: bounded buffer, explicit full behaviour, bounded workers.
type Ingress struct {
    work chan job
    wg   sync.WaitGroup
}

type job struct {
    actor app.Actor
    cmd   app.PublishCommand
}

func NewIngress(svc app.DocumentService, depth, workers int) *Ingress {
    in := &Ingress{work: make(chan job, depth)}
    for i := 0; i < workers; i++ {
        in.wg.Add(1)
        go func() {
            defer in.wg.Done()
            for j := range in.work {
                ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
                _ = svc.Publish(ctx, j.actor, j.cmd) // errors go to the audit log inside
                cancel()
            }
        }()
    }
    return in
}

// Offer rejects rather than blocking the HTTP handler. 503 + Retry-After beats a hang.
func (in *Ingress) Offer(j job) error {
    select {
    case in.work <- j:
        return nil
    default:
        queueRejects.Inc() // a metric, not just a log line
        return app.ErrOverloaded
    }
}

func (in *Ingress) Close() { close(in.work); in.wg.Wait() }
```

The actor travels with the job. Losing it on the way into the queue is how "process
asynchronously" turns into "process as root". Backpressure strategy — block, drop, or reject,
and how to size `depth` — is `skills/architecture/scalability/`.

## Configuration and Secrets Enter Through an Adapter

`A02:2025`, `A04:2025` · ASVS V13, V14

A core that reads `os.Getenv` cannot be tested with two configurations, cannot be scoped per
tenant, and has an untyped dependency on deployment state that no signature declares.

```java
// Vulnerable: the use case reaches for the environment and for a secret directly.
public class InvoiceService {
    public void send(Invoice invoice) {
        if (!"true".equals(System.getenv("INVOICE_EMAIL_ENABLED"))) return;
        String key = System.getenv("SMTP_PASSWORD"); // now a String on the heap, forever
        // ...
    }
}
```

```java
// Fixed: settings are a driven port, resolved once, validated at startup.
public record InvoiceSettings(boolean emailEnabled, Duration sendTimeout, int maxAttachmentBytes) {}

public interface SettingsPort {
    InvoiceSettings invoiceSettings();
}

public interface Mailer {            // the secret never enters the core at all
    void send(EmailMessage message); // the adapter holds the credential
}

public final class InvoiceService {
    private final SettingsPort settings;
    private final Mailer mailer;

    public InvoiceService(SettingsPort settings, Mailer mailer) {
        this.settings = settings;
        this.mailer = mailer;
    }

    public void send(Actor actor, Invoice invoice) {
        if (!invoice.isOwnedBy(actor)) throw new NotFoundException();
        if (!settings.invoiceSettings().emailEnabled()) return;
        mailer.send(EmailMessage.forInvoice(invoice));
    }
}

// adapters/config/EnvSettings.java — parsing, defaults, and failure live here
public final class EnvSettings implements SettingsPort {
    private final InvoiceSettings invoice;

    public EnvSettings(Map<String, String> env) {
        this.invoice = new InvoiceSettings(
            Boolean.parseBoolean(env.getOrDefault("INVOICE_EMAIL_ENABLED", "false")),
            Duration.ofSeconds(Long.parseLong(env.getOrDefault("INVOICE_SEND_TIMEOUT_S", "10"))),
            Integer.parseInt(env.getOrDefault("INVOICE_MAX_ATTACHMENT_BYTES", "5242880"))
        );
        // Fail at startup, not on the first request that needs the value.
        if (invoice.maxAttachmentBytes() <= 0) throw new IllegalStateException("bad config");
    }

    @Override public InvoiceSettings invoiceSettings() { return invoice; }
}
```

Two wins beyond testability. Misconfiguration fails at boot instead of at 3am on the first
request that reads the variable — that is `A02:2025` moved from runtime to deploy time. And
the secret stays inside the mailer adapter, so no core object, log line, or exception message
can carry it.

Default the feature flag to `false`. A missing variable that enables a feature is fail-open.

## Testing the Abuse Case

`A01:2025` · ASVS V8

This is the benefit that pays for the indirection. A fake driven adapter lets you construct
state that the real adapter would never let you produce, and drive the port as an attacker.

```go
package app_test

// Fake driven adapter. In-memory, keyed by tenant, so a cross-tenant read
// is a test outcome rather than a production incident.
type fakeDocs struct {
    byTenant map[string]map[string]*app.Document
}

func (f *fakeDocs) FindOwned(_ context.Context, tenant, id, owner string) (*app.Document, error) {
    d := f.byTenant[tenant][id]
    if d == nil || d.OwnerID != owner {
        return nil, nil
    }
    return d, nil
}

func (f *fakeDocs) Save(_ context.Context, tenant string, d *app.Document) error {
    f.byTenant[tenant][d.ID] = d
    return nil
}

func TestPublish_DeniesForeignActor(t *testing.T) {
    docs := &fakeDocs{byTenant: map[string]map[string]*app.Document{
        "tenant-a": {"doc-1": {ID: "doc-1", OwnerID: "user-1"}},
    }}
    svc := app.NewService(docs, fixedClock{}, nopAudit{})

    cases := []struct {
        name  string
        actor app.Actor
    }{
        {"other user, same tenant", app.Actor{UserID: "user-2", TenantID: "tenant-a"}},
        {"same user id, other tenant", app.Actor{UserID: "user-1", TenantID: "tenant-b"}},
        {"empty actor", app.Actor{}},
        {"role escalation attempt", app.Actor{UserID: "user-2", TenantID: "tenant-a",
            Roles: []string{"admin", "superuser"}}},
    }

    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            err := svc.Publish(context.Background(), tc.actor,
                app.PublishCommand{DocumentID: "doc-1"})
            if !errors.Is(err, app.ErrNotFound) && !errors.Is(err, app.ErrUnauthenticated) {
                t.Fatalf("expected denial, got %v", err)
            }
            if docs.byTenant["tenant-a"]["doc-1"].PublishedAt != nil {
                t.Fatal("document was published by an unauthorized actor")
            }
        })
    }
}
```

The last assertion is the one that matters. Asserting on the returned error only proves the
caller was told no; asserting on state proves nothing happened. A use case that returns
`ErrNotFound` after writing is a real bug shape.

Run this suite once per driving port and you have covered every adapter, because they all
converge on the same method. That is the security argument for the pattern in one sentence.

Cost: fakes drift. An in-memory `FindOwned` that ignores tenant while the SQL one enforces it
turns green tests into false confidence. Keep one contract test suite that both the fake and
the real adapter must pass, run the real one against a container in CI, and treat the fake as
a fast approximation, not as proof.

## Sources

- <https://alistair.cockburn.us/hexagonal-architecture/>
- <https://owasp.org/Top10/2025/>
- <https://owasp.org/www-project-application-security-verification-standard/>
- <https://cwe.mitre.org/data/definitions/602.html>
- <https://cwe.mitre.org/data/definitions/653.html>
- <https://cwe.mitre.org/data/definitions/918.html>
