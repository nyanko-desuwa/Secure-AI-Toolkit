# Best Practices

The safe default for each of the seven families. Every section leads with what the mistake
costs, then shows the code shape an AI usually produces, then the replacement.

The test for a fix here is not "is it correct". It is "can the mistake come back without anyone
noticing". A rule you have to remember is not a fix. A structure where the unsafe option no
longer exists is.

## 1. Secrets and the Browser Bundle

`A04:2025 Cryptographic Failures` · ASVS V14 (Data Protection) · `CWE-798`, `CWE-540`

Anyone who opens your website can read every value your frontend code was built with. Not
"a skilled attacker" - anyone, using the browser's own view-source. If that value is an API
key, they can spend your credits, read your customer records, or send email as you, until you
revoke the key.

The reason this surprises people is the word "environment". A file called `.env` sounds private.
For anything prefixed `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`, or `PUBLIC_`, the
build tool takes the value out of the file and writes it into the JavaScript that ships to
visitors. The prefix is the instruction to make it public. That is its entire purpose.

```typescript
// Vulnerable: the key is compiled into the JavaScript every visitor downloads
// app/components/Summarise.tsx
"use client";

export function Summarise({ text }: { text: string }) {
  async function run() {
    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": process.env.NEXT_PUBLIC_ANTHROPIC_KEY!,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: "claude-sonnet-4-5",
        max_tokens: 512,
        messages: [{ role: "user", content: `Summarise: ${text}` }],
      }),
    });
    console.log(await res.json());
  }
  return <button onClick={run}>Summarise</button>;
}
```

The fix is to move the call to a server route. The key stays on the server, the browser talks to
your route, and your route talks to the provider. If you have no backend, the smallest version
that works is a single serverless function - one file in `app/api/` on Vercel or Netlify, no
server to run.

```typescript
// Fixed: key lives on the server, browser never sees it
// app/api/summarise/route.ts
import { NextRequest, NextResponse } from "next/server";
import { getSession } from "@/lib/session";

const MAX_INPUT_CHARS = 4_000;

export async function POST(req: NextRequest) {
  const session = await getSession(req);
  if (!session) return NextResponse.json({ error: "unauthorized" }, { status: 401 });

  const { text } = await req.json();
  if (typeof text !== "string" || text.length === 0 || text.length > MAX_INPUT_CHARS) {
    return NextResponse.json({ error: "invalid_input" }, { status: 400 });
  }

  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": process.env.ANTHROPIC_API_KEY!, // no NEXT_PUBLIC_ prefix
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: "claude-sonnet-4-5",
      max_tokens: 512,
      messages: [{ role: "user", content: `Summarise: ${text}` }],
    }),
    signal: AbortSignal.timeout(30_000),
  });

  if (!res.ok) {
    console.error("upstream_failed", { status: res.status });
    return NextResponse.json({ error: "upstream_failed" }, { status: 502 });
  }

  const data = await res.json();
  return NextResponse.json({ summary: data.content?.[0]?.text ?? "" });
}
```

Why the mistake cannot come back: the variable no longer has a public prefix, so the bundler
will not inline it, and the client component has no code path that carries a credential. If
someone re-adds the prefix, the build-output grep in
[references/secret-exposure.md](references/secret-exposure.md) catches it.

Two rules that go with this:

- A key that was ever in a bundle, a public repo, a chat message, or a screenshot is burned.
  Rotate it at the provider. Deleting the line does not un-leak it, because copies exist that
  you do not control.
- The server route needs its own authentication and its own rate limit. Otherwise you replaced
  a stolen key with a free, open proxy to the same paid API.

### The Firebase and Supabase case

Two things are true at once here, and mixing them up is what causes the damage.

The client key is meant to be public. The Firebase config object and the Supabase anon or
publishable key are identifiers, not secrets. Shipping them in the frontend is the documented
design.

The actual problem is that the database will answer anyone who asks, unless you write rules.
Without Row Level Security in Postgres or Security Rules in Firebase, that public key is a
readable, writable handle on every row in your project. See
[examples/README.md](examples/README.md#supabase-anon-key-exposed-fine-no-rls-not-fine) for the
policy that closes it.

What is never public is the elevated key: `service_role` in Supabase, the Admin SDK service
account in Firebase. Those bypass every rule by design. They belong on a server only
(`A01:2025`, ASVS V8, `CWE-798`).

## 2. Hardcoded Values That Should Be Configuration

`A02:2025 Security Misconfiguration` · ASVS V13 (Configuration) · `CWE-1188`

The harm is not tidiness. Either the app fails in production because `localhost` does not exist
there, or worse, it succeeds against the wrong thing. A hardcoded fallback to a development
database means real customer writes land in a scratch database, and nobody notices until
someone asks where the data went.

```typescript
// Vulnerable: falls back to a dev database when the real value is missing
const DB_URL = process.env.DATABASE_URL || "postgres://dev:dev@localhost:5432/app_dev";
const API_BASE = "http://localhost:3001";
const UPLOAD_BUCKET = "my-test-bucket";
```

The fallback is the bug. It converts a loud, immediate startup failure into a silent, wrong
success.

```typescript
// Fixed: validated at startup, no fallbacks, process refuses to boot if misconfigured
// src/config.ts
import { z } from "zod";

const Env = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]),
  DATABASE_URL: z.string().url(),
  API_BASE_URL: z.string().url(),
  UPLOAD_BUCKET: z.string().min(1),
  SESSION_SECRET: z.string().min(32),
});

const parsed = Env.safeParse(process.env);

if (!parsed.success) {
  console.error("config_invalid", parsed.error.flatten().fieldErrors);
  process.exit(1);
}

export const config = parsed.data;
```

Why the mistake cannot come back: there is one place that reads `process.env`, and a missing or
malformed value stops the process before it can serve a request. Crashing at startup is the
cheapest possible failure. A wrong database connection discovered a week later is the most
expensive.

The same reasoning applies to identity checks written as literals:

```typescript
// Vulnerable: the permission model is a person's user ID
if (userId === 12345) enableAdminPanel();
if (["me@example.com", "cofounder@example.com"].includes(user.email)) allowExport();

// Fixed: a role on the record, checked server-side
if (await hasPermission(actor, "admin:panel")) enableAdminPanel();
```

A hardcoded ID cannot be revoked without a deploy, does not appear in any audit of who has
access, and gets copied into the next feature.

## 3. Limits: Hardcoded Where They Should Be Policy, Missing Where They Are Required

`A06:2025 Insecure Design` · `API4:2023 Unrestricted Resource Consumption` · ASVS V2, V4 ·
`CWE-770`, `CWE-400`

Missing limits are a security finding, not a performance nitpick. One request with no maximum
attached can take the whole application down, and the person sending it needs no credentials
and no skill.

A hardcoded limit fails the other way. `LIMIT 100` in a report query means the totals are wrong
once there are 101 records, and nothing warns anyone. Silently truncated data is worse than an
error, because people act on it.

```typescript
// Vulnerable: returns the entire table, and lets the caller choose the size
app.get("/api/orders", requireAuth, async (req, res) => {
  const orders = await db.order.findMany({ where: { customerId: req.user.id } });
  res.json(orders);
});
```

At a hundred rows this is fine. At two million rows the process loads all of them into memory,
serialises them to JSON, and dies. Every subsequent request fails while it restarts.

```typescript
// Fixed: cursor pagination with a server-enforced ceiling
const DEFAULT_PAGE_SIZE = 25;
const MAX_PAGE_SIZE = 100;

app.get("/api/orders", requireAuth, async (req, res) => {
  const requested = Number.parseInt(String(req.query.limit ?? ""), 10);
  const limit = Number.isFinite(requested)
    ? Math.min(Math.max(requested, 1), MAX_PAGE_SIZE)
    : DEFAULT_PAGE_SIZE;

  const cursor = typeof req.query.cursor === "string" ? req.query.cursor : undefined;

  const rows = await db.order.findMany({
    where: { customerId: req.user.id },
    orderBy: [{ createdAt: "desc" }, { id: "desc" }],
    take: limit + 1,
    ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
  });

  const hasMore = rows.length > limit;
  res.json({
    items: hasMore ? rows.slice(0, limit) : rows,
    nextCursor: hasMore ? rows[limit - 1].id : null,
  });
});
```

Why the mistake cannot come back: `MAX_PAGE_SIZE` is applied with `Math.min` on the server, so
`?limit=1000000` clamps instead of obeying. The ceiling is not a convention, it is arithmetic.

Every outbound call needs a timeout, and most HTTP libraries default to none:

```typescript
// Vulnerable: a slow dependency holds this request open forever
const res = await fetch(url);

// Fixed: bounded, and the failure is distinguishable
const res = await fetch(url, { signal: AbortSignal.timeout(5_000) });
```

Starting values for page sizes, timeouts, upload caps, retry ceilings, and pool sizes are in
[references/resource-limits.md](references/resource-limits.md).

## 4. Security Decisions Made in the Client

`A01:2025 Broken Access Control` · `A07:2025 Authentication Failures` · ASVS V6, V8, V9 ·
`CWE-602`, `CWE-807`, `CWE-347`

This family is the most dangerous, because the code looks like it works. The admin panel is
hidden from normal users, the test passes, the demo goes well. Then someone sends the request
without using your website at all, and there is nothing there to stop them.

Your UI is a suggestion. The server is the only thing that decides. A hidden button is a
convenience for the user, never a control.

```typescript
// Vulnerable: the role comes from a token that was decoded but never verified
import { jwtDecode } from "jwt-decode";

app.get("/api/admin/users", (req, res) => {
  const token = req.headers.authorization?.replace("Bearer ", "") ?? "";
  const payload = jwtDecode<{ sub: string; role: string }>(token);
  if (payload.role !== "admin") return res.status(403).json({ error: "forbidden" });
  res.json(listAllUsers());
});
```

Decoding a JWT is unpacking a piece of text. It proves nothing. The middle segment is
base64 - anyone can write `{"sub":"1","role":"admin"}`, encode it, and send it. Verifying
checks the signature against a key only your server holds. That is the step that matters
(`CWE-347`).

```typescript
// Fixed: signature verified, algorithm pinned, role read from your own database
import jwt from "jsonwebtoken";

const JWT_SECRET = process.env.JWT_SECRET!; // 32+ random bytes, server-only

function requireAuth(req, res, next) {
  const token = req.headers.authorization?.replace("Bearer ", "") ?? "";
  try {
    const payload = jwt.verify(token, JWT_SECRET, {
      algorithms: ["HS256"],       // never accept the token's own alg claim
      issuer: "https://app.example.com",
      audience: "api",
    }) as { sub: string };
    req.userId = payload.sub;
    next();
  } catch {
    res.status(401).json({ error: "unauthorized" });
  }
}

async function requireAdmin(req, res, next) {
  const user = await db.user.findUnique({
    where: { id: req.userId },
    select: { role: true },
  });
  if (user?.role !== "admin") return res.status(403).json({ error: "forbidden" });
  next();
}

app.get("/api/admin/users", requireAuth, requireAdmin, async (_req, res) => {
  res.json(await listAllUsers());
});
```

Why the mistake cannot come back: `algorithms` is pinned, so a token claiming `alg: none` is
rejected. The role is read from your database rather than from anything the caller sent, so
editing the token changes nothing that matters.

Rules for this family:

- Never trust a role, price, quantity, user ID, or tenant ID from a request body. Derive the
  actor from the verified session, then look up everything else server-side.
- Scope every query by the actor rather than checking ownership afterwards. There is no `if` to
  forget: `where: { id, customerId: req.user.id }`.
- Test one protected endpoint with `curl` and no browser. If it answers, you have no control.
- `verify: false`, `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, and
  `curl --insecure` turn off the check that proves you are talking to the right server. They
  make the error message disappear and the attack possible (`CWE-295`). The fix is to install
  the correct certificate authority, not to stop checking. See
  [examples/README.md](examples/README.md#rejectunauthorized-false-to-silence-a-tls-error).
- CORS with `credentials: true` and an origin of `*`, or an origin reflected from the request,
  lets any website make authenticated requests as your logged-in user. Name your origins.

## 5. Memory and Resource Leaks

`A10:2025 Mishandling of Exceptional Conditions` · ASVS V15 (Secure Coding and Architecture) ·
`CWE-401`, `CWE-772`, `CWE-770`

The symptom is an app that works fine after a restart and gets worse over hours. Memory climbs,
responses slow, the process is killed and restarted, and eventually the restarts overlap with
traffic and users see errors.

For the deep version of this topic - the eight leak shapes, heap snapshot workflow per runtime,
backpressure design - use the `performance` skill at
`skills/architecture/performance/`. What follows is the subset that shows up in
AI-generated web code.

### The cache that is a denial-of-service vector

Take this one seriously. It is simultaneously a memory leak and a way for a stranger to kill
your server with ordinary-looking requests (`CWE-401`, `CWE-770`, `API4:2023`).

```javascript
// Vulnerable: unbounded map keyed by whatever the caller sends
const cache = new Map();

app.get("/api/search", async (req, res) => {
  const q = String(req.query.q ?? "");
  if (!cache.has(q)) {
    cache.set(q, await db.product.findMany({ where: { name: { contains: q } } }));
  }
  res.json(cache.get(q));
});
```

Every distinct search term adds an entry that is never removed. An attacker sends
`?q=a`, `?q=aa`, `?q=aaa` and so on. Each request is valid, none looks like an attack, and the
process runs out of memory. There is no authentication needed and no rate limit to trip.

```javascript
// Fixed: bounded size, TTL, and normalised keys
import { LRUCache } from "lru-cache";

const cache = new LRUCache({
  max: 500,                 // hard ceiling on entries
  ttl: 60_000,              // entries expire after a minute
  maxSize: 5_000_000,       // and a ceiling on total bytes
  sizeCalculation: (value) => JSON.stringify(value).length,
});

app.get("/api/search", async (req, res) => {
  const raw = String(req.query.q ?? "").trim().toLowerCase();
  if (raw.length < 2 || raw.length > 64) {
    return res.status(400).json({ error: "invalid_query" });
  }

  const hit = cache.get(raw);
  if (hit) return res.json(hit);

  const rows = await db.product.findMany({
    where: { name: { contains: raw } },
    take: 50,
  });
  cache.set(raw, rows);
  res.json(rows);
});
```

Why the mistake cannot come back: `max` and `maxSize` mean memory use has a ceiling no input can
raise. The worst an attacker achieves is evicting other people's cache entries.

If the cached value depends on who is asking, the user or tenant ID has to be part of the key.
A cache keyed on the search term alone will serve one customer's rows to another.

### React cleanup

Every subscription, timer, listener, and observer started in a component has to be stopped when
that component goes away. Without it, navigating between pages leaves invisible copies running.
Memory grows, and handlers fire against components that no longer exist.

```typescript
// Vulnerable: a new socket every mount, none ever closed
useEffect(() => {
  const socket = new WebSocket(url);
  socket.onmessage = (e) => setMessages((prev) => [...prev, JSON.parse(e.data)]);
  window.addEventListener("resize", handleResize);
  setInterval(() => refetch(), 5_000);
}, []);

// Fixed: everything started here is stopped here
useEffect(() => {
  const socket = new WebSocket(url);
  const onMessage = (e: MessageEvent) =>
    setMessages((prev) => [...prev.slice(-200), JSON.parse(e.data)]);
  socket.addEventListener("message", onMessage);
  window.addEventListener("resize", handleResize);
  const timer = setInterval(() => refetch(), 5_000);

  return () => {
    socket.removeEventListener("message", onMessage);
    socket.close();
    window.removeEventListener("resize", handleResize);
    clearInterval(timer);
  };
}, [url, handleResize, refetch]);
```

Two details that are easy to miss. `removeEventListener` matches by reference, so an inline
arrow function cannot be removed - name it. And `prev.slice(-200)` bounds the state array; a
list that only ever grows is a leak even with correct cleanup.

### Node and Python

```javascript
// Vulnerable: a listener added per request, never removed
app.post("/api/jobs", (req, res) => {
  jobEmitter.on("done", () => res.json({ ok: true }));
});

// Fixed: bounded to this request, removed on every exit path
app.post("/api/jobs", (req, res) => {
  const onDone = () => {
    cleanup();
    res.json({ ok: true });
  };
  const timer = setTimeout(() => {
    cleanup();
    res.status(504).json({ error: "timeout" });
  }, 30_000);

  function cleanup() {
    jobEmitter.off("done", onDone);
    clearTimeout(timer);
  }

  jobEmitter.once("done", onDone);
  res.on("close", cleanup);
});
```

```python
# Vulnerable: module-level list grows forever, file handle leaks on a parse error
RECENT = []

def handle(request):
    RECENT.append(request.body)          # never trimmed
    f = open(request.path)               # not closed if parse raises
    return parse(f.read())

# Fixed: bounded deque, context manager releases on the error path too
from collections import deque

RECENT = deque(maxlen=1000)              # oldest entries drop automatically

def handle(request):
    RECENT.append(request.body)
    with open(request.path) as f:        # closed even when parse raises
        return parse(f.read())
```

`functools.lru_cache` on a method keeps `self` alive for as long as the entry is cached, which
holds the whole object graph. Cache a module-level function that takes plain arguments instead.

## 6. Performance Traps That Become Outages or Bills

`A10:2025` · ASVS V15 · `CWE-400` · `API4:2023`

These are invisible in development, where the table has twenty rows. They arrive as a page that
takes forty seconds, or an invoice with an extra digit.

The most common one by far is a database query inside a loop.

```typescript
// Vulnerable: one query for the list, then one per row
const orders = await db.order.findMany({ where: { customerId } });
for (const order of orders) {
  order.customer = await db.customer.findUnique({ where: { id: order.customerId } });
  order.items = await db.orderItem.findMany({ where: { orderId: order.id } });
}
```

Two hundred orders is four hundred and one round trips, each waiting for the previous one.

```typescript
// Fixed: the database does the join, one round trip
const orders = await db.order.findMany({
  where: { customerId },
  take: 100,
  include: { customer: true, items: true },
});
```

Where a join is not available, fetch the related rows in one query and group them in memory:

```typescript
const orders = await db.order.findMany({ where: { customerId }, take: 100 });
const items = await db.orderItem.findMany({
  where: { orderId: { in: orders.map((o) => o.id) } },
});
const byOrder = new Map<string, typeof items>();
for (const item of items) {
  const list = byOrder.get(item.orderId) ?? [];
  list.push(item);
  byOrder.set(item.orderId, list);
}
```

The rest of this family, in short form:

- Independent awaits run concurrently with `Promise.all`. Serial awaits over three APIs take the
  sum of their latencies instead of the maximum.
- Fan-out needs a concurrency cap. `Promise.all` over ten thousand items opens ten thousand
  connections and takes down the service you are calling.
- Every column in a `WHERE`, `JOIN`, or `ORDER BY` needs an index. Without one the database reads
  every row, so the page gets slower as the table grows.
- Count and sum in the database. `rows.length` after loading a table is the same query with the
  memory cost added.
- Slow work belongs on a queue. Image processing, PDF generation, and email sending on the
  request path hold a connection open and time out under load.
- Create clients, pools, and config readers once at startup. Per-request construction is a
  connection leak with a performance cost attached.
- A metered API in a loop, or a polling interval against one, is a bill. Multiply the interval
  out to a month before shipping it, and set a spend alert at the provider.

## 7. Swallowed Errors and Data Loss

`A09:2025 Security Logging and Alerting Failures` · `A10:2025` · ASVS V16 · `CWE-390`,
`CWE-209`

An empty `catch` block is the most expensive line in this document. The write failed, the
function returned normally, the UI said "Saved", and the data is gone. Nobody finds out until a
customer asks.

```typescript
// Vulnerable: the failure is discarded and reported as success
async function saveProfile(data: Profile) {
  try {
    await db.profile.update({ where: { id: data.id }, data });
  } catch {}
  return { ok: true };
}
```

```typescript
// Fixed: logged with context, surfaced to the caller, generic message to the user
async function saveProfile(data: Profile) {
  try {
    const result = await db.profile.update({ where: { id: data.id }, data });
    return { ok: true, profile: result };
  } catch (err) {
    logger.error("profile_update_failed", {
      profileId: data.id,
      error: err instanceof Error ? err.message : String(err),
    });
    throw new AppError("profile_update_failed", { status: 500 });
  }
}
```

The other side of this is showing too much. A stack trace rendered in the browser gives away
file paths, library versions, and fragments of your queries (`CWE-209`). Send the user a generic
message and a correlation ID; keep the detail in the log.

```typescript
// Fixed: one error handler, generic response, full detail logged
app.use((err, req, res, _next) => {
  const correlationId = crypto.randomUUID();
  logger.error("unhandled_error", { correlationId, path: req.path, stack: err.stack });
  res.status(err.status ?? 500).json({ error: "internal_error", correlationId });
});
```

Data-loss rules worth following without exception:

- Multi-step writes go in a transaction. Half a booking is worse than no booking.
- Retry only what is safe to repeat. A retried payment with no idempotency key charges twice.
- Run any bulk `UPDATE` or `DELETE` as a `SELECT` with the same `WHERE` first, and read the row
  count.
- A backup you have never restored is a hypothesis. Restore one into a scratch environment.

## Sources

- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>
- OWASP API Security Top 10 2023 - <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- OWASP ASVS - <https://owasp.org/www-project-application-security-verification-standard/>
- CWE list - <https://cwe.mitre.org/data/index.html>
