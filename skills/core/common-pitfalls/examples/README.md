# Examples

Twelve pairs. Every `Vulnerable:` block is code an AI plausibly produces from a reasonable
request — not a caricature. Each pair leads with what it costs in plain words, because that is
the part worth understanding if you only read one line.

Do not copy a `Vulnerable:` block into a project.

---

## 1. API key in a `NEXT_PUBLIC_` variable

Anyone who opens your site can read this key and spend your money. `.env` does not mean secret.
The bundler copies any `NEXT_PUBLIC_*` value into the JavaScript it sends to every visitor.

`A04:2025` · `ASVS V13, V14` · `CWE-798`, `CWE-540`

Vulnerable:

```tsx
// app/weather/page.tsx  — runs in the browser
"use client";

export default function Weather() {
  const load = async () => {
    // NEXT_PUBLIC_ means "inline this into the public bundle"
    const res = await fetch(
      `https://api.weathervendor.example/v1/current?key=${process.env.NEXT_PUBLIC_WEATHER_API_KEY}`,
    );
    console.log(await res.json());
  };
  return <button onClick={load}>Load</button>;
}
```

The key is in `.next/static/chunks/*.js`. View source finds it in about ten seconds.

Fixed — the key stays on the server and the browser calls your own route:

```ts
// app/api/weather/route.ts — server only, never bundled
export async function GET(req: Request) {
  const city = new URL(req.url).searchParams.get("city") ?? "";
  if (!/^[a-zA-Z\s-]{1,64}$/.test(city)) {
    return Response.json({ error: "invalid city" }, { status: 400 });
  }

  const res = await fetch(
    `https://api.weathervendor.example/v1/current?key=${process.env.WEATHER_API_KEY}` +
      `&q=${encodeURIComponent(city)}`,
    { signal: AbortSignal.timeout(5_000) },
  );
  if (!res.ok) return Response.json({ error: "upstream failed" }, { status: 502 });
  return Response.json(await res.json());
}
```

```tsx
// app/weather/page.tsx
const res = await fetch(`/api/weather?city=${encodeURIComponent(city)}`);
```

Why it cannot recur: the name no longer has the `NEXT_PUBLIC_` prefix, so the bundler will not
inline it, and referencing `process.env.WEATHER_API_KEY` from a client component yields
`undefined` rather than silently working. The mistake now fails visibly in development.

If the key was ever deployed with the public prefix, rotate it. Removing the line does not
un-leak it — it is in every visitor's cache and in your build artifacts.

---

## 2. Anthropic key called straight from the browser

Same shape, higher bill. A metered AI key in client code is a stranger's free API access, and
the charges are yours.

`A04:2025` · `ASVS V13, V14` · `CWE-798`

Vulnerable:

```ts
// src/chat.ts — shipped to the browser
const ANTHROPIC_API_KEY = "sk-ant-api03-EXAMPLE-PLACEHOLDER-NOT-REAL";

export async function ask(question: string) {
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "x-api-key": ANTHROPIC_API_KEY,
      "anthropic-version": "2023-06-01",
      "content-type": "application/json",
    },
    body: JSON.stringify({
      model: "claude-sonnet-5",
      max_tokens: 1024,
      messages: [{ role: "user", content: question }],
    }),
  });
  return (await res.json()).content[0].text;
}
```

Fixed — one server endpoint holds the key and owns the limits:

```ts
// server/routes/ask.ts (Express)
import { Router } from "express";
import Anthropic from "@anthropic-ai/sdk";

const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
const MAX_QUESTION_CHARS = 2_000;
const MAX_TOKENS = 1_024;

export const askRouter = Router();

askRouter.post("/ask", requireSession, perUserRateLimit, async (req, res) => {
  const question = String(req.body?.question ?? "");
  if (!question || question.length > MAX_QUESTION_CHARS) {
    return res.status(400).json({ error: "question must be 1-2000 characters" });
  }

  const msg = await client.messages.create({
    model: "claude-sonnet-5",
    max_tokens: MAX_TOKENS,
    messages: [{ role: "user", content: question }],
  });
  res.json({ answer: msg.content });
});
```

Why it cannot recur: the browser has no credential to leak. The server route is also where the
spend ceiling lives — `requireSession` stops anonymous use and `perUserRateLimit` stops one
account draining the account budget. A key in client code has neither.

If you have no backend, the smallest version that works is a single serverless function. That is
enough; it does not need to be a service.

---

## 3. Supabase: the anon key is public (fine), but there is no RLS (not fine)

Two true statements at once. The anon key is designed to be public, so seeing it in your bundle
is not the problem. The problem is that without row-level security, that public key can read
and write every row in the table — every user's data, from a browser console.

`A01:2025` · `ASVS V8` · `CWE-862`

Vulnerable — the table has RLS disabled, which is the default state after `create table`:

```ts
// src/notes.ts
import { createClient } from "@supabase/supabase-js";

// This key is meant to be public. That part is correct.
export const supabase = createClient(
  import.meta.env.VITE_SUPABASE_URL,
  import.meta.env.VITE_SUPABASE_ANON_KEY,
);

// The app only ever asks for its own notes, so this looks safe.
export const myNotes = (userId: string) =>
  supabase.from("notes").select("*").eq("user_id", userId);
```

The filter is in the client. Anyone can open the console and send the same query with no filter
at all.

Fixed — the database enforces it, so the client filter becomes a convenience rather than a
control:

```sql
alter table public.notes enable row level security;

create policy "read own notes"
  on public.notes for select
  using (auth.uid() = user_id);

create policy "insert own notes"
  on public.notes for insert
  with check (auth.uid() = user_id);

create policy "update own notes"
  on public.notes for update
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);
```

Why it cannot recur: `auth.uid()` comes from the verified JWT on the connection, not from
anything the caller typed. A request with no filter now returns only that user's rows. A request
forging `user_id` fails the `with check`.

Never put the `service_role` key in client code. It bypasses RLS by design — that is its whole
purpose — so it belongs only in server code.

---

## 4. Role read from a JWT that was decoded but never verified

The token's contents are readable and editable by whoever holds it. Decoding is not checking.
Anyone can flip `"role": "user"` to `"role": "admin"` and re-send.

`A07:2025` · `ASVS V9` · `CWE-347`, `CWE-807`

Vulnerable:

```ts
import { jwtDecode } from "jwt-decode";

export function requireAdmin(req, res, next) {
  const token = req.headers.authorization?.replace("Bearer ", "") ?? "";
  const claims = jwtDecode<{ sub: string; role: string }>(token); // no signature check
  if (claims.role !== "admin") return res.status(403).json({ error: "forbidden" });
  req.userId = claims.sub;
  next();
}
```

`jwtDecode` only base64-decodes. It has no key and cannot verify anything. A hand-written token
with `alg: none` and `role: admin` passes.

Fixed — verify the signature, pin the algorithm, and read the role from your own store:

```ts
import jwt from "jsonwebtoken";

const ISSUER = process.env.JWT_ISSUER!;
const AUDIENCE = process.env.JWT_AUDIENCE!;

export async function requireAdmin(req, res, next) {
  const token = req.headers.authorization?.replace("Bearer ", "") ?? "";
  let claims: jwt.JwtPayload;
  try {
    claims = jwt.verify(token, await publicKeyForKid(token), {
      algorithms: ["RS256"], // pinned: prevents alg confusion and alg:none
      issuer: ISSUER,
      audience: AUDIENCE,
    }) as jwt.JwtPayload;
  } catch {
    return res.status(401).json({ error: "unauthenticated" }); // fail closed
  }

  // Authoritative role comes from the database, not from the token body.
  const user = await db.user.findUnique({
    where: { id: claims.sub as string },
    select: { id: true, role: true, disabledAt: true },
  });
  if (!user || user.disabledAt) return res.status(401).json({ error: "unauthenticated" });
  if (user.role !== "admin") return res.status(403).json({ error: "forbidden" });

  req.userId = user.id;
  next();
}
```

Why it cannot recur: forging the claim no longer helps, because the signature check rejects the
token before the role is read, and the role is then looked up server-side anyway. Pinning
`algorithms` closes the `alg` substitution path. The `catch` denies rather than continuing —
an error inside a security decision must not fall through.

---

## 5. React route guard with no server check behind it

The guard hides a page. It does not protect the data. The API still answers anyone who asks it
directly.

`A01:2025` · `ASVS V8` · `CWE-602`

Vulnerable:

```tsx
function AdminRoute({ children }: { children: React.ReactNode }) {
  const { user } = useAuth();
  if (user?.role !== "admin") return <Navigate to="/" />;
  return <>{children}</>;
}
```

```ts
// server: the endpoint the hidden page called
app.get("/api/admin/users", async (_req, res) => {
  res.json(await db.user.findMany()); // no check at all
});
```

`curl https://app.example/api/admin/users` returns every user. The React guard never ran.

Fixed — authorize at the data layer, and scope the query to the actor:

```ts
app.get("/api/admin/users", requireAdmin, async (req, res) => {
  const users = await db.user.findMany({
    where: { organizationId: req.actor.organizationId }, // scoped, not global
    select: { id: true, email: true, role: true, createdAt: true }, // no password hash
    take: Math.min(Number(req.query.limit ?? 50), 100),
  });
  res.json({ users });
});
```

Keep the React guard. It is a good UX detail — it stops users landing on a page that will only
error. Just do not count it as a control.

Why it cannot recur: the check now sits on the path the data actually travels. There is no route
to the rows that skips it, and `organizationId` comes from the verified session rather than the
request.

---

## 6. `rejectUnauthorized: false` added to silence a TLS error

This turns off the check that proves you are talking to the right server. Anyone positioned
between you and the API can read and change the traffic, including credentials. The error it
silenced was the system working.

`A04:2025` · `ASVS V12` · `CWE-295`

Vulnerable:

```ts
import https from "node:https";

// "self signed certificate in certificate chain" — this made it go away
const agent = new https.Agent({ rejectUnauthorized: false });

export const api = axios.create({
  baseURL: "https://internal-api.corp.example",
  httpsAgent: agent,
});
```

Worse variants that show up for the same reason: `NODE_TLS_REJECT_UNAUTHORIZED=0` in `.env`,
`verify=False` in Python `requests`, `curl --insecure` copied into a script.

Fixed — trust the certificate authority that signed it, rather than trusting nothing:

```ts
import fs from "node:fs";
import https from "node:https";

// The internal CA certificate. Public information: it contains no private key.
const agent = new https.Agent({
  ca: fs.readFileSync(process.env.INTERNAL_CA_BUNDLE_PATH!),
  minVersion: "TLSv1.2",
});

export const api = axios.create({
  baseURL: "https://internal-api.corp.example",
  httpsAgent: agent,
  timeout: 5_000,
});
```

Python equivalent:

```python
import os
import requests

session = requests.Session()
session.verify = os.environ["INTERNAL_CA_BUNDLE_PATH"]  # not False
response = session.get("https://internal-api.corp.example/v1/status", timeout=5)
```

Why it cannot recur: verification stays on. A certificate that is genuinely wrong still fails,
which is the point. Adding the CA fixes the one case that was broken without blinding every
other case.

---

## 7. Module-level `Map` cache keyed by user input

Two problems in one line. Memory grows until the process is killed, and a stranger controls how
fast — they send requests with new values until it dies. No login required.

`A06:2025` · `API4:2023` · `CWE-401`, `CWE-770`

Vulnerable:

```ts
const cache = new Map<string, Profile>(); // never bounded, never evicted

export async function getProfile(handle: string): Promise<Profile> {
  const hit = cache.get(handle);
  if (hit) return hit;
  const profile = await db.profile.findUnique({ where: { handle } });
  cache.set(handle, profile); // caches misses too, so nonsense keys stick
  return profile;
}
```

`GET /profile/aaaa1`, `aaaa2`, `aaaa3`… each one adds an entry forever. Caching the `null` result
means invalid handles are the cheapest way to fill it.

Fixed — bounded size, TTL, and do not cache misses:

```ts
import { LRUCache } from "lru-cache";

const MAX_ENTRIES = 10_000;
const TTL_MS = 60_000;

const cache = new LRUCache<string, Profile>({ max: MAX_ENTRIES, ttl: TTL_MS });

export async function getProfile(handle: string): Promise<Profile | null> {
  if (!/^[a-z0-9_]{1,30}$/.test(handle)) return null; // shrink the key space first

  const hit = cache.get(handle);
  if (hit) return hit;

  const profile = await db.profile.findUnique({ where: { handle } });
  if (profile) cache.set(handle, profile); // only successes
  return profile;
}
```

Why it cannot recur: memory has a ceiling that does not depend on traffic. At `max` entries the
oldest is dropped, so the worst case is a lower hit rate, not an out-of-memory kill. Validating
the key first means most junk never reaches the cache at all.

A bounded cache is the fix. A bigger server is not — it only moves the deadline.

---

## 8. `useEffect` subscription with no cleanup

Every navigation opens another connection and leaves the last one running. The tab gets slower,
then the browser tab crashes. On a long-lived page the same shape exhausts server connections.

`A10:2025` · `CWE-401`, `CWE-772`

Vulnerable:

```tsx
function Messages({ roomId }: { roomId: string }) {
  const [messages, setMessages] = useState<Message[]>([]);

  useEffect(() => {
    const socket = new WebSocket(`wss://app.example/rooms/${roomId}`);
    socket.onmessage = (e) => setMessages((m) => [...m, JSON.parse(e.data)]);
    window.addEventListener("resize", handleResize);
    const timer = setInterval(refresh, 5_000);
    // nothing returned: socket, listener, and interval all outlive the component
  }, [roomId]);

  return <List items={messages} />;
}
```

The `messages` array also only ever grows, which is a second leak in the same component.

Fixed — return a cleanup function, and bound the state:

```tsx
const MAX_RENDERED = 500;

function Messages({ roomId }: { roomId: string }) {
  const [messages, setMessages] = useState<Message[]>([]);

  useEffect(() => {
    const controller = new AbortController();
    const socket = new WebSocket(`wss://app.example/rooms/${roomId}`);

    socket.addEventListener(
      "message",
      (e) =>
        setMessages((m) => {
          const next = [...m, JSON.parse(e.data)];
          return next.length > MAX_RENDERED ? next.slice(-MAX_RENDERED) : next;
        }),
      { signal: controller.signal },
    );
    window.addEventListener("resize", handleResize, { signal: controller.signal });

    const timer = setInterval(refresh, 5_000);

    return () => {
      controller.abort(); // removes every listener registered with this signal
      clearInterval(timer);
      socket.close();
    };
  }, [roomId]);

  return <List items={messages} />;
}
```

Why it cannot recur: one `AbortController` owns every listener in the effect, so a new listener
added later is cleaned up by the existing `controller.abort()` without anyone remembering to add
a line. Capping `MAX_RENDERED` bounds the state regardless of how long the room stays open.

`AbortSignal` support in `addEventListener` is standard in current browsers and Node. If you
target older runtimes, remove each listener by reference instead.

---

## 9. `setInterval` retry with no backoff and no ceiling

When the dependency goes down, this hammers it every two seconds forever — from every running
instance. It turns someone else's brief outage into a self-inflicted flood, and if that
dependency is metered, into a bill.

`A06:2025` · `API4:2023` · `CWE-770`, `CWE-400`

Vulnerable:

```ts
function startSync() {
  setInterval(async () => {
    try {
      await syncWithUpstream();
    } catch (err) {
      console.error("sync failed, will retry", err); // retries at the same rate, forever
    }
  }, 2_000);
}
```

Fixed — exponential backoff, jitter, a ceiling on the delay, and a cap on attempts:

```ts
const BASE_DELAY_MS = 1_000;
const MAX_DELAY_MS = 60_000;
const MAX_ATTEMPTS = 8;

async function syncWithRetry(signal: AbortSignal): Promise<void> {
  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    try {
      await syncWithUpstream({ signal });
      return;
    } catch (err) {
      if (signal.aborted) return;
      if (attempt === MAX_ATTEMPTS - 1) {
        // Give up loudly. A silent permanent failure is worse than an alert.
        logger.error({ err, attempt }, "sync failed permanently");
        metrics.increment("sync.gave_up");
        throw err;
      }
      const backoff = Math.min(BASE_DELAY_MS * 2 ** attempt, MAX_DELAY_MS);
      const jitter = Math.random() * backoff * 0.3; // spread instances apart
      await sleep(backoff + jitter, signal);
    }
  }
}
```

Why it cannot recur: the delay grows on its own, so a longer outage automatically means less
traffic instead of the same amount. Jitter stops every instance retrying in lockstep. The
attempt cap converts an infinite loop into an alert someone can act on.

---

## 10. `await` inside a `for` loop over rows

Fast with ten records, unusable with ten thousand. One query becomes one query per row, and the
page gets slower every week as the table grows.

`A10:2025` · `API4:2023` · `CWE-400`

Vulnerable:

```ts
const orders = await db.order.findMany({ where: { userId } });

for (const order of orders) {
  order.customer = await db.customer.findUnique({ where: { id: order.customerId } });
  order.items = await db.orderItem.findMany({ where: { orderId: order.id } });
}
```

500 orders is 1,001 queries, run one after another.

Fixed — let the database do the join:

```ts
const orders = await db.order.findMany({
  where: { userId },
  include: { customer: true, items: true }, // one query, or one per relation
  take: Math.min(Number(limit ?? 50), 100),
});
```

When an ORM cannot express it, batch the lookup instead of looping:

```ts
const customerIds = [...new Set(orders.map((o) => o.customerId))];
const customers = await db.customer.findMany({ where: { id: { in: customerIds } } });
const byId = new Map(customers.map((c) => [c.id, c]));
for (const order of orders) order.customer = byId.get(order.customerId);
```

Python, same shape with `asyncio` — note that independent calls should run concurrently, but
with a bound:

```python
import asyncio

semaphore = asyncio.Semaphore(10)  # bounded fan-out, not unbounded gather

async def fetch(order_id: int) -> Detail:
    async with semaphore:
        return await client.get_detail(order_id, timeout=5)

details = await asyncio.gather(*(fetch(o.id) for o in orders))
```

Why it cannot recur: the number of round trips no longer scales with the number of rows. The
`take` cap also means one request cannot ask for the whole table, which is the related finding
in the next example.

Unbounded `Promise.all` or `asyncio.gather` over user-sized input is its own trap: it fixes
latency by fanning out enough concurrent calls to take down the service you are calling.

---

## 11. List endpoint with no pagination

Works during development with 40 rows. At 400,000 rows the query loads the whole table into
memory and the process dies. Anyone can trigger it by loading the page.

`A06:2025` · `API4:2023` · `ASVS V4` · `CWE-770`

Vulnerable:

```ts
app.get("/api/orders", requireSession, async (req, res) => {
  const orders = await db.order.findMany({ where: { userId: req.actor.id } });
  res.json(orders); // everything, always
});
```

Fixed — cursor pagination with a maximum the client cannot raise:

```ts
const DEFAULT_PAGE_SIZE = 50;
const MAX_PAGE_SIZE = 100;

app.get("/api/orders", requireSession, async (req, res) => {
  const requested = Number(req.query.limit ?? DEFAULT_PAGE_SIZE);
  const limit = Number.isFinite(requested)
    ? Math.min(Math.max(Math.trunc(requested), 1), MAX_PAGE_SIZE)
    : DEFAULT_PAGE_SIZE;

  const cursor = typeof req.query.cursor === "string" ? req.query.cursor : undefined;

  const rows = await db.order.findMany({
    where: { userId: req.actor.id }, // scoped to the actor, not to a client-sent id
    orderBy: { id: "desc" },
    take: limit + 1, // one extra row tells us whether more exist
    ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
  });

  const hasMore = rows.length > limit;
  const page = hasMore ? rows.slice(0, limit) : rows;

  res.json({ orders: page, nextCursor: hasMore ? page.at(-1)!.id : null });
});
```

Why it cannot recur: the cap is applied after parsing, so `?limit=100000`, `?limit=abc`, and
`?limit=-1` all resolve to something bounded. Cursor pagination also stays fast deep into the
list, unlike `OFFSET`, which makes the database count rows it then throws away.

The index matters as much as the limit. `orderBy: { id: "desc" }` filtered by `userId` wants a
composite index on `(user_id, id desc)`, or the query scans regardless of page size.

---

## 12. `catch {}` hiding a failed write

The user sees "Saved". Nothing was saved. You find out when someone asks where their data went,
which may be weeks later, and by then there is nothing to recover.

`A10:2025` · `ASVS V16` · `CWE-390`, `CWE-209`

Vulnerable:

```ts
app.post("/api/profile", requireSession, async (req, res) => {
  try {
    await db.profile.update({ where: { id: req.actor.id }, data: req.body });
  } catch {
    // ignore
  }
  res.json({ ok: true }); // always
});
```

Python equivalent, equally common:

```python
try:
    save_profile(user_id, payload)
except Exception:
    pass
return {"ok": True}
```

Fixed — fail loudly, log with context, and return an honest status:

```ts
app.post("/api/profile", requireSession, async (req, res) => {
  const parsed = ProfileSchema.safeParse(req.body); // explicit allowlist of fields
  if (!parsed.success) {
    return res.status(400).json({ error: "invalid profile", issues: parsed.error.issues });
  }

  try {
    await db.profile.update({ where: { id: req.actor.id }, data: parsed.data });
    return res.json({ ok: true });
  } catch (err) {
    const ref = crypto.randomUUID();
    // Full detail server-side, where it is useful and not visible to the caller.
    logger.error({ err, ref, actorId: req.actor.id }, "profile update failed");
    // Nothing about the database, the query, or the stack goes to the client.
    return res.status(500).json({ error: "could not save profile", ref });
  }
});
```

Why it cannot recur: there is no path that returns `ok: true` without the write having
succeeded, because the success response now lives inside the `try` after the `await`. The
reference id links the user's report to the log line without leaking anything.

Two details worth keeping:

The schema replaces `data: req.body`. Passing the request body straight into an update lets a
caller set fields you never intended — `role`, `emailVerified`, `credits`. That is a separate
finding (`A01:2025`, `API3:2023`) that lives in the same line of code.

Returning the raw error to the client is the opposite mistake and just as common. A stack trace
names your file paths, library versions, and often fragments of the query.

---

## What these have in common

Each fix removes the unsafe option rather than relying on someone remembering:

- The secret is not reachable from the browser, so it cannot be read from the browser.
- The check runs on the path the data travels, so no route bypasses it.
- The limit is applied after parsing, so no input evades it.
- The cleanup is owned by one object, so a new subscription is covered by existing code.
- The success response is inside the `try`, so a failure cannot report success.

That is the test to apply to any fix here: if it works only while everyone stays careful, it is
not finished.
