# Common Mistakes

The catalogue. Each entry gives the shape the mistake takes in generated code, what it costs in
plain terms, the fix, and why the mistake cannot come back once fixed.

Ordered by what it costs before anyone notices, not by how often it appears.

## `.env` treated as a secret store for the frontend

`A04:2025` · ASVS V14 · `CWE-540`

```typescript
// Vulnerable: .env.local
// NEXT_PUBLIC_OPENAI_KEY=sk-REPLACE-ME-not-a-real-key
const key = process.env.NEXT_PUBLIC_OPENAI_KEY;
```

Cost: anyone who opens your site reads the key from the downloaded JavaScript and spends your
credits. Bills of several thousand dollars in a weekend come from exactly this.

The misunderstanding is that `.env` means private. The `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`,
`EXPO_PUBLIC_`, and `PUBLIC_` prefixes are instructions to the build tool to copy the value into
the public bundle. That is what they are for.

Fix: move the call behind a server route that holds the unprefixed variable, then rotate the
exposed key. Cannot recur because the client code no longer references a credential, and the
build-output grep in [references/secret-exposure.md](references/secret-exposure.md) fails the
check if one reappears.

## Service-role or admin key used from the browser

`A01:2025` · ASVS V8 · `CWE-798`

```typescript
// Vulnerable: this key ignores every security policy you wrote
const supabase = createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!);
```

Cost: total database compromise. Read, edit, and delete every row for every customer. Row Level
Security does not apply to this key by design.

Fix: the browser gets the anon or publishable key only. Anything needing elevated rights goes
through a server route or an Edge Function. Cannot recur because the elevated key is never
present in the client build; grep the bundle for `service_role` to confirm.

## Assuming a deleted line un-leaks a key

`A04:2025` · ASVS V14 · `CWE-615`

```bash
# Vulnerable: the key is still in the repository, forever
git rm --cached .env
git commit -m "remove secrets"
```

Cost: every clone, fork, and CI cache still has the value. Public-repo scanners find committed
keys in minutes.

Fix: revoke and reissue at the provider first. History cleanup is second and optional. Cannot
recur because the exposed value stops working, so possession of it is worthless.

## JWT decoded but never verified

`A07:2025` · ASVS V9 · `CWE-347`, `CWE-807`

```javascript
// Vulnerable
const payload = jwtDecode(token);
if (payload.role === "admin") return allAdminData();
```

Cost: anyone becomes an admin. The token's middle section is base64 text with no protection.
Write `{"role":"admin"}`, encode it, send it.

Fix: `jwt.verify(token, secret, { algorithms: ["HS256"] })`, then read the role from your
database rather than from the token. Cannot recur because an unsigned or re-signed token throws,
and the role no longer comes from the caller.

## Authorization enforced only in the UI

`A01:2025` · ASVS V8 · `CWE-602`

```tsx
// Vulnerable: the guard is decoration
{user.isAdmin && <DeleteAllButton />}
<Route path="/admin" element={user.isAdmin ? <Admin /> : <Navigate to="/" />} />
```

Cost: the endpoint behind the button answers anyone who calls it directly. The attacker never
loads your React app.

Fix: authorize in the route handler and scope the query by the acting user. Keep the UI check
for looks. Cannot recur because the server refuses regardless of what the client renders. Verify
with `curl` and no session.

## `rejectUnauthorized: false` to make an error go away

`A02:2025` · ASVS V12 · `CWE-295`

```javascript
// Vulnerable
const agent = new https.Agent({ rejectUnauthorized: false });
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
```

Cost: encryption still happens, but you no longer know who you are talking to. Anyone on the
network path can sit in the middle, read the traffic, and change it. Credentials in that traffic
are theirs.

Fix: add the correct certificate authority to the trust store, or fix the hostname mismatch.
`NODE_EXTRA_CA_CERTS=/path/to/ca.pem` for a private CA. Cannot recur because the setting is gone
and a genuine certificate problem fails loudly again.

## Test credentials and bypasses left in the shipped path

`A07:2025` · ASVS V6 · `CWE-259`, `CWE-798`

```javascript
// Vulnerable
if (password === "admin123") return grantSession(userId);
const isAdmin = true; // TODO: remove before launch
if (req.headers["x-skip-auth"] === "yes") return next();
```

Cost: a single known string is a master key to every account.

Fix: delete them. Test with seeded data in a test environment, not with a branch in production
code. Cannot recur if CI greps for `TODO`, `FIXME`, `skip-auth`, and hardcoded comparisons and
fails the build.

## CORS wildcard with credentials, or a reflected origin

`A02:2025` · ASVS V3 · `CWE-1188`

```javascript
// Vulnerable
app.use(cors({ origin: true, credentials: true }));           // reflects any origin
res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
```

Cost: any website your logged-in user visits can make authenticated requests to your API as
them, and read the responses.

Fix: an explicit array of origins. Cannot recur because an unlisted origin gets no CORS header
and the browser blocks the read.

```javascript
const ALLOWED = ["https://app.example.com", "https://admin.example.com"];
app.use(cors({ origin: ALLOWED, credentials: true }));
```

## Trusting a price, role, or quantity from the request body

`A01:2025` · `API3:2023` · ASVS V2 · `CWE-807`

```javascript
// Vulnerable: the client chooses what to pay
const { productId, price, quantity } = req.body;
await charge(req.user.id, price * quantity);
```

Cost: someone sets `price` to `0.01` and buys everything. Or sets `role` to `admin` on signup.

Fix: take only the identifier from the client and look the rest up server-side. Cannot recur
because there is no field to tamper with.

```javascript
const { productId, quantity } = req.body;
if (!Number.isInteger(quantity) || quantity < 1 || quantity > 10) {
  return res.status(400).json({ error: "invalid_quantity" });
}
const product = await db.product.findUniqueOrThrow({ where: { id: productId } });
await charge(req.user.id, product.priceCents * quantity);
```

## Unbounded cache keyed by user input

`A06:2025` · `API4:2023` · ASVS V15 · `CWE-401`, `CWE-770`

```javascript
// Vulnerable
const cache = new Map();
cache.set(req.query.q, await search(req.query.q));
```

Cost: two things at once. Memory grows forever, and a stranger sending distinct search terms can
run the process out of memory using nothing but valid requests.

Fix: `LRUCache` with `max`, `ttl`, and `maxSize`, plus input length validation. Cannot recur
because the ceiling is enforced by the cache itself, not by how the keys happen to be shaped.
Full code in [best-practices.md](best-practices.md#5-memory-and-resource-leaks).

## No pagination on a list endpoint

`A06:2025` · `API4:2023` · ASVS V4 · `CWE-770`

```javascript
// Vulnerable
app.get("/api/products", async (_req, res) => res.json(await db.product.findMany()));
```

Cost: works for a year, then the table is large enough that one request loads every row into
memory and the process is killed. Every other user sees an error while it restarts.

Fix: cursor pagination with a server-side `MAX_PAGE_SIZE` applied via `Math.min`. Cannot recur
because a client-supplied `limit` clamps instead of being obeyed.

## Client-supplied limit obeyed as sent

`API4:2023` · ASVS V4 · `CWE-770`

```javascript
// Vulnerable: pagination that the caller can switch off
const limit = Number(req.query.limit) || 20;
await db.order.findMany({ take: limit });   // ?limit=999999999
```

Cost: pagination exists on paper and provides no protection.

Fix: `Math.min(limit, MAX_PAGE_SIZE)`. Cannot recur because the maximum is arithmetic, not
documentation.

## `LIMIT 100` standing in for a real query

`A10:2025` · ASVS V2 · no CWE assigned here

```sql
-- Vulnerable: the totals are silently wrong past 100 rows
SELECT * FROM invoices WHERE month = '2026-07' LIMIT 100;
```

Cost: not a crash, which is why it survives. The report is quietly incomplete and people make
decisions on it.

Fix: aggregate in the database (`SELECT SUM(total) ...`), or paginate and say so in the response.
Cannot recur because the number no longer depends on how many rows fit.

## No timeout on an outbound call

`A10:2025` · ASVS V15 · `CWE-400`

```javascript
// Vulnerable: most HTTP clients wait forever by default
const res = await fetch(thirdPartyUrl);
```

Cost: when the dependency hangs rather than fails, your requests pile up until the connection
pool is empty. Your app is down because of someone else's outage.

Fix: `AbortSignal.timeout(5_000)` on `fetch`, an explicit `timeout` on `axios`, `timeout=` on
Python `requests`. Cannot recur because the call cannot outlive its budget.

## Retry with no backoff and no ceiling

`A10:2025` · `API4:2023` · ASVS V15 · `CWE-400`

```javascript
// Vulnerable: a hot loop against something that is already struggling
setInterval(() => fetch("/api/status").catch(() => {}), 1_000);
```

Cost: when the dependency fails, every client retries every second forever. You turn a small
outage into a self-inflicted flood, and if the endpoint is metered, into a bill.

Fix: capped exponential backoff with jitter and a maximum attempt count. Cannot recur because
the delay grows and the loop terminates. Code in
[examples/README.md](examples/README.md#setinterval-retry-with-no-backoff-or-ceiling).

## `useEffect` with no cleanup

`A10:2025` · ASVS V15 · `CWE-401`

```typescript
// Vulnerable
useEffect(() => {
  const socket = new WebSocket(url);
  socket.onmessage = onMessage;
}, [url]);
```

Cost: a new socket, listener, or timer per mount and none released. The tab gets slower the
longer it is open, and handlers fire against components that are gone.

Fix: return a cleanup function that undoes everything the effect started. Cannot recur because
React calls the cleanup on unmount and before every re-run.

## Listener added per request in Node

`A10:2025` · ASVS V15 · `CWE-401`

```javascript
// Vulnerable
app.post("/api/jobs", (req, res) => jobEmitter.on("done", () => res.json({ ok: true })));
```

Cost: handlers accumulate on a long-lived emitter and keep each request's response object alive.
Memory climbs with traffic, then the process is killed. Node's max-listeners warning is the only
hint.

Fix: `once`, with removal on the `close` path and a timeout. Cannot recur because every exit
path runs the same cleanup.

## `await` inside a `for` loop

`A10:2025` · ASVS V15 · `CWE-400`

```javascript
// Vulnerable: one round trip per row, run one at a time
for (const order of orders) {
  order.items = await db.orderItem.findMany({ where: { orderId: order.id } });
}
```

Cost: the page gets slower in direct proportion to the data. Fine in a demo, forty seconds in
production.

Fix: a join or `include`, or one batched query with `in` and grouping in memory. Cannot recur
because there is no per-row query left to multiply.

## Serial awaits over independent calls

`A10:2025` · ASVS V15

```javascript
// Vulnerable: 900ms for three 300ms calls
const user = await getUser(id);
const plan = await getPlan(id);
const usage = await getUsage(id);

// Fixed: 300ms
const [user, plan, usage] = await Promise.all([getUser(id), getPlan(id), getUsage(id)]);
```

Only safe when the calls do not depend on each other. Add a concurrency cap when the list is
user-sized rather than three items long.

## Client or config recreated per request

`A10:2025` · ASVS V15 · `CWE-772`

```javascript
// Vulnerable
app.get("/api/x", async (_req, res) => {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  res.json((await pool.query("SELECT 1")).rows);
});
```

Cost: connections are created and abandoned until the database hits its own limit, at which point
unrelated applications on that database also fail.

Fix: one pool with a `max`, created at startup, closed at shutdown. Cannot recur because there is
no per-request construction to leak.

## Empty catch

`A09:2025` · `A10:2025` · ASVS V16 · `CWE-390`

```javascript
// Vulnerable
try { await saveOrder(order); } catch {}
return { ok: true };
```

Cost: the UI says saved, the data is not saved, and nothing is logged. You find out from a
customer weeks later.

Fix: log with context and rethrow, or handle the error meaningfully. Cannot recur if a lint rule
forbids an empty block and CI enforces it.

## Raw error rendered to the user

`A09:2025` · ASVS V16 · `CWE-209`

```javascript
// Vulnerable
res.status(500).json({ error: err.stack });
```

Cost: hands over file paths, dependency names, and query fragments. That is reconnaissance for
the next attempt.

Fix: generic message plus a correlation ID, full detail in the log. Cannot recur if one error
handler owns every response shape.

## Retry on a non-idempotent write

`A10:2025` · ASVS V15

```javascript
// Vulnerable: a timeout that actually succeeded is charged twice
await retry(() => stripe.charges.create({ amount, customer }), { attempts: 3 });
```

Cost: duplicate charges and duplicate rows. A timeout means unknown, not failed.

Fix: pass an idempotency key derived from the request so the provider deduplicates. Cannot recur
because the second attempt returns the first result instead of creating a new charge.

## Bulk write with no `WHERE`, run against production

`A01:2025` · ASVS V16

```sql
-- Vulnerable
UPDATE users SET plan = 'free';
DELETE FROM sessions;
```

Cost: every row changed, and with no verified backup, unrecoverable.

Fix: run the `SELECT` with the identical `WHERE` first and read the row count. Wrap in a
transaction so a wrong count can be rolled back. Cannot recur if production write access is not
routine and backups are tested.

## Multi-step write with no transaction

`A10:2025` · ASVS V15

```javascript
// Vulnerable: a failure after the first line leaves a paid order with no items
await db.order.create({ data: order });
await db.orderItem.createMany({ data: items });
await db.inventory.decrement({ where: { id }, data: { count: items.length } });

// Fixed
await db.$transaction(async (tx) => {
  await tx.order.create({ data: order });
  await tx.orderItem.createMany({ data: items });
  await tx.inventory.update({ where: { id }, data: { count: { decrement: items.length } } });
});
```

## Python: module-level accumulator and `lru_cache` on a method

`A10:2025` · ASVS V15 · `CWE-401`

```python
# Vulnerable
AUDIT = []                                # grows for the life of the process

class Report:
    @functools.lru_cache(maxsize=None)    # keeps self alive, unbounded
    def render(self, month): ...
```

Cost: steadily rising memory in a worker that looks stateless. `maxsize=None` is unlimited, and
caching a method holds every instance it was called on.

Fix: `collections.deque(maxlen=N)` for the accumulator, and move the cached work to a
module-level function with `maxsize` set. Cannot recur because both structures have a bound.

## The Wrong Fixes

| Wrong fix | Why it fails |
|---|---|
| Obfuscating or base64-encoding a frontend key | The browser has to decode it to use it. So can anyone reading the code |
| Hiding the admin button more thoroughly | The endpoint is what answers requests, not the button |
| A UUID primary key instead of authorization | Obscurity. IDs leak through exports, logs, and referrers |
| Deleting the commit that had the key | Copies exist. Revoke at the provider first |
| Raising the memory limit or the instance size | Buys time proportional to the increase. The leak rate is unchanged |
| A nightly restart to clear memory | Hides the leak until traffic grows enough to need it hourly |
| Blocking the IP that triggered the outage | The limit is still missing for the next caller |
| Wrapping the flaky call in a retry | Without backoff and idempotency you add load and duplicate writes |
| Catching the error and logging it, then continuing | Correct only when continuing is actually safe. Usually it is not |
| Adding an index for every column | Writes slow down. Index what is filtered, joined, or ordered |
