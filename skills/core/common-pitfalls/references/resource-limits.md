# Limits Worth Starting From

Every number here is a starting point, not a standard. The value that matters is that a limit
exists at all. A wrong-but-present maximum degrades one feature. A missing maximum lets one
request take the whole app down.

`A06:2025` · `API4:2023` · ASVS V2, V4, V5 · `CWE-770`, `CWE-400`

## Pagination

| Setting | Start with | Why |
|---|---|---|
| Default page size | 20-50 | Fits a screen, keeps the response small |
| Maximum page size | 100 | Clamped on the server. The client asking for 10000 gets 100 |
| Deep offset limit | reject offset above ~10000 | `OFFSET 500000` scans and discards half a million rows |
| Ordering | always explicit, on an indexed column | Without it, pages overlap and skip rows |

Cursor pagination — keyset, based on the last row's sort value — stays fast at any depth because
the database seeks instead of counting. Offset pagination gets slower the further in you go.

Clamp, do not reject, when the client asks for too much:

```typescript
const MAX_PAGE = 100;
const limit = Math.min(Number(req.query.limit) || 20, MAX_PAGE);
```

## Timeouts

Most HTTP clients default to no timeout. A hung dependency then holds your request, its
connection, and its memory until the process is restarted.

| Call | Start with |
|---|---|
| Internal service HTTP call | 2-5s total, 1s to connect |
| Third-party API | 10s |
| LLM completion (non-streaming) | 60-120s |
| Database query | 5-10s statement timeout |
| Whole HTTP request handler | 30s, below the load balancer's own timeout |
| Serverless function | shorter than the platform maximum, and set deliberately |

```typescript
// Node 18+ has no default fetch timeout. Set one.
const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
```

```python
# requests has no default timeout either. Connect and read, separately.
r = requests.get(url, timeout=(3.05, 10))
```

Each layer's timeout should be shorter than the layer that calls it, or the outer layer gives up
first and the inner work continues with nobody waiting for it.

## Retries

| Setting | Start with |
|---|---|
| Maximum attempts | 3 total, including the first |
| Backoff | exponential, base 1s, doubling |
| Jitter | random, up to the full delay |
| Ceiling | 30s between attempts |
| Retryable | timeouts, connection errors, 429, 502, 503, 504 |
| Never retry | 400, 401, 403, 404, 422, and any non-idempotent write without an idempotency key |

Jitter matters when many clients fail at the same moment. Without it they all retry in lockstep
and the recovering service is knocked over again.

## Upload and body size

| Setting | Start with |
|---|---|
| JSON body | 100KB-1MB |
| Image upload | 5-10MB |
| Document upload | 25MB |
| Files per request | 5-10 |
| Total multipart size | sum of the above, enforced separately |
| Archive extraction | cap total output bytes and file count, not just the archive size |

Enforce at both layers. The framework limit protects the process; the reverse proxy or CDN limit
stops the bytes before they reach it.

```javascript
app.use(express.json({ limit: "100kb" }));
```

Nginx: `client_max_body_size 10m;`

## Rate limits

Per authenticated user where you can, per IP where you cannot. Anything that costs money per
call needs a limit even if it is not security-sensitive.

| Endpoint | Start with |
|---|---|
| Login | 5 per 15 minutes per account, plus a per-IP limit |
| Password reset, signup | 3 per hour |
| Email or SMS send | 10 per hour per user |
| Search | 30 per minute |
| Upload | 10 per hour |
| General authenticated API | 100-300 per minute |
| Unauthenticated API | 20-60 per minute per IP |
| LLM or metered API call | 20 per hour per user, and a spend ceiling |

Rate limits keyed only on IP are weak — one office shares an address, one attacker rents
thousands. Depth on this is in `api-security` and `brute-force-defense`.

## Concurrency

| Setting | Start with |
|---|---|
| Database pool size | 5-20 per process, and process count times pool size below the database maximum |
| Pool acquire timeout | 5s, so a saturated pool fails fast instead of queueing forever |
| Outbound fan-out | 5-10 in flight, never one promise per row |
| Background job workers | sized to the slowest downstream dependency |
| Serverless concurrency | an explicit cap, so a traffic spike is throttled rather than billed |

A pool with no maximum is the same bug as no pool: the database hits its own connection limit and
every other client fails too.

## LLM and metered API spend

| Setting | Start with |
|---|---|
| Max output tokens | set explicitly on every call |
| Max input tokens | truncate or reject before sending |
| Per-request cost ceiling | computed from the model's price, enforced in code |
| Per-user daily cap | a number you can afford to lose |
| Provider spend limit | set in the provider dashboard as the backstop |
| Concurrent calls | capped, so a retry storm cannot multiply spend |

An LLM call inside a loop over user-supplied items is the most expensive shape of this mistake.
Cap the item count first.

## Loops over user input

Any iteration count derived from a request needs a maximum: array length in a body, batch
operations, rows in an uploaded CSV, pages walked in a paginated fetch, recursion depth in a
nested structure, matches in a regular expression. Reject at the boundary with a clear message
rather than truncating silently.

## Where these numbers came from

They are conventional operational defaults, chosen to be safe rather than optimal. They are not
drawn from a published standard, and no OWASP document specifies numeric values for them. The
requirement that limits exist is what the standards state; the values are yours to tune with
measurement.
