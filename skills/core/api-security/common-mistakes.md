# Common API Security Mistakes

Failures seen repeatedly in API code. Each entry says what it looks like, why it is exploitable,
and the control that closes it.

## Authentication mistaken for authorization

```python
# Vulnerable: login proves identity, not access to this invoice
@require_login
def get_invoice(invoice_id):
    return db.query(Invoice).get(invoice_id)
```

The decorator proves who the caller is. It says nothing about whether this invoice is theirs.
Any logged-in user increments IDs and reads other tenants' data.

Fix: put the actor or policy in the object lookup. `API1:2023` · CWE-639 · ASVS 8.2.2.

## UUID used as the authorization fix

A random ID makes guessing harder. It does not make a leaked ID safe. IDs appear in exports,
logs, support tickets, referrers, and shared links. The control is an object-level policy on every
read, write, and delete. `API1:2023` · CWE-639.

## Ownership checked after fetch, then not enforced

```javascript
// Vulnerable: the failed check only logs
const order = await db.order.findUnique({ where: { id: req.params.id } });
if (order.customerId !== req.user.id) logger.warn("unauthorized");
return res.json(order); // the unauthorized value still leaves the service
```

Logging is not denial. Fetch with the actor constraint or raise/return before serializing.
`API1:2023` · CWE-639 · ASVS 8.2.2.

## Mass assignment fixed with a denylist

```javascript
// Vulnerable: a denylist goes stale when the model grows
const blocked = ["role", "balance", "tenantId"];
const data = Object.fromEntries(Object.entries(req.body).filter(([key]) => !blocked.includes(key)));
await db.user.update({ where: { id }, data });
```

A denylist fails when a new server-owned field arrives, and nested objects hide alternate paths.
`is_verified`, `permissions`, and `owner.id` are common additions.

Fix: an allowlist schema with unknown keys rejected, then explicitly map fields to the update.
`API3:2023` · CWE-915 · ASVS 8.2.3.

## Returning the model because the caller asked for JSON

```python
# Vulnerable: the model's columns become response fields
return jsonify(user.to_dict())
```

The database schema becomes the response contract. One migration later, a private column leaks.
Client-side hiding is not a control: the bytes already crossed the trust boundary.

Fix: an explicit response schema and a separate shape for each audience. `API3:2023` · CWE-213 ·
ASVS 8.1.2.

## Rate limiting by IP only

NAT causes unrelated users to share a limit. A proxy pool lets an attacker rotate out of it.

Fix: key the primary limit by verified actor or client credential, with IP as a pre-auth fallback.
Also rate limit the operation, not merely the global API. `API4:2023` · CWE-799.

## Rate limiting the request, not the business flow

A scalper buys one item per request and stays below the limit, or distributes orders across
accounts. Every request is authorized. The stock is still gone.

Fix: identify sensitive flows and cap the business object per actor, instrument, or promotion.
Rate limits supplement this; they do not replace it. `API6:2023`.

## Depth limit treated as a GraphQL cost limit

```graphql
# Vulnerable: shallow does not mean cheap
{ products { id } }
```

This is shallow and can still request a million products. Aliases and batching multiply work
without increasing depth.

Fix: amount limits on lists plus a complexity/cost budget; count operations and aliases, not just
HTTP requests. `API4:2023` · ASVS 4.3.1.

## Authorization only at GraphQL entry point

```javascript
// Vulnerable: the child field has no authorization
Query: { me: (_, __, ctx) => ctx.user },
User: { email: (user) => user.email }
```

The same `User` can be reached through a report, team, or post. The parent check does not follow
it to every field. A private email or location leaks through the alternate path.

Fix: field-level authorization in the resolver or data layer. `API3:2023` · ASVS 8.2.3.

## Introspection disabled and declared secure

Disabling introspection raises the cost for an unauthenticated schema dump. It does not enforce
authorization, and field names can still leak through errors and suggestion hints. A deliberately
public partner API may need introspection on.

Fix: disable it in private production APIs, suppress schema suggestions, and treat it as
hardening, not as the authorization control. `API9:2023` · ASVS 4.3.2.

## gRPC metadata treated as identity

```go
// Vulnerable: metadata is supplied by the caller
userID := metadata.ValueFromIncomingContext(ctx, "user-id")[0]
```

Metadata is client input. It is no more trustworthy than `?user_id=...`.

Fix: derive identity from a verified bearer token or verified mTLS peer certificate. Strip
client copies of gateway identity headers. `API2:2023`, `API5:2023` · ASVS 4.1.3, V12.

## gRPC reflection left on in production

Reflection publishes services and methods to anyone who can connect. It turns inventory work
into one RPC call and makes forgotten admin methods easy to find.

Fix: register reflection only in controlled development environments. It is not a replacement
for authorization. `API9:2023` · CWE-1059.

## Webhook signature checked after JSON parsing

```javascript
// Vulnerable: verification uses re-serialized JSON
const body = JSON.stringify(req.body);
verify(signature, body);
```

JSON parsing and serialization can change key order, whitespace, unicode escapes, and number
format. The verifier is not checking the bytes the sender signed. A naive `===` compare also
leaks how much of the signature matched.

Fix: capture the raw bytes, sign `timestamp + "." + rawBody`, enforce a replay window, use a
constant-time comparison with a length check, then parse. `API2:2023` · ASVS 4.1.5 · CWE-345.

## Webhook duplicate treated as a server error

Providers retry non-2xx. If processing succeeded and the acknowledgment was lost, returning 500
on the duplicate creates a retry storm. If the handler is not idempotent, it may charge or credit
twice.

Fix: claim the delivery ID atomically, make a duplicate a no-op with 200, and persist the result.
`API4:2023`, `API6:2023`.

## Outbound webhook retries without a cap

A dead subscriber consumes all workers. Retrying with a new delivery ID also defeats receiver
deduplication.

Fix: fixed delivery ID, exponential backoff, bounded attempts, timeouts, no blind redirects, and
a dead-letter queue. `API4:2023`, `API7:2023`.

## Idempotency implemented as a read then write

```python
# Vulnerable: read-then-write races concurrent requests
if not store.exists(actor.id, key):
    result = charge()
    store.save(actor.id, key, result)
```

Two concurrent requests both observe absence and both charge. The retry protection is a race.

Fix: a database uniqueness constraint or atomic insert for `(actor_id, key)`, store the request
fingerprint, and reject the same key with a different body. This is a security control against
replay and double-spend, not only reliability plumbing.

## Redirects trusted because the first host was allowed

```python
# Vulnerable: validating only the first hop
if hostname == "images.example.com":
    return requests.get(url, allow_redirects=True)
```

The allowed host redirects to an internal service or metadata endpoint.

Fix: disable redirects, or validate every destination hop and pin the connection. `API7:2023` ·
CWE-918.

## Resolve once, then let the HTTP client resolve again

A hostname resolves to a public IP for the check and to a private IP for the connection. That is
DNS rebinding. A private-range list alone does not close the window.

Fix: pin the validated address into the connection or use an egress proxy with an allowlist.
State the gap when the architecture cannot do either. `API7:2023` · CWE-918.

## Upstream response trusted because the provider is reputable

Partner JSON can be malformed, unexpectedly large, slow, redirected, or compromised. "Known
provider" is not a schema or a timeout.

Fix: TLS, schema validation, bounded response, connect/read timeouts, redirect allowlist, and
sink-specific encoding. `API10:2023` · CWE-20 · ASVS V1, V2, V12.

## Internal API trusted because it is internal

A service receives a machine-to-machine token from service A and authorizes based on A's broad
permission instead of the originating user's permission. Compromising A becomes cross-tenant
access through B.

Fix: propagate the originating subject and enforce authorization at the trusted service layer.
ASVS 8.3.3; `API1:2023`.
