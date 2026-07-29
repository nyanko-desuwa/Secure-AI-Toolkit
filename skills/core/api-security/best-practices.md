# API Best Practices

Patterns that survive review. Each names its API Security Top 10 2023 category, the ASVS 5.0
requirement or chapter, and a CWE where one applies.

## Object level authorization

`API1:2023` · ASVS 8.2.2, 8.3.1 · CWE-639

Put the actor into the query. A separate `if` is a branch someone will forget, and there is a
window where the object sits in memory unchecked.

```python
# Vulnerable: the ID decides which object, and nothing decides who may have it
@router.get("/api/orders/{order_id}")
def get_order(order_id: int, actor: User = Depends(current_user)):
    return db.query(Order).filter(Order.id == order_id).one_or_none()

# Fixed: ownership is a filter, not a follow-up check
@router.get("/api/orders/{order_id}")
def get_order(order_id: int, actor: User = Depends(current_user)):
    order = (
        db.query(Order)
        .filter(Order.id == order_id, Order.tenant_id == actor.tenant_id)
        .one_or_none()
    )
    if order is None:
        raise HTTPException(404, "not_found")
    return OrderResponse.from_orm(order)
```

Direct ownership only covers direct ownership. Shared documents, team-owned records, and
delegated access need a policy call - OWASP says this explicitly, because comparing the session
user ID to a request ID is the fix people stop at.

```python
# Fixed: shared objects go through a policy, still server-side
def load_document(doc_id: int, actor: User, action: str) -> Document:
    doc = db.query(Document).filter(Document.id == doc_id).one_or_none()
    if doc is None or not policy.allows(actor, action, doc):
        raise HTTPException(404, "not_found")
    return doc
```

Return 404 for someone else's object. A 403 confirms the ID exists, which is the information the
enumeration was after.

Nested routes need both levels. `/orgs/1/members/999` must confirm the actor may act on org 1 and
that member 999 belongs to org 1 - otherwise the parent check passes and the child leaks.

The tempting wrong fix is a UUID primary key. OWASP does list unpredictable IDs as a preventive
measure and they do raise the cost of enumeration, but an ID that leaks through a CSV export, a
`Referer` header, a support ticket, or a shared link is still accepted. Obscurity is not the
control.

## Property level authorization, write side

`API3:2023` · ASVS 8.2.3 · CWE-915

Mass assignment. The caller is allowed to perform this operation on this object; one extra key
turns it into an attack.

```javascript
// Vulnerable: the host may approve their own booking, so the request passes every other check
app.patch("/api/host/bookings/:id", requireHost, async (req, res) => {
  const booking = await db.booking.findFirst({
    where: { id: req.params.id, hostId: req.user.id },
  });
  if (!booking) return res.status(404).json({ error: "not_found" });
  await db.booking.update({ where: { id: booking.id }, data: req.body });
  res.json({ ok: true });
});
```

`{"approved": true, "comment": "...", "totalPriceCents": 100000000}` and the guest is charged a
million dollars. This is OWASP's own scenario, and note that API1 was enforced correctly.

```javascript
// Fixed: an explicit schema decides which fields exist at all
const HostApproval = z.object({
  approved: z.boolean(),
  comment: z.string().max(500).optional(),
}).strict();

app.patch("/api/host/bookings/:id", requireHost, async (req, res) => {
  const parsed = HostApproval.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "invalid_request" });

  const booking = await db.booking.findFirst({
    where: { id: req.params.id, hostId: req.user.id, status: "PENDING" },
  });
  if (!booking) return res.status(404).json({ error: "not_found" });

  await db.booking.update({
    where: { id: booking.id },
    data: { approved: parsed.data.approved, comment: parsed.data.comment },
  });
  res.json({ ok: true });
});
```

Why this works: `.strict()` rejects unknown keys, and the `data` object names its fields, so a new
column on the model cannot become writable by accident. Two independent layers, because schemas
drift.

Denylisting forbidden keys is the tempting wrong fix. It fails the day someone adds
`is_verified`, and it fails on nested paths like `{"owner": {"id": 7}}`.

Field permissions can depend on object state. `status: "PENDING"` in the query above is a control,
not a convenience - price is editable while a booking is draft and not after approval.

## Property level authorization, read side

`API3:2023` · ASVS 8.1.2 · CWE-213

Over-fetching. The serializer decides what the API exposes, which means the database schema
decides.

```python
# Vulnerable: whatever columns exist become API fields
@router.get("/api/users/{user_id}")
def get_user(user_id: int, actor: User = Depends(current_user)):
    user = load_visible_user(user_id, actor)
    return user.to_dict()
```

`to_dict()` ships `password_hash`, `internal_risk_score`, `last_known_lat`, `stripe_customer_id`.
OWASP names `to_json()` and `to_string()` as the anti-pattern directly.

```python
# Fixed: response shape is declared, and it is the same for every caller of this endpoint
class PublicUser(BaseModel):
    id: int
    display_name: str
    avatar_url: str | None
    joined_at: datetime

    model_config = ConfigDict(from_attributes=True)

@router.get("/api/users/{user_id}", response_model=PublicUser)
def get_user(user_id: int, actor: User = Depends(current_user)):
    return load_visible_user(user_id, actor)
```

Why this works: adding a column to the model cannot add a field to the response. The schema is the
contract, and `response_model` enforces it on the way out even if the handler returns more.

Where the same object has two audiences, write two schemas. One schema with conditional field
stripping is where the leak hides.

Filtering in the client is not a fix. The bytes already left the server.

## Function level authorization

`API5:2023` · ASVS 8.2.1, 4.1.4 · CWE-285

Deny by default at the router, per method. A guard on the path prefix or on one handler is not a
guard on the operation.

```javascript
// Vulnerable: the read is guarded, the destructive verb is not
router.get("/api/users/:id", requireRole("admin"), getUser);
router.delete("/api/users/:id", deleteUser);
```

Nothing in the path says `DELETE` is admin-only. OWASP's warning applies: do not infer whether an
endpoint is administrative from its URL. Admin functions sit next to regular ones.

```javascript
// Fixed: routes are declared with a required permission, and the table is the source of truth
const ROUTES = [
  { method: "get",    path: "/api/users/:id", permission: "user:read",   handler: getUser },
  { method: "delete", path: "/api/users/:id", permission: "user:delete", handler: deleteUser },
];

for (const r of ROUTES) {
  router[r.method](r.path, requirePermission(r.permission), r.handler);
}

// Anything not in the table is unreachable
app.use("/api", router, (req, res) => res.status(404).json({ error: "not_found" }));
app.use("/api", (req, res) => res.status(405).json({ error: "method_not_allowed" }));
```

Why this works: registration and authorization happen in one place, so a new route without a
permission is a missing property rather than a silent public endpoint. Reviewing the table is
cheaper than reviewing every handler.

Find admin capability by grepping for what it does - `export`, `impersonate`, `bulk`, `refund`,
`recalculate`, `sync` - not for `/admin`.

## Credential choice

`API2:2023` · ASVS V6, V9, V10 · CWE-307

| Mechanism | Use for | Do not use for |
|---|---|---|
| API key | Identifying a client application, quota accounting | User authentication. OWASP states this outright |
| Bearer token | User sessions, delegated access with scopes | Anything needing revocation before expiry, if self-contained |
| mTLS | Service-to-service, partner B2B | User-facing clients; certificate lifecycle is real work |

```javascript
// Vulnerable: the token's own header decides how it is verified, and nothing pins the audience
const claims = jwt.verify(token, SECRET);

// Fixed: the server states the algorithm, issuer, and audience
const claims = jwt.verify(token, SECRET, {
  algorithms: ["RS256"],
  issuer: "https://auth.example.com",
  audience: "https://api.example.com/orders",
});
```

Why this works: nothing in the token influences its own verification, so `{"alg":"none"}` and
HS256-signed-with-the-public-key both fail. Pinning the audience stops a token minted for another
service being replayed here.

Store API keys hashed, like passwords. A leaked database of plaintext keys is a leaked set of
credentials. Give each key a prefix so it is identifiable in a secret scanner, and compare with a
constant-time function.

A self-contained token cannot be revoked before expiry. Short TTL narrows the window. If immediate
logout is required, hold server-side state and say so - ASVS 8.3.2 makes the same point about
authorization data inside tokens.

## Resource consumption

`API4:2023` · ASVS 4.2.5, V2 · CWE-770

```python
# Vulnerable: the client chooses how much work the server does
@router.get("/api/invoices")
def list_invoices(limit: int = 50, offset: int = 0, actor: User = Depends(current_user)):
    return q(actor).limit(limit).offset(offset).all()
```

`limit=10000000` is a memory exhaustion. Deep `offset` is a table scan on every page.

```python
# Fixed: clamped page size, keyset pagination, bounded work per request
MAX_PAGE = 100

@router.get("/api/invoices", response_model=InvoicePage)
def list_invoices(
    limit: int = Query(50, ge=1, le=MAX_PAGE),
    cursor: str | None = None,
    actor: User = Depends(current_user),
):
    query = q(actor).order_by(Invoice.id.desc())
    if cursor:
        query = query.filter(Invoice.id < decode_cursor(cursor))
    rows = query.limit(limit + 1).all()
    return InvoicePage(
        items=rows[:limit],
        next_cursor=encode_cursor(rows[limit - 1].id) if len(rows) > limit else None,
    )
```

Why this works: `le=MAX_PAGE` rejects the request rather than silently clamping, so a client
relying on a larger page finds out. Keyset pagination keeps cost flat regardless of how deep the
client walks.

Rate limit per actor, not per IP:

```python
# Vulnerable: IP is shared by NAT and rotated for pennies
key = f"rl:{request.client.host}"

# Fixed: the identity that costs something to obtain
key = f"rl:user:{actor.id}" if actor else f"rl:ip:{client_ip(request)}"
```

Per-IP is a pre-auth fallback, not the primary key. It punishes offices behind one NAT and does
nothing to an attacker with a proxy pool. Where the client IP comes from `X-Forwarded-For`, the
edge must strip a client-supplied copy - ASVS 4.1.3 - or the limit is bypassed by setting the
header.

Cap the body at the proxy, not in the handler. By the time your code checks `len(body)`, the bytes
are already buffered.

Paid operations need their own limit and a provider spending cap. An endpoint that sends one SMS
per call is a billing vulnerability at any request rate the infrastructure tolerates.

## Sensitive business flow

`API6:2023`

Every request authenticated, authorized, and inside its rate limit. The aggregate is the attack.

```python
# Vulnerable: correct, and abusable. 200 requests under any sane rate limit buys the stock
@router.post("/api/orders")
def create_order(body: OrderRequest, actor: User = Depends(current_user)):
    reserve_stock(body.sku, body.quantity)
    return charge_and_create(actor, body)
```

```python
# Fixed: the cap is on the business object, not on the request rate
MAX_UNITS_PER_CUSTOMER = {"console-x": 1}

@router.post("/api/orders")
def create_order(body: OrderRequest, actor: User = Depends(current_user)):
    cap = MAX_UNITS_PER_CUSTOMER.get(body.sku)
    if cap is not None:
        already = units_purchased(actor, body.sku, window=timedelta(days=30))
        if already + body.quantity > cap:
            raise HTTPException(409, "purchase_limit_reached")
        if not payment_instrument_is_distinct(actor):
            raise HTTPException(409, "purchase_limit_reached")
    ...
```

Why this works: the limit is denominated in the thing the attacker wants. Distributing across IPs
does not help, and distributing across accounts now costs a distinct payment instrument per unit.

Rate limiting helps API6 and does not solve it. OWASP's mitigations slow automation rather than
stop it: device fingerprinting, human detection, non-human pattern analysis such as add-to-cart
and checkout under a second apart, and blocking Tor exit nodes and known proxies.

Two design questions that catch this class before code exists. Which flow, run perfectly and at
scale, harms us? And which action is free for the attacker to reverse but costly for us - the
airline case, where the damage was cancellation, not booking.

Machine-facing APIs need the same protections. Developer and B2B surfaces usually skip them.

## SSRF

`API7:2023` · ASVS V2, V12 · CWE-918

```python
# Vulnerable: reaches the metadata service, internal admin panels, and localhost
def fetch_avatar(url: str) -> bytes:
    return requests.get(url, timeout=5).content
```

```python
# Fixed: scheme and port allowlist, resolve and check every address, no redirects, bounded read
import ipaddress, socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443}
MAX_BYTES = 2 * 1024 * 1024

def fetch_avatar(url: str) -> bytes:
    parsed = urlparse(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if parsed.scheme not in ALLOWED_SCHEMES or not parsed.hostname or port not in ALLOWED_PORTS:
        raise BadRequest("unsupported_url")

    for info in socket.getaddrinfo(parsed.hostname, port, proto=socket.IPPROTO_TCP):
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global or ip.is_multicast:
            raise BadRequest("unsupported_url")

    resp = requests.get(url, timeout=(2, 5), allow_redirects=False, stream=True)
    if resp.status_code >= 300:
        raise BadRequest("unsupported_url")
    return resp.raw.read(MAX_BYTES + 1)[:MAX_BYTES]
```

Why this works: every resolved address is checked rather than the first, `is_global` covers
private, loopback, link-local, and reserved ranges in one predicate instead of a hand-written
list, and redirects are off so an allowed host cannot forward to `169.254.169.254`.

Honest gap: this is still open to DNS rebinding. The name is resolved once for the check and again
by `requests` for the connection. Closing it means pinning the validated IP into the connection -
a custom adapter, or in production an egress proxy with a destination allowlist. Do not present
the code above as complete.

Do not return the upstream body raw to the caller. That converts a blind SSRF into a readable one.

## GraphQL

`API4`, `API3` · ASVS 4.3.1, 4.3.2, 8.2.3

Depth alone is not enough. ASVS 4.3.1 offers a query allowlist, depth limiting, amount limiting,
or cost analysis. A query one level deep asking for 100,000 items passes a depth limit.

```javascript
// Vulnerable: introspection on, no cost control, resolvers trust the query entry point
const server = new ApolloServer({ typeDefs, resolvers });

// Fixed: cost and depth capped, introspection off, batching bounded
import depthLimit from "graphql-depth-limit";
import { createComplexityLimitRule } from "graphql-validation-complexity";

const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: false,
  validationRules: [depthLimit(8), createComplexityLimitRule(1500)],
  allowBatchedHttpRequests: false,
  formatError: (formatted) => ({
    message: formatted.extensions?.code === "BAD_USER_INPUT"
      ? formatted.message
      : "internal_error",
    extensions: { code: formatted.extensions?.code ?? "INTERNAL_ERROR" },
  }),
});
```

Why this works: complexity accounts for list multipliers that depth ignores, and rejecting batched
arrays stops one HTTP request from carrying a hundred operations past a per-request rate limit.

Authorization belongs in the resolver or the data layer, not at the entry point:

```javascript
// Vulnerable: the parent query is authorized, the child field is not
const resolvers = {
  Query: { me: (_, __, ctx) => ctx.user },
  User: { emailAddress: (user) => user.email },
};
```

Any query that reaches a `User` - through `post.author`, `team.members`, `report.reportedUser` -
gets the email. OWASP's dating-app scenario is exactly this: `reportUser` returns the reported
user's `fullName` and `recentLocation`.

```javascript
// Fixed: the field decides, using the object and the actor
const resolvers = {
  User: {
    emailAddress: (user, _, ctx) => {
      if (ctx.user?.id !== user.id && !ctx.user?.permissions.has("user:read_pii")) {
        return null;
      }
      return user.email;
    },
  },
};
```

Why this works: the check travels with the field, so a new query path that reaches `User` inherits
it. Guarding at the top-level query means each new traversal is a new hole.

Disabling introspection raises cost; it does not hide the schema. Field names come back from error
messages and "did you mean" suggestions. Disable suggestions too if the schema is meant to be
private, and do not count either as a control.

Batched and aliased queries need cost accounting per operation, not per HTTP request. Ten aliases
of the same expensive field is one request.

## gRPC

`API2`, `API5`, `API8` · ASVS V12, 8.2.1

```go
// Vulnerable: no transport security, reflection on, identity read from client-set metadata
s := grpc.NewServer()
reflection.Register(s)
```

```go
// Fixed: mTLS, reflection only outside production, deny-by-default interceptor
creds := credentials.NewTLS(&tls.Config{
    ClientAuth:   tls.RequireAndVerifyClientCert,
    ClientCAs:    clientCAPool,
    MinVersion:   tls.VersionTLS13,
})

s := grpc.NewServer(
    grpc.Creds(creds),
    grpc.MaxRecvMsgSize(4*1024*1024),
    grpc.UnaryInterceptor(authorize),
)

if env != "production" {
    reflection.Register(s)
}

var required = map[string]string{
    "/billing.Billing/GetInvoice": "invoice:read",
    "/billing.Billing/VoidInvoice": "invoice:void",
}

func authorize(ctx context.Context, req any, info *grpc.UnaryServerInfo,
    handler grpc.UnaryHandler) (any, error) {

    perm, known := required[info.FullMethod]
    if !known {
        return nil, status.Error(codes.PermissionDenied, "not_permitted")
    }
    caller, err := callerFromPeerCert(ctx) // from the verified TLS peer, not metadata
    if err != nil || !caller.Has(perm) {
        return nil, status.Error(codes.PermissionDenied, "not_permitted")
    }
    return handler(ctx, req)
}
```

Why this works: an unregistered method is denied rather than allowed, so adding an RPC without a
permission entry fails closed. Identity comes from the verified certificate, so it cannot be set
by the caller.

Metadata is client-controlled. A `user-id` or `tenant-id` header in gRPC metadata is exactly as
trustworthy as a query parameter. If a gateway injects identity, it must strip the client's copy -
ASVS 4.1.3 - and the backend should prefer a signed token it can verify itself.

Reflection is a service catalogue. Leaving it on in production is API9 with extra convenience for
the attacker.

## Webhooks, inbound

`API2`, `API10` · ASVS 4.1.5, V12 · CWE-345

```javascript
// Vulnerable: anyone who knows the URL can post a paid-invoice event
app.post("/webhooks/psp", express.json(), async (req, res) => {
  await markInvoicePaid(req.body.invoice_id);
  res.sendStatus(200);
});
```

```javascript
// Fixed: signature over the raw body, constant-time compare, replay window, delivery-id dedupe
import crypto from "node:crypto";

const TOLERANCE_SECONDS = 300;

app.post("/webhooks/psp", express.raw({ type: "*/*", limit: "128kb" }), async (req, res) => {
  const timestamp = req.get("X-Psp-Timestamp") ?? "";
  const provided = req.get("X-Psp-Signature") ?? "";
  const deliveryId = req.get("X-Psp-Delivery-Id") ?? "";

  const age = Math.abs(Date.now() / 1000 - Number(timestamp));
  if (!Number.isFinite(age) || age > TOLERANCE_SECONDS) return res.sendStatus(400);

  const expected = crypto
    .createHmac("sha256", process.env.PSP_WEBHOOK_SECRET)
    .update(`${timestamp}.`)
    .update(req.body)              // raw bytes, not the parsed object
    .digest();

  const providedBuf = Buffer.from(provided, "hex");
  if (
    providedBuf.length !== expected.length ||
    !crypto.timingSafeEqual(providedBuf, expected)
  ) {
    return res.sendStatus(400);
  }

  if (!(await claimDelivery(deliveryId))) return res.sendStatus(200); // already processed
  await markInvoicePaid(JSON.parse(req.body).invoice_id);
  res.sendStatus(200);
});
```

Why this works, point by point. The HMAC is computed over the exact bytes received, so
re-serializing cannot change the signed content - key order and unicode escaping differ between
JSON encoders, and a signature over the re-encoded body will not match. The timestamp is inside
the signed string, so it cannot be edited to defeat the window. `timingSafeEqual` removes the
byte-by-byte timing leak, with a length check first because it throws on mismatched lengths.
`claimDelivery` makes a replay inside the window a no-op.

A shared secret in the URL path is the tempting wrong fix. It lands in proxy logs, browser
history, and referrer headers, and it cannot be rotated without the sender's cooperation.

Return 200 for a duplicate, not an error. Providers retry on non-2xx, so erroring on a duplicate
manufactures a retry storm.

## Webhooks, outbound

`API7`, `API4`

Your own outbound webhooks are an SSRF vector: the customer supplies the URL.

```python
# Fixed: validate the destination, sign the payload, retry with a cap
def deliver(subscription: Subscription, event: dict) -> None:
    url = validate_destination(subscription.url)   # the SSRF checks above
    body = canonical_json(event).encode()
    ts = str(int(time.time()))
    sig = hmac.new(subscription.secret, f"{ts}.".encode() + body, hashlib.sha256).hexdigest()

    for attempt in range(MAX_ATTEMPTS):           # 6 attempts, exponential backoff, then dead-letter
        resp = session.post(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "X-Ourapp-Timestamp": ts,
                "X-Ourapp-Signature": sig,
                "X-Ourapp-Delivery-Id": event["delivery_id"],
            },
            timeout=(2, 10),
            allow_redirects=False,
        )
        if resp.status_code < 300:
            return
        time.sleep(BACKOFF_BASE * 2 ** attempt)
    dead_letter(subscription, event)
```

Why this works: the destination goes through the same SSRF validation as any user-supplied URL,
the signature and timestamp let the receiver do everything in the inbound section, and the attempt
cap plus dead-letter queue keeps a broken endpoint from becoming an unbounded retry loop against
your own workers.

Keep payloads minimal. A webhook body is a data export to a URL the customer controls, so send
identifiers and let the receiver fetch detail over an authenticated API.

Retries must reuse the same delivery ID. A new ID per attempt makes the receiver's dedupe useless.

## Idempotency keys

`API4:2023`, `API6:2023` · ASVS V2

Usually filed under reliability. It is a security control, because a retried request is
indistinguishable from a replayed one.

```python
# Vulnerable: a client timeout and retry charges twice; an attacker replays deliberately
@router.post("/api/payments")
def create_payment(body: PaymentRequest, actor: User = Depends(current_user)):
    return psp.charge(actor, body.amount_cents)
```

```python
# Fixed: first request wins, retries replay the stored result
@router.post("/api/payments")
def create_payment(
    body: PaymentRequest,
    idempotency_key: str = Header(..., alias="Idempotency-Key", max_length=255),
    actor: User = Depends(current_user),
):
    fingerprint = sha256(canonical_json(body).encode()).hexdigest()

    with db.begin():
        row = db.execute(
            insert(IdempotencyRecord)
            .values(
                actor_id=actor.id,               # scoped to the actor
                key=idempotency_key,
                request_fingerprint=fingerprint,
                state="IN_PROGRESS",
            )
            .on_conflict_do_nothing()
            .returning(IdempotencyRecord.id)
        ).first()

    if row is None:
        existing = get_record(actor.id, idempotency_key)
        if existing.request_fingerprint != fingerprint:
            raise HTTPException(422, "idempotency_key_reuse")
        if existing.state == "IN_PROGRESS":
            raise HTTPException(409, "request_in_progress")
        return existing.response_body

    result = psp.charge(actor, body.amount_cents)
    complete_record(actor.id, idempotency_key, result)
    return result
```

Why this works, and why it is security rather than plumbing. The uniqueness is enforced by the
database, so two concurrent requests cannot both pass a "does this key exist" check - a
read-then-write in application code is a race, and the race is the exploit. The key is scoped to
the actor, so one caller cannot occupy or read another's key. The body fingerprint means a
replayed key with a modified amount is rejected rather than silently returning the old result,
which would otherwise let an attacker probe for accepted keys.

Apply it to anything that moves money, sends a message, grants credit, or creates a record a
duplicate of which is harmful. Skip it on idempotent verbs, where the semantics already hold.

## Sources

- <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x13-V4-API-and-Web-Service.md>
- <https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html>
- <https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html>
- <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
