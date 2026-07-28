# API Security Examples

Eight vulnerable/fixed pairs. Each names its API Security Top 10 2023 category, CWE, and the ASVS
5.0 chapter or requirement it serves.

These are patterns, not drop-in production code. Every vulnerable block is labelled.

## Contents

- [Object level authorization](#object-level-authorization) — API1, CWE-639
- [Mass assignment on write](#mass-assignment-on-write) — API3, CWE-915
- [Over-fetching on read](#over-fetching-on-read) — API3, CWE-213
- [Function authorization by HTTP verb](#function-authorization-by-http-verb) — API5, CWE-285
- [GraphQL field authorization and cost](#graphql-field-authorization-and-cost) — API3/API4, CWE-213/CWE-770
- [Inbound webhook signature and replay](#inbound-webhook-signature-and-replay) — API2, CWE-345
- [gRPC metadata trust](#grpc-metadata-trust) — API2/API5, CWE-345/CWE-285
- [Idempotency key race](#idempotency-key-race) — API4/API6, CWE-362

---

## Object level authorization

`API1:2023` · `CWE-639` · ASVS 8.2.2, 8.3.1

```javascript
// Vulnerable: any logged-in user reads any order
app.get("/api/orders/:id", requireAuth, async (req, res) => {
  const order = await db.order.findUnique({ where: { id: req.params.id } });
  if (!order) return res.status(404).json({ error: "not_found" });
  res.json(order);
});
```

`GET /api/orders/4192` succeeds for whichever user can guess or obtain 4192.

```javascript
// Fixed: tenant and actor constrain the lookup
app.get("/api/orders/:id", requireAuth, async (req, res) => {
  const order = await db.order.findFirst({
    where: {
      id: req.params.id,
      tenantId: req.user.tenantId,
      customerId: req.user.id,
    },
    select: { id: true, status: true, totalCents: true, createdAt: true },
  });
  if (!order) return res.status(404).json({ error: "not_found" });
  res.json(order);
});
```

Why this works: the database cannot return a cross-actor row, and the same 404 covers missing and
unauthorized objects. The explicit `select` also closes the API3 read-side gap.

The tempting wrong fix is replacing integer IDs with UUIDs. An ID from an export or support ticket
still works; authorization does not depend on whether an attacker guessed it.

---

## Mass assignment on write

`API3:2023` · `CWE-915` · ASVS 8.2.3

```python
# Vulnerable: client controls every model attribute accepted by the ORM
@router.patch("/api/profile")
def update_profile(body: dict, actor: User = Depends(current_user)):
    db.query(User).filter(User.id == actor.id).update(body)
    db.commit()
```

`PATCH /api/profile {"display_name":"A","role":"admin","tenant_id":1}` edits server-owned
properties on the right object.

```python
# Fixed: strict input type plus explicit persistence mapping
class ProfilePatch(BaseModel):
    display_name: str | None = Field(None, min_length=1, max_length=64)
    bio: str | None = Field(None, max_length=500)

    model_config = ConfigDict(extra="forbid")

@router.patch("/api/profile")
def update_profile(body: ProfilePatch, actor: User = Depends(current_user)):
    values = body.model_dump(exclude_unset=True)
    db.query(User).filter(User.id == actor.id).update({
        key: values[key] for key in ("display_name", "bio") if key in values
    })
    db.commit()
    return {"ok": True}
```

Why this works: `extra="forbid"` rejects the malicious keys and the field map independently keeps
model additions out of the update path. A denylist of `role` and `tenant_id` would fail when
`is_verified` is added.

---

## Over-fetching on read

`API3:2023` · `CWE-213` · ASVS 8.1.2, 8.2.3

```python
# Vulnerable: database schema becomes public schema
@router.get("/api/team/members")
def members(actor: User = Depends(current_user)):
    return [member.to_dict() for member in load_team(actor)]
```

The response includes whichever columns happen to exist: password hash, risk score, last login IP,
payroll ID.

```python
# Fixed: endpoint-specific response schema
class TeamMember(BaseModel):
    id: int
    display_name: str
    avatar_url: str | None

    model_config = ConfigDict(from_attributes=True)

@router.get("/api/team/members", response_model=list[TeamMember])
def members(actor: User = Depends(current_user)):
    return load_team(actor)
```

Why this works: the framework filters and validates the response against the declared shape. A new
model column cannot leak. Client-side hiding fails because the bytes already left the service.

---

## Function authorization by HTTP verb

`API5:2023` · `CWE-285` · ASVS 8.2.1, 4.1.4

```javascript
// Vulnerable: role guard covers GET only
router.get("/api/users/:id", requirePermission("user:read"), getUser);
router.delete("/api/users/:id", deleteUser);
```

A regular authenticated user guesses `DELETE /api/users/4192`. The path does not look
administrative, and the handler is unguarded.

```javascript
// Fixed: method and capability registered together
const routes = [
  ["get", "/api/users/:id", "user:read", getUser],
  ["delete", "/api/users/:id", "user:delete", deleteUser],
];

for (const [method, path, permission, handler] of routes) {
  router[method](path, requirePermission(permission), handler);
}

router.all("*", (_, res) => res.status(405).json({ error: "method_not_allowed" }));
```

Why this works: there is no route registration that omits the permission argument, and unused
methods are rejected. Moving the delete route under `/admin` would only make it easier to find;
the capability check is the control.

---

## GraphQL field authorization and cost

`API3:2023`, `API4:2023` · `CWE-213`, `CWE-770` · ASVS 8.2.3, 4.3.1, 4.3.2

```javascript
// Vulnerable: entry point authenticated, child fields unrestricted, no query bounds
const server = new ApolloServer({
  typeDefs,
  resolvers: {
    Mutation: { reportUser: (_, args, ctx) => reports.create(ctx.user, args) },
    Report: { reportedUser: (report) => users.get(report.reportedUserId) },
    User: {
      recentLocation: (user) => user.recentLocation,
      reports: (user) => reports.forUser(user.id),
    },
  },
});
```

A reporter asks for a private field on someone they just reported, and recursively expands lists:

```graphql
mutation {
  reportUser(userId: "313", reason: "offensive") {
    reportedUser { recentLocation reports { reportedUser { recentLocation } } }
  }
}
```

```javascript
// Fixed: field decides access; depth, amount and cost all bounded
const server = new ApolloServer({
  typeDefs,
  introspection: process.env.NODE_ENV !== "production",
  validationRules: [depthLimit(8), createComplexityLimitRule(1500)],
  allowBatchedHttpRequests: false,
  resolvers: {
    Report: { reportedUser: (report) => users.getPublic(report.reportedUserId) },
    User: {
      recentLocation: (user, _, ctx) => {
        if (ctx.user.id !== user.id && !ctx.user.permissions.has("user:read_location")) {
          return null;
        }
        return user.recentLocation;
      },
      reports: (user, { first = 20 }, ctx) => {
        if (!ctx.user.permissions.has("report:read")) throw new ForbiddenError();
        return reports.forUser(user.id, Math.min(first, 100));
      },
    },
  },
});
```

Why this works: the field check applies no matter which query path reaches `User`, the list has a
hard amount cap, and complexity catches multiplication that depth ignores. Batches are rejected so
one HTTP request cannot carry a hundred operations past a per-request limiter.

Disabling introspection raises reconnaissance cost; it is not the authorization control, and ASVS
4.3.2 allows it when the API is meant for third parties.

---

## Inbound webhook signature and replay

`API2:2023` · `CWE-345` · ASVS 4.1.5, V12

```javascript
// Vulnerable: parsed JSON, timing-unsafe compare, no freshness or dedupe
app.post("/webhooks/payments", express.json(), async (req, res) => {
  const expected = hmac(JSON.stringify(req.body), SECRET);
  if (req.get("X-Signature") !== expected) return res.sendStatus(401);
  await markPaid(req.body.invoice_id);
  res.sendStatus(200);
});
```

A captured valid delivery can be replayed forever. Re-serialization may not match what the sender
signed, and `!==` leaks prefix timing.

```javascript
// Fixed: raw body, signed timestamp, constant-time compare, replay window and delivery dedupe
app.post("/webhooks/payments", express.raw({ type: "*/*", limit: "128kb" }), async (req, res) => {
  const ts = req.get("X-Timestamp") ?? "";
  const id = req.get("X-Delivery-Id") ?? "";
  const supplied = Buffer.from(req.get("X-Signature") ?? "", "hex");

  const age = Math.abs(Date.now() / 1000 - Number(ts));
  if (!Number.isFinite(age) || age > 300) return res.sendStatus(400);

  const expected = crypto.createHmac("sha256", SECRET)
    .update(`${ts}.`).update(req.body).digest();
  if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
    return res.sendStatus(400);
  }

  if (!(await claimDelivery(id))) return res.sendStatus(200);
  const event = JSON.parse(req.body);
  await markPaid(event.invoice_id);
  res.sendStatus(200);
});
```

Why this works: it verifies the exact bytes, the timestamp cannot be changed without invalidating
the MAC, a captured event expires in five minutes, and an atomic delivery claim blocks replays
inside the window. A duplicate returns 200 so the sender does not retry forever.

If the provider does not sign a timestamp or stable event ID, full replay prevention is impossible.
State that limitation; do not invent a header the sender did not sign.

---

## gRPC metadata trust

`API2:2023`, `API5:2023` · `CWE-345`, `CWE-285` · ASVS 4.1.3, 8.2.1, V12

```go
// Vulnerable: insecure transport and client-controlled metadata become identity
s := grpc.NewServer()
func VoidInvoice(ctx context.Context, req *VoidRequest) (*Empty, error) {
    md, _ := metadata.FromIncomingContext(ctx)
    if md.Get("role")[0] == "admin" {
        return void(req.InvoiceId)
    }
    return nil, status.Error(codes.PermissionDenied, "denied")
}
```

The caller sends `role: admin`. gRPC metadata is client input.

```go
// Fixed: mTLS identity plus a deny-by-default full-method permission map
s := grpc.NewServer(
    grpc.Creds(credentials.NewTLS(&tls.Config{
        ClientAuth: tls.RequireAndVerifyClientCert,
        ClientCAs: clientCAPool,
        MinVersion: tls.VersionTLS13,
    })),
    grpc.MaxRecvMsgSize(4*1024*1024),
    grpc.UnaryInterceptor(authorize),
)

var permission = map[string]string{
    "/billing.Billing/GetInvoice": "invoice:read",
    "/billing.Billing/VoidInvoice": "invoice:void",
}

func authorize(ctx context.Context, req any, info *grpc.UnaryServerInfo,
    next grpc.UnaryHandler) (any, error) {
    needed, known := permission[info.FullMethod]
    caller, err := callerFromVerifiedPeerCertificate(ctx)
    if !known || err != nil || !caller.Has(needed) {
        return nil, status.Error(codes.PermissionDenied, "not_permitted")
    }
    return next(ctx, req)
}
```

Why this works: identity comes from a verified peer certificate, and an RPC missing from the map
is denied. The map keys on the full method name, so `Get` and `Void` are separate functions even
inside one service.

Keep reflection off on the public production listener. It is API9 inventory exposure, not an
authorization failure by itself.

---

## Idempotency key race

`API4:2023`, `API6:2023` · `CWE-362` · ASVS V2

```python
# Vulnerable: concurrent requests both see absence and both charge
@router.post("/api/payments")
def pay(body: PaymentRequest, key: str = Header(alias="Idempotency-Key")):
    if not records.exists(key):
        result = provider.charge(body.amount_cents)
        records.save(key, result)
        return result
    return records.get(key)
```

Two requests with the same key arrive together. Both pass `exists`, both charge. This is an
exploitable replay race, not only a reliability bug.

```python
# Fixed: database uniqueness serialises first execution; body and actor are bound to the key
@router.post("/api/payments")
def pay(
    body: PaymentRequest,
    key: str = Header(alias="Idempotency-Key", max_length=255),
    actor: User = Depends(current_user),
):
    fingerprint = sha256(canonical_json(body).encode()).hexdigest()
    claimed = records.atomic_insert(actor.id, key, fingerprint, state="IN_PROGRESS")

    if not claimed:
        row = records.get(actor.id, key)
        if row.fingerprint != fingerprint:
            raise HTTPException(422, "idempotency_key_reuse")
        if row.state == "IN_PROGRESS":
            raise HTTPException(409, "request_in_progress")
        return row.response

    result = provider.charge(
        amount=body.amount_cents,
        idempotency_key=f"{actor.id}:{key}",
    )
    records.complete(actor.id, key, result)
    return result
```

Why this works: a unique database constraint on `(actor_id, key)` admits only one executor; the
fingerprint rejects same-key/different-body confusion; actor scope prevents one caller occupying or
reading another's key; and forwarding a stable key to the provider covers a local crash after the
provider succeeds but before the result is saved.

Do not store sensitive full responses forever. Retain the minimal replayable result for a defined
window, and keep a business uniqueness constraint where execution after expiry would double-spend.

---

## Sources

- <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x13-V4-API-and-Web-Service.md>
- <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x17-V8-Authorization.md>
- <https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html>
- <https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html>
