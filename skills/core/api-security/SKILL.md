---
name: api-security
description: 'Secure API surfaces — REST, GraphQL, gRPC, and webhooks — against the OWASP API Security Top 10 2023 and ASVS 5.0 V4. Triggers: "API security", "REST", "GraphQL", "gRPC", "webhook", "BOLA", "mass assignment", "rate limit", "idempotency", "bảo mật API", "xác thực webhook".'
allowed-tools: Read, Glob, Grep, WebSearch, WebFetch
---

# API Security

An API has no browser to hide behind. Every route is a callable function, every parameter is
attacker-controlled, and the client is whatever the attacker wrote. This skill owns the OWASP
API Security Top 10 2023 in depth.

## When to Use

- Adding or changing an endpoint, resolver, RPC method, or webhook handler
- Reviewing an API for authorization gaps, quota abuse, or exposed fields
- Designing a public, partner, or internal service-to-service API
- Verifying a webhook receiver or an outbound delivery pipeline
- Choosing between API keys, bearer tokens, and mTLS

## Ownership Boundary

**Owns:** The server-facing API boundary: request/response contracts, object/function/field
authorization, webhook handlers, and API resource controls.

**Does not own:**

| Concern | Route to |
|---|---|
| Credential, session, token, and OAuth lifecycle policy | `authentication` |
| Reverse-proxy trust, HTTP framing, and shared cache configuration | `http-edge-security` |
| Secret lifecycle and signing-key storage | `secrets-management` |
| Application-wide audit retention and detection operations | `logging-audit` |

## The Standard

OWASP API Security Top 10 2023 is the primary list here. ASVS 5.0 V4 (API and Web Service)
and V8 (Authorization) supply the testable requirements. The main OWASP Top 10 2025 is for
reporting to a non-API audience.

| Category | The failure, in one line |
|---|---|
| API1 Broken Object Level Authorization | Wrong object. `GET /orders/4192` returns someone else's order |
| API2 Broken Authentication | Identity can be forged, replayed, or brute-forced |
| API3 Broken Object Property Level Authorization | Wrong field on the right object. Reads `password_hash`, writes `role` |
| API4 Unrestricted Resource Consumption | One caller exhausts CPU, memory, storage, or a paid quota |
| API5 Broken Function Level Authorization | Wrong operation. `DELETE` works because only `GET` had a guard |
| API6 Unrestricted Access to Sensitive Business Flows | Every request is authorized; the aggregate is the attack |
| API7 Server Side Request Forgery | The API fetches a URL the caller supplied |
| API8 Security Misconfiguration | Headers, CORS, TLS, verbs, error verbosity wrong somewhere |
| API9 Improper Inventory Management | `v1` is still online, unpatched, undocumented |
| API10 Unsafe Consumption of APIs | Upstream response trusted more than user input |

Full detail, per-category questions, and controls in
[references/api-top10-2023.md](references/api-top10-2023.md).

## Workflow

### 1. Enumerate the surface

List what is actually reachable, not what the docs claim. Routes, methods, GraphQL
operations, gRPC services, and webhook receivers. Include older versions and non-production
hosts — that is API9, and it is the step people skip.

```bash
grep -rnE "@(app|router)\.(get|post|put|patch|delete)|app\.(get|post|put|patch|delete)\(" src/
```

### 2. For each operation, answer four questions

- Who may call this at all? (API2, API5)
- Which objects may this caller touch? (API1)
- Which fields may they read, and which may they write? (API3)
- What bounds the cost of one call, and of ten thousand? (API4, API6)

An endpoint you cannot answer all four for is not reviewed.

### 3. Apply controls in this order

1. Deny by default at the router, per method. Function level authorization is a routing
   property, not a handler property.
2. Scope every object lookup by the actor in the query itself.
3. Declare an explicit input schema and an explicit output schema. Never serialize the ORM
   object, never spread the request body.
4. Bound the request: page size cap, body size cap, depth and complexity cap, timeout.
5. Rate limit per authenticated actor, with per-IP only as a pre-auth fallback.
6. Treat every response from an upstream API as untrusted input.

### 4. Verify

Run [checklist.md](checklist.md). An unchecked box is a fix or a stated limitation, never a
silent skip.

### 5. Report

Per finding: API category, operation, the request that exploits it, the fix. Include the
concrete request — `PATCH /api/bookings/12 {"approved":true,"total_stay_price":"1"}` is a
finding; "possible mass assignment" is a guess.

## Severity

Rank by who can reach it and what they get.

- Critical — unauthenticated cross-tenant read or write; admin function reachable by any user
- High — authenticated cross-tenant access; mass assignment onto a privilege or money field
- Medium — over-fetched sensitive field; missing rate limit on an expensive or paid operation
- Low — introspection enabled, verbose errors, missing header with no direct path

An unbounded page size on a public catalogue is Medium. The same bug on an endpoint that
fans out to a per-record paid API call is High, because it spends money.

## Related Skills

- `owasp` — the main Top 10 2025 and ASVS chapter map
- `authentication` — password, MFA, session, and OAuth flows in depth
- `logging-audit` — audit trails for authorization denials
- `secure-code-review` — reviewing an existing codebase end to end

## Supporting Files

- [README.md](README.md) — purpose, standards table, limitations
- [checklist.md](checklist.md) — pre-return verification, grouped by API category
- [best-practices.md](best-practices.md) — patterns, each with a vulnerable/fixed pair
- [common-mistakes.md](common-mistakes.md) — what goes wrong, and why the fix works
- [troubleshooting.md](troubleshooting.md) — when the guidance conflicts or cannot be applied
- [prompts.md](prompts.md) — prompts that produce findings
- [references/api-top10-2023.md](references/api-top10-2023.md) — the ten categories in depth
- [references/asvs-v4-api.md](references/asvs-v4-api.md) — ASVS 5.0 V4 requirement text
- [examples/README.md](examples/README.md) — eight vulnerable/fixed pairs
