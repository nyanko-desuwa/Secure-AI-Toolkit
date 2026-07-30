# API Security Prompt Examples

Prompts that produce findings instead of a category recital. State the surface, the standard, and
what evidence the answer must include.

## Enumerate the real surface

```text
Enumerate every REST route and method, GraphQL operation, gRPC service/method, and webhook
receiver reachable in this repo. Compare it with the OpenAPI, GraphQL, and protobuf definitions.
Report undocumented endpoints and old versions as API9:2023. Include file:line evidence.
```

Why it works: inventory is based on what routes, not what the documentation claims.

## Object authorization review

```text
Read src/api/orders.ts. For every handler that accepts an order ID, show where the actor and
tenant constrain the database lookup. Cover read, update, and delete. For each missing constraint,
give the exact cross-user request, API1:2023, CWE-639, and the smallest fix.
```

Asking for the exact query constraint distinguishes a BOLA finding from "the endpoint has auth".

## Property authorization review

```text
Review every create, update, and response path for User in this repo against API3:2023. List the
fields the client can write and the fields each endpoint returns. Flag request schemas that ignore
unknown keys, ORM spreads, toJSON/to_dict, and server-owned fields such as role, status, tenant,
balance, and verification. Give an exploit request for each finding.
```

API3 needs both directions. A prompt that says only "mass assignment" misses over-fetching.

## Function authorization matrix

```text
Build a matrix of method + path (or full gRPC method) against required role/permission. Do not
infer admin status from /admin in the URL. Grep for export, impersonate, bulk, refund, sync, and
recalculate. Flag any operation that is reachable without an explicit grant as API5:2023.
```

The matrix makes verb guessing visible. `GET /users/:id` and `DELETE /users/:id` are two functions.

## Resource consumption review

```text
Review src/api for API4:2023. Find unbounded page size, offset pagination, body and upload size,
array length, outbound response size, timeouts, GraphQL depth/complexity/batching, stream duration,
and paid third-party calls. For every rate limit, tell me its key - actor, client, or IP - and why
that key survives proxy rotation.
```

"Does it have rate limiting" is the wrong question. The key and the bounded resource are what
matter.

## Sensitive business flow threat model

```text
Threat model checkout, reservation, cancellation, referral, and promotion flows against
API6:2023. Assume every request is authenticated and individually authorized, and that the
attacker distributes traffic across accounts and IPs. Identify the business object they want,
the aggregate harm, free reversals, and controls at the business-object level. Do not answer with
rate limiting alone.
```

The attacker assumption prevents the answer from collapsing API6 back into API4.

## GraphQL review

```text
Review schema.graphql and all resolvers against API1, API3, API4, API5, and ASVS 4.3.1-4.3.2.
Trace authorization through nested fields, test list amount caps, aliases and batched operations,
query depth and complexity, introspection, and error suggestions. Show one query for each exploitable
path and name the resolver where the check belongs.
```

## gRPC review

```text
Review every protobuf service registration and server interceptor. Build a table of full method
name to permission. Check TLS/mTLS, peer identity, client-set metadata, reflection, max receive size,
and stream duration. Flag unknown methods that fail open as API5:2023.
```

## Inbound webhook review

```text
Review the webhook receiver against signature forgery and replay. Show whether it hashes the raw
body, what exact signed string it constructs, whether comparison is constant-time, whether the
timestamp is signed and within a replay window, and whether delivery IDs are claimed atomically.
Then trace a duplicate delivery through the side effect.
```

## Outbound webhook review

```text
Review outbound webhook delivery for API7 and API4. Trace a customer-supplied URL through DNS,
redirects, and the actual connection. Check signing, minimal payloads, fixed delivery IDs,
timeouts, retry backoff and cap, dead-letter handling, and whether retries can duplicate events.
State any DNS rebinding gap explicitly.
```

## Idempotency review

```text
Review POST endpoints that move money, grant credit, send a message, or create a record. For each,
show how the idempotency key is scoped, inserted atomically, bound to the request body, and replayed.
Look for read-then-write races and unknown outcomes after downstream timeouts. Explain the security
impact, not only reliability.
```

## Verify before returning code

```text
Run skills/core/api-security/checklist.md against the change. Mark each applicable item pass, fail,
or not applicable with a reason. Do not mark gateway, TLS, DNS, or deployed rate limits pass unless
you inspected the runtime configuration or exercised it. Fix failures in scope and state the rest.
```

## Report format

```text
For each API finding give:
1. API Security Top 10 2023 category and CWE
2. operation and file:line
3. attacker precondition
4. exact request/query/RPC that exploits it
5. data or business impact
6. smallest fix and the ASVS chapter or verified requirement ID
7. residual limitation
Skip anything without an exploitation path; label uncertain paths with the missing precondition.
```

## Anti-patterns

| Prompt | Problem |
|---|---|
| "Is this API secure?" | No surface or standard. Produces ten generic bullets |
| "Make it OWASP compliant" | The Top 10 is a risk list, not a certification; no target ASVS level |
| "Add authentication" | Does not ask who may call which operation, object, or field |
| "Check authorization" | Conflates API1, API3, and API5, whose fixes are different |
| "Add rate limiting" | Does not name the resource, operation, actor key, burst, or business flow |
| "Disable GraphQL introspection" | Hardening mistaken for authorization and cost control |
| "Use UUIDs to stop IDOR" | Raises guessing cost without enforcing access |
| "Verify the webhook secret" | Omits raw bytes, constant time, freshness, replay, and idempotency |
| "Sanitize the URL" | No definition of safe destination, redirect, DNS, or network boundary |
| "Trust internal APIs" | Network location is not identity; upstream data remains untrusted |
