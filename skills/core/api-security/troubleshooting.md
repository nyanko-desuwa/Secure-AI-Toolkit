# Troubleshooting API Security

What to do when the guidance does not resolve cleanly.

## The API cannot return 404 for an unauthorized object

Some published contracts promise 403. Do not quietly break clients. Preserve 403, document that
it confirms object existence, and make response body and timing uniform. If existence itself is
sensitive, version the endpoint and migrate clients to 404.

The authorization check is non-negotiable; the status code is defence in depth. `API1:2023` ·
CWE-639.

## The object has shared, delegated, or team ownership

Do not force `owner_id == actor.id` onto a model that does not have direct ownership. Scope by a
join to membership where possible, or call a policy engine with actor, action, object, and context.
Cache policy decisions only as long as the underlying permission can safely be stale.

ASVS 8.2.2 is about explicit permission to the data item, not ownership specifically. That is why
"compare the user ID" is not a general fix.

## Unknown request fields must remain forward-compatible

Ignoring unknown fields makes rolling clients easier and silently turns a future model field into
an attack path when someone later spreads the body into an update.

Separate compatibility from persistence. Parse a versioned input schema that captures unknown
fields into a quarantine map, never passes that map to the domain model, and logs a metric by key
without its value. Or version the endpoint. Do not accept arbitrary fields into a persistence
operation. `API3:2023` · CWE-915.

## The framework strips output fields allegedly

Verify it with a response test. Some frameworks validate request models but serialize the value
the handler returned; some use response schemas only for documentation; some include undeclared
fields unless a strict option is enabled.

Write a test that adds a sentinel private property to the domain object and asserts the JSON omits
it. If the framework cannot enforce the response shape, construct the response DTO manually.
`API3:2023` · CWE-213.

## Immediate bearer-token revocation is required

A self-contained JWT cannot be revoked by itself before expiry. A five-minute expiry narrows the
window and does not satisfy immediate logout or immediate privilege removal.

Choices: opaque tokens with server-side lookup; a revocation list keyed by token ID; or short JWTs
plus a server-side session version checked on sensitive calls. State the availability and latency
trade-off. ASVS 8.3.2 explicitly notes that compensating alert-and-revert controls do not mitigate
information leakage.

## Rate limiting sits at the gateway, outside this repository

Do not mark it pass from an architectural diagram. Ask for the deployed rule, its key, scope,
burst, window, failure mode, and an observed 429 test. Confirm the edge strips client-set
`X-Forwarded-For` before the limiter uses it — ASVS 4.1.3.

If deployment cannot be inspected, report "not verifiable from application code" rather than
"handled by gateway". `API4:2023` · CWE-799.

## Per-actor limits do not exist before authentication

Use layered keys: IP and account identifier before authentication, verified actor after. Avoid an
account-only pre-auth key that lets an attacker lock out a victim by naming them. Keep responses
uniform so the limiter does not become a user-enumeration oracle. `API2:2023` · CWE-204, CWE-307.

## A public GraphQL API needs introspection

ASVS 4.3.2 allows it when the API is meant for other parties. Leave it on deliberately, rate limit
it, cap response cost, and remove private directives and descriptions from the public schema.
Introspection off is hardening, not authorization.

Depth and cost limits still apply. Persisted queries are stronger but incompatible with arbitrary
third-party documents; choose and document the trade-off. `API4:2023`, `API9:2023`.

## GraphQL complexity scoring is inaccurate

Complexity depends on list cardinality and resolver behaviour. A static score cannot see an N+1
query or a cache miss.

Start with explicit multipliers on list arguments, cap `first`/`last`, and measure resolver
latency and database calls in staging. Persisted-query allowlisting is the fallback for a closed
client ecosystem. Set a server execution timeout and database statement timeout as a final bound.
ASVS 4.3.1.

## gRPC reflection is needed by production tooling

Do not expose reflection on the public listener. Run a separate authenticated admin listener, or
restrict reflection at the interceptor by verified mTLS identity. Remember that reflection is
inventory, not authorization; every RPC still needs its own permission. `API9:2023` · CWE-1059.

## A gRPC gateway injects identity metadata

The backend cannot trust plain metadata unless the client cannot set it. The gateway must strip
incoming copies, inject its own value, and authenticate to the backend over mTLS. Better: inject a
short-lived signed token whose audience is the backend and verify it there.

ASVS 4.1.3 covers intermediary-set headers that end users must not override. The transport changes;
the trust problem does not.

## The webhook provider has no timestamp or delivery ID

A valid HMAC without freshness can be replayed forever.

If there is a stable event ID in the signed body, store it permanently or for the maximum business
window and make processing idempotent. If neither timestamp nor event ID is signed, you cannot
cryptographically prevent replay. Use a dedicated secret, narrow the handler's capability, store a
short digest of recent signed bodies as a limited fallback, ask the provider to add replay
protection, and state the residual risk. Do not invent a timestamp header the provider did not sign.

## The webhook provider signs parsed fields, not raw bytes

Follow its documented canonicalization exactly. Constant-time compare still applies. Build test
vectors from provider documentation and pin them in tests. Never invent your own JSON
canonicalization on one side; whitespace and number formats will differ.

## A webhook secret must rotate without downtime

Accept the current and immediately previous secret for a short, defined overlap. Compute both
expected MACs and perform constant-time comparisons; do not return early after the first mismatch.
Tag secrets by key ID where the provider supports it, and remove the previous key when the overlap
ends. Log the key ID, never the secret.

## The outbound webhook destination has dynamic DNS

Revalidating DNS before each attempt is necessary and still leaves a check/connect race. Pin the
validated IP in the HTTP connection while preserving the TLS hostname for certificate validation,
or route delivery through an egress proxy that resolves and enforces network policy. Revalidate
redirects if any are allowed; the safer default is none. `API7:2023` · CWE-918.

## Idempotency key persistence outlives the response data

Do not retain full sensitive responses solely for idempotency. Store the minimal replayable result,
encrypted where necessary, with a TTL matching the retry window. Keep a longer-lived tombstone or
business uniqueness constraint if replay after expiry would duplicate money movement. Document the
point after which the key may execute again.

## The operation cannot be made fully idempotent

Reserve the key atomically before the side effect and pass the same key downstream if that provider
supports idempotency. If the process can crash after the side effect but before recording success,
reconcile by querying the provider using a stable external reference. Do not mark `IN_PROGRESS` as
failed and blindly retry an unknown-outcome charge.

## Business flow abuse has no obvious technical control

That is normal. `API6` is a product and fraud problem. Report the flow and the economic harm,
identify the actor and the business object, then ask product owners for the acceptable policy.
"One console per verified payment instrument per 30 days" is a business decision; the assistant
must not invent it.

Roll out friction proportionally. Device fingerprinting, captcha, and proxy blocking produce false
positives and accessibility costs. Measure and provide a manual path for legitimate users.

## A secure fix breaks an existing API contract

Report four things: current behaviour, secure behaviour, affected clients, migration path. Add the
control in a new version or behind a negotiated capability, give a deprecation date, monitor old
version use, then retire it. Keeping the vulnerable version forever is API9, not compatibility.

## The upstream schema changes without notice

Fail closed on security-relevant or money fields. For optional display fields, tolerate absence but
not a type change. Capture the invalid payload's hash and correlation ID, not the sensitive body.
Use contract tests against a sandbox, and alert on schema rejection rates. `API10:2023` · CWE-20.
