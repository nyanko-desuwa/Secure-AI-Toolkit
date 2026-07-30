# API Verification Checklist

Run before returning API code. Mark each item pass, fail, or not applicable. "Not applicable"
needs a one-line reason - an unexplained skip reads the same as an oversight.

Only run the sections the change touches. A GraphQL-only change does not need the gRPC section.

## Object Level Authorization (API1 · ASVS 8.2.2, 8.3.1, 8.4.1)

- [ ] [critical] Every handler taking an object ID scopes the lookup by the actor, or calls a policy
- [ ] [critical] Read, write, and delete are all covered - check delete explicitly
- [ ] [critical] Tenant comes from the session, never from a request field or header
- [ ] [critical] Nested routes check the child, not only the parent
- [ ] [recommended] Objects that are not the actor's return 404, not 403
- [ ] [recommended] A test exists that fails if the ownership constraint is removed

## Property Level Authorization (API3 · ASVS 8.1.2, 8.2.3)

- [ ] [critical] Responses are built from an explicit schema, not from the ORM or domain object
- [ ] [critical] Input schemas reject unknown keys, not ignore them
- [ ] [critical] Server-owned fields enumerated and unsettable: role, status, balance, price, tenant,
      timestamps, verification and moderation flags
- [ ] [recommended] Create and update paths each have their own schema, and both were reviewed
- [ ] [recommended] State-dependent field rules enforced where they exist (editable while draft, not after)
- [ ] [critical] Nested and related objects in the response are filtered too

## Authentication (API2 · ASVS V6, V7, V9, V10)

- [ ] [recommended] Every authentication path enumerated, including mobile, deep link, and legacy clients
- [ ] [critical] API keys used only for client identification, never as user authentication
- [ ] [critical] Bearer tokens verified with a server-pinned algorithm, issuer, and audience
- [ ] [critical] Token expiry validated; revocation strategy stated if immediate logout is required
- [ ] [critical] Credentials and tokens never in a URL, query string, or log line
- [ ] [recommended] Password recovery throttled at least as hard as login
- [ ] [critical] Re-authentication required to change email, password, or MFA factor
- [ ] [critical] Internal service-to-service calls authenticated, not trusted by network position

## Function Level Authorization (API5 · ASVS 8.2.1, 4.1.4, 8.4.2)

- [ ] [critical] Router denies by default; each route and method needs an explicit grant
- [ ] [critical] Guards attached per method, not once per path prefix
- [ ] [recommended] Unused HTTP methods blocked, including auto-handled `HEAD` and `TRACE`
- [ ] [critical] Admin functions found by capability, not by path - grep `export`, `impersonate`, `bulk`,
      `sync`, `recalculate`, `refund`
- [ ] [critical] Admin handlers inherit or compose a role check that cannot be omitted per handler

## Resource Consumption (API4 · ASVS 4.2.5, 4.3.1, V2)

- [ ] [recommended] Page size and `limit` clamped server-side, with a hard maximum
- [ ] [recommended] Request body size capped at the proxy, before the handler buffers it
- [ ] [recommended] Upload size capped, and the cap applies to cloud-destined uploads too
- [ ] [recommended] String length and array length bounded in every input schema
- [ ] [recommended] Read and connect timeouts set on every outbound call
- [ ] [recommended] Rate limit keyed on the authenticated actor; per-IP used only pre-auth
- [ ] [recommended] Paid operations have their own tighter limit and a provider spending cap or billing alert
- [ ] [recommended] Repeated single operations throttled separately: OTP verify, resend, invite, password reset

## Business Flow Abuse (API6)

- [ ] [recommended] Flows that harm the business at scale identified, not just expensive ones
- [ ] [recommended] Per-actor cap on the business object, not only on request rate
- [ ] [recommended] Free-to-reverse actions considered - cancellations, refunds, unredeemed holds
- [ ] [recommended] Signup, referral, and promotion flows have an anti-automation control
- [ ] [recommended] B2B, developer, and internal APIs carry the same protections as the public one

## SSRF (API7 · CWE-918 · ASVS V2, V12)

- [ ] [critical] Every place a request-supplied URL reaches an HTTP client, parser, or renderer is known
- [ ] [critical] Scheme allowlisted to `http`/`https`; port allowlisted
- [ ] [critical] Hostname resolved and every returned address checked against private, loopback,
      link-local, and reserved ranges
- [ ] [critical] Redirects disabled, or each hop re-validated
- [ ] [recommended] Upstream response not returned raw to the caller
- [ ] [recommended] Residual DNS rebinding gap stated, or the connection pinned to the validated IP

## Misconfiguration (API8 · ASVS 4.1.1, 4.1.2, 4.1.3, V13)

- [ ] [critical] TLS on every hop, including internal service-to-service
- [ ] [critical] CORS names explicit origins; no wildcard with credentials; no reflected `Origin`
- [ ] [recommended] `Content-Type` on every response with a body, with charset
- [ ] [recommended] Accepted request content types restricted to what the endpoint needs
- [ ] [critical] Client-supplied `X-Forwarded-*`, `X-Real-IP`, and gateway identity headers stripped at
      the edge
- [ ] [recommended] Error responses schema-defined; no stack traces, internal hostnames, or driver messages
- [ ] [recommended] Debug endpoints, profilers, and framework default routes removed

## Inventory (API9)

- [ ] [recommended] Every reachable route is either in the spec or removed
- [ ] [recommended] Deprecated versions either retired or patched to the same level as current
- [ ] [recommended] Non-production hosts do not hold production data, or are treated as production
- [ ] [recommended] Documentation generated from code in CI, not hand-maintained
- [ ] [recommended] Third-party data flows documented: which provider, which fields, why

## Upstream Consumption (API10 · ASVS V1, V2, V12)

- [ ] [critical] Upstream responses schema-validated before use
- [ ] [recommended] Response size bounded and timeouts set
- [ ] [recommended] Redirects from upstream not followed blindly
- [ ] [critical] Upstream data encoded at its sink - SQL, template, shell, deserializer
- [ ] [recommended] Upstream failure fails closed, with no partial state persisted

## GraphQL (ASVS 4.3.1, 4.3.2)

- [ ] [recommended] Depth limit and complexity or cost limit both configured
- [ ] [recommended] Amount limiting on list arguments - a shallow query asking for 100,000 rows is bounded
- [ ] [recommended] Introspection disabled in production, or the schema is deliberately public
- [ ] [recommended] Batched arrays and aliased duplicate fields counted against the limit, not per HTTP request
- [ ] [critical] Authorization enforced in resolvers or the data layer, not only at the query entry point
- [ ] [recommended] Resolver errors do not leak internal messages through the `errors` array

## gRPC

- [ ] [recommended] Server reflection disabled in production
- [ ] [critical] TLS or mTLS enabled; no insecure credentials outside local development
- [ ] [critical] Identity taken from the verified TLS peer or a verified token, never from plain metadata
- [ ] [critical] Interceptor denies by default per full method name
- [ ] [recommended] Max receive message size set; streams bounded in count and duration

## Webhooks

- [ ] [critical] Inbound signatures verified over the raw body, before parsing
- [ ] [critical] Comparison is constant-time
- [ ] [critical] Timestamp checked against a replay window, and the timestamp is inside the signed payload
- [ ] [recommended] Delivery IDs recorded so a replay inside the window is rejected
- [ ] [recommended] Handler idempotent - a duplicate delivery does not double-apply
- [ ] [critical] Outbound deliveries signed, retried with backoff and a cap, and the destination URL is
      SSRF-checked
- [ ] [recommended] Outbound payloads carry only fields the receiver needs

## Idempotency

- [ ] [recommended] State-changing endpoints that move money or create records accept an idempotency key
- [ ] [critical] Key scoped to the actor, so one caller cannot claim another's key
- [ ] [recommended] Stored result replayed on retry; a key reused with a different body is rejected
- [ ] [recommended] Concurrent requests with the same key serialised, not both executed

## Before Returning

- [ ] [critical] Build or compile step run
- [ ] [critical] Authorization tests run, including a cross-actor negative case
- [ ] [recommended] Temporary files removed
- [ ] [critical] API documentation or spec updated to match the change
- [ ] [critical] Anything unverifiable stated plainly, not implied to be fine
