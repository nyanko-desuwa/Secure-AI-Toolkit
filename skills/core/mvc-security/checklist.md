# MVC Security Verification Checklist

Run before returning code. Mark each item pass, fail, or not applicable. A pass needs code or
configuration evidence. "The framework probably does that" is not evidence.

## Routing (A01, A02 · ASVS V8, V13 · CWE-639)

- [ ] [critical] Every public action is intentionally exposed; no conventional, wildcard, or resource route
  reaches extra controller methods
- [ ] [critical] Each state-changing action accepts only the intended unsafe verb (`POST`, `PUT`, `PATCH`, or
  `DELETE`), never `GET`
- [ ] [critical] Method override / verb tunnelling is either disabled or limited to CSRF-protected form posts
- [ ] [critical] A wildcard route cannot consume an admin prefix or dispatch a user-controlled action name
- [ ] [critical] Route parameters are identifiers only; no role, owner, tenant, price, or permission from the
  path is treated as trusted
- [ ] [critical] Authentication and coarse role guards cover the route, but are not counted as object-level
  authorization

## Controllers (A01, A06 · ASVS V2, V8 · CWE-639)

- [ ] [recommended] Controller actions bind a request DTO/form object, resolve the actor from the authenticated
  context, call one service, and map the result to a response
- [ ] [critical] No controller computes a price, discount, quota, workflow transition, or permission rule
- [ ] [critical] No controller fetches by route ID without actor scoping or a policy called with the object
- [ ] [critical] Read, create, update, delete, bulk, export, and attachment actions enforce the same policy
- [ ] [recommended] The filter/middleware guard is used only for facts available before object lookup
- [ ] [critical] A missing object and an object outside the actor's scope do not expose different existence
  signals unless the product explicitly requires it

## Binding and Models (A01, A06 · ASVS V2, V8 · CWE-915)

- [ ] [critical] Each write path uses an allowlist, never a denylist, for assignable fields
- [ ] [critical] Laravel models use a narrow `$fillable`; `$guarded = []` is absent from request-backed writes
- [ ] [critical] Rails strong parameters enumerate scalar and nested keys; no `permit!`, `to_unsafe_h`, or raw
  `params` reaches `create`, `update`, `assign_attributes`, or a constructor
- [ ] [critical] Django `ModelForm.Meta.fields` is explicit; `exclude` and `"__all__"` are absent from
  untrusted forms
- [ ] [critical] ASP.NET Core actions bind a dedicated input model; `[Bind]` is not the only defence on a
  domain entity
- [ ] [critical] Spring MVC actions bind a DTO, not a JPA entity; server-owned properties are not present
- [ ] [critical] Privilege, ownership, tenant, approval, balance, price, audit, and internal state fields are
  assigned only from trusted server state
- [ ] [recommended] New database columns stay non-writable by default without changing request-layer code

## Request Validation (A06 · ASVS V2 · CWE-915)

- [ ] [critical] Validation runs server-side before the service call
- [ ] [recommended] Required fields, types, lengths, ranges, formats, and cross-field constraints are explicit
- [ ] [critical] Unknown fields are rejected, not silently dropped, on security-sensitive writes
- [ ] [recommended] Laravel FormRequest uses `validated()` / `safe()`, not `all()`
- [ ] [critical] DRF serializers use explicit `fields` and do not accept writable privilege fields; unknown
  fields are rejected or a documented parser policy enforces rejection
- [ ] [recommended] ASP.NET Core checks automatic `[ApiController]` responses or `ModelState.IsValid` as
  appropriate; no invalid model reaches the service
- [ ] [recommended] Rails is configured to log or raise on unpermitted parameters in development and test
- [ ] [critical] Client-side validation exists only for UX; every rule that matters is repeated server-side

## Service and Repository (A01, A06 · ASVS V2, V8 · CWE-639)

- [ ] [recommended] Business rules have one service-layer enforcement point used by web, API, jobs, and imports
- [ ] [critical] Prices, roles, ownership, tenant, permissions, and state transitions derive from trusted
  records or the authenticated actor
- [ ] [critical] Repository queries include actor/tenant scope in the predicate, including child collections
- [ ] [critical] Raw SQL / HQL / JPQL / Eloquent raw expressions use bound values; dynamic identifiers map
  through a server allowlist
- [ ] [critical] No fetch-then-check branch can accidentally continue after denial
- [ ] [critical] Bulk update/delete and relation lookups carry the same scope as single-object reads

## Views and Templates (A05 · ASVS V1, V3 · CWE-79)

- [ ] [critical] Template auto-escaping is enabled for the file type and environment actually used
- [ ] [critical] Every raw escape hatch (`{!! !!}`, `|raw`, `|safe`, `html_safe`/`raw`, `Html.Raw`, `th:utext`)
  has a documented trusted or sanitized source
- [ ] [recommended] User data in HTML text uses normal escaped interpolation
- [ ] [critical] Attribute values are quoted and use an attribute-aware mechanism where the engine provides
  one
- [ ] [critical] Data entering a script block is JSON-serialized with the framework helper, not HTML-escaped
  string interpolation
- [ ] [critical] User-controlled URL values are restricted to allowed schemes; HTML escaping alone is not
  treated as URL validation
- [ ] [critical] User content cannot select event-handler attributes, tag names, CSS, or template source
- [ ] [critical] A sanitizer, not escaping alone, handles the explicit rich-HTML feature

## CSRF (A01 · ASVS V3, V8)

- [ ] [critical] Every cookie-authenticated state-changing request passes the framework's CSRF validation
- [ ] [critical] Laravel `web` middleware and `@csrf`, Django `CsrfViewMiddleware` and `{% csrf_token %}`,
  Rails `protect_from_forgery`/form helpers, ASP.NET antiforgery filters, or Spring Security CSRF
  are confirmed active as applicable
- [ ] [critical] No broad CSRF exemption covers a session-authenticated controller
- [ ] [critical] Unsafe actions do not accept `GET`
- [ ] [critical] Tokens are not sent to untrusted origins, logged, or placed in URLs

## Errors and Debugging (A02 · ASVS V13 · CWE-489)

- [ ] [critical] Production disables `APP_DEBUG`, Django `DEBUG`, Rails detailed exceptions, ASP.NET
  Developer Exception Page, and Spring stack traces / Whitelabel details
- [ ] [recommended] Debug configuration is deployment-enforced, not dependent on a developer remembering to edit
  a file
- [ ] [recommended] The client receives a generic error and correlation ID; details go to protected logs
- [ ] [critical] Error templates do not render exception messages raw
- [ ] [critical] Secrets are not present in request dumps, local variables, model inspection, or stack traces
- [ ] [recommended] A deployment test requests a known failure and verifies no debug page, paths, SQL, locals,
  configuration, or stack is returned

## Architecture and Auditability (A06 · ASVS V2, V8, V13)

- [ ] [recommended] A reviewer can point to one location for each business invariant and authorization policy
- [ ] [recommended] No fat controller duplicates service logic across HTML and JSON actions
- [ ] [recommended] No anemic model/domain object allows arbitrary state mutation around the service
- [ ] [recommended] Templates do not decide whether an operation is allowed; hiding a button is UX only
- [ ] [recommended] Framework callbacks and ORM hooks that change security state are documented and tested
- [ ] [recommended] Regression tests call the endpoint with another actor's ID, an extra privilege field, the
  wrong verb, a missing CSRF token, and an XSS payload in every rendered context touched

## Before Returning

- [ ] [recommended] Framework and major version identified
- [ ] [recommended] Route table or route definitions reviewed
- [ ] [recommended] Request-to-write field flow traced end to end
- [ ] [recommended] Relevant controller, service, repository, model/schema, and template read together
- [ ] [recommended] Production security configuration inspected
- [ ] [critical] Relevant tests run and results reported honestly
- [ ] [recommended] Every finding names the wrong layer, exploitation path, OWASP category, ASVS chapter, and CWE
- [ ] [critical] Unverified framework defaults are stated as unknown, not marked pass
