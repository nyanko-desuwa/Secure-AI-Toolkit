# MVC Security Verification Checklist

Run before returning code. Mark each item pass, fail, or not applicable. A pass needs code or
configuration evidence. "The framework probably does that" is not evidence.

## Routing (A01, A02 · ASVS V8, V13 · CWE-639)

- [ ] Every public action is intentionally exposed; no conventional, wildcard, or resource route
  reaches extra controller methods
- [ ] Each state-changing action accepts only the intended unsafe verb (`POST`, `PUT`, `PATCH`, or
  `DELETE`), never `GET`
- [ ] Method override / verb tunnelling is either disabled or limited to CSRF-protected form posts
- [ ] A wildcard route cannot consume an admin prefix or dispatch a user-controlled action name
- [ ] Route parameters are identifiers only; no role, owner, tenant, price, or permission from the
  path is treated as trusted
- [ ] Authentication and coarse role guards cover the route, but are not counted as object-level
  authorization

## Controllers (A01, A06 · ASVS V2, V8 · CWE-639)

- [ ] Controller actions bind a request DTO/form object, resolve the actor from the authenticated
  context, call one service, and map the result to a response
- [ ] No controller computes a price, discount, quota, workflow transition, or permission rule
- [ ] No controller fetches by route ID without actor scoping or a policy called with the object
- [ ] Read, create, update, delete, bulk, export, and attachment actions enforce the same policy
- [ ] The filter/middleware guard is used only for facts available before object lookup
- [ ] A missing object and an object outside the actor's scope do not expose different existence
  signals unless the product explicitly requires it

## Binding and Models (A01, A06 · ASVS V2, V8 · CWE-915)

- [ ] Each write path uses an allowlist, never a denylist, for assignable fields
- [ ] Laravel models use a narrow `$fillable`; `$guarded = []` is absent from request-backed writes
- [ ] Rails strong parameters enumerate scalar and nested keys; no `permit!`, `to_unsafe_h`, or raw
  `params` reaches `create`, `update`, `assign_attributes`, or a constructor
- [ ] Django `ModelForm.Meta.fields` is explicit; `exclude` and `"__all__"` are absent from
  untrusted forms
- [ ] ASP.NET Core actions bind a dedicated input model; `[Bind]` is not the only defence on a
  domain entity
- [ ] Spring MVC actions bind a DTO, not a JPA entity; server-owned properties are not present
- [ ] Privilege, ownership, tenant, approval, balance, price, audit, and internal state fields are
  assigned only from trusted server state
- [ ] New database columns stay non-writable by default without changing request-layer code

## Request Validation (A06 · ASVS V2 · CWE-915)

- [ ] Validation runs server-side before the service call
- [ ] Required fields, types, lengths, ranges, formats, and cross-field constraints are explicit
- [ ] Unknown fields are rejected, not silently dropped, on security-sensitive writes
- [ ] Laravel FormRequest uses `validated()` / `safe()`, not `all()`
- [ ] DRF serializers use explicit `fields` and do not accept writable privilege fields; unknown
  fields are rejected or a documented parser policy enforces rejection
- [ ] ASP.NET Core checks automatic `[ApiController]` responses or `ModelState.IsValid` as
  appropriate; no invalid model reaches the service
- [ ] Rails is configured to log or raise on unpermitted parameters in development and test
- [ ] Client-side validation exists only for UX; every rule that matters is repeated server-side

## Service and Repository (A01, A06 · ASVS V2, V8 · CWE-639)

- [ ] Business rules have one service-layer enforcement point used by web, API, jobs, and imports
- [ ] Prices, roles, ownership, tenant, permissions, and state transitions derive from trusted
  records or the authenticated actor
- [ ] Repository queries include actor/tenant scope in the predicate, including child collections
- [ ] Raw SQL / HQL / JPQL / Eloquent raw expressions use bound values; dynamic identifiers map
  through a server allowlist
- [ ] No fetch-then-check branch can accidentally continue after denial
- [ ] Bulk update/delete and relation lookups carry the same scope as single-object reads

## Views and Templates (A05 · ASVS V1, V3 · CWE-79)

- [ ] Template auto-escaping is enabled for the file type and environment actually used
- [ ] Every raw escape hatch (`{!! !!}`, `|raw`, `|safe`, `html_safe`/`raw`, `Html.Raw`, `th:utext`)
  has a documented trusted or sanitized source
- [ ] User data in HTML text uses normal escaped interpolation
- [ ] Attribute values are quoted and use an attribute-aware mechanism where the engine provides
  one
- [ ] Data entering a script block is JSON-serialized with the framework helper, not HTML-escaped
  string interpolation
- [ ] User-controlled URL values are restricted to allowed schemes; HTML escaping alone is not
  treated as URL validation
- [ ] User content cannot select event-handler attributes, tag names, CSS, or template source
- [ ] A sanitizer, not escaping alone, handles the explicit rich-HTML feature

## CSRF (A01 · ASVS V3, V8)

- [ ] Every cookie-authenticated state-changing request passes the framework's CSRF validation
- [ ] Laravel `web` middleware and `@csrf`, Django `CsrfViewMiddleware` and `{% csrf_token %}`,
  Rails `protect_from_forgery`/form helpers, ASP.NET antiforgery filters, or Spring Security CSRF
  are confirmed active as applicable
- [ ] No broad CSRF exemption covers a session-authenticated controller
- [ ] Unsafe actions do not accept `GET`
- [ ] Tokens are not sent to untrusted origins, logged, or placed in URLs

## Errors and Debugging (A02 · ASVS V13 · CWE-489)

- [ ] Production disables `APP_DEBUG`, Django `DEBUG`, Rails detailed exceptions, ASP.NET
  Developer Exception Page, and Spring stack traces / Whitelabel details
- [ ] Debug configuration is deployment-enforced, not dependent on a developer remembering to edit
  a file
- [ ] The client receives a generic error and correlation ID; details go to protected logs
- [ ] Error templates do not render exception messages raw
- [ ] Secrets are not present in request dumps, local variables, model inspection, or stack traces
- [ ] A deployment test requests a known failure and verifies no debug page, paths, SQL, locals,
  configuration, or stack is returned

## Architecture and Auditability (A06 · ASVS V2, V8, V13)

- [ ] A reviewer can point to one location for each business invariant and authorization policy
- [ ] No fat controller duplicates service logic across HTML and JSON actions
- [ ] No anemic model/domain object allows arbitrary state mutation around the service
- [ ] Templates do not decide whether an operation is allowed; hiding a button is UX only
- [ ] Framework callbacks and ORM hooks that change security state are documented and tested
- [ ] Regression tests call the endpoint with another actor's ID, an extra privilege field, the
  wrong verb, a missing CSRF token, and an XSS payload in every rendered context touched

## Before Returning

- [ ] Framework and major version identified
- [ ] Route table or route definitions reviewed
- [ ] Request-to-write field flow traced end to end
- [ ] Relevant controller, service, repository, model/schema, and template read together
- [ ] Production security configuration inspected
- [ ] Relevant tests run and results reported honestly
- [ ] Every finding names the wrong layer, exploitation path, OWASP category, ASVS chapter, and CWE
- [ ] Unverified framework defaults are stated as unknown, not marked pass
