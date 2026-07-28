# MVC Security Prompts

Good prompts force a request to be traced through every MVC layer. Asking whether one controller is
"secure" misses the model binder, route, query scope, template sink, and production configuration.

## Review a feature end to end

```text
Read the route, request/form object, controller, service, repository, model/schema, and every
template used by the account update feature. Trace one request end to end. For each security
control, state the layer where it currently lives, the layer that has enough information to
enforce it, and whether the current placement is effective. Report file:line, exploitation path,
OWASP Top 10 2025 category, ASVS 5.0 chapter, and CWE. Skip unsupported findings.
```

Why it works: it prevents a controller-only review and makes wrong-layer controls visible.

## Audit mass assignment

```text
Audit every create, update, patch, serializer save, form save, and model constructor reachable
from this MVC application. Enumerate caller-supplied keys and the database columns they can write.
Flag Laravel $guarded=[], broad $fillable, Rails permit!/to_unsafe_h, Django ModelForm exclude or
__all__, ASP.NET domain-entity binding/[Bind], and Spring JPA entity binding. For each finding,
show an HTTP request with the extra privilege field and the exact persisted effect. Map to
A01/A06:2025, ASVS V2/V8, CWE-915.
```

Why it works: it asks for reachability and impact, not keyword matches.

## Review object authorization

```text
For each route parameter that selects an object, trace the lookup. Does middleware only authenticate,
does route model binding fetch globally, is the query scoped by the authenticated actor/tenant,
and is a policy called with the object before use? Test read, update, delete, export, attachments,
and nested resources with another actor's ID. Report A01:2025, ASVS V8, CWE-639 findings.
```

Why it works: delete, exports, and child collections are where otherwise consistent ownership
checks disappear.

## Separate controller and service responsibilities

```text
Review these controllers for business decisions: price, discount, quota, ownership, approval,
role transition, inventory, and workflow state. For each rule, find every HTML, JSON, job, and
import entry point. Propose the smallest service-layer extraction that gives the rule one
enforcement point and keeps controllers limited to HTTP mapping. Distinguish exploitable bypasses
from architecture debt.
```

## Review templates by context

```text
Inventory every interpolation in Blade, Twig, Jinja2, ERB, Razor, or Thymeleaf templates in this
feature. Classify the sink as HTML text, quoted attribute, URL, CSS, JavaScript, JSON-in-HTML, or
raw HTML. Find raw escape hatches and prove whether each value is trusted or sanitized. Do not
credit HTML escaping in JavaScript or URL contexts. Give a working payload for each CWE-79 finding
and a context-correct fix.
```

Why it works: "autoescape enabled" is not an answer to a script-context bug.

## Verify framework defaults

```text
Identify the exact framework and template-engine versions. Using project configuration and official
docs, build a table for mass assignment, unknown-field handling, auto-escaping, CSRF validation,
method override, ORM parameterization, and debug errors. Mark each on by default, opt-in, or off,
and cite where this application registers or disables it. Treat anything unverified as unknown.
```

## Review routing and verbs

```text
List the effective route table. Flag wildcard/conventional routes, resource routes exposing unused
actions, public controller methods reached implicitly, state changes over GET, catch-all ordering,
and verb override. For each state-changing route, verify the final effective HTTP method, CSRF,
authentication, function authorization, and per-object authorization.
```

## Review CSRF placement

```text
Trace a state-changing browser form from token generation through middleware/filter validation.
Confirm the application, not merely the framework package, enables the validator. Find broad
exemptions, mixed session/API controllers, unsafe GET actions, forms that suppress token helpers,
and tests that submit without a token. Map findings to A01:2025 and ASVS V3/V8.
```

## Review production error handling

```text
Inspect production configuration and middleware for Laravel APP_DEBUG, Django DEBUG, Rails detailed
exceptions, ASP.NET Developer Exception Page, and Spring error details as applicable. Then request
a known failing route as an unauthenticated client. Report any traceback, local/request value,
path, SQL, route, dependency version, environment value, or configuration disclosed. Map to
A02:2025, ASVS V13, CWE-489.
```

## Generate a secure implementation

```text
Implement this MVC feature with: explicit routes and verbs; a request DTO/form that rejects unknown
fields; a thin controller; one service transaction for business invariants; an actor-scoped
repository; allowlisted model assignment; framework CSRF; and context-safe templates. Before
returning, run skills/core/mvc-security/checklist.md and include negative tests for another actor's
ID, an extra is_admin field, wrong verb, missing CSRF token, and an XSS payload. Do not add custom
security code where the framework default is confirmed active.
```

## Compare two proposed fixes

```text
Compare these fixes for the same MVC finding. For each, say what information is available at its
layer, whether every entry point passes through it, how it fails when a new model field/action is
added, and what regression test proves it. Prefer the smallest fix that fails closed. Cite OWASP
Top 10 2025, ASVS 5.0, and CWE where applicable.
```

## Anti-patterns

| Prompt | Problem | Better demand |
|---|---|---|
| "Is this controller secure?" | Ignores route, binder, repository, model, template, config | Trace the feature across layers |
| "Add authorization middleware" | Middleware lacks the target object | Scope the query or call policy with actor and object |
| "Sanitize all input" | No sink or policy; often corrupts data | Validate at request, encode at each sink |
| "Use UUIDs to prevent IDOR" | Obscurity, not authorization | Scope every lookup by actor/tenant |
| "Guard is_admin" | Denylist misses the next privilege field | Allowlist the complete writable contract |
| "Turn on client validation" | Browser is attacker-controlled | Enforce the same invariant in the service |
| "Enable autoescape" | Says nothing about raw, URL, CSS, script contexts | Classify every sink and use context helper |
| "Make routes RESTful" | Resource routes may expose unused actions | Enumerate actions with verbs and `only` |
| "Disable CSRF for the API" | May exempt session-authenticated routes too | Separate authentication models and routes |
| "Hide stack traces" | A source setting may differ at runtime | Smoke-test a deployed failing request |
| "Refactor the fat controller" | Can move opacity into callbacks | Name one enforcement point per rule |
| "Make it OWASP compliant" | Top 10 is not a certification | Ask for concrete A01/A02/A05/A06 controls and tests |
