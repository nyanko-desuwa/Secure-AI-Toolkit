---
name: mvc-security
description: 'Place security controls in the correct MVC layer when writing or reviewing Laravel, Django, Rails, ASP.NET Core, or Spring MVC code. Covers mass assignment, template escaping, controller guards, and debug exposure. Triggers: "MVC", "mass assignment", "strong parameters", "fillable", "Blade", "Thymeleaf", "controller", "bảo mật MVC", "gán hàng loạt".'
allowed-tools: Read, Write, Edit, Glob, Grep, Bash(ls:*), Bash(cat:*), WebSearch, WebFetch
---

# MVC Security

A control placed in the wrong layer looks correct and does nothing.

That is the whole subject. A route middleware that checks `hasRole('USER')` reads like
authorization and cannot answer "is invoice 4192 yours". A `required` attribute on a form field
reads like validation and is deleted by anyone with devtools. A `$fillable` list on the model is
the only thing standing between a signup form and `is_admin = 1`. Each of these is a placement
question, not a coding question.

## When to Use

- Writing or reviewing a controller, model, form, serializer, or template
- Adding a route or an action to an existing controller
- Reviewing a diff in a server-rendered application
- Deciding where a new validation or authorization rule belongs
- Auditing a framework's default protections before relying on them

## The Layer Map

Where each control belongs, and what happens when it lands elsewhere.

| Control | Correct layer | Wrong-layer failure |
|---|---|---|
| Authentication | Middleware / filter | Duplicated per action, one action forgets |
| Coarse function access (is this an admin route) | Middleware / filter | Fine, this is the right place |
| Per-object authorization | Data access, or a policy called with the object | Middleware cannot see the object; passes everyone |
| Which fields a request may write | Model / form / DTO | Controller `if` chains miss the next new column |
| Field type, range, format | Request object / serializer | Template or client check, trivially bypassed |
| Business invariants (price, quota, state machine) | Service layer | Controller copy-paste drift; template versions are cosmetic |
| Output encoding | Template engine, per context | Encoding at input time; wrong context escape |
| Query scoping by actor | Repository / query | Post-fetch `if` that someone forgets to `raise` on |
| CSRF token | Framework middleware | Hand-rolled per form, exempted "temporarily" |

## Workflow

### 1. Identify the layers the change touches

Read the route, the controller action, the model, and the template before writing. An MVC change
is rarely confined to one file, and the vulnerability is usually in the file you did not open.

### 2. Check what the framework already does

Do not add a control the framework provides, and do not assume it provides one it does not.
Jinja2 autoescapes in Flask and not in bare Jinja2. Spring Boot turns off Jackson's
`fail-on-unknown-properties`. See [references/framework-defaults.md](references/framework-defaults.md).

### 3. Place each control at its layer

Work inward from the request:

1. Routing — is the action reachable only by the verbs and paths you intended?
2. Request validation — typed, allowlisted fields, unknown fields rejected.
3. Controller — resolve the actor, delegate, return. No policy logic, no queries.
4. Authorization — with the object in hand, at the query or in a policy call.
5. Service — business invariants, recomputed server-side from trusted data.
6. Model — writable field allowlist. Never a denylist.
7. Template — auto-escaping on, correct escape for the context.

### 4. Verify

Run [checklist.md](checklist.md). The mass assignment and template sections are the two that
catch the most in practice.

### 5. Report

Name the layer, not just the file. "Authorization is enforced in `RouteServiceProvider`
middleware, which never sees the `Invoice`, so any authenticated user reads any invoice" is a
finding. "Missing access control in `InvoiceController`" is a guess at the fix.

## Severity

Rank by who can reach it and what they gain.

- **Critical** — mass assignment reaching a role, permission, or tenant column; stored XSS in a
  page an admin views; debug page exposed on the internet with credentials in the environment dump
- **High** — object-level authorization missing on a read of other tenants' data; raw template
  output of user content; verb tunnelling reaching a destructive action
- **Medium** — mass assignment reaching a non-privilege column, business logic enforced only in
  the controller and duplicated inconsistently, unknown fields silently ignored
- **Low** — fat controller with no current bypass, missing defence in depth

A mass assignment finding is not automatically critical. It depends entirely on which columns are
reachable. Read the schema before you rank it.

## Standards

- OWASP Top 10 2025: A01 Broken Access Control, A02 Security Misconfiguration, A05 Injection,
  A06 Insecure Design
- ASVS 5.0: V1 Encoding and Sanitization, V2 Validation and Business Logic, V3 Web Frontend
  Security, V8 Authorization, V13 Configuration
- CWE-915 (mass assignment), CWE-79 (XSS), CWE-639 (authorization bypass through user-controlled
  key), CWE-489 (active debug code)

## Related Skills

- `owasp` — the standards themselves, and controls outside MVC
- `api-security` — object and property level authorization on API surfaces
- `frontend-security` — CSP, headers, and the browser side of XSS
- `database-security` — query construction beyond the ORM escape hatches
- `secure-code-review` — reviewing an existing codebase in depth

## Supporting Files

- [README.md](README.md) — purpose, standards table, limitations
- [checklist.md](checklist.md) — pre-return verification, grouped by layer
- [best-practices.md](best-practices.md) — patterns per layer, with vulnerable/fixed pairs
- [common-mistakes.md](common-mistakes.md) — what goes wrong and why the fix works
- [troubleshooting.md](troubleshooting.md) — when the guidance conflicts with the framework
- [prompts.md](prompts.md) — prompts that produce findings
- [references/framework-defaults.md](references/framework-defaults.md) — on by default, opt-in, off
- [references/template-escaping.md](references/template-escaping.md) — engine by engine
- [examples/README.md](examples/README.md) — eight vulnerable/fixed pairs
