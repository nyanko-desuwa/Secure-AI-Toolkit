# CWE References for MVC Security

Verified 2026-07-28 against the MITRE CWE entries linked below. CWE is a weakness taxonomy, not a
severity score. Rank the demonstrated outcome.

## CWE-915 — Improperly Controlled Modification of Dynamically-Determined Object Attributes

Source: <https://cwe.mitre.org/data/definitions/915.html>

MVC shape: a binder, ORM constructor, or model form copies attacker-supplied names into object
attributes. A hidden or newly added `is_admin`, `tenant_id`, `approved`, `price`, or ownership field
becomes writable.

Controls:

- use an allowlisted request DTO/form and explicit mapping,
- keep server-owned fields out of the request type,
- use Laravel `$fillable`, Rails strong parameters, Django `ModelForm.fields`, ASP.NET input models,
  or Spring DTOs as appropriate,
- reject or visibly handle unknown fields,
- test with one extra privilege-bearing key.

The presence of `$fillable`, `permit`, or `[Bind]` is not proof. Trace the exact narrowed object into
the persistence call.

## CWE-79 — Improper Neutralization of Input During Web Page Generation

Source: <https://cwe.mitre.org/data/definitions/79.html>

MVC shape: a template raw escape hatch renders user data, autoescape is disabled, or HTML encoding
is used in a JavaScript, CSS, URL, or unquoted attribute context.

Controls:

- keep autoescape on,
- encode at the sink for that sink,
- serialize script data as JSON using the framework helper,
- validate URL schemes,
- sanitize intentional rich HTML with a maintained policy,
- never compile attacker-controlled template source.

A CSP is defence in depth. It does not make raw output safe.

## CWE-639 — Authorization Bypass Through User-Controlled Key

Source: <https://cwe.mitre.org/data/definitions/639.html>

MVC shape: a route parameter, form field, or query key selects an object globally. Authentication
middleware or a coarse role guard runs, but the query is not scoped by actor/tenant and no policy
receives the object.

Controls:

- treat every route parameter as attacker input,
- include actor or tenant in repository predicates,
- apply a centralized object policy where ownership alone is insufficient,
- cover read, update, delete, export, attachment, bulk, and nested-resource paths,
- use uniform non-disclosing errors where the product permits.

UUIDs reduce guessability and do not enforce authorization.

## CWE-489 — Active Debug Code

Source: <https://cwe.mitre.org/data/definitions/489.html>

MVC shape: Laravel Ignition, Django technical 500, Rails detailed exceptions, ASP.NET Developer
Exception Page, or Spring error details remain reachable in production.

Controls:

- production-safe default and deployment fail-fast,
- framework debug middleware excluded outside the development environment,
- generic client error plus protected structured logs,
- post-deployment failure smoke test,
- secret filtering as defence in depth, never as permission to expose the page.

Debug pages can reveal stack frames, local values, request bodies, SQL, routes, filesystem paths,
configuration, environment data, and dependency versions. Assess the runtime response, not only a
settings file.
