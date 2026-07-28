# MVC Security Troubleshooting

Use this when the secure layer boundary conflicts with a framework convention or an existing
application.

## The framework already protects this

Verify three things before marking pass:

1. The exact framework version supports the protection.
2. The application registered the middleware, filter, formatter, or template engine.
3. Production did not disable or override it.

A CSRF token in a form proves token generation, not server validation. A template file extension
does not prove the selected Jinja2 environment autoescapes it. A model annotation does not prove
another write path uses model binding.

If code and runtime configuration are unavailable, report the control as unverified. Do not add a
second hand-rolled control around it.

## The service layer does not exist

Do not solve a five-line controller by creating an abstract factory, interface, and dependency
container graph. Extract the security-sensitive use case into one concrete service with one public
method. Pass the authenticated actor and typed input. Keep the transaction there.

The minimum safe migration is:

1. Add a request DTO/form object.
2. Add an actor-scoped repository method.
3. Move the invariant and write into one service transaction.
4. Make the old controller delegate.
5. Move the next adapter to the same method.

Until every entry point delegates, state which ones still duplicate the rule. A partial extraction
can create false confidence.

## A business rule appears in both client and server

Keep both. The client copy is UX; the service copy is the control. Do not attempt to share generated
JavaScript validation as the sole enforcement mechanism.

Test the service or endpoint without loading the page. If it rejects the invalid transition, the
control works. If only the browser prevents submission, it does not.

## The policy needs object state, so repository scoping is not enough

Simple ownership or tenancy belongs in the query. Rich policy decisions may need the loaded object:
"edit if owner and draft, or compliance officer for this region."

Use both:

1. Scope the candidate set by actor/tenant in the repository.
2. Call a centralized policy with actor, object, and operation.
3. Deny before mutation.

Do not broaden the query to global data merely because the policy is rich. Coarse scoping limits
existence disclosure and the damage from a missed policy call.

## Returning 404 conflicts with a documented 403

A uniform 404 avoids confirming that another tenant's object exists. A documented 403 may be a
contract requirement or an important distinction for an internal administrative tool.

State the trade-off. If 403 is required, ensure list, timing, cache, and error body do not leak more
than the contract already reveals. Keep the query actor-scoped; map an authorized-but-forbidden
operation separately only if the service can distinguish it without a global attacker-controlled
lookup.

## Updating assignment controls would break existing clients

Do not preserve accidental mass assignment. Inventory current fields and classify each as:

- caller-writable,
- server-derived,
- privileged workflow input, or
- obsolete/unknown.

Create a versioned DTO or form with the intended writable list. Log rejected unknown keys without
logging values. Give clients a migration period where required, but never continue assigning role,
tenant, approval, balance, or ownership from the old bag.

A compatibility layer may translate old safe field names. It must not pass the original request
through.

## The framework silently ignores unknown fields

Silent dropping prevents some assignment attacks, but it hides contract mistakes and probing. For
security-sensitive commands, prefer rejection.

- Rails: set `action_on_unpermitted_parameters = :raise` in development and test; decide whether
  production returns a controlled 400 or logs a safe event.
- Spring MVC: enable Jackson failure on unknown properties for command DTOs, or use a strict mapper
  for those endpoints.
- ASP.NET Core: use dedicated DTOs and configure JSON unmapped-member handling where supported;
  form posts may need an explicit key allowlist check.
- Laravel: operate only on `validated()` data and compare input keys with the accepted contract when
  strict rejection is required.
- DRF: default serializers reject unknown writable keys; verify custom `to_internal_value` methods
  do not discard them.

Do not leak the value of a rejected sensitive field into logs.

## A template must render rich HTML

Escaping would turn the feature into text. Raw output without sanitation creates XSS.

Define a content policy: allowed elements, attributes, URL schemes, link behavior, and whether
images are allowed. Sanitize with a maintained parser-based library. Store the original separately
only if the product needs re-sanitization after policy updates. Render only the sanitizer-owned
representation through the engine's raw escape hatch.

Known limitation: sanitizer bugs and policy mistakes remain. Add CSP as defence in depth, patch the
library, and re-sanitize stored content when the policy changes. CSP is not the primary fix.

## Data must appear inside JavaScript

Do not search for a generic "JavaScript escape" and concatenate into a quoted literal. Serialize
the complete value as JSON using the framework helper designed for HTML script context. Better,
place data in an `application/json` element or a safe `data-*` attribute and keep executable code
static.

Check how the helper handles `<`, `>`, `&`, quotes, U+2028, U+2029, and `</script>`. If the exact
version's documentation does not promise safe HTML embedding, use a non-script data channel or
fetch JSON from a same-origin endpoint.

## The raw query is needed for performance

Raw SQL is not prohibited. Unbound attacker input is.

- Bind all values.
- Map identifiers and sort directions from enums or fixed maps.
- Keep actor/tenant scope in the raw statement.
- Add a test with another tenant's ID and injection metacharacters.
- Wrap the query in one repository method so callers cannot forget the scope.

If the ORM cannot express a parameter safely, do not write a custom escaper. Change the query shape
or use the database driver's composition API for identifiers.

## Method override is required for HTML forms

HTML forms support GET and POST, so frameworks tunnel PUT/PATCH/DELETE through a POST. Keep it only
for CSRF-protected same-origin forms.

Confirm the pipeline order, the accepted parameter/header, and whether proxies and logs preserve
the effective method. Route and authorize the final action. Do not enable wildcard verbs merely to
make tunnelling work. If the application uses JavaScript `fetch`, send the real method and disable
override.

## CSRF breaks a webhook or bearer-token API

Do not exempt an entire mixed controller. Separate the endpoint by route and authentication model.
A third-party webhook should use a signature and replay protection. A bearer-token API should not
also accept ambient session cookies. Keep CSRF on every cookie-authenticated browser action.

If SameSite cookies appear to solve the issue, treat them as defence in depth. Browser behavior,
legacy clients, sibling-domain attacks, and flows that require `SameSite=None` keep token-based
validation relevant.

## Debug information is needed during a production incident

Do not expose the framework debug page. Send the user a correlation ID and capture structured detail
in access-controlled logs or tracing. Temporarily increase server-side logging for the narrow
component, with secret filtering and an expiry.

If remote debugging is unavoidable, use an isolated replica with production-like synthetic data,
not the live public process. Never rely only on a source IP check: proxies, SSRF, VPN sharing, and
configuration drift weaken it.

## Framework docs and this skill disagree

The pinned project version wins. Read its official documentation and source defaults. Record:

- package and version,
- configuration key,
- value in each environment,
- where middleware/filter order is established, and
- date verified.

Update the project decision, not the framework code. If the behavior cannot be confirmed, state the
uncertainty and add a runtime test.

## The secure change alters a public contract

Do not quietly weaken it. Report:

1. Current behavior and why it is unsafe.
2. Secure behavior and its HTTP status/field/verb change.
3. Affected clients.
4. Compatibility window.
5. Removal date for the old route or field.

For an authorization or mass-assignment bypass, the unsafe behavior is not a compatibility promise.
A transition can preserve safe field names, but not attacker control over server-owned state.

## A finding spans too many layers to rank confidently

Trace one concrete request end to end. Name the actor, submitted fields, route, object ID, query,
assignment operation, template sink, and response. Rank the demonstrated outcome, not the number of
code smells.

"Fat controller" alone is Low or architecture debt. "The JSON action duplicates checkout and omits
the server-side price lookup, allowing any user to buy for one cent" is High. The exploitation path
is what changes the ranking.
