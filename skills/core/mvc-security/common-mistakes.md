# Common MVC Security Mistakes

Each mistake has a control that looks plausible in review. The question is whether that layer has
the object, context, and authority needed to enforce it.

## Authentication middleware counted as object authorization

`A01:2025` · ASVS V8 · CWE-639

```php
// Vulnerable: auth proves identity, not ownership.
Route::middleware('auth')->get('/invoices/{invoice}', function (Invoice $invoice) {
    return view('invoices.show', compact('invoice'));
});
```

Any logged-in user supplies another invoice ID. Implicit route model binding fetches globally; it
does not infer ownership.

Fix: query `whereBelongsTo($request->user())` in a repository or call an `InvoicePolicy` with the
resolved object before rendering. Why it works: the decision receives both actor and target. A
UUID route key only makes enumeration slower and remains CWE-639.

## Authorization in the controller after a global fetch

`A01:2025` · ASVS V8 · CWE-639

```csharp
// Vulnerable: a future refactor can use invoice before this branch or forget the branch entirely.
var invoice = await _db.Invoices.FindAsync(id);
if (invoice.OwnerId != CurrentUserId()) return Forbid();
```

The code may be correct today, but the unscoped object exists before authorization and every
action must repeat the branch.

Fix: `SingleOrDefaultAsync(x => x.Id == id && x.OwnerId == actorId)` in an actor-scoped repository,
or a mandatory policy immediately after loading where the policy needs richer state. Why it works:
unauthorized rows are absent from the result set, so there is no object to accidentally use.

## A mass-assignment denylist

`A01:2025` · `A06:2025` · ASVS V2, V8 · CWE-915

```python
# Vulnerable: the next sensitive field added to Account becomes writable automatically.
class AccountForm(forms.ModelForm):
    class Meta:
        model = Account
        exclude = ("is_superuser", "tenant_id")
```

A later `can_refund`, `credit_limit`, or `billing_status` column enters the form without changing
this file. It may not be visible in the rendered page, but the attacker posts it directly.

Fix: `fields = ("display_name", "timezone")`. Why it works: schema growth is fail-closed. Only an
explicit edit to the allowlist exposes a new field.

## Strong parameters followed by unsafe parameters

`A01:2025` · `A06:2025` · ASVS V2, V8 · CWE-915

```ruby
# Vulnerable: validation happened, then the original bag was persisted.
def update
  params.expect(user: %i[name timezone])
  current_user.update!(params[:user].to_unsafe_h)
end
```

The first line looks like a guard but its returned safe object is discarded. `role=admin` survives
in the second line.

Fix: assign the returned permitted hash: `current_user.update!(params.expect(user: %i[name timezone]))`.
Why it works: data downstream is the narrowed value, not the original request. Treat request
validation as a transformation, not a side effect.

## `[Bind]` used as a permanent domain boundary

`A06:2025` · ASVS V2 · CWE-915

```csharp
// Vulnerable over time: adding a field to this string is easy, and excluded fields can be reset
// during edit binding.
public IActionResult Edit([Bind("Id,Name,Email")] User user) { /* save entity */ }
```

`[Bind]` is an allowlist and does mitigate overposting. The mistake is binding the persistence
entity and treating an HTTP annotation as the domain's permanent write policy. Edit scenarios can
replace omitted properties with defaults, and another action may omit the annotation.

Fix: bind `EditProfileInput`, load the actor-scoped `User`, and explicitly copy `Name` and `Email`.
Why it works: server-owned fields never enter the request type, and persistence updates the tracked
entity rather than an attacker-shaped replacement.

## Client-side validation counted as a control

`A06:2025` · ASVS V2

```html
<!-- Vulnerable as a security boundary: curl has no max and sends hidden values freely. -->
<input name="quantity" type="number" min="1" max="5" required>
<input name="price_cents" type="hidden" value="1999">
```

Fix: keep these attributes for UX, then enforce quantity server-side and load the price from the
database inside the service transaction. Why it works: the decision runs for every HTTP client and
uses trusted state. Duplicating a rule in JavaScript is fine; relying on that copy is not.

## Escaping on input

`A05:2025` · ASVS V1, V3 · CWE-79

```python
# Vulnerable design: HTML-encoded data is later used in JavaScript and URL contexts.
profile.display_name = html.escape(request.POST["display_name"])
```

This corrupts stored data, creates double-encoding, and provides the wrong encoding for a script,
CSS, or URL sink.

Fix: validate canonical input, store it unchanged, and let the template escape at each sink. Use a
JSON serializer in scripts and URL scheme allowlists for links. Why it works: each interpreter sees
data encoded for its own grammar.

## Raw output justified by "admins only"

`A05:2025` · ASVS V1, V3 · CWE-79

```html
<!-- Vulnerable Thymeleaf: a customer support note becomes stored XSS in an admin session. -->
<div th:utext="${ticket.note}"></div>
```

Admin-only rendering raises the impact. It does not make untrusted input safe.

Fix: use `th:text` for text, or sanitize through a maintained allowlist policy before storing an
explicit `sanitizedNoteHtml` representation. Why it works: active elements, event attributes, and
dangerous URL schemes cannot reach the raw HTML parser.

## HTML escaping inside JavaScript

`A05:2025` · ASVS V1, V3 · CWE-79

```cshtml
@* Vulnerable: Razor's HTML encoding is not JavaScript string encoding. *@
<script>const message = '@Model.Message';</script>
```

A payload containing quotes and script syntax is interpreted by JavaScript after the browser parses
the HTML. `Html.Raw(Json.Serialize(...))` is also easy to misuse if the serializer does not escape
HTML-significant characters.

Fix: place JSON in a non-executable `application/json` element using a safe framework serializer,
or pass data through `data-*` and read it as text. Use the documented JSON options that escape `<`,
`>`, `&`, and quotes. Why it works: the value is serialized as data, not spliced into program text.

## ORM means raw SQL is safe

`A05:2025` · ASVS V1

```java
// Vulnerable: JPQL is still an interpreter when assembled as a string.
entityManager.createQuery(
    "select i from Invoice i where i.tenantId = " + tenantId + " order by " + sort
).getResultList();
```

Fix: bind `tenantId` as a named parameter and map `sort` from an enum to a server-owned criteria
expression. Why it works: the actor value cannot change query syntax, and the identifier comes from
an allowlist. ORM parameterization protects ordinary method calls, not strings passed through a raw
escape hatch.

## Validation allows unknown fields and later code uses the original request

`A06:2025` · ASVS V2 · CWE-915

```php
// Vulnerable: rules validate three keys, but all request keys reach the model.
$request->validate(['name' => 'required', 'email' => 'required|email']);
$user->update($request->all());
```

Fix: use a FormRequest and pass `$request->validated()` to an explicit mapper; reject unknown keys
for sensitive operations. Why it works: downstream code cannot rediscover `is_admin` in the
original bag. Silent dropping is safer than assignment but can hide client errors and probes;
strict rejection makes the contract auditable.

## Hiding a button as authorization

`A01:2025` · ASVS V8 · CWE-639

```erb
<% if current_user.admin? %>
  <%= button_to "Delete", user_path(@user), method: :delete %>
<% end %>
```

This is useful UX. It says nothing about `DELETE /users/7`, which an attacker sends directly.

Fix: keep the conditional and authorize the controller/service action. Why it works: the server
rejects the request independent of which page was rendered. The template may mirror a policy but
never own it.

## Conventional or wildcard routes expose methods implicitly

`A01:2025` · `A02:2025` · ASVS V8, V13 · CWE-639

```ruby
# Vulnerable: any public controller method can become an endpoint.
match ':controller(/:action(/:id))', via: :all
```

Fix: enumerate `resources` actions with `only:` and add each non-REST action with one explicit
verb. Why it works: a new public method is not network-reachable until routing is reviewed. A
wildcard denylist repeats the mass-assignment mistake at the route layer.

## Verb tunnelling reviewed as POST instead of the final method

`A01:2025` · ASVS V8 · CWE-639

A request `POST /orders/7` with `_method=DELETE` may be rewritten by Laravel, Rails, or Spring
filtering. A guard that authorizes "POST update" before rewrite can miss a destructive action; a
proxy or rate limiter may log only the outer method.

Fix: authorize the routed action and final server method, put method override in the documented
framework pipeline, require CSRF, and disable it if HTML forms do not need it. Why it works: every
layer agrees the request is a delete. Blocking `_method` in JavaScript is not a server control.

## Broad CSRF exemption for a mixed web/API controller

`A01:2025` · ASVS V3, V8

```python
# Vulnerable: session-authenticated requests are now forgeable.
@csrf_exempt
def profile(request):
    if request.method == "POST":
        request.user.email = request.POST["email"]
        request.user.save()
```

Fix: keep Django's CSRF middleware for browser sessions. Put bearer-token API endpoints in a
separate view with authentication that does not automatically ride browser cookies. Why it works:
a malicious origin cannot create a valid CSRF token for the session-backed state change.

## Debug mode controlled by an unsafe fallback

`A02:2025` · ASVS V13 · CWE-489

```php
// Vulnerable: missing production configuration enables the dangerous state.
'debug' => env('APP_DEBUG', true),
```

Fix: default to `false`, make production deployment fail if required configuration is missing, and
request a known exception in a smoke test. Why it works: absence of configuration fails safe and
the test verifies runtime behavior rather than a source file. An IP allowlist around a debug page
is defence in depth, not a reason to leave it active.

## Fat controller moved wholesale into ORM callbacks

`A06:2025` · ASVS V2, V8, V13

Moving price calculation, role checks, notifications, and tenant assignment into `before_save`
removes lines from the controller but does not produce an auditable boundary. Callbacks may run on
unrelated write paths, be skipped by bulk updates, and execute in surprising order.

Fix: put use-case rules in an explicit service transaction, valid transitions in named domain
methods, and actor scope in repositories. Keep callbacks for narrow persistence invariants that do
not need request context. Why it works: every entry point has a visible call graph and tests can
exercise the same enforcement point.
