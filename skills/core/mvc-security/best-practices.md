# MVC Security Best Practices

Each pattern places the control where it has enough information to work. The vulnerable version is
often not missing a check. It has a check in a layer that cannot enforce it.

## Keep controllers thin

`A01:2025` · `A06:2025` · ASVS V2, V8 · CWE-639

A controller owns HTTP concerns: bind the request, obtain the authenticated actor, call a service,
and choose a response. A middleware guard may establish authentication or coarse function access.
It cannot establish ownership before the object has been loaded.

Vulnerable — Spring MVC controller carries authorization and state-transition logic:

```java
// Vulnerable: duplicated business and authorization rules live in the HTTP adapter.
@PostMapping("/orders/{id}/cancel")
public String cancel(@PathVariable long id, Principal principal) {
    Order order = orderRepository.findById(id).orElseThrow();
    if (!order.getCustomer().getEmail().equals(principal.getName())) {
        throw new ResponseStatusException(HttpStatus.FORBIDDEN);
    }
    if (order.getStatus() == OrderStatus.SHIPPED) {
        throw new ResponseStatusException(HttpStatus.CONFLICT);
    }
    order.setStatus(OrderStatus.CANCELLED);
    orderRepository.save(order);
    return "redirect:/orders/" + id;
}
```

Fixed — controller delegates; repository scope and invariant live behind one service method:

```java
@PostMapping("/orders/{id}/cancel")
public String cancel(@PathVariable long id, Principal principal) {
    orderService.cancelOwnedOrder(principal.getName(), id);
    return "redirect:/orders/" + id;
}

@Transactional
public void cancelOwnedOrder(String actorEmail, long orderId) {
    Order order = orderRepository.findByIdAndCustomerEmail(orderId, actorEmail)
        .orElseThrow(() -> new OrderNotFoundException(orderId));
    order.cancel(); // The domain transition rejects SHIPPED and already-cancelled orders.
}
```

Why this works: the route ID selects nothing on its own. Ownership is in the query, and every
adapter that calls `cancelOwnedOrder` gets the same transition rule. The controller has no branch
that another action can copy incorrectly.

## Allowlist assignable fields

`A01:2025` · `A06:2025` · ASVS V2, V8 · CWE-915

Mass assignment is the dominant MVC vulnerability because frameworks are built to map request
objects into model objects. The attack is one extra field:

```http
POST /register HTTP/1.1
Content-Type: application/json

{"name":"Mallory","email":"mallory@example.test","password":"correct horse","is_admin":true}
```

Vulnerable — Laravel accepts every submitted key and the model guards nothing:

```php
// Vulnerable: is_admin, tenant_id, and account_credit are request-writable.
final class User extends Authenticatable
{
    protected $guarded = [];
}

public function store(Request $request): RedirectResponse
{
    $user = User::create($request->all());
    return redirect()->route('users.show', $user);
}
```

Fixed — request and model both use positive field lists; server-owned fields come from trusted
state:

```php
final class RegisterUserRequest extends FormRequest
{
    public function rules(): array
    {
        return [
            'name' => ['required', 'string', 'max:80'],
            'email' => ['required', 'email:rfc', 'max:254', 'unique:users,email'],
            'password' => ['required', 'string', 'min:12'],
        ];
    }
}

final class User extends Authenticatable
{
    protected $fillable = ['name', 'email', 'password'];
}

public function store(RegisterUserRequest $request): RedirectResponse
{
    $data = $request->validated();
    $user = User::create([
        ...$data,
        'password' => Hash::make($data['password']),
        'tenant_id' => $request->user()->tenant_id,
        'is_admin' => false,
    ]);
    return redirect()->route('users.show', $user);
}
```

Why this works: the extra `is_admin` key is not in validated data or `$fillable`, and its value is
chosen by the server. `$guarded = ['is_admin']` is the tempting wrong fix. The next privilege field
added to the table is writable until someone remembers to add it to the denylist.

### Framework assignment controls

| Framework | Vulnerable shape | Use instead | Important limitation |
|---|---|---|---|
| Laravel | `$guarded = []`; `create($request->all())` | narrow `$fillable`; `validated()` | `$fillable` is not validation or authorization |
| Rails | `permit!`; `to_unsafe_h`; broad nested params | `expect` / `require(...).permit(...)` with explicit keys | unpermitted keys are often silently dropped outside strict config; test the attempted extra field |
| Django | `ModelForm.Meta.exclude`; `fields = "__all__"` | explicit `Meta.fields` tuple | direct ORM `create(**request.POST.dict())` bypasses ModelForm |
| ASP.NET Core | bind a domain entity directly; broad or missing `[Bind]` | dedicated input model, then explicit mapping | `[Bind]` is an allowlist, but Microsoft recommends view models for overposting; it can erase omitted fields in edit flows |
| Spring MVC | bind JPA entity from `@RequestBody` / form | request DTO with validation, explicit mapping | Jackson ignores unknown JSON fields by default in common Spring Boot configurations unless strictness is enabled |

## Validate at the request boundary and reject unknown fields

`A06:2025` · ASVS V2 · CWE-915

Field validation and write authorization are related but distinct. Validate type, shape, and range
in a request object. Allowlist the fields that may mutate state when mapping to the domain.

Vulnerable — ASP.NET Core binds a persistence entity. The `[Required]` checks do not stop
`IsApproved=true`:

```csharp
// Vulnerable: model validation validates every property it successfully binds.
[HttpPost]
public async Task<IActionResult> Create(Expense expense)
{
    if (!ModelState.IsValid) return View(expense);
    _db.Expenses.Add(expense);
    await _db.SaveChangesAsync();
    return RedirectToAction(nameof(Index));
}
```

Fixed — a request model exposes exactly three client fields; the service assigns identity and
approval:

```csharp
public sealed record CreateExpenseInput(
    [property: Required, StringLength(120)] string Description,
    [property: Range(typeof(decimal), "0.01", "10000")] decimal Amount,
    [property: DataType(DataType.Date)] DateOnly IncurredOn);

[HttpPost]
[ValidateAntiForgeryToken]
public async Task<IActionResult> Create(CreateExpenseInput input)
{
    if (!ModelState.IsValid) return View(input);
    await _expenseService.CreateAsync(User, input);
    return RedirectToAction(nameof(Index));
}
```

Why this works: `IsApproved`, `OwnerId`, and reimbursement state do not exist in the binding type.
A `[Bind("Description,Amount,IncurredOn")] Expense expense` allowlist is better than binding the
whole entity, but the dedicated type remains safe when the entity grows and avoids clearing fields
that were omitted from an edit form.

Unknown fields deserve an explicit policy. DRF serializers reject unknown fields by default;
Laravel FormRequest returns only validated keys when `validated()` is used; Rails strong parameters
usually filter unpermitted keys unless configured to raise. In ASP.NET Core and Spring MVC JSON
binding, configure strict unknown-member handling for security-sensitive commands or pre-validate
the JSON shape. Never pass the original request object after validation.

Vulnerable — DRF's serializer exposes every model field, including the role added by a later
migration:

```python
# Vulnerable: "__all__" grows with the model and makes role writable.
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = "__all__"
```

Fixed — the input contract is explicit and server-owned state is read-only:

```python
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ("display_name", "timezone", "role", "tenant_id")
        read_only_fields = ("role", "tenant_id")

    def update(self, instance, validated_data):
        instance.display_name = validated_data["display_name"]
        instance.timezone = validated_data["timezone"]
        instance.save(update_fields=("display_name", "timezone"))
        return instance
```

Why this works: DRF rejects an unknown `is_admin` key, and declared privilege fields remain
non-writable even if returned in the representation. A custom `to_internal_value` that silently
discards unknown fields changes that default; review overrides before relying on it.

## Put business logic in the service, not the controller or template

`A06:2025` · ASVS V2

A hidden button is not a rule. A JavaScript minimum, disabled checkbox, or template `if` is user
experience. The attacker sends the request without rendering the page.

Vulnerable — Rails trusts a browser-computed total and uses a template check as the only limit:

```erb
<!-- Vulnerable: the user can remove max=5 and alter total_cents in the request. -->
<%= number_field_tag :quantity, 1, min: 1, max: 5 %>
<%= hidden_field_tag :total_cents, @product.price_cents %>
<% if current_user.orders_today < 5 %>
  <%= submit_tag "Buy" %>
<% end %>
```

```ruby
# Vulnerable: controller persists client business data.
def create
  Order.create!(user: current_user, quantity: params[:quantity], total_cents: params[:total_cents])
  redirect_to orders_path
end
```

Fixed — controller supplies identifiers and typed input; service locks and recomputes:

```ruby
def create
  Checkout.call(
    actor: current_user,
    product_id: params.expect(:product_id),
    quantity: Integer(params.expect(:quantity), 10)
  )
  redirect_to orders_path
end

class Checkout
  def self.call(actor:, product_id:, quantity:)
    raise InvalidQuantity unless (1..5).cover?(quantity)

    Product.transaction do
      product = Product.lock.find(product_id)
      raise DailyLimitReached if actor.orders.where(created_at: Time.current.all_day).count >= 5
      actor.orders.create!(
        product: product,
        quantity: quantity,
        total_cents: product.price_cents * quantity
      )
    end
  end
end
```

Why this works: the authoritative price comes from the locked product row, and the limit is checked
where every caller must pass. Client validation should remain for immediate feedback, but it is not
credited as a security control.

## Scope ORM queries by the actor

`A01:2025` · ASVS V8 · CWE-639

A route parameter is attacker input even when the router converted it to an integer or model
instance. Scope the query before the object exists.

Vulnerable — Django fetches globally, then relies on a decorator that knows only that someone is
logged in:

```python
# Vulnerable: @login_required cannot answer whether this invoice belongs to request.user.
@login_required
def invoice_detail(request: HttpRequest, invoice_id: int) -> HttpResponse:
    invoice = get_object_or_404(Invoice, pk=invoice_id)
    return render(request, "billing/invoice.html", {"invoice": invoice})
```

Fixed — repository scope is part of the lookup:

```python
class InvoiceRepository:
    @staticmethod
    def get_visible(*, actor: User, invoice_id: int) -> Invoice:
        return get_object_or_404(
            Invoice.objects.select_related("customer"),
            pk=invoice_id,
            customer__organization_id=actor.organization_id,
        )

@login_required
def invoice_detail(request: HttpRequest, invoice_id: int) -> HttpResponse:
    invoice = InvoiceRepository.get_visible(actor=request.user, invoice_id=invoice_id)
    return render(request, "billing/invoice.html", {"invoice": invoice})
```

Why this works: the generated SQL contains both ID and organization scope. A UUID ID is not a fix;
it is still a bearer secret that leaks through links, logs, exports, and browser history.

### ORM raw escape hatches

ORMs parameterize ordinary comparisons. Each still exposes a door back to string-built SQL.

| Framework | Raw door to review | Safe direction |
|---|---|---|
| Laravel / Eloquent | `DB::raw`, `whereRaw`, `selectRaw`, `orderByRaw`, `unprepared` | bindings for values; allowlist-map identifiers |
| Django ORM | `RawSQL`, `Manager.raw`, `QuerySet.extra`, `cursor.execute` | `%s` parameters; no quoted placeholder; allowlist identifiers |
| Rails Active Record | `find_by_sql`, `connection.execute`, string conditions/order | bind arrays/hashes; `sanitize_sql_*` where appropriate; allowlist order expressions |
| EF Core | `FromSqlRaw`, `ExecuteSqlRaw` | `FromSql` / `FromSqlInterpolated` for values; allowlist schema identifiers |
| Spring Data / JPA | native `@Query`, `EntityManager.createNativeQuery`, concatenated JPQL | named parameters; `Sort` from server allowlist |

Parameter placeholders do not represent a table, column, direction, or SQL keyword. Map a user
choice such as `sort=created` to a server-owned expression.

## Keep template auto-escaping on and escape for the sink

`A05:2025` · ASVS V1, V3 · CWE-79

Vulnerable — Blade raw output turns a profile bio into stored XSS:

```blade
{{-- Vulnerable: <img src=x onerror=fetch('/account/delete',{method:'POST'})> executes. --}}
<section class="bio">{!! $user->bio !!}</section>
```

Fixed for plain text:

```blade
<section class="bio">{{ $user->bio }}</section>
```

Fixed for a deliberately supported rich-HTML feature:

```php
// Sanitize on write with a maintained HTML sanitizer and a narrow policy.
$user->bio_html = $sanitizer->sanitize($request->validated('bio_html'));
```

```blade
{{-- Raw is acceptable only because bio_html is the sanitizer-owned representation. --}}
<section class="bio">{!! $user->bio_html !!}</section>
```

Why this works: normal Blade output encodes HTML metacharacters at the HTML sink. For rich HTML,
encoding would remove the feature; a policy-based sanitizer removes active content before the
explicit raw sink. The remaining risk is sanitizer bypass or stale policy, so keep the sanitizer
patched and cover permitted tags and URL schemes with tests.

HTML escaping is not universal. This is wrong even though `{{ }}` is escaped:

```blade
{{-- Vulnerable context: HTML escaping does not make a JavaScript string literal safe. --}}
<script>window.profileName = '{{ $user->name }}';</script>
```

Use a JavaScript/JSON helper:

```blade
<script>window.profileName = {{ Js::from($user->name) }};</script>
```

A value safe in an HTML body can still break an unquoted attribute, use a `javascript:` URL, or
terminate a script block. See [references/template-escaping.md](references/template-escaping.md).

## Let the framework enforce CSRF, then verify the registration

`A01:2025` · ASVS V3, V8

CSRF belongs at the request pipeline because it applies consistently before unsafe controller
actions. Server-rendered MVC frameworks already have a mechanism. The review question is whether
the application disabled, bypassed, or failed to register it.

Vulnerable — ASP.NET Core emits a form token but no MVC filter validates it:

```csharp
// Vulnerable in an MVC app with no global antiforgery filter.
[HttpPost]
public async Task<IActionResult> ChangeEmail(ChangeEmailInput input)
{
    await _accountService.ChangeEmailAsync(User, input.Email);
    return RedirectToAction(nameof(Profile));
}
```

Fixed — enable validation broadly for unsafe methods:

```csharp
builder.Services.AddControllersWithViews(options =>
{
    options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
});
```

```cshtml
<form asp-action="ChangeEmail" method="post">
    <input asp-for="Email" />
    <button type="submit">Save</button>
</form>
```

Why this works: the form tag helper generates the token and the global filter validates it on
unsafe methods. Emission without validation is security theatre. `[ValidateAntiForgeryToken]` per
action works, but one forgotten action is enough; broad `AutoValidateAntiforgeryToken` is safer for
non-API MVC controllers.

## Constrain routes and verbs explicitly

`A01:2025` · `A02:2025` · ASVS V8, V13 · CWE-639

Routing is an access-control inventory. Conventional or wildcard routes can make a public method
reachable before anyone reviews it as an endpoint.

Vulnerable — Rails exposes every conventional action and accepts destructive work over GET:

```ruby
# Vulnerable: the catch-all can reach actions not deliberately routed.
match ':controller(/:action(/:id))', via: :all

class ReportsController < ApplicationController
  def purge
    Report.where('created_at < ?', 90.days.ago).delete_all
    redirect_to reports_path
  end
end
```

Fixed — enumerate routes and use the intended unsafe verb:

```ruby
resources :reports, only: %i[index show] do
  delete :purge, on: :collection
end
```

Why this works: `purge` is exposed once, under one verb, and the normal Rails CSRF path can protect
the non-GET request. An action-name denylist on the wildcard is the wrong fix; the next public
method becomes a route.

Verb tunnelling needs the same review. Laravel's `_method`, Rails' Rack method override, and
Spring's `HiddenHttpMethodFilter` allow an HTML `POST` to become `PUT`, `PATCH`, or `DELETE`.
Enable it only when needed, after CSRF validation, and ensure authorization is based on the final
method. Never let a query parameter on a GET tunnel to a write.

## Disable framework debug pages in production

`A02:2025` · ASVS V13 · CWE-489

A framework debug page is a full information disclosure. It commonly contains stack frames, local
variables, request bodies, file paths, routes, dependency versions, SQL, environment values, and
configuration. Some combinations turn disclosure into code execution.

Vulnerable — Django production settings inherit `DEBUG=True`:

```python
# Vulnerable: an attacker triggers an exception and receives traceback and request details.
DEBUG = True
ALLOWED_HOSTS = ["*"]
```

Fixed — production fails during deployment unless explicit safe settings are present:

```python
DEBUG = False
ALLOWED_HOSTS = [host for host in os.environ["ALLOWED_HOSTS"].split(",") if host]
if not ALLOWED_HOSTS:
    raise RuntimeError("ALLOWED_HOSTS must not be empty")
```

Why this works: the production error path no longer invokes Django's technical 500 page, and host
validation is not disabled. Django's sensitive-data filtering is not a reason to expose the page;
filtering is name-based and cannot guarantee secrets stay out of locals or request objects.

Apply the equivalent control to Laravel `APP_DEBUG=false`, Rails `consider_all_requests_local=false`,
ASP.NET Core `UseDeveloperExceptionPage()` only in `IsDevelopment()`, and Spring's error settings.
Test it after deployment by triggering a known exception through an unprivileged client.

## Avoid the fat-controller / anemic-model split

`A06:2025` · ASVS V2, V8, V13

A 300-line controller plus entities that accept arbitrary setters is not merely hard to maintain.
It is hard to audit. Price checks live in one action, ownership in a filter, role transitions in a
callback, and a second JSON action omits one of them. No reviewer can name the enforcement point.

Use thin HTTP adapters, request DTOs, one service method per use case, actor-scoped repositories,
and domain methods for valid state transitions. Do not move everything into ORM callbacks: hidden
execution order is just a different audit problem. The security test should call the same service
from every adapter and assert the invariant once.

Why this works: control placement becomes part of the architecture. A reviewer can answer "where
is this enforced?" with one file and one method, then verify every entry point delegates there.
