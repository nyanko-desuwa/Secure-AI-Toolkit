# MVC Security Examples

Eight vulnerable/fixed pairs. Each example names the layer that cannot enforce the apparent control.
Code assumes the standard project setup for the named framework.

## Contents

- [Laravel mass assignment privilege escalation](#laravel-mass-assignment-privilege-escalation) - A01/A06, CWE-915
- [Django ModelForm exclude exposes a new privilege field](#django-modelform-exclude-exposes-a-new-privilege-field) - A01/A06, CWE-915
- [ASP.NET Core entity binding overposts approval](#aspnet-core-entity-binding-overposts-approval) - A01/A06, CWE-915
- [Controller middleware misses invoice ownership](#controller-middleware-misses-invoice-ownership) - A01, CWE-639
- [Blade raw output stores XSS](#blade-raw-output-stores-xss) - A05, CWE-79
- [Spring MVC trusts a browser-computed price](#spring-mvc-trusts-a-browser-computed-price) - A06
- [Rails wildcard route exposes a destructive action](#rails-wildcard-route-exposes-a-destructive-action) - A01/A02, CWE-639
- [Django debug page left on](#django-debug-page-left-on) - A02, CWE-489

---

## Laravel mass assignment privilege escalation

`A01:2025` · `A06:2025` · ASVS V2, V8 · `CWE-915`

The registration form renders three fields. The attacker adds a fourth; the model accepts every
column.

Vulnerable:

```php
final class User extends Authenticatable
{
    protected $guarded = [];

    protected $casts = ['is_admin' => 'boolean'];
}

final class RegistrationController extends Controller
{
    public function store(Request $request): RedirectResponse
    {
        $user = User::create($request->all());
        Auth::login($user);
        return redirect('/dashboard');
    }
}
```

Attack:

```http
POST /register HTTP/1.1
Content-Type: application/x-www-form-urlencoded

name=Mallory&email=mallory%40example.test&password=correct-horse&is_admin=1
```

`is_admin` is cast correctly and persisted as true. Validation of the visible fields would not stop
it if the controller still passes `$request->all()`.

Fixed:

```php
final class RegisterRequest extends FormRequest
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
    protected $hidden = ['password'];
    protected $casts = ['is_admin' => 'boolean'];
}

public function store(RegisterRequest $request): RedirectResponse
{
    $data = $request->validated();
    $user = User::create([
        'name' => $data['name'],
        'email' => $data['email'],
        'password' => Hash::make($data['password']),
        'is_admin' => false,
    ]);
    Auth::login($user);
    return redirect('/dashboard');
}
```

Why this works: `is_admin` is absent from both allowlists and assigned from server policy. The
wrong fix is `$guarded = ['is_admin']`: adding `role_id`, `tenant_id`, or `can_refund` later silently
exposes it.

---

## Django ModelForm exclude exposes a new privilege field

`A01:2025` · `A06:2025` · ASVS V2, V8 · `CWE-915`

A form denylist was safe when written. A migration later adds `can_issue_refunds`; it becomes
request-writable without touching the form.

Vulnerable:

```python
# models.py
class StaffProfile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    display_name = models.CharField(max_length=80)
    timezone = models.CharField(max_length=40)
    can_issue_refunds = models.BooleanField(default=False)

# forms.py
class StaffProfileForm(forms.ModelForm):
    class Meta:
        model = StaffProfile
        exclude = ("user",)

# views.py
@login_required
def edit_profile(request: HttpRequest) -> HttpResponse:
    form = StaffProfileForm(request.POST or None, instance=request.user.staffprofile)
    if request.method == "POST" and form.is_valid():
        form.save()
        return redirect("profile")
    return render(request, "accounts/edit_profile.html", {"form": form})
```

Attack:

```http
POST /profile/edit HTTP/1.1
Content-Type: application/x-www-form-urlencoded

user=7&display_name=Mallory&timezone=UTC&can_issue_refunds=on
```

The browser need not render the field. ModelForm binds submitted model fields regardless of what a
custom template chose to display.

Fixed:

```python
class StaffProfileForm(forms.ModelForm):
    class Meta:
        model = StaffProfile
        fields = ("display_name", "timezone")
```

Why this works: a new model field stays excluded until explicitly added. `editable=False` on the
privilege field is useful defence in depth for every ModelForm, but explicit `fields` keeps the
form's write contract reviewable.

---

## ASP.NET Core entity binding overposts approval

`A01:2025` · `A06:2025` · ASVS V2, V8 · `CWE-915`

Model validation works exactly as configured. It validates an attacker-supplied property that
should never have been in the input model.

Vulnerable:

```csharp
public sealed class Expense
{
    public int Id { get; set; }
    [Required, StringLength(120)] public string Description { get; set; } = "";
    [Range(0.01, 10000)] public decimal Amount { get; set; }
    public string OwnerId { get; set; } = "";
    public bool IsApproved { get; set; }
}

[HttpPost]
[ValidateAntiForgeryToken]
public async Task<IActionResult> Create(Expense expense)
{
    if (!ModelState.IsValid) return View(expense);
    expense.OwnerId = _userManager.GetUserId(User)!;
    _db.Add(expense);
    await _db.SaveChangesAsync();
    return RedirectToAction(nameof(Index));
}
```

Attack:

```http
POST /Expenses/Create HTTP/1.1
Content-Type: application/x-www-form-urlencoded

Description=Flight&Amount=9999&IsApproved=true&__RequestVerificationToken=VALID_TOKEN
```

CSRF is valid because the attacker is the logged-in user. CSRF does not authorize fields.

Fixed:

```csharp
public sealed record CreateExpenseInput(
    [property: Required, StringLength(120)] string Description,
    [property: Range(typeof(decimal), "0.01", "10000")] decimal Amount);

[HttpPost]
[ValidateAntiForgeryToken]
public async Task<IActionResult> Create(CreateExpenseInput input)
{
    if (!ModelState.IsValid) return View(input);

    await _expenseService.CreateAsync(
        ownerId: _userManager.GetUserId(User)!,
        description: input.Description,
        amount: input.Amount);
    return RedirectToAction(nameof(Index));
}

public async Task CreateAsync(string ownerId, string description, decimal amount)
{
    _db.Expenses.Add(new Expense {
        OwnerId = ownerId,
        Description = description,
        Amount = amount,
        IsApproved = false
    });
    await _db.SaveChangesAsync();
}
```

Why this works: the binder has nowhere to put `IsApproved`. `[Bind("Description,Amount")]` would
allowlist those properties, but a dedicated input type remains safe when the entity grows and
avoids edit-time field clearing.

---

## Controller middleware misses invoice ownership

`A01:2025` · ASVS V8 · `CWE-639`

The route has authentication and a role guard. Both pass for every normal customer, so neither can
answer which invoice belongs to the customer.

Vulnerable:

```java
@Configuration
class WebConfig implements WebMvcConfigurer {
    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new CustomerGuard())
            .addPathPatterns("/invoices/**");
    }
}

@Controller
class InvoiceController {
    private final InvoiceRepository invoices;

    @GetMapping("/invoices/{id}")
    String show(@PathVariable long id, Model model) {
        model.addAttribute("invoice", invoices.findById(id).orElseThrow());
        return "invoice/show";
    }
}
```

Attack: Alice, a valid customer, changes `/invoices/41` to `/invoices/42` and reads Bob's invoice.
The interceptor sees the path and authenticated role, not the loaded invoice.

Fixed:

```java
interface InvoiceRepository extends JpaRepository<Invoice, Long> {
    Optional<Invoice> findByIdAndCustomerEmail(long id, String customerEmail);
}

@Controller
class InvoiceController {
    private final InvoiceRepository invoices;

    @GetMapping("/invoices/{id}")
    String show(@PathVariable long id, Principal principal, Model model) {
        Invoice invoice = invoices.findByIdAndCustomerEmail(id, principal.getName())
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        model.addAttribute("invoice", invoice);
        return "invoice/show";
    }
}
```

Why this works: actor and target ID are predicates in one query. The guard still belongs on the
route for authentication/coarse role access; it is not credited as object authorization. A UUID ID
would only obscure the missing predicate.

---

## Blade raw output stores XSS

`A05:2025` · ASVS V1, V3 · `CWE-79`

A profile bio is stored, then rendered raw on every account page.

Vulnerable:

```blade
<article class="profile-bio">
    {!! $user->bio !!}
</article>
```

Attack value:

```html
<img src=x onerror="fetch('/settings/email',{method:'POST',body:'email=attacker@example.test'})">
```

The exact forged request may still need a CSRF token, but XSS runs as the victim and can often read
one from the page or invoke same-origin application behavior. XSS and CSRF protections are not
substitutes.

Fixed for a plain-text bio:

```blade
<article class="profile-bio">
    {{ $user->bio }}
</article>
```

Fixed for intentional rich HTML:

```php
$cleanHtml = $htmlSanitizer->sanitize($request->validated('bio_html'));
$user->update(['sanitized_bio_html' => $cleanHtml]);
```

```blade
{{-- Raw only for the sanitizer-owned representation. --}}
<article class="profile-bio">{!! $user->sanitized_bio_html !!}</article>
```

Why this works: normal interpolation invokes Blade's HTML encoding for plain text. The rich variant
uses a parser-based allowlist before the explicit raw sink. The sanitizer must be maintained;
`strip_tags`, a regex, or "admins only" is not a complete fix.

---

## Spring MVC trusts a browser-computed price

`A06:2025` · ASVS V2

The page constrains quantity and stores the displayed price in a hidden field. The controller treats
both as authoritative business data.

Vulnerable:

```html
<form th:action="@{/orders}" method="post">
  <input type="hidden" name="productId" th:value="${product.id}">
  <input type="hidden" name="unitPrice" th:value="${product.price}">
  <input type="number" name="quantity" min="1" max="5" value="1">
  <button type="submit">Buy</button>
</form>
```

```java
public record OrderForm(long productId, BigDecimal unitPrice, int quantity) {}

@PostMapping("/orders")
String create(@ModelAttribute OrderForm form, Principal principal) {
    orderRepository.save(new Order(
        principal.getName(), form.productId(), form.unitPrice(), form.quantity()));
    return "redirect:/orders";
}
```

Attack:

```http
POST /orders HTTP/1.1
Content-Type: application/x-www-form-urlencoded

productId=17&unitPrice=0.01&quantity=1000&_csrf=VALID_TOKEN
```

Fixed:

```java
public record OrderForm(long productId, @Min(1) @Max(5) int quantity) {}

@PostMapping("/orders")
String create(@Valid @ModelAttribute OrderForm form,
              BindingResult errors,
              Principal principal) {
    if (errors.hasErrors()) return "orders/new";
    checkout.placeOrder(principal.getName(), form.productId(), form.quantity());
    return "redirect:/orders";
}

@Transactional
public void placeOrder(String actorEmail, long productId, int quantity) {
    Product product = products.findByIdForUpdate(productId).orElseThrow();
    if (quantity < 1 || quantity > 5) throw new InvalidQuantityException();
    orders.save(Order.create(actorEmail, product, quantity, product.getPrice()));
}
```

Why this works: client validation remains useful UX, but price and range are enforced server-side
inside the use-case transaction. A hidden field is not more trusted than a visible one.

---

## Rails wildcard route exposes a destructive action

`A01:2025` · `A02:2025` · ASVS V8, V13 · `CWE-639`

A maintenance method was written as a public controller action. A legacy catch-all turns it into an
internet endpoint accepting every verb.

Vulnerable:

```ruby
# config/routes.rb
match ':controller(/:action(/:id))', via: :all

class ReportsController < ApplicationController
  def purge
    Report.where(created_at: ...90.days.ago).delete_all
    redirect_to reports_path
  end
end
```

Attack:

```http
GET /reports/purge HTTP/1.1
```

A link previewer or cross-origin image can trigger the GET. If an application-wide role guard is
absent or coarse, ordinary users may trigger it too.

Fixed:

```ruby
# config/routes.rb
resources :reports, only: %i[index show] do
  delete :purge, on: :collection
end

class ReportsController < ApplicationController
  before_action :require_report_admin!, only: :purge

  def purge
    ReportRetention.purge_expired!(actor: current_user)
    redirect_to reports_path
  end
end
```

Why this works: a new public method is no longer exposed implicitly. The destructive action has one
unsafe verb, follows the framework CSRF path, and delegates policy/business logic. An action-name
denylist on the catch-all leaves the next method exposed.

---

## Django debug page left on

`A02:2025` · ASVS V13 · `CWE-489`

Production inherits development settings. An unauthenticated request triggers a database exception.

Vulnerable:

```python
# settings/base.py
DEBUG = True
ALLOWED_HOSTS = ["*"]

# views.py
def debug_order(request: HttpRequest) -> HttpResponse:
    order = Order.objects.get(pk=request.GET["id"])
    raise RuntimeError(f"failed to render order {order.pk}")
```

The technical 500 page can expose the full traceback, frame local variables, request attributes,
paths, settings names, and query context. Name-based secret filtering cannot guarantee arbitrary
locals and objects are clean.

Fixed:

```python
# settings/production.py
DEBUG = False
ALLOWED_HOSTS = [h for h in os.environ["ALLOWED_HOSTS"].split(",") if h]
if not ALLOWED_HOSTS:
    raise RuntimeError("ALLOWED_HOSTS must be configured")

# views.py
logger = logging.getLogger(__name__)

def order_detail(request: HttpRequest, order_id: int) -> HttpResponse:
    try:
        order = OrderRepository.get_visible(actor=request.user, order_id=order_id)
        return render(request, "orders/detail.html", {"order": order})
    except OrderRenderError:
        incident_id = uuid.uuid4()
        logger.exception("order_render_failed", extra={"incident_id": str(incident_id)})
        return render(request, "500.html", {"incident_id": incident_id}, status=500)
```

Deployment regression test:

```python
def test_production_errors_do_not_disclose_traceback(client, settings, monkeypatch):
    settings.DEBUG = False
    monkeypatch.setattr(
        "orders.views.OrderRepository.get_visible",
        lambda **kwargs: (_ for _ in ()).throw(OrderRenderError()),
    )
    response = client.get("/orders/41")
    body = response.content.decode()
    assert response.status_code == 500
    assert "Traceback" not in body
    assert "orders/views.py" not in body
```

Why this works: production selects the generic error path, details stay in protected logs under a
correlation ID, and a runtime-style test verifies the response. Merely setting `DEBUG=False` in a
sample `.env` does not prove deployment used it.

---

## Sources

- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>
- OWASP ASVS 5.0 - <https://owasp.org/www-project-application-security-verification-standard/>
- CWE-915 - <https://cwe.mitre.org/data/definitions/915.html>
- CWE-79 - <https://cwe.mitre.org/data/definitions/79.html>
- CWE-639 - <https://cwe.mitre.org/data/definitions/639.html>
- CWE-489 - <https://cwe.mitre.org/data/definitions/489.html>
