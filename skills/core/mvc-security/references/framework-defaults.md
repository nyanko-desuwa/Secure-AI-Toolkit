# Framework Defaults for MVC Security

Verified 2026-07-28 against the official framework documentation linked in each row. Defaults are
version-sensitive. "On" means the common framework path provides it; it does not prove this
application retained the middleware or did not use an escape hatch.

| Framework | Protection | On by default | Opt-in / application choice | Off or unsafe by default | Evidence |
|---|---|---|---|---|---|
| Laravel 12.x | Eloquent mass-assignment guard | Model assignment is guarded by `$fillable` / `$guarded` policy | Define a narrow `$fillable`; request code must use `validated()` | `$guarded = []` disables the model guard for request-backed assignment | [Eloquent mass assignment](https://laravel.com/docs/12.x/eloquent#mass-assignment) |
| Laravel 12.x | FormRequest validation | FormRequest runs rules when injected | Use `validated()` / `safe()` and explicit rules | `$request->all()` includes unvalidated keys | [Validation](https://laravel.com/docs/12.x/validation) |
| Laravel 12.x | Blade HTML escaping | `{{ }}` escapes; `e()` escapes | `Js::from()` for JSON in HTML script context; sanitizer for rich HTML | `{!! !!}` raw output; `@php` can bypass templates | [Blade](https://laravel.com/docs/12.x/blade) |
| Laravel 12.x | CSRF | `web` middleware group includes CSRF protection in the standard application setup | Include `@csrf`; confirm `web` group and exceptions | `api` routes do not get browser session CSRF automatically; `withoutMiddleware` / exemptions bypass | [CSRF](https://laravel.com/docs/12.x/csrf) |
| Laravel 12.x | Debug errors | Production convention is `APP_DEBUG=false` | Configure server-side logging and a correlation ID | `APP_DEBUG=true` exposes Ignition details; historical Laravel Ignition CVE-2021-3129 required debug exposure | [Configuration](https://laravel.com/docs/12.x/configuration), [CVE-2021-3129](https://nvd.nist.gov/vuln/detail/CVE-2021-3129) |
| Django 5.2 | ModelForm assignment | `ModelForm` uses fields chosen by `Meta.fields` / `exclude` | Explicit `fields` tuple; model field `editable=False` stays excluded | `exclude` and `fields="__all__"` are blocklist/broad approaches and can expose newly added fields | [Selecting ModelForm fields](https://docs.djangoproject.com/en/5.2/topics/forms/modelforms/#selecting-the-fields-to-use) |
| Django 5.2 | CSRF | `CsrfViewMiddleware` is in the generated middleware settings; `{% csrf_token %}` in forms | Keep middleware and token on unsafe forms | `@csrf_exempt` bypasses; forgetting the token causes rejection, not silent protection | [CSRF](https://docs.djangoproject.com/en/5.2/howto/csrf/) |
| Django 5.2 | Template escaping | Django templates autoescape by default | `{% autoescape on %}`; `format_html` / safe sanitizer for reviewed HTML | `|safe`, `mark_safe`, and `{% autoescape off %}` bypass; bare Jinja2 is not Django templates | [Built-in tags and filters](https://docs.djangoproject.com/en/5.2/ref/templates/builtins/) |
| Django 5.2 | Debug errors | `DEBUG=False` is the production setting | `sensitive_variables` and `sensitive_post_parameters` filter selected reports | `DEBUG=True` displays traceback frames, local variables, request details, and more; filter is not a reason to expose it | [Error reporting](https://docs.djangoproject.com/en/5.2/howto/error-reporting/), [DEBUG](https://docs.djangoproject.com/en/5.2/ref/settings/#debug) |
| Rails 8.1 | Strong parameters | `ActionController::Parameters` blocks raw params from Active Model mass assignment | `expect` / `require(...).permit(...)` explicit keys | `permit!`, `to_unsafe_h`, and broad nested permits; unpermitted handling must be checked in project config | [Strong Parameters](https://api.rubyonrails.org/classes/ActionController/StrongParameters.html) |
| Rails 8.1 | ERB escaping | `<%= %>` HTML-escapes in Rails ERB output | `json_escape` for JSON embedded in HTML; sanitizer for trusted rich HTML | `raw`, `html_safe`, `<%== %>` bypass HTML escaping | [ERB output](https://guides.rubyonrails.org/action_view_overview.html#output-safety), [XSS API](https://api.rubyonrails.org/classes/ERB/Util.html) |
| Rails 8.1 | CSRF | `protect_from_forgery` is in the standard ApplicationController generated setup | Form helpers emit authenticity tokens; verify controller inheritance and config | `skip_forgery_protection` or `protect_from_forgery with: :null_session` changes behavior; APIs may intentionally differ | [Security guide](https://guides.rubyonrails.org/security.html#cross-site-request-forgery-csrf) |
| ASP.NET Core 9 | Model binding | Binding and DataAnnotations validation exist; controllers are not automatically protected against overposting | Dedicated view/input model; `[Bind]` allowlist for narrow cases; check `ModelState.IsValid` | Binding domain entities accepts all bindable fields; `[ValidateAntiForgeryToken]` is not automatic for MVC controllers | [Model binding](https://learn.microsoft.com/en-us/aspnet/core/mvc/models/model-binding), [Overposting](https://learn.microsoft.com/en-us/aspnet/core/data/ef-mvc/crud#security-note-about-overposting) |
| ASP.NET Core 9 | Razor encoding | Razor expressions HTML-encode by default | `Json.Serialize` / safe JSON data channel; sanitizer for rich HTML | `Html.Raw` disables encoding; HTML encoding is not JS, CSS, or URL validation | [Razor syntax](https://learn.microsoft.com/en-us/aspnet/core/mvc/views/razor), [XSS](https://learn.microsoft.com/en-us/aspnet/core/security/cross-site-scripting) |
| ASP.NET Core 9 | MVC CSRF | Razor Pages are automatically protected; MVC controllers need a filter | `AutoValidateAntiforgeryToken` globally or `[ValidateAntiForgeryToken]`; form tag helper emits token for qualifying POST forms | `AddControllers` does not enable built-in antiforgery token support; `IgnoreAntiforgeryToken` and `asp-antiforgery="false"` bypass | [Antiforgery](https://learn.microsoft.com/en-us/aspnet/core/security/anti-request-forgery?view=aspnetcore-9.0) |
| Spring Boot 3.x / Spring MVC | DTO validation | `@Valid` / `@Validated` works when placed on the binding parameter and validator is configured | Bind request DTOs; configure Jackson unknown-property handling for command DTOs | Binding a JPA entity exposes writable properties; common Jackson config ignores unknown JSON properties unless strictness is enabled | [Validation](https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-controller/ann-validation.html), [Jackson Boot properties](https://docs.spring.io/spring-boot/appendix/application-properties/index.html) |
| Spring Boot 3.x / Thymeleaf | Template escaping | `th:text` escapes; standard Thymeleaf HTML mode escapes text and ordinary attributes | `th:inline="javascript"` for JavaScript serialization; sanitizer for HTML | `th:utext` renders unescaped; JavaScript string concatenation remains context-sensitive | [Thymeleaf tutorial](https://www.thymeleaf.org/doc/tutorials/3.1/usingthymeleaf.html) |
| Spring Boot 3.x / Spring Security | CSRF | Spring Security CSRF is enabled by default for typical browser security configuration | Include token in form/header; configure repository and matcher intentionally | Disabling CSRF on a cookie-authenticated browser app removes the control; stateless bearer APIs need a separate assessment | [Spring Security CSRF](https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html) |
| Spring Boot 3.x / Spring MVC | Hidden method override | `spring.mvc.hiddenmethod.filter.enabled=false` in modern Spring Boot | Enable only for HTML forms that need `_method` | Method tunnelling is off in modern Boot; if enabled, authorize the effective verb and keep CSRF | [Spring Boot properties](https://docs.spring.io/spring-boot/appendix/application-properties/index.html) |

## What this table does not prove

- A generated application may have removed standard middleware.
- A route may use a different template engine or a raw response writer.
- An ORM query may use a raw escape hatch.
- A model guard may be bypassed by bulk SQL, an import, a job, or an admin tool.
- An error page may be supplied by a reverse proxy or a dependency rather than the framework.

Read the application registration and run a negative test. Defaults are a starting hypothesis, not a
security review.

## Standard mapping

- A01:2025 / ASVS V8: actor-scoped queries, assignment authorization, CSRF, routes and verbs
- A02:2025 / ASVS V13: debug pages, framework configuration, middleware registration
- A05:2025 / ASVS V1, V3: template escaping, raw output, ORM raw queries
- A06:2025 / ASVS V2: business rules, DTO boundaries, unknown fields, service placement
- CWE-915: model binding and mass assignment
- CWE-79: raw template output and context confusion
- CWE-639: object access selected by an attacker-controlled key
- CWE-489: debug code or debug mode left active
