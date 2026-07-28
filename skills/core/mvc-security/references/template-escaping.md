# Template Escaping by Engine

Verified 2026-07-28 against the official documentation linked below.

Auto-escaping answers one question: how to represent text without creating HTML markup in the
current template mode. It does not validate a URL scheme, quote an unquoted attribute, serialize a
JavaScript program value, sanitize rich HTML, or make attacker-controlled template source safe.

`A05:2025` · ASVS V1, V3 · CWE-79

## Engine comparison

| Engine | Normal escaped output | Raw escape hatch | Context-aware facility | Review note |
|---|---|---|---|---|
| Blade (Laravel) | `{{ $value }}` through `htmlspecialchars` / `e()` | `{!! $value !!}` | `Js::from($value)` for JSON placed in HTML/JavaScript | `{{ }}` is HTML encoding. Do not splice it into quoted JavaScript |
| Twig | `{{ value }}` when autoescape is enabled (common framework integrations enable it) | `{{ value|raw }}`; `{% autoescape false %}` | `|e('html_attr')`, `|e('js')`, `|e('css')`, `|e('url')`; prefer structural helpers over manual escaping | A standalone Twig `Environment` configuration must be checked; `raw` must be last in the filter chain |
| Jinja2 | `{{ value }}` only when the `Environment` has autoescape enabled; Flask/select_autoescape commonly enable HTML/XML templates | `{{ value|safe }}`; `{% autoescape false %}`; `Markup(...)` | `|tojson` for JSON/JavaScript data; quote HTML attributes | Bare Jinja2 does not guarantee autoescape. Verify environment and filename policy |
| ERB (Rails) | `<%= value %>` in Rails output-safe buffers | `<%= raw(value) %>`, `<%= value.html_safe %>`, `<%== value %>` | `json_escape` / `j` for JSON embedded in HTML; Rails tag helpers for attributes | `html_safe` marks trust; it does not sanitize. Concatenation safety depends on string type |
| Razor (ASP.NET Core) | `@Model.Value` HTML-encodes strings | `@Html.Raw(value)`; `HtmlString`/`IHtmlContent` can bypass encoding | Tag Helpers for attributes; `Json.Serialize` or a non-executable JSON data channel for script data | Razor HTML encoding is not JavaScript encoding. Avoid untrusted input in `HtmlString` |
| Thymeleaf | `th:text="${value}"`; escaped inline `[[${value}]]` | `th:utext="${value}"`; unescaped inline `[(${value})]` | Natural template attributes; `th:inline="javascript"` serializes quoted JS expressions | Use `th:text` for user text. `th:utext` needs a sanitizer-owned value |

## HTML body text

The safe pattern is normal escaped interpolation:

```blade
<p>{{ $comment->body }}</p>
```

```twig
<p>{{ comment.body }}</p>
```

```jinja2
<p>{{ comment.body }}</p>
```

```erb
<p><%= @comment.body %></p>
```

```cshtml
<p>@Model.Comment.Body</p>
```

```html
<p th:text="${comment.body}"></p>
```

A payload `<img src=x onerror=alert(1)>` should display as text. If it creates an element, a raw
escape hatch or disabled autoescape is involved.

## HTML attributes

Quote attributes and let the template engine own the whole attribute value.

```twig
<div class="profile" title="{{ user.displayName }}"></div>
```

```html
<div th:title="${user.displayName}"></div>
```

Never do this:

```html
<!-- Vulnerable even if the engine escapes angle brackets: whitespace creates another attribute. -->
<div data-name={{ user.display_name }}></div>
```

A value such as `x onmouseover=alert(1)` can become markup in an unquoted attribute without using
`<` or `>`. Quoting is structural, not optional.

For an attribute name, event handler, element name, or template fragment selected by the user,
encoding is not a sufficient design. Use a fixed server allowlist or do not make it dynamic.

## URLs

HTML attribute escaping does not make a URL safe:

```jinja2
<!-- Vulnerable: javascript:alert(1) can remain a syntactically valid URL. -->
<a href="{{ profile.website }}">Website</a>
```

Parse the URL server-side. Permit only the schemes and host policy the feature needs, usually
`https` and sometimes `http`. For relative navigation, prefer route helpers fed with server-owned
route names and validated parameters.

URL percent-encoding and HTML attribute encoding solve different grammars. Build/query-encode the
URL first with the URL API, then let the template attribute mechanism HTML-encode it.

## JavaScript and JSON inside HTML

This is a context transition: the browser first parses HTML and then JavaScript. HTML escaping
alone is not enough.

Vulnerable Blade:

```blade
<script>const name = '{{ $user->name }}';</script>
```

Fixed Blade:

```blade
<script>const name = {{ Js::from($user->name) }};</script>
```

Fixed Jinja2:

```jinja2
<script>const profile = {{ profile|tojson }};</script>
```

Fixed Thymeleaf:

```html
<script th:inline="javascript">
  const profileName = /*[[${user.displayName}]]*/ "";
</script>
```

For Rails, use a JSON serializer plus `json_escape` when placing serialized JSON in HTML. For
ASP.NET Core, use the documented JSON helper/options and prefer a non-executable data block:

```html
<script id="profile-data" type="application/json">{"name":"...safe serialized JSON..."}</script>
<script src="/js/profile.js"></script>
```

Then parse `textContent` from static code. Do not put untrusted values into event-handler attributes
such as `onclick`, even with a JavaScript escaper. Do not build code with string concatenation.

Check that the helper safely handles the HTML parser terminator `</script>` and HTML-significant
characters. JSON validity by itself does not guarantee safe embedding in an HTML script element.

## CSS

Do not place untrusted data into a `<style>` block or `style` attribute. CSS has its own grammar,
URL-bearing properties, legacy browser behavior, and dangerous layout effects even without script
execution.

If a product needs user-selected colors or sizes, parse into a typed value and map it to a fixed
class or a tightly constrained CSS custom property:

```html
<div class="theme theme-blue"></div>
```

A generic HTML escape does not make `background:url(...)` or `position:fixed` safe.

## Raw HTML features

Raw output is not always wrong. It is correct only when the product intentionally supports a safe
subset of HTML and the value has a trusted provenance.

Use this flow:

1. Define allowed tags, attributes, URL schemes, and link rules.
2. Parse and sanitize with a maintained library.
3. Store the sanitizer-owned representation separately from raw input.
4. Render that representation through the one reviewed raw escape hatch.
5. Test dropped scripts, event handlers, dangerous URLs, SVG/MathML, malformed markup, and nesting.
6. Add CSP as defence in depth, not as the sanitizer.

`html_safe`, `Markup`, `HtmlString`, and similar types are trust markers. They do not clean data.

## Template source is code

Escaping variables does not help if the attacker controls the template itself:

```python
# Vulnerable: user input is compiled as Jinja2 template source.
Template(request.POST["template"]).render(context)
```

Treat template source like code. Select templates by a server-owned identifier or use a sandbox
whose limitations have been threat-modelled. Server-side template injection is A05:2025 and usually
has higher impact than reflected XSS because it may read files or execute server-side functionality.

## Engine notes

### Blade

- Normal `{{ }}` output is escaped.
- `{!! !!}` is raw.
- `Js::from` returns a JSON parse expression escaped for inclusion within HTML quotes according to
  Laravel's Blade documentation.
- `@php` and PHP echo statements bypass the normal template review surface.

Source: <https://laravel.com/docs/12.x/blade>

### Twig

- Autoescape strategy is configured on the `Environment`; Symfony integrations commonly choose it
  by template filename.
- `raw` disables escaping for that expression and must be last in the filter chain.
- The `escape` filter supports explicit contexts including `html`, `html_attr`, `js`, `css`, and
  `url`.
- An `{% autoescape %}` block does not change included templates' own escaping decision.

Sources: <https://twig.symfony.com/doc/3.x/api.html>,
<https://twig.symfony.com/doc/3.x/filters/escape.html>,
<https://twig.symfony.com/doc/3.x/filters/raw.html>

### Jinja2

- Autoescaping is an `Environment` option and should be selected explicitly, commonly with
  `select_autoescape` for `.html`, `.htm`, and `.xml`.
- `safe` / `Markup` opts a value out.
- `tojson` serializes data and marks it safe for HTML documents and script tags, with documented
  caveats in double-quoted attributes.

Sources: <https://jinja.palletsprojects.com/en/stable/api/>,
<https://jinja.palletsprojects.com/en/stable/templates/#jinja-filters.tojson>

### ERB in Rails

- Rails' output buffer escapes ordinary `<%= %>` expressions.
- `raw`, `html_safe`, and `<%== %>` bypass output escaping.
- `json_escape` escapes JSON-significant HTML characters for safe HTML embedding but the result's
  safety marking depends on the calling pattern; follow the API example.

Sources: <https://guides.rubyonrails.org/action_view_overview.html#output-safety>,
<https://api.rubyonrails.org/classes/ERB/Util.html>

### Razor

- Ordinary string expressions are HTML-encoded.
- `Html.Raw` and `IHtmlContent` bypass normal string encoding.
- Microsoft warns not to use `HtmlString` with untrusted input.
- Tag Helpers generate quoted attributes but do not validate dangerous URL schemes or arbitrary JS.

Sources: <https://learn.microsoft.com/en-us/aspnet/core/mvc/views/razor>,
<https://learn.microsoft.com/en-us/aspnet/core/security/cross-site-scripting>

### Thymeleaf

- `th:text` is escaped; `th:utext` is unescaped.
- Escaped inlining uses `[[...]]`; unescaped inlining uses `[(...)]`.
- JavaScript inlining serializes strings, numbers, booleans, arrays, collections, maps, and beans.

Source: <https://www.thymeleaf.org/doc/tutorials/3.1/usingthymeleaf.html>

## Test payloads by context

Use inert test endpoints and a controlled browser. Do not use a single `<script>` payload for every
context.

| Context | Probe | Secure result |
|---|---|---|
| HTML text | `<img src=x onerror=alert(1)>` | Visible text, no element |
| Quoted attribute | `" autofocus onfocus="alert(1)` | Remains within one quoted value |
| Unquoted attribute | `x onmouseover=alert(1)` | Design rejected or attribute quoted |
| URL attribute | `javascript:alert(1)` | Scheme rejected or neutralized by URL policy |
| JavaScript string | `';alert(1);//` | JSON string value, no code execution |
| Script element | `</script><img src=x onerror=alert(1)>` | Terminator escaped/serialized; one script node remains |
| Rich HTML | `<svg><a onload=alert(1)>x</a></svg>` | Active element/attribute removed by sanitizer policy |

Tests prove the selected engine and configuration. A reference table cannot.
