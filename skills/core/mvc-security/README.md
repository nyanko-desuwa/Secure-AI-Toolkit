# MVC Security

## Purpose

Any logged-in user changes `/invoices/41` to `/invoices/42` and reads another tenant's invoice.
The authentication middleware worked. It was simply incapable of answering a question about an
object it never loaded.

This skill reviews security by MVC layer. It treats placement as part of the control. The same
check in the controller, template, middleware, and repository is not equivalent.

## How It Works

The skill is plain Markdown. Nothing executes. The entry point maps each control to a layer, then
the supporting files provide framework defaults, sink-specific template rules, review prompts,
and code pairs.

```text
SKILL.md                       workflow, layer map, severity, file index
README.md                      this file
checklist.md                   pre-return verification by layer
best-practices.md              controls with vulnerable/fixed code
common-mistakes.md             tempting wrong fixes and why they fail
troubleshooting.md             framework conflicts and migration choices
prompts.md                     review and implementation prompts
references/
  framework-defaults.md        what is on, opt-in, or off
  template-escaping.md         six engines, raw forms, context rules
examples/
  README.md                    eight vulnerable/fixed pairs
```

## Standards Covered

| Standard | Scope here | Version | Verified |
|---|---|---|---|
| OWASP Top 10 | A01, A02, A05, A06 | 2025 | 2026-07-28 |
| OWASP ASVS | V1, V2, V3, V8, V13 | 5.0.0 | 2026-07-28 |
| CWE | 915, 79, 639, 489 | Current entries | 2026-07-28 |

The skill cites ASVS at chapter level. It does not invent requirement IDs. A formal assessment
must use the official ASVS 5.0 CSV and state a verification level.

## Framework Coverage

| Framework | Code shown for |
|---|---|
| Laravel (PHP) | `$fillable`, FormRequest, Blade, policies, scoped Eloquent queries, CSRF |
| Django (Python) | `ModelForm`, services, repository scoping, debug pages, CSRF |
| Rails (Ruby) | strong parameters, service objects, ERB, routing |
| ASP.NET Core (C#) | `[Bind]`, view models, model validation, Razor, antiforgery |
| Spring MVC (Java) | DTO binding, Thymeleaf, repository scoping, HTTP verbs, method override |

Not every section repeats all five frameworks. [references/framework-defaults.md](references/framework-defaults.md)
provides the comparison when framework differences affect a decision.

## Configuration

None. There is no build step or dependency. The guidance assumes server-rendered MVC or an MVC
application that also exposes JSON endpoints.

To use it, keep this repository readable or copy `skills/core/mvc-security/` to the assistant's
skill directory. The frontmatter restricts tools to file reads and writes, search, web lookup, and
`ls`/`cat`.

Project review does need two pieces of configuration evidence:

1. The exact framework version and production environment settings.
2. The registration of middleware, filters, formatters, and template engines.

A package appearing in a lockfile does not prove its protection is active.

## Example Usage

```text
Review this Laravel update flow for mass assignment. Trace every request field from the
FormRequest through update(), read the model's $fillable/$guarded settings, and report any
privilege-bearing column reachable by the caller. Map findings to A01:2025, ASVS V2/V8, and
CWE-915.
```

```text
Review the Django route, view, service, queryset, ModelForm, and template for this feature.
For every security control, say which MVC layer owns it and whether the current placement can
actually enforce it. Give file:line and an exploitation path for each finding.
```

More in [prompts.md](prompts.md).

## Limitations

- This is guidance, not dataflow analysis. A write spread across a serializer, mapper, event
  listener, and ORM callback needs manual tracing or SAST.
- Framework behavior is version-sensitive. The references state the behavior checked on
  2026-07-28, but a project may pin an older branch or override it.
- Auto-escaping cannot make arbitrary HTML, URLs, CSS, and JavaScript safe. It is context-specific.
  Rich HTML requires a maintained sanitizer and an explicit content policy.
- Repository scoping does not replace policy checks for operations that depend on state, role,
  amount, or relationship beyond ownership.
- `[Bind]`, strong parameters, `$fillable`, and `ModelForm.fields` control assignment. They do not
  validate business invariants or authorize the actor.
- CSRF tokens protect cookie-authenticated state changes. They do not fix XSS, and XSS can often
  read or submit a valid token.
- Examples omit persistence error handling and UI details to keep the security decision visible.
  They are runnable fragments inside their named framework, not complete applications.
- No claim of ASVS compliance or verification level is made.

## Security Notes

Deliberately vulnerable code appears in `best-practices.md`, `common-mistakes.md`, and
`examples/README.md`. Every vulnerable block is labelled and paired with a fixed block. Do not
copy vulnerable blocks into an application.

The strongest review signal is a mismatch between what the code appears to check and what data is
available at that layer. Follow the data, not the annotation name.

## References

- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>
- OWASP ASVS - <https://owasp.org/www-project-application-security-verification-standard/>
- OWASP Mass Assignment Cheat Sheet - <https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html>
- OWASP Cross Site Scripting Prevention Cheat Sheet - <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
- OWASP CSRF Prevention Cheat Sheet - <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html>
- CWE-915 - <https://cwe.mitre.org/data/definitions/915.html>
- CWE-79 - <https://cwe.mitre.org/data/definitions/79.html>
- CWE-639 - <https://cwe.mitre.org/data/definitions/639.html>
- CWE-489 - <https://cwe.mitre.org/data/definitions/489.html>
