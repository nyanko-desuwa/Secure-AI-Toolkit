# OWASP Top 10 (2025) for MVC Security

Version: 2025. Verified 2026-07-28 against <https://owasp.org/Top10/2025/>.

The 2025 edition is not a renumbering of 2021. Injection is A05, Security Misconfiguration is A02,
and Insecure Design is A06.

## Categories used by this skill

| Category | MVC question | Typical finding here |
|---|---|---|
| A01 Broken Access Control | Does every route, action, field, and object operation enforce what this actor may do? | global lookup by route ID, client-writable role/tenant, missing CSRF, unintended action exposure |
| A02 Security Misconfiguration | Which framework features are reachable or verbose in production? | debug page, wildcard route, unnecessary method override, disabled security middleware |
| A05 Injection | Can data become syntax in SQL, HTML, JavaScript, CSS, a URL, or template source? | raw template output, wrong-context escaping, raw ORM query interpolation |
| A06 Insecure Design | Is a business rule enforceable by the server at one unavoidable use-case boundary? | client-only validation, browser-computed price, scattered controller logic, assignment denylist |

## Mapping principles

- Mass assignment of a privilege field is A01 because it changes what the actor is authorized to do,
  and A06 when the writable-contract design fails open. Attach CWE-915.
- An object ID used without actor scope is A01. Attach CWE-639.
- Raw template output and wrong-context encoding are A05. Attach CWE-79.
- A framework debug page in production is A02. Attach CWE-489.
- A fat controller or anemic domain model without a demonstrated bypass is an A06 design concern,
  not automatically a vulnerability. Report the concrete omitted or inconsistent rule when one
  exists.
- CSRF on a cookie-authenticated state change is A01 because the server accepts an action the actor
  did not intend. ASVS V3 and V8 provide the verification lens.

## What not to cite

Do not cite A03 merely because a framework dependency exists. Do not cite A05 for ordinary ORM use
that remains parameterized. Do not cite A01 for a hidden button unless the server action also lacks
authorization. Categories describe demonstrated risk, not keywords.

## Source

- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>
