# OWASP ASVS 5.0.0 for MVC Security

Version: 5.0.0, released 2025-05-30. Verified 2026-07-28 against
<https://owasp.org/www-project-application-security-verification-standard/>.

This skill cites ASVS by chapter. It does not claim a verification level or invent requirement IDs.
Requirement IDs changed in 5.0; use the official repository/CSV when a precise requirement is needed.

## Relevant chapters

| Chapter | Title | MVC use |
|---|---|---|
| V1 | Encoding and Sanitization | HTML, attribute, URL, JavaScript, CSS, SQL, and raw template sinks |
| V2 | Validation and Business Logic | request DTOs, unknown fields, service invariants, state transitions |
| V3 | Web Frontend Security | CSRF, browser-facing templates, headers and cookie-facing server pages |
| V8 | Authorization | route/function access, actor-scoped queries, object and property authorization |
| V13 | Configuration | debug mode, middleware/filter registration, safe production defaults |

## Applying chapters

- A route review normally needs V8 and V13. Add V3 for browser forms and CSRF.
- A model-binding review needs V2 for the input contract and V8 when fields carry privilege or
  ownership.
- A template review needs V1 for output encoding and V3 for browser execution contexts.
- A repository review needs V1 for raw query construction and V8 for actor/tenant scope.
- A debug/error review needs V13; use V16 as a related chapter when logs and error handling are in
  scope, though this skill's required mapping focuses on V13.

## Verification levels

ASVS describes Level 1 as the baseline, Level 2 for applications handling sensitive data, and Level
3 for applications where failure is severe. This skill does not declare a level. A project must verify
requirements one by one before making an ASVS level claim.

## Source

- OWASP ASVS project - <https://owasp.org/www-project-application-security-verification-standard/>
- OWASP ASVS repository - <https://github.com/OWASP/ASVS>
