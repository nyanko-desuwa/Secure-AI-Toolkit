# Pattern Sources

Primary sources used for the design guidance. Pages were checked 2026-07-28.

## Refactoring.Guru Design Patterns Catalog

<https://refactoring.guru/design-patterns/catalog>

Used for the basic intent vocabulary of Factory Method, Adapter, Decorator, Strategy, Observer,
Facade, and related patterns. The catalog describes patterns as reusable solutions to common design
problems; it does not establish a security boundary. This skill adds the boundary, bypass, and
lifetime review rather than treating the catalog as a recommendation to apply every pattern.

## Python standard library

`functools` - <https://docs.python.org/3/library/functools.html>

Used for the warning that memoization has a size choice and can retain arguments and return values.
An unbounded memoizer is a retained store, not a harmless optimization.

`queue` - <https://docs.python.org/3/library/queue.html>

Used for bounded queue examples. `Queue(maxsize=...)` provides a capacity; callers still need an
explicit timeout and a decision for full behavior.

## Node.js Events

<https://nodejs.org/api/events.html>

Used for listener registration and removal. Removal depends on the same listener function reference;
creating a new equivalent callback does not remove the original. Listener lifetime is an application
responsibility.

## OWASP sources

OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>

Used for A01 Broken Access Control, A05 Injection, A06 Insecure Design, and A10 Mishandling of
Exceptional Conditions. Verified 2026-07-28.

OWASP ASVS - <https://owasp.org/www-project-application-security-verification-standard/>

Version 5.0.0 was released 2025-05-30. This skill cites V8 Authorization, V15 Secure Coding and
Architecture, and V16 Security Logging and Error Handling at chapter level only. Verified 2026-07-28.

## Deliberately not claimed

No pattern source proves a design is secure, compliant, race-free, or leak-free. No CVE, RFC, or
ASVS requirement ID is used. Runtime values such as pool capacity, cache size, and listener count
must be measured in the target deployment.
