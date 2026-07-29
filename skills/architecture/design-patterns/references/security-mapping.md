# Security Mapping for Design Patterns

Mappings verified 2026-07-28 against OWASP Top 10 2025, OWASP ASVS 5.0 project material, and MITRE
CWE entries. Cite only when code demonstrates the mechanism.

## Failure mapping

| Failure | OWASP Top 10 2025 | ASVS 5.0 chapter | CWE |
|---|---|---|---|
| Decorator or repository bypass exposes another tenant | A01 | V8 | CWE-653, CWE-1220 |
| Client-selected privileged strategy is trusted | A01, A06 | V8, V15 | CWE-602 |
| Adapter/repository builds executable SQL from input | A05 | V15 | Cite a verified injection CWE from database review; do not invent one here |
| Pattern boundary is named but concrete path remains public | A06 | V15 | CWE-653 |
| Singleton retains request actor or tenant across work | A01, A06 | V8, V15 | CWE-401 |
| Observer/listener is never removed | A06, A10 | V15, V16 | CWE-401, CWE-772 |
| Memoization/cache has no maximum or TTL | A06 | V15 | CWE-401, CWE-770 |
| Pool lease is not released after failure | A10 | V16 | CWE-772 |
| Pool allocation or waiter queue has no limit | A06 | V15 | CWE-770 |
| Callback failure is swallowed and state advances | A10 | V16 | No forced CWE; cite only a verified specific weakness |

## How to use the map

A pattern itself is not a vulnerability. The finding must name the entry point, the object or
resource, what an unauthorized caller can do or what grows, and the missing control.

Use A01 when data or an operation crosses an authorization boundary. Use A05 when untrusted data
reaches an interpreter or query language. Use A06 when the design makes safe behavior optional or
has no resource policy. Use A10 when exceptional paths leave state, resources, or processing in an
ambiguous condition.

ASVS chapter references are not compliance claims. Requirement identifiers are intentionally omitted
because current chapter content and identifiers can change; consult the official ASVS source for a
formal assessment.

## CWE distinctions

- CWE-401 is memory retained after effective lifetime, including reachable maps, closures, and
  request data held by a singleton or listener.
- CWE-772 is a handle or resource not released after effective lifetime, including leases, sockets,
  cursors, timers, and subscriptions.
- CWE-770 is allocation without a maximum or throttling, including cache cardinality, pool growth,
  and waiter queues.
- CWE-602 is relying on the client to enforce a security decision. A client discriminator may select
  presentation, but it cannot grant server capability.
- CWE-653 is improper compartmentalization. A wrapper or module name is not a compartment if direct
  access to the privileged implementation remains available.
- CWE-1220 is insufficiently granular access control. A generic repository or broad interface can
  grant more data or operation than the caller needs.

## Sources

- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>
- OWASP ASVS - <https://owasp.org/www-project-application-security-verification-standard/>
- CWE-401 - <https://cwe.mitre.org/data/definitions/401.html>
- CWE-602 - <https://cwe.mitre.org/data/definitions/602.html>
- CWE-653 - <https://cwe.mitre.org/data/definitions/653.html>
- CWE-770 - <https://cwe.mitre.org/data/definitions/770.html>
- CWE-772 - <https://cwe.mitre.org/data/definitions/772.html>
- CWE-1220 - <https://cwe.mitre.org/data/definitions/1220.html>
