# ASVS 5.0.0 - V4 API and Web Service

Version: OWASP Application Security Verification Standard 5.0.0, released May 2025.
Source: <https://github.com/OWASP/ASVS> - `5.0/en/0x13-V4-API-and-Web-Service.md`
Verified: 2026-07-28, requirement text and level numbers read from that file.

Requirement IDs are not stable across ASVS major versions. A `V4.x` citation from a 4.0.3
report means something different. Re-map, do not assume.

## What this chapter covers, and what it does not

V4 is narrower than "API security". It covers web service hygiene, HTTP message structure,
GraphQL, and WebSocket. Authentication (V6), session management (V7), authorization (V8),
validation (V2), and encoding (V1) apply to APIs too and live elsewhere. The chapter says so
directly: it cannot be tested in isolation.

That means most API1/API3/API5 findings cite V8, not V4. Reach for V4 when the finding is
about the protocol surface itself.

## V4.1 Generic Web Service Security

| ID | L | Requirement, condensed |
|---|---|---|
| 4.1.1 | 1 | Every response with a body has a `Content-Type` matching the actual content, including the charset parameter, per IANA media types |
| 4.1.2 | 2 | Only user-facing endpoints auto-redirect HTTP to HTTPS. Other services must not, so a client mistakenly sending cleartext is discovered rather than silently fixed |
| 4.1.3 | 2 | Header fields set by an intermediary - load balancer, proxy, BFF - cannot be overridden by the end user. Examples given: `X-Real-IP`, `X-Forwarded-*`, `X-User-ID` |
| 4.1.4 | 3 | Only HTTP methods the application explicitly supports (including `OPTIONS` for preflight) are usable; unused methods are blocked |
| 4.1.5 | 3 | Per-message digital signatures on highly sensitive requests, or ones traversing several systems, on top of transport protection |

4.1.3 is the one that surprises people. If the app reads `X-Forwarded-For` for rate limiting or
`X-User-ID` from a gateway, and the edge does not strip a client-supplied copy, the attacker
sets their own. That is how per-IP rate limits get bypassed and how gateway-injected identity
becomes an authentication bypass.

4.1.2 reads backwards until you think about it. A blanket HTTP-to-HTTPS redirect on an API is a
convenience that hides a client shipping bearer tokens in cleartext - the token is already
disclosed by the time the redirect arrives.

4.1.4 is the ASVS anchor for API5 by-verb attacks: blocking unused methods means a `DELETE`
against a read-only route never reaches a handler.

## V4.2 HTTP Message Structure Validation

Aimed at request smuggling, response splitting, header injection, and DoS via oversized
messages. Most important when HTTP messages are converted between versions - an HTTP/2 edge in
front of an HTTP/1.1 origin.

| ID | L | Requirement, condensed |
|---|---|---|
| 4.2.1 | 2 | All components - load balancers, firewalls, app servers - determine message boundaries using the mechanism correct for the HTTP version. In HTTP/1.x, `Transfer-Encoding` present means `Content-Length` is ignored. In HTTP/2 and /3, a present `Content-Length` must be consistent with the DATA frame length |
| 4.2.2 | 3 | When generating messages, `Content-Length` does not conflict with the length implied by the protocol framing |
| 4.2.3 | 3 | Neither send nor accept HTTP/2 or /3 messages with connection-specific header fields such as `Transfer-Encoding` |
| 4.2.4 | 3 | Only accept HTTP/2 and /3 requests whose header fields and values contain no CR, LF, or CRLF sequences |
| 4.2.5 | 3 | If the application builds and sends requests, it validates or sanitizes to avoid creating URIs or header fields too long for the receiving component - an oversized cookie header that makes the server always error is a denial of service |

These are mostly infrastructure requirements, not code ones. If the answer is "the CDN handles
it", verify the CDN version and configuration rather than assuming; 4.2.1 fails when two hops
disagree, and each hop individually looks correct.

## V4.3 GraphQL

Two requirements, both Level 2.

| ID | L | Requirement, condensed |
|---|---|---|
| 4.3.1 | 2 | A query allowlist, depth limiting, amount limiting, or query cost analysis prevents GraphQL or data-layer expression DoS from expensive nested queries |
| 4.3.2 | 2 | Introspection is disabled in production unless the API is meant for other parties |

4.3.1 offers four alternatives, not a stack. A persisted-query allowlist is the strongest - the
server executes only documents it already knows - and it is the one that breaks ad-hoc clients.
Depth plus complexity limits are the usual compromise. Note "amount limiting": a query one level
deep asking for 100,000 items is not caught by a depth limit.

4.3.2 is conditional. A public partner API legitimately keeps introspection on. Disabling it
also does not hide the schema - field names are recoverable from error messages and suggestion
hints. Treat it as raising cost, not as a control.

GraphQL field-level authorization has no requirement in V4. It lives in V8 - 8.2.3 for
field-level access. The chapter's references point to graphql.org and Apollo for authorization
guidance rather than restating it.

## V4.4 WebSocket

| ID | L | Requirement, condensed |
|---|---|---|
| 4.4.1 | 1 | WSS (WebSocket over TLS) for all connections |
| 4.4.2 | 2 | During the initial HTTP handshake, the `Origin` header field is checked against an allowed origin list |
| 4.4.3 | 2 | Where standard session management cannot be used, dedicated tokens are used and comply with the session management requirements |
| 4.4.4 | 2 | Dedicated WebSocket session tokens are obtained or validated through the already-authenticated HTTPS session when upgrading |

4.4.2 exists because WebSocket handshakes are not covered by the same-origin policy and
browsers do not send preflights for them. Without an `Origin` check, any site can open an
authenticated socket in the victim's browser - cross-site WebSocket hijacking.

## Chapters to cite alongside V4

Verified IDs only. Where no ID is listed, cite the chapter.

| Concern | Chapter | Verified IDs |
|---|---|---|
| Object level authorization (API1) | V8 Authorization | 8.2.2, 8.3.1, 8.4.1 |
| Property/field level authorization (API3) | V8 | 8.1.2, 8.2.3 |
| Function level authorization (API5) | V8 | 8.2.1, 8.4.2 |
| Authorization documentation | V8 | 8.1.1, 8.1.3, 8.1.4 |
| Immediate effect of permission change | V8 | 8.3.2 |
| Downstream calls use the originating subject's permissions | V8 | 8.3.3 |
| Authentication (API2) | V6 Authentication | - |
| Session lifecycle | V7 Session Management | - |
| JWT and self-contained tokens | V9 Self-contained Tokens | - |
| OAuth and OIDC flows | V10 OAuth and OIDC | - |
| Input validation, business logic (API4, API10) | V2 Validation and Business Logic | - |
| Encoding at the sink (API10 downstream) | V1 Encoding and Sanitization | - |
| Upload handling (API4 size caps) | V5 File Handling | - |
| TLS, certificate validation (API8, API10) | V12 Secure Communication | - |
| Environment and secret configuration (API8) | V13 Configuration | - |
| Logging, fail-closed error handling | V16 Security Logging and Error Handling | - |

Three from V8 are worth reading in full because they shape API design rather than a single
check:

- 8.3.1 (L1) - rules enforced at a trusted service layer, not in anything an untrusted consumer
  controls. This is why a client-side role check is not a control.
- 8.3.2 (L3) - authorization-relevant changes apply immediately. Where they cannot, because the
  decision data lives in a self-contained token, there must be a compensating control that
  alerts on and reverts an action taken after the permission was removed. ASVS notes the
  alternative does not mitigate information leakage.
- 8.3.3 (L3) - an object access is decided by the originating subject's permissions, not by an
  intermediary's. Service B decides using the consumer's token, not a machine-to-machine token
  from service A. This is the requirement that internal-service-trusts-internal-service
  architectures fail.

## Levels

Level 1 is a black-box-testable floor. Level 2 is the sensible default for applications
handling sensitive data. Level 3 is for severe-consequence systems.

Do not claim a level you have not verified requirement by requirement. "We followed ASVS V4 and
V8 guidance" is honest. "We are ASVS Level 2" claims a completed assessment.

## Sources

- <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x13-V4-API-and-Web-Service.md>
- <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x17-V8-Authorization.md>
- <https://owasp.org/www-project-application-security-verification-standard/>
- <https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html>
- <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL>
