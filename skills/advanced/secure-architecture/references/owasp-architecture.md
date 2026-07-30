# OWASP for architecture - Top 10 2025 and ASVS 5.0

Verified 2026-07-28 against:

- <https://owasp.org/Top10/2025/>
- <https://owasp.org/www-project-application-security-verification-standard/>

OWASP Top 10 2025 is the current released edition. It is not a renumbering of 2021: A03 and
A10 are new, and Injection moved from A03 to A05. ASVS 5.0.0 was released 2025-05-30 and
renumbers chapters relative to 4.0.3, so a `V2.x` citation from a 4.x report means something
different here.

## The three categories that are architectural

Most Top 10 categories are implementation findings. Three are design findings - you cannot fix
them in a diff.

### A01:2025 Broken Access Control

Architectural shape: the authorization decision is made in a different component from the one
that holds the data, so any path that skips the first component skips the check. A gateway that
validates tenant membership in front of services that trust an `X-Tenant-Id` header is the
canonical example.

Design questions:

- Where is the single point that resolves subject => permitted resources? If there are several,
  they will drift.
- Can a request reach the data store without passing that point? Internal callers, batch jobs,
  admin tools, and replicas all count.
- Is the tenant derived from a verified token, or read from a request field?

### A02:2025 Security Misconfiguration

Architectural shape: the secure state depends on someone remembering to set something. Defaults
that are open, environments that diverge, and controls applied per-resource rather than by the
platform.

Design questions:

- What is the default when a field is absent - deny or allow?
- If a new service is deployed with no security config, what can it reach?
- Which controls are enforced by the platform, and which by developer discipline?

### A06:2025 Insecure Design

Architectural shape: a control that was never designed in. No amount of careful implementation
adds rate limiting to a flow that has no place to put it, or adds an audit trail to a mutation
that happens directly in the database.

Design questions:

- What is the abuse case, not the use case?
- Which flows are expensive, and what meters them?
- What happens when a dependency is unavailable - deny, allow, or queue?

The other categories still land on architecture indirectly. A03 (Software Supply Chain
Failures) is a build-system design problem; A08 (Software or Data Integrity Failures) covers
unverified artefacts and untrusted deserialization across a boundary; A09 (Security Logging and
Alerting Failures) is a design question about whether the audit path can be bypassed.

## ASVS 5.0 chapters used in this skill

Citations here are at chapter level. The 5.0 numbering is new enough that recalled requirement
IDs are unreliable - pull specific requirement text from <https://github.com/OWASP/ASVS> before
quoting an ID.

| Chapter | Title | Architectural use |
|---|---|---|
| V8 | Authorization | Where decisions are made and enforced; tenant and object scoping |
| V13 | Configuration | Build, deploy, dependency, and secret configuration; environment parity |
| V15 | Secure Coding and Architecture | Design-level and supply chain requirements |

Supporting chapters that come up in architecture reviews: V4 (API and Web Service) for service
boundaries, V7 (Session Management) and V9 (Self-contained Tokens) for what a token is allowed
to assert, V11 (Cryptography) and V12 (Secure Communication) for boundary protection, V14 (Data
Protection) for privacy and retention, V16 (Security Logging and Error Handling) for failure
modes.

## ASVS levels

Level 1 is a black-box-testable floor. Level 2 is the right default for applications handling
sensitive data. Level 3 is for systems where failure is severe - health, finance, safety,
critical infrastructure.

State the level you targeted. "We followed ASVS V8 guidance" is honest. "We are ASVS Level 2"
claims a completed requirement-by-requirement assessment.

## Full Top 10 2025 list

A01 Broken Access Control · A02 Security Misconfiguration · A03 Software Supply Chain Failures ·
A04 Cryptographic Failures · A05 Injection · A06 Insecure Design · A07 Authentication Failures ·
A08 Software or Data Integrity Failures · A09 Security Logging and Alerting Failures ·
A10 Mishandling of Exceptional Conditions

SSRF has no standalone 2025 category. Report it under A01 or A06 with CWE-918. For architecture
that usually means A06: the design permitted an outbound request to an address the caller chose.

## Full ASVS 5.0.0 chapter list

V1 Encoding and Sanitization · V2 Validation and Business Logic · V3 Web Frontend Security ·
V4 API and Web Service · V5 File Handling · V6 Authentication · V7 Session Management ·
V8 Authorization · V9 Self-contained Tokens · V10 OAuth and OIDC · V11 Cryptography ·
V12 Secure Communication · V13 Configuration · V14 Data Protection ·
V15 Secure Coding and Architecture · V16 Security Logging and Error Handling · V17 WebRTC
