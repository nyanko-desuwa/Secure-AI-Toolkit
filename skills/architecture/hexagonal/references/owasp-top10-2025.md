# OWASP Top 10 2025

Verified 2026-07-28: <https://owasp.org/Top10/2025/>.

The 2025 edition is not a renumbering of 2021. A03 and A10 are new, and Injection moved from A03
to A05. If you see `A03:2025` used for injection anywhere, it is a stale mapping.

## Categories

| ID | Category |
|---|---|
| A01:2025 | Broken Access Control |
| A02:2025 | Security Misconfiguration |
| A03:2025 | Software Supply Chain Failures |
| A04:2025 | Cryptographic Failures |
| A05:2025 | Injection |
| A06:2025 | Insecure Design |
| A07:2025 | Authentication Failures |
| A08:2025 | Software or Data Integrity Failures |
| A09:2025 | Security Logging and Alerting Failures |
| A10:2025 | Mishandling of Exceptional Conditions |

## How this skill maps them to ports and adapters

### A01 Broken Access Control

The category this skill is mostly about. A driving port whose signature has no actor cannot
enforce ownership, so the check lands in whichever adapter its author remembered. The second
adapter — a queue consumer, a CLI, a scheduled job — is then an unauthenticated path to the same
mutation.

Also A01: a tenant taken from a request header instead of a verified credential; a driven port
that returns rows without a tenant predicate; a system actor with unrestricted permissions used
by a job.

### A02 Security Misconfiguration

A core that reads environment variables directly has an undeclared dependency on deployment
state, and a missing variable fails at the first request that needs it rather than at boot. A
settings port that parses and validates once at composition time moves that failure to deploy
time. A feature flag that defaults to enabled when the variable is absent is fail-open.

### A04 Cryptographic Failures

Keep secrets inside the adapter that uses them. A credential that enters the core as a string can
reach a log line, an exception message, or a serialized error. A mailer port that takes a message
and no password means no core object ever holds the credential.

### A05 Injection

A driven port that accepts a query fragment, sort expression, or filter string leaks the injection
surface through the abstraction. The port looked safe; the parameter is a query. Ports take
values, and the adapter builds the statement with placeholders. Column and direction names come
from a closed allowlist, never from a caller-supplied string.

### A06 Insecure Design

The bucket for the structural failures: an unbounded queue between an inbound adapter and the
core, an outbound adapter that fetches a user-supplied URL with no egress control, an adapter that
creates a client per call, a fake adapter that is more permissive than the real one so the passing
test proves nothing, a port that hides an open cursor.

### A10 Mishandling of Exceptional Conditions

Error translation belongs at the inbound adapter. A domain or driver exception rendered verbatim
gives a client the SQL fragment, the internal hostname, or the stack. The core returns typed
domain errors; each adapter maps them to a transport status and a stable code, and logs the detail
with a correlation id. Also A10: catching an authorization dependency failure and continuing,
which turns an outage into a grant.

## Not used by this skill

A03 Software Supply Chain Failures, A07 Authentication Failures, A08 Software or Data Integrity
Failures, and A09 Security Logging and Alerting Failures are real concerns for an adapter — a
vendor SDK, a token verifier, a webhook signature, an audit trail — but they are not consequences
of the port structure. They belong to `skills/core/` skills, and this skill links rather than
restates.

## Verification notes

- Category numbers and titles were read on 2026-07-28 from the URL above and are reproduced as
  given.
- The mappings in this file are this skill's interpretation. OWASP does not publish a ports and
  adapters mapping, and no category text is quoted here.
- No CWE list, prevalence figure, or ranking rationale from the edition is reproduced or inferred.
