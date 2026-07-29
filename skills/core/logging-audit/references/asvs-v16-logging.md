# ASVS 5.0.0 - V16 Security Logging and Error Handling

> Version 5.0.0 (released 2025-05-30), verified 2026-07-28 against
> <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md>

Chapter overview: <https://owasp.org/www-project-application-security-verification-standard/>

## Control objective, in the standard's own framing

Security logs are distinct from error and performance logs. Their purpose is to support
detection, response, and investigation by producing high-signal structured data for tools
like a SIEM. Logs must not include sensitive personal data unless legally required, and
logged data must be protected as a high-value asset.

Two consequences worth pulling out, because they change design decisions:

- If you log classified data, the log inherits that classification - and with it encryption,
  retention, and disclosure obligations. Logging less is cheaper than protecting more.
- Alerting and correlation are explicitly out of ASVS scope. ASVS gets you the events;
  A09:2025 is where the alerting obligation lives. Do not read ASVS compliance as coverage
  of the alerting half.

## Requirements

Requirement text below is summarised. Levels are as published. For verbatim text, read the
source file linked above.

### V16.1 Security Logging Documentation

| # | Requirement | L |
|---|---|---|
| 16.1.1 | An inventory exists documenting, per layer of the stack: what is logged, log formats, where logs are stored, how they are used, how access is controlled, and retention period | 2 |

### V16.2 General Logging

| # | Requirement | L |
|---|---|---|
| 16.2.1 | Each entry includes the metadata needed to reconstruct a timeline - when, where, who, what | 2 |
| 16.2.2 | Time sources synchronized across logging components; timestamps in UTC or with an explicit offset. UTC recommended, to avoid DST ambiguity across distributed systems | 2 |
| 16.2.3 | The application only stores or broadcasts logs to the files and services in the documented inventory | 2 |
| 16.2.4 | Logs are readable and correlatable by the log processor in use, preferably via a common format | 2 |
| 16.2.5 | Sensitive data logging is enforced by the data's protection level. Some data must not be logged at all (credentials, payment details); some may be logged only hashed or masked, fully or partially (session tokens) | 2 |

### V16.3 Security Events

| # | Requirement | L |
|---|---|---|
| 16.3.1 | All authentication operations logged, success and failure, with metadata such as authentication type or factors used | 2 |
| 16.3.2 | Failed authorization attempts logged. At L3, all authorization decisions logged, including access to sensitive data - without logging the data itself | 2 |
| 16.3.3 | The application logs the security events named in its documentation, plus attempts to bypass security controls: input validation, business logic, anti-automation | 2 |
| 16.3.4 | Unexpected errors and security control failures logged, such as backend TLS failures | 2 |

Note 16.3.2 carefully. Logging only failures is the L2 floor. The L3 requirement - every
authorization decision, including successful sensitive-data reads - is what makes bulk-export
detection possible. If a project needs that rule, it needs the L3 behaviour.

### V16.4 Log Protection

| # | Requirement | L |
|---|---|---|
| 16.4.1 | All logging components encode data appropriately to prevent log injection | 2 |
| 16.4.2 | Logs are protected from unauthorized access and cannot be modified | 2 |
| 16.4.3 | Logs are securely transmitted to a logically separate system for analysis, detection, alerting, and escalation, so that a breach of the application does not compromise the logs | 2 |

16.4.3 is the requirement most often failed by design rather than by oversight: logs written
to the same host, in the same trust zone, deletable by the same service account.

### V16.5 Error Handling

| # | Requirement | L |
|---|---|---|
| 16.5.1 | A generic message is returned to the consumer on unexpected or security-sensitive errors - no stack traces, queries, keys, or tokens | 2 |
| 16.5.2 | The application continues to operate securely when external resource access fails, e.g. circuit breakers or graceful degradation | 2 |
| 16.5.3 | The application fails gracefully and securely, preventing fail-open conditions such as processing a transaction despite validation errors | 2 |
| 16.5.4 | A last-resort handler catches all unhandled exceptions, so error detail is not lost and one error does not take down the process | 3 |

The standard adds a note on 16.5.4: Swift, Go, and many functional languages have no
exceptions or last-resort handler. There, use the language-idiomatic equivalent -
`recover()` in a Go middleware, an error-returning boundary - rather than claiming the
requirement does not apply.

## Level guidance

Almost every requirement in V16 is Level 2. Two are Level 3: the full
authorization-decision logging in 16.3.2, and the last-resort handler in 16.5.4.

There is no Level 1 logging requirement in this chapter. A black-box tester cannot see your
logs. That is a testing artefact, not permission to skip logging in a Level 1 application.

## Citation practice

Cite the requirement number only for the statements above, which were read from the source.
For anything else in V16, cite the chapter - `ASVS V16` - or fetch the file. ASVS 5.0
renumbered everything from 4.0.3, so a recalled `V7.x` logging ID from an older report does
not map.

## Related cheat sheets, referenced by the chapter itself

- OWASP Logging Cheat Sheet - <https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html>
- OWASP Application Logging Vocabulary Cheat Sheet - <https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html>
- OWASP WSTG: Testing for Error Handling - <https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/README>
