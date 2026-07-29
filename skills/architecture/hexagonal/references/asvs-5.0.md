# OWASP ASVS 5.0.0

Verified 2026-07-28:
<https://owasp.org/www-project-application-security-verification-standard/>.

Version 5.0.0, released 2025-05-30. This skill cites ASVS at chapter level only. Requirement IDs
are not reproduced here and must not be inferred from a chapter citation - if you need a specific
requirement, open the standard and quote it.

## Chapters

| Chapter | Title |
|---|---|
| V1 | Encoding and Sanitization |
| V2 | Validation and Business Logic |
| V3 | Web Frontend Security |
| V4 | API and Web Service |
| V5 | File Handling |
| V6 | Authentication |
| V7 | Session Management |
| V8 | Authorization |
| V9 | Self-contained Tokens |
| V10 | OAuth and OIDC |
| V11 | Cryptography |
| V12 | Secure Communication |
| V13 | Configuration |
| V14 | Data Protection |
| V15 | Secure Coding and Architecture |
| V16 | Security Logging and Error Handling |
| V17 | WebRTC |

## Chapters this skill leans on

### V2 Validation and Business Logic

The inbound adapter is the validation point. Schema, types, ranges, lengths, unknown-field
rejection, and a body size limit belong there, per adapter, because each transport carries a
different payload shape. Business invariants stay in the domain so every adapter reaches the same
rule.

The corollary is the one this skill repeats: validation placed in the domain instead of the
adapter does not protect the adapter's parsing step, and each new adapter is a fresh place for
malformed input to enter.

### V4 API and Web Service

Applies to the HTTP driving adapter specifically - content type handling, method semantics, error
shape, rate limiting. Controls live in `skills/core/api-security/`. The relevant structural point
here is that these are adapter concerns and none of them may be pushed into the core.

### V8 Authorization

The chapter behind the central claim. The authorization decision belongs behind the driving port,
where every adapter converges, and it needs the actor as a required input. Adapter-level checks
are defence in depth, not the decision.

Also V8 territory: making not-found and not-yours indistinguishable, denying by default on an
unrecognised action, and giving background work a narrow principal instead of a superuser.

### V13 Configuration

Settings enter through a driven port, are parsed and validated once at composition time, and fail
the boot rather than the first request. Flags default to off.

### V14 Data Protection

Secrets stay inside the adapter that needs them. Response mapping in the outbound direction is an
allowlist, so a field added to a domain object does not appear in a response.

### V15 Secure Coding and Architecture

Where the structural items land: import direction enforced by the build, no transport type in a
core signature, driven ports that do not accept query fragments, resource ownership stated per
adapter, and fakes held to a contract the real adapter also passes.

### V16 Security Logging and Error Handling

Error translation at the adapter boundary. Log the detail with a correlation id, return a stable
code. Log the authorization decision - allowed and denied - with the actor, and never log the
credential or the secret the adapter holds.

## Chapters this skill does not address

V1, V3, V5, V6, V7, V9, V10, V11, V12, and V17 are adapter-level or platform-level concerns that
the port structure does not change. They belong to the `skills/core/` skills.

## Verification notes

- Chapter numbers, titles, version, and release date were read on 2026-07-28 from the project page
  above.
- The chapter-to-pattern mapping in this file is this skill's own. ASVS does not publish an
  architecture-pattern mapping.
- No requirement ID, verification level, or requirement text is reproduced. If a review needs one,
  fetch it from the standard at the time of the review.
