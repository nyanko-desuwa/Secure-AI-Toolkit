# OWASP ASVS 5.0.0 — V13, V14, and V15 for publishing

Application Security Verification Standard, version 5.0.0, released 30 May 2025.

Source: <https://owasp.org/www-project-application-security-verification-standard/> ·
verified 2026-07-28

5.0 is a restructure of 4.0.3, not an increment. Chapter numbers and requirement IDs do not carry
over — a `V2.10.x` citation from a 4.x report points somewhere else in 5.0. Re-map, do not translate.

## Why cite ASVS on a publish decision

The Top 10 tells you that misconfiguration is common. ASVS gives you a statement that passes or
fails. "The build output contains no configuration value that is not intended to be public" is
checkable; "publishing is risky" is not.

## The three chapters that own publishing

| Chapter | Title | Scope for publish work |
|---|---|---|
| V13 | Configuration | Whether configuration is separated from code and from the artifact. Ignore rules, allowlists, build-time inlining, and what the deployed bundle contains |
| V14 | Data Protection | The sensitive value itself: at rest in a repository or artifact, in a log, in a screenshot, and how long it is retained where you cannot delete it |
| V15 | Secure Coding and Architecture | The supply-chain side: what you ship to a consumer, and build-time handling of anything sensitive |

The boundary in practice: V13 is "what is in the artifact and why", V14 is "what that value is worth
to whoever reads it", V15 is "what a consumer of your artifact inherits". A committed `.env` fails
all three — configuration is not separated, the value is at rest unprotected, and anyone who clones
the repository inherits it.

## Adjacent chapters that come up

| Chapter | When it applies |
|---|---|
| V16 Security Logging and Error Handling | A published log or an error page carrying a credential, a stack trace, or an internal path |
| V12 Secure Communication | Only when the publish channel itself is the finding, which is rare |
| V3 Web Frontend Security | A deployed bundle that inlines a value the browser can read |

## Levels

ASVS defines three verification levels. Say which one you targeted; "ASVS compliant" means nothing
alone.

- Level 1 — baseline, verifiable black-box. A floor, not a goal
- Level 2 — the right default for most business applications
- Level 3 — severe-consequence applications: health, finance, safety, critical infrastructure

Do not claim a level you have not verified requirement by requirement. "We followed ASVS V13
guidance on configuration separation" is honest. "We are ASVS Level 2" implies a completed
assessment.

## Citing correctly

Cite the chapter when the finding is general, the requirement only when you have read the specific
statement. `ASVS V14 (Data Protection)` is a correct and useful citation. A precise requirement
number recalled from memory is worse than a chapter, because it looks verifiable and is not.

For requirement text, work from the official repository rather than recall — 5.0 numbering is new
enough that remembered IDs are unreliable:

<https://github.com/OWASP/ASVS>

## Mapping, given what the publish action touches

| The action touches | Chapters |
|---|---|
| An ignore file or a packaging allowlist | V13, V15 |
| Repository visibility, or history | V13, V14 |
| A build artifact that inlines configuration | V13, V3 |
| A published package or image consumed by others | V15, V13 |
| A published log, plan output, or error page | V16, V14 |
| A screenshot, pasted diff, or AI prompt containing a value | V14 |
| A credential that is now public | V14, V13 |
