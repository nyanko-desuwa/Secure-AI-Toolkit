# OWASP ASVS 5.0.0 — V13 and V14 for secrets

Application Security Verification Standard, version 5.0.0, released 30 May 2025.

Source: <https://owasp.org/www-project-application-security-verification-standard/> ·
verified 2026-07-28

5.0 is a restructure of 4.0.3, not an increment. Chapter numbers and requirement IDs do not
carry over — a `V2.10.x` secrets citation from a 4.x report points somewhere else in 5.0. Re-map,
do not translate.

## Why cite ASVS at all

The Top 10 says misconfiguration is common. ASVS gives a statement you can pass or fail. Use the
Top 10 to decide what to look at and ASVS to decide whether it is correct.

## The two chapters that own secrets

| Chapter | Title | Scope for secrets work |
|---|---|---|
| V13 | Configuration | How the secret reaches the running application: build, deploy, dependency, and secret configuration. Also the absence of hardcoded values and the shape of the delivery path |
| V14 | Data Protection | The credential as sensitive data: at rest, in transit, in memory, in logs, and its retention |

The boundary in practice: V13 is "where does it come from", V14 is "what happens to it once it
exists". A hardcoded key is both — it fails V13 because configuration is not separated from code,
and V14 because the value is at rest unprotected.

## Adjacent chapters that come up

| Chapter | When it applies |
|---|---|
| V11 Cryptography | Key selection, key lifetime, randomness for generated secrets, constant-time comparison |
| V12 Secure Communication | TLS for the path between the application and the secret manager or the credentialled service |
| V15 Secure Coding and Architecture | Supply chain and build-time secret handling, dependency provenance |
| V16 Security Logging and Error Handling | Redaction, and errors that must not carry the credential |
| V6 Authentication | Password and credential storage where the secret belongs to a user rather than a service |

A secret that authenticates a human is a V6 problem. This skill is about secrets that
authenticate a machine — V13 and V14.

## Levels

ASVS defines three verification levels. Pick one and say which you targeted; "ASVS compliant"
means nothing alone.

- Level 1 — baseline, verifiable black-box. A floor, not a goal
- Level 2 — for applications handling sensitive data. The right default for most business
  applications, and the level at which centralised secret management stops being optional
- Level 3 — for severe-consequence applications: health, finance, safety, critical
  infrastructure

Do not claim a level you have not verified requirement by requirement. "We followed ASVS V13
guidance" is honest. "We are ASVS Level 2" implies a completed assessment.

## Citing correctly

Cite the chapter when the finding is general, the requirement only when you have read the
specific statement. `ASVS V13 (Configuration)` is a correct and useful citation. A precise
requirement number recalled from memory is worse than a chapter, because it looks verifiable and
is not.

For requirement text, work from the official repository rather than recall — the 5.0 numbering is
new enough that remembered IDs are unreliable:

<https://github.com/OWASP/ASVS>

## Mapping, given what the change touches

| Change touches | Chapters |
|---|---|
| A new credential in application config | V13, V14 |
| Secret manager client code | V13, V12 |
| Rotation design | V13, V14, V11 |
| Constant-time comparison of a token | V11, V14 |
| Dockerfile, CI workflow, Kubernetes manifest | V13, V15 |
| Terraform or other IaC | V13 |
| Logging or an error handler near a credential | V16, V14 |
| Generating a new secret value | V11 |
| LLM prompt or tool argument carrying a credential | V13, V14 |
