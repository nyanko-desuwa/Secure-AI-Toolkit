# SSO Federation Prompts

## Beginner

```text
Explain which organization is allowed to sign a login, how the app proves the login is meant for
this service, and what user information can become a role. Show the evidence instead of saying the
SAML library handles it.
```

## Developer

```text
Review SAML setup, ACS handlers, metadata import, and role mapping. Trace assertion bytes through
signature validation, issuer/audience/recipient/time checks, tenant binding, local account mapping,
and session creation. Give file:line, CWE, exploit path, and smallest fix.
```

## Review

```text
Build a matrix of tenant, IdP entity ID, metadata/key source, SP entity ID, ACS URL, accepted
Audience/Recipient/Destination, subject mapping, and role map. Flag any caller-controlled selection
or missing validation with severity and evidence.
```

## Audit

```text
Assess federation against ASVS 5.0 V2/V3/V6/V7/V8 and OWASP A07/A08. For every control provide code
or IdP configuration evidence, test evidence, owner, and facts unavailable from this repository.
```

## Anti-patterns

| Weak prompt | Finding prompt |
|---|---|
| "Is SAML configured?" | "Show the exact validator call and every expected issuer, audience, recipient, destination, and time value." |
| "Check SSO roles." | "Trace each assertion attribute to a local role and prove unknown values default to least privilege." |
