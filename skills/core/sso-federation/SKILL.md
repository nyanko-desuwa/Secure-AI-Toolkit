---
name: sso-federation
description: 'Enterprise SSO federation - SAML assertion validation, ACS/Audience/Recipient, metadata trust, IdP mix-up, signature wrapping. Triggers: "SAML", "SSO", "IdP", "SP metadata", "ACS", "federation", "đăng nhập doanh nghiệp", "liên kết IdP".'
allowed-tools: Read, Glob, Grep, WebSearch, WebFetch
---

# SSO Federation Security

A signed assertion is not automatically an assertion for this service, this user, or this login.
This skill owns SAML and enterprise federation trust: assertions, ACS, audience and recipient,
metadata, attribute mapping, IdP mix-up, and logout.

## When to Use

- Adding a SAML service provider or enterprise IdP connection
- Reviewing ACS endpoints, metadata import, assertion parsers, or role mappings
- Debugging a login that succeeds for the wrong tenant or IdP
- Designing IdP-initiated SSO or federation logout

## When NOT to Use

| Concern | Route to |
|---|---|
| OAuth/OIDC authorization code, refresh tokens, sessions, MFA, passwords | `authentication` |
| API authorization after a session is established | `api-security` |
| XML upload or parser safety outside federation | `deserialization-security` |
| Browser DOM/CSP controls | `frontend-security` |

## The Standard

| Failure | Mapping |
|---|---|
| Assertion signature skipped or mis-bound | CWE-347 · A07 |
| Audience, recipient, ACS, or time not validated | CWE-345 · ASVS V2/V3 |
| Unsigned/unpinned metadata changes trust | CWE-829 · A08 |
| Attribute maps directly to privileged role | CWE-269 · A01 |
| Wrong IdP/tenant accepts an assertion | CWE-290 · A07 |

OWASP Top 10 2025 A07, ASVS 5.0 V2/V3/V6/V7/V8, and CWE provide the mapping. Read
[references/](references/) for source pins.

## Workflow

1. Map each SP, IdP, entity ID, ACS URL, certificate, metadata source, and tenant rule.
2. Identify the library validation path. Confirm it validates a signed assertion *and* binds the
   validated object to issuer, audience, recipient, destination, time, and request when applicable.
3. Allowlist IdPs and metadata origins. Pin or rotate signing keys by controlled metadata update.
4. Map only approved attributes to a local identity and least privilege; never grant a role from an
   arbitrary string claim.
5. Run [checklist.md](checklist.md), then report the assertion field, exploit precondition, CWE,
   fix, and unverified IdP-side configuration.

## Severity

- Critical - arbitrary assertion or unsigned metadata grants an account or administrator role
- High - wrong audience/recipient, IdP mix-up, or privileged role mapping across tenants
- Medium - weak logout/session binding, replay window, or excessive attribute exposure
- Low - verbose federation errors without a demonstrated bypass

## Related Skills

- `authentication` - sessions and OAuth/OIDC flows after federation
- `api-security` - downstream authorization
- `deserialization-security` - generic XML parser boundaries
- `logging-audit` - federation events and denial evidence

## Supporting Files

- [README.md](README.md), [checklist.md](checklist.md), [best-practices.md](best-practices.md)
- [common-mistakes.md](common-mistakes.md), [troubleshooting.md](troubleshooting.md), [prompts.md](prompts.md)
- [references/](references/) and [examples/README.md](examples/README.md)
