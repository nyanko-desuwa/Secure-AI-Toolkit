# SSO Federation Security Skill

## Purpose

Enterprise federation adds a second identity authority. The service must prove not merely that XML
was signed, but that the validated assertion came from the configured IdP for this tenant and is
meant for this SP, ACS endpoint, request, and time.

## How It Works

```text
SKILL.md                   federation workflow and severity
README.md                  purpose and limits
checklist.md               assertion, metadata, mapping, logout checks
best-practices.md          vulnerable/fixed patterns
common-mistakes.md         wrong fixes
troubleshooting.md         multi-tenant and rollout conflicts
prompts.md                 four review tiers
references/                SAML and ASVS source pins
examples/README.md         seven vulnerable/fixed pairs
```

## Standards Covered

| Standard | Version | Verified |
|---|---|---|
| OWASP Top 10 | 2025 A07/A08/A01 | 2026-07-28, <https://owasp.org/Top10/2025/> |
| OWASP ASVS | 5.0.0 | 2026-07-28, V2/V3/V6/V7/V8 |
| SAML | SAML 2.0 | 2026-07-28, OASIS SAML specifications |
| CWE | CWE-347, CWE-345, CWE-290, CWE-269 | 2026-07-28, <https://cwe.mitre.org/> |

## Configuration

None. This is Markdown guidance with research-only tool access.

## Example Usage

```text
Review every SAML ACS endpoint and metadata import. Show the trusted IdP entity ID, signing-key
source, assertion validation library call, Audience/Recipient/Destination checks, and attribute to
role mapping. Findings need an assertion field, exploit path, CWE, and fix.
```

## Limitations

- SP code cannot prove the IdP's MFA policy, account lifecycle, signing-key protection, or tenant
  configuration. State those as unverified.
- XML signature wrapping and parser behavior depend on the exact library/version; use vendor fixes
  and controlled tests, not hand-written XML parsing.
- This skill does not replace OAuth/OIDC/session guidance in `authentication`.
- Federation metadata and certificates change; verify the configured values in the deployment.

## Security Notes

All XML, entity IDs, certificates, and hostnames are placeholders. Vulnerable examples are labelled
and paired with fixes. They are not production SAML implementations.
