# SSO Federation Checklist

## Trust and metadata - A08 · CWE-829

- [ ] [critical] Each tenant has an explicit IdP entity ID and metadata source allowlist.
- [ ] [critical] Metadata is authenticated, signed, pinned, or updated through a controlled review process.
- [ ] [recommended] Signing certificates have rotation ownership and expiry monitoring.
- [ ] [critical] No arbitrary metadata URL or uploaded certificate becomes trusted.

## Assertion validation - A07 · CWE-347/CWE-345

- [ ] [critical] Library validates XML signatures using the configured IdP key before application reads claims.
- [ ] [critical] Validated assertion issuer equals the configured IdP entity ID.
- [ ] [critical] Audience contains this SP entity ID; recipient and destination equal the configured ACS.
- [ ] [critical] `NotBefore` and `NotOnOrAfter` are checked with a bounded clock skew.
- [ ] [critical] InResponseTo is checked for SP-initiated flows; assertion IDs have replay protection where supported.
- [ ] [critical] Parser/library is supported and hardened against signature wrapping; no custom XPath verification.

## Identity and authorization - A01

- [ ] [critical] NameID/subject maps to a local tenant-bound account, not a globally guessed email alone.
- [ ] [critical] Attribute-to-role mapping is an allowlist and defaults to least privilege.
- [ ] [critical] IdP selection is bound to tenant/domain policy; a different tenant's IdP cannot satisfy login.
- [ ] [critical] JIT provisioning cannot overwrite a local privileged account through an unverified claim.

## Session and logout

- [ ] [critical] Federation login creates a new local session with normal session protections.
- [ ] [recommended] Logout/session revocation behavior is documented; local session cannot outlive required policy.
- [ ] [recommended] Audit logs record issuer, tenant, correlation ID, outcome, and safe failure reason.
