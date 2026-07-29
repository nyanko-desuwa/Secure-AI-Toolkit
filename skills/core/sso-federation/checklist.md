# SSO Federation Checklist

## Trust and metadata - A08 · CWE-829

- [ ] Each tenant has an explicit IdP entity ID and metadata source allowlist.
- [ ] Metadata is authenticated, signed, pinned, or updated through a controlled review process.
- [ ] Signing certificates have rotation ownership and expiry monitoring.
- [ ] No arbitrary metadata URL or uploaded certificate becomes trusted.

## Assertion validation - A07 · CWE-347/CWE-345

- [ ] Library validates XML signatures using the configured IdP key before application reads claims.
- [ ] Validated assertion issuer equals the configured IdP entity ID.
- [ ] Audience contains this SP entity ID; recipient and destination equal the configured ACS.
- [ ] `NotBefore` and `NotOnOrAfter` are checked with a bounded clock skew.
- [ ] InResponseTo is checked for SP-initiated flows; assertion IDs have replay protection where supported.
- [ ] Parser/library is supported and hardened against signature wrapping; no custom XPath verification.

## Identity and authorization - A01

- [ ] NameID/subject maps to a local tenant-bound account, not a globally guessed email alone.
- [ ] Attribute-to-role mapping is an allowlist and defaults to least privilege.
- [ ] IdP selection is bound to tenant/domain policy; a different tenant's IdP cannot satisfy login.
- [ ] JIT provisioning cannot overwrite a local privileged account through an unverified claim.

## Session and logout

- [ ] Federation login creates a new local session with normal session protections.
- [ ] Logout/session revocation behavior is documented; local session cannot outlive required policy.
- [ ] Audit logs record issuer, tenant, correlation ID, outcome, and safe failure reason.
