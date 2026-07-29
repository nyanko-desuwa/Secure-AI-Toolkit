# SSO Federation Examples

## Skipped signature validation - CWE-347

```python
# Vulnerable: decoded XML is treated as identity
login(parse_assertion(xml)["email"])
```

```python
# Fixed: validated assertion feeds identity mapping
login(map_subject(validate_assertion(xml, tenant.policy)))
```

## Missing audience check - CWE-345

```text
Vulnerable: any assertion signed by the IdP is accepted.
Fixed: validator requires this SP entity ID in AudienceRestriction.
```

## Open ACS destination - CWE-345

```text
Vulnerable: callback/Recipient is accepted for any endpoint.
Fixed: recipient and destination exactly match configured ACS URL.
```

## Unauthenticated metadata - CWE-829

```text
Vulnerable: service fetches arbitrary metadata URL and trusts returned signing key.
Fixed: allowlisted authenticated metadata source and reviewed key rotation establish trust.
```

## Direct role claim - CWE-269

```python
# Vulnerable: claim becomes local administrator
user.role = assertion.attributes["role"]
```

```python
# Fixed: known group IDs map to approved local roles
user.role = ROLE_MAP.get(assertion.attributes.get("group_id"), "member")
```

## IdP mix-up - CWE-290

```text
Vulnerable: ?idp= selects any configured connection before tenant is established.
Fixed: verified tenant policy selects its single approved IdP connection.
```

## Signature wrapping awareness - CWE-347

```text
Vulnerable: custom XPath verifies one signed XML element but reads claims from another.
Fixed: supported validator binds the verified assertion object and claims are read only from it.
```
