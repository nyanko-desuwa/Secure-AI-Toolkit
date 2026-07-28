# SSO Federation Best Practices

## Use a maintained SAML validator — CWE-347

```python
# Vulnerable: parses claims before a library validates the signed object
claims = parse_xml(request.data)
login(claims["email"])
```

```python
# Fixed: library validates signature, issuer, audience, recipient, and time first
assertion = saml_validator.validate(request.data, expected=tenant.saml_policy)
login(map_subject(assertion.subject, tenant))
```

## Pin the audience and ACS — CWE-345

```python
# Vulnerable: any otherwise-valid assertion is accepted
assertion = validate_signature(xml)
```

```python
# Fixed: accepted assertion is bound to this SP endpoint
assertion = validate_signature(xml, audience=SP_ENTITY_ID, recipient=ACS_URL)
```

## Map roles through an allowlist — CWE-269

```python
# Vulnerable: IdP attribute controls local privilege
user.role = assertion.attributes["role"]
```

```python
# Fixed: only configured group IDs map to local roles
user.role = ROLE_MAP.get(assertion.attributes.get("group_id"), "member")
```

## Bind IdP selection to tenant — CWE-290

```python
# Vulnerable: caller chooses an arbitrary IdP connection
policy = connections[request.args["idp"]]
```

```python
# Fixed: tenant discovery selects from its configured connection
policy = tenant_from_verified_domain(request).saml_policy
```

## Treat metadata as code — CWE-829

```text
Vulnerable: admin pastes a metadata URL and the service trusts whatever certificate it returns.
Fixed: allowlisted, authenticated metadata source is reviewed; key rotation has an owner and alert.
```

Why: federation trust is a configuration boundary, not an XML convenience feature.
