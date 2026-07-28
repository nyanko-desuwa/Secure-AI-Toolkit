# OWASP Best Practices

Patterns that hold up under review. Each one names the Top 10 category and ASVS chapter it
serves, so a finding can be traced back to a standard.

## Authorization

`A01:2025` · ASVS V8 (Authorization)

Decide access at the data layer, not the route layer. Route guards answer "is this user
logged in". They cannot answer "does this user own row 4192".

Scope every query by the actor:

```python
# Vulnerable: any authenticated user reads any invoice
def get_invoice(invoice_id: int) -> Invoice | None:
    return db.query(Invoice).filter(Invoice.id == invoice_id).one_or_none()

# Fixed: ownership is part of the query, not a separate check
def get_invoice(invoice_id: int, actor: User) -> Invoice | None:
    return (
        db.query(Invoice)
        .filter(Invoice.id == invoice_id, Invoice.owner_id == actor.id)
        .one_or_none()
    )
```

Scoping in the query beats fetch-then-compare because there is no window where the object
exists in memory without its check, and no way to forget the `if`.

Rules that follow:

- Deny by default. New endpoints are unreachable until a policy is attached.
- Never trust an ID, role, or tenant from the client. Derive the actor from the session.
- Return 404, not 403, when the object exists but is not the actor's. 403 confirms it exists.
- Enforce the same rule on read, write, and delete. Delete is the one people miss.
- Re-check on every request. A capability granted at login is stale by the next call.

## Input Validation

`A05:2025` · ASVS V2 (Validation and Business Logic)

Validate at the trust boundary, once, against an allowlist. Parse into a typed structure
and reject anything that does not fit.

```typescript
// Fixed: schema rejects unknown keys and coerces nothing silently
const CreateUser = z.object({
  email: z.string().email().max(254),
  displayName: z.string().min(1).max(64),
  age: z.number().int().min(13).max(130),
}).strict();

const parsed = CreateUser.safeParse(req.body);
if (!parsed.success) return res.status(400).json({ error: "invalid_request" });
```

`.strict()` matters. Without it, extra keys pass through and mass-assignment becomes
possible downstream.

Validation is not a substitute for encoding. It reduces the input space; encoding is what
makes the sink safe.

## Output Encoding

`A05:2025` · ASVS V1 (Encoding and Sanitization)

Encode at the sink, for that sink. The same string is safe in one context and dangerous in
another.

| Sink | Control |
|---|---|
| SQL | Parameterized query. Never string formatting |
| HTML body | Template auto-escaping, left on |
| HTML attribute | Attribute-context escaping, quoted |
| JavaScript | Serialize as JSON data, do not interpolate into a script |
| Shell | Argument array, no shell. `subprocess.run([...], shell=False)` |
| LDAP / XPath | Library-provided escaping |

Never build a query with string interpolation, even for identifiers. If a table or column
name must be dynamic, map it through an allowlist:

```python
SORTABLE = {"created_at": Invoice.created_at, "total": Invoice.total}

column = SORTABLE.get(request.args.get("sort", "created_at"))
if column is None:
    raise BadRequest("invalid_sort")
```

## Fail Closed

`A10:2025` · ASVS V16 (Security Logging and Error Handling)

An error inside a security decision denies the action. This is the single most common way a
correct-looking control becomes a no-op.

```python
# Vulnerable: an outage in the policy service grants access
def can_edit(actor, doc) -> bool:
    try:
        return policy_service.check(actor.id, doc.id)
    except Exception:
        return True

# Fixed: unavailable means denied, and the failure is visible
def can_edit(actor, doc) -> bool:
    try:
        return policy_service.check(actor.id, doc.id)
    except PolicyServiceError:
        logger.error("policy_check_failed", extra={"actor": actor.id, "doc": doc.id})
        return False
```

Keep error responses uniform. "Wrong password" and "no such user" get the same message and
comparable timing, or the endpoint becomes a user enumeration oracle.

## Secrets

`A04:2025` · ASVS V14 (Data Protection)

Secrets come from the environment or a secret manager, never from source. Reference them by
name in logs and documentation, never by value.

- No secrets in source, fixtures, or test files
- No secrets in error messages or stack traces
- Rotate on exposure, and assume exposure once committed to git history
- Compare secrets with a constant-time function, not `==`

## Cryptography

`A04:2025` · ASVS V11 (Cryptography)

Use the highest-level primitive available. Do not assemble your own construction from
cipher and MAC.

- Passwords: Argon2id, or bcrypt where Argon2 is unavailable. Never a general-purpose hash
- Random values: the platform CSPRNG (`secrets`, `crypto.randomBytes`), never `random`
- Symmetric encryption: an AEAD mode. AES-GCM or ChaCha20-Poly1305, unique nonce per message
- Transport: TLS 1.2 minimum, certificate validation on. Never disable verification "for now"

## Dependencies

`A03:2025` · ASVS V15 (Secure Coding and Architecture)

- Pin exact versions. Commit the lockfile
- Prefer maintained packages with real download volume
- Check unfamiliar names for typosquatting before installing
- Run dependency and secret scanning in CI, not manually

## Logging

`A09:2025` · ASVS V16

Log security-relevant decisions: authentication outcomes, authorization denials, privilege
changes, and administrative actions. Include actor, action, target, outcome, timestamp, and
source IP.

Mask on the way in, not on the way out. Passwords, tokens, keys, full card numbers, and
government IDs never reach the log pipeline.

## Sources

- <https://owasp.org/Top10/2025/>
- <https://owasp.org/www-project-application-security-verification-standard/>
- <https://cheatsheetseries.owasp.org/>
