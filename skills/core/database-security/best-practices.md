# Database Security Best Practices

Patterns for the data layer. Each one names the Top 10 2025 category, the ASVS 5.0 chapter, and
a CWE where one applies.

## Parameterize values

`A05:2025` · ASVS V1 · `CWE-89`

The driver sends the query and the data separately, so the data never reaches the parser as
syntax. That is why binding works and escaping does not: escaping tries to enumerate every
dangerous character, binding removes the parse step.

```python
# Vulnerable: psycopg, f-string
cur.execute(f"SELECT id, email FROM users WHERE email = '{email}'")

# Fixed: %s is a placeholder, not string formatting. Pass a tuple.
cur.execute("SELECT id, email FROM users WHERE email = %s", (email,))
```

```typescript
// Vulnerable: Knex raw with interpolation
await knex.raw(`SELECT * FROM users WHERE email = '${email}'`);

// Fixed: positional bindings
await knex.raw("SELECT * FROM users WHERE email = ?", [email]);
// Or stay in the builder, which parameterizes by default
await knex("users").where({ email }).select("*");
```

```php
// Vulnerable: PDO with concatenation
$stmt = $pdo->query("SELECT * FROM users WHERE email = '" . $email . "'");

// Fixed: named placeholder, emulation off so the server prepares the statement
$pdo = new PDO($dsn, $user, $pass, [PDO::ATTR_EMULATE_PREPARES => false]);
$stmt = $pdo->prepare("SELECT id, email FROM users WHERE email = :email");
$stmt->execute([":email" => $email]);
```

`ATTR_EMULATE_PREPARES => false` matters. With emulation on, PDO interpolates client-side using
the connection charset. It is usually safe, but it is escaping, not binding, and it has had
charset-dependent bypasses. Turn it off and the guarantee is structural.

Never use a string-formatting placeholder where a bind placeholder is expected:

```python
# Vulnerable: the % happens in Python before psycopg sees it
cur.execute("SELECT * FROM users WHERE id = %s" % user_id)
```

## The gaps parameterization does not cover

`A05:2025` · ASVS V1 · `CWE-89`

Binds cover values. Identifiers, sort direction, `IN` arity, and predicate structure are syntax,
and no driver will bind them. This is where injection survives in otherwise careful code.

### Identifiers - allowlist map

```python
# Vulnerable
cur.execute(f"SELECT * FROM invoices ORDER BY {sort} {direction}")

# Fixed: input selects a key; the server owns the SQL text
SORT = {"created": "created_at", "total": "total_cents", "status": "status"}
DIRECTION = {"asc": "ASC", "desc": "DESC"}

column = SORT.get(sort)
order = DIRECTION.get(direction)
if column is None or order is None:
    raise BadRequest("invalid_sort")

cur.execute(f"SELECT * FROM invoices WHERE tenant_id = %s ORDER BY {column} {order}",
            (tenant_id,))
```

The map is the control, not the f-string. A regex like `^[a-zA-Z_]+$` on `sort` is the tempting
wrong fix: it blocks the payloads you imagined and still lets a user sort by a column you never
meant to expose, which leaks data through ordering and error messages.

Where the engine offers identifier quoting, use it as a second layer rather than the only one:

```python
from psycopg import sql
query = sql.SQL("SELECT * FROM invoices ORDER BY {}").format(sql.Identifier(column))
```

`sql.Identifier` quotes and escapes correctly, but it will happily quote a column you did not
intend to allow. Allowlist first, quote second.

### `IN` lists - generate placeholders, cap the length

```python
# Vulnerable
cur.execute(f"SELECT * FROM orders WHERE id IN ({','.join(ids)})")

# Fixed: one placeholder per element, bounded count, typed elements
ids = [int(i) for i in ids][:200]
if not ids:
    return []
placeholders = ",".join(["%s"] * len(ids))
cur.execute(f"SELECT * FROM orders WHERE tenant_id = %s AND id IN ({placeholders})",
            (tenant_id, *ids))
```

PostgreSQL lets you skip the arity problem entirely, which also removes the unbounded-plan-cache
side effect of a different query text per list length:

```python
cur.execute("SELECT * FROM orders WHERE tenant_id = %s AND id = ANY(%s)",
            (tenant_id, ids))
```

The cap is not cosmetic. An unbounded `IN` list is `CWE-770` - a single request asking for
100,000 ids is a cheap way to saturate the database. `A06:2025`, API4:2023.

### `LIKE` patterns - bind, then escape wildcards

Binding a `LIKE` argument stops injection but not wildcard abuse. A search of `%` matches every
row; `%a%b%c%d%` on a large text column forces a scan per row.

```sql
-- Fixed: escape the metacharacters, declare the escape character
SELECT id, title FROM documents
WHERE tenant_id = $1 AND title LIKE $2 ESCAPE '\';
```

```python
def like_prefix(term: str) -> str:
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return escaped + "%"
```

Escape the backslash first, or you double-escape the escapes. Prefer prefix matching over
leading-wildcard matching so an index can still be used, and require a minimum term length.

### Dynamic `WHERE` - compose server-owned fragments

```python
# Fixed: each fragment is a fixed string plus its own binds
FILTERS = {
    "status": ("status = %s", str),
    "min_total": ("total_cents >= %s", int),
    "since": ("created_at >= %s", parse_date),
}

clauses = ["tenant_id = %s"]
params = [tenant_id]
for key, raw in request.args.items():
    spec = FILTERS.get(key)
    if spec is None:
        raise BadRequest(f"unknown_filter:{key}")
    sql_text, coerce = spec
    clauses.append(sql_text)
    params.append(coerce(raw))

cur.execute("SELECT * FROM invoices WHERE " + " AND ".join(clauses), params)
```

The tenant clause is unconditional and first. The loop can only add fragments the server wrote,
and each value is coerced to a type before binding.

## ORM escape hatches

`A05:2025` · ASVS V1 · `CWE-89`, `CWE-564`

An ORM parameterizes its own query building. Every ORM also ships a way out, and that is where
the injection is.

| ORM | Safe | Escape hatch to audit |
|---|---|---|
| SQLAlchemy | `select()`, `filter()`, `text()` with bound params | `text()` with an f-string, `.filter(text(...))`, raw `engine.exec_driver_sql` |
| Django | `filter()`, `Q()` | `.raw()`, `.extra()`, `RawSQL()`, `annotate(RawSQL(...))` |
| Prisma | `findMany`, `where` | `$queryRawUnsafe`, `$executeRawUnsafe`, template-built `Prisma.sql` |
| Knex | builder methods, `?` bindings | `whereRaw`, `orderByRaw`, `joinRaw`, `raw` with interpolation |
| Hibernate / JPA | Criteria API, named parameters | `createQuery` with concatenation (`CWE-564`), `createNativeQuery` |
| Eloquent | builder, bindings | `DB::raw`, `whereRaw`, `orderByRaw`, `selectRaw` |

```python
# Vulnerable: SQLAlchemy text() is not a sanitizer
db.execute(text(f"SELECT * FROM users WHERE role = '{role}'"))

# Fixed: named bind parameters
db.execute(text("SELECT * FROM users WHERE role = :role"), {"role": role})
```

```typescript
// Vulnerable: Unsafe is in the name for a reason
await prisma.$queryRawUnsafe(`SELECT * FROM "User" WHERE email = '${email}'`);

// Fixed: tagged template - Prisma parameterizes the interpolations
await prisma.$queryRaw`SELECT * FROM "User" WHERE email = ${email}`;
```

Note the trap: `prisma.$queryRaw(\`... ${email} ...\`)` called with parentheses instead of as a
tagged template builds the string first and parameterizes nothing. The tag is what makes it
safe, not the function name.

```java
// Vulnerable: JPQL by concatenation - CWE-564
em.createQuery("FROM Invoice i WHERE i.status = '" + status + "'").getResultList();

// Fixed: named parameter, typed query
em.createQuery("FROM Invoice i WHERE i.status = :status", Invoice.class)
  .setParameter("status", status)
  .getResultList();
```

## Mass assignment

`A01:2025` · ASVS V2 · `CWE-915`

Passing a request body into a model constructor lets the client set any column it names,
including `role`, `tenant_id`, `is_verified`, and `credit_balance`.

```typescript
// Vulnerable: whatever the client sent becomes column values
await prisma.user.update({ where: { id: req.user.id }, data: req.body });

// Fixed: parse to a closed schema, then map explicitly
const Patch = z.object({
  displayName: z.string().min(1).max(64).optional(),
  locale: z.string().length(5).optional(),
}).strict();

const patch = Patch.parse(req.body);
await prisma.user.update({
  where: { id: req.user.id },
  data: { displayName: patch.displayName, locale: patch.locale },
});
```

`.strict()` rejects unknown keys instead of dropping them silently, so an attempt to set `role`
becomes a 400 you can alert on. A denylist of forbidden fields is the wrong shape - the next
migration adds a sensitive column and nobody updates the list.

## Second-order injection

`A05:2025` · ASVS V1 · `CWE-89`

Input is stored with a bind parameter, so the write is safe. A later job reads it back and
interpolates it. Reviewers check the insert, see a placeholder, and move on.

```python
# Safe write
cur.execute("INSERT INTO saved_reports (owner_id, group_by) VALUES (%s, %s)",
            (owner_id, group_by))

# Vulnerable read path: the stored value is trusted because "it's from our database"
def run_report(report_id: int):
    row = cur.execute("SELECT group_by FROM saved_reports WHERE id = %s",
                      (report_id,)).fetchone()
    cur.execute(f"SELECT {row['group_by']}, COUNT(*) FROM events GROUP BY {row['group_by']}")
```

```python
# Fixed: validate on write against the same allowlist the read path uses
GROUPABLE = {"country": "country", "plan": "plan", "day": "date_trunc('day', created_at)"}

def save_report(owner_id: int, group_by: str):
    if group_by not in GROUPABLE:
        raise BadRequest("invalid_group_by")
    cur.execute("INSERT INTO saved_reports (owner_id, group_by) VALUES (%s, %s)",
                (owner_id, group_by))

def run_report(report_id: int):
    row = cur.execute("SELECT group_by FROM saved_reports WHERE id = %s",
                      (report_id,)).fetchone()
    expr = GROUPABLE.get(row["group_by"])
    if expr is None:
        raise DataIntegrityError("unrecognised_group_by")
    cur.execute(f"SELECT {expr} AS bucket, COUNT(*) FROM events GROUP BY bucket")
```

Validating on write alone is not enough. Rows arrive from migrations, imports, admin tools, and
other services. The read path re-checks because it cannot assume who wrote the row. Treat the
database as an untrusted source for anything that becomes SQL text.

## NoSQL operator injection

`A05:2025` · ASVS V2 · `CWE-943`

A MongoDB query is a document, so an attacker does not need to break out of a string. Sending
`{"$ne": null}` where a string was expected changes the query's structure. Escaping quotes is
irrelevant here, which is why "we use an ODM so we're safe" fails.

```javascript
// Vulnerable: req.body values go straight into the filter
const user = await db.collection("users").findOne({
  email: req.body.email,
  password: req.body.password,
});
// POST {"email":{"$gt":""},"password":{"$gt":""}} authenticates as the first user
```

```javascript
// Fixed: types are asserted before the object is built
const Login = z.object({
  email: z.string().email().max(254),
  password: z.string().min(8).max(200),
}).strict();

const { email, password } = Login.parse(req.body);
const user = await db.collection("users").findOne({ email });
if (!user || !(await argon2.verify(user.passwordHash, password))) {
  return res.status(401).json({ error: "invalid_credentials" });
}
```

Two things fixed it. The schema guarantees `email` is a string, so no object with `$` keys can
reach the filter. And the password is verified in the application against a hash instead of
being matched in the query, so the database never compares a client-supplied structure.

A recursive "strip keys starting with `$`" sanitizer is the tempting wrong fix. It has to handle
nested documents, arrays, dotted paths like `profile.role`, and unicode variants, and it still
leaves the value typed as an object. Assert the type; do not clean the shape.

The same applies to `$where`, `$expr`, and `mapReduce`, which take expressions. Never build them
from input, and prefer disabling server-side JavaScript.

## Multi-tenancy

`A01:2025` · ASVS V8 · `CWE-566`

`WHERE tenant_id = ?` that every query author must remember is a bug waiting for the next
handler. There is no compiler error for a missing predicate, and a code review catches it only
if the reviewer thinks to look.

Layer one: make the unscoped query impossible to write.

```python
class TenantRepo:
    """Every query starts from a scoped base. There is no accessor for the raw session."""

    def __init__(self, session, tenant_id):
        self._session = session
        self._tenant_id = tenant_id

    def _base(self, model):
        return self._session.query(model).filter(model.tenant_id == self._tenant_id)

    def invoice(self, invoice_id):
        return self._base(Invoice).filter(Invoice.id == invoice_id).one_or_none()
```

Layer two: row-level security, so the engine enforces it even when a query bypasses the
repository. See [references/privilege-model.md](references/privilege-model.md#row-level-security)
for the policy, the `FORCE ROW LEVEL SECURITY` requirement, and the transaction-scoped
`set_config` that keeps a pooled connection from carrying one tenant's context into the next
request.

Test the boundary directly: with tenant A's context set, fetch a known tenant B row by primary
key and assert zero rows. A test that only checks tenant A can read its own data passes on a
completely unscoped query.

## Encryption: pick the layer that matches the threat

`A04:2025` · ASVS V11, V14 · `CWE-311`, `CWE-312`

| Layer | Protects against | Does not protect against |
|---|---|---|
| Disk / volume encryption (TDE) | Stolen disks, decommissioned hardware, snapshot copied out of the account | Anything with a valid database connection. A SQL injection reads plaintext |
| Column encryption in-engine | Some operator roles, depending on key custody | The application, and anyone holding the app credential |
| Application-level encryption | Database compromise, backups, replicas, DBA access, log leakage | A compromised application. Keys are in its process |

At-rest encryption is the cheapest and the weakest. It is table stakes for compliance, and it
does nothing about the threat most incidents actually take: a valid credential.

```python
# Application-level, AEAD, KMS-held key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def encrypt_ssn(plaintext: str, dek: bytes, record_id: str) -> bytes:
    nonce = os.urandom(12)
    # record_id as AAD binds the ciphertext to its row: moving it to another
    # row makes decryption fail instead of silently succeeding.
    return nonce + AESGCM(dek).encrypt(nonce, plaintext.encode(), record_id.encode())
```

Randomized AEAD means you cannot query the column. If you must look values up by equality, that
is a deliberate tradeoff:

- Deterministic encryption - same plaintext, same ciphertext - supports equality and joins, and
  leaks equality. On a low-cardinality column (a country, a status, a boolean) frequency
  analysis recovers the values, so deterministic encryption there is decoration.
- A keyed hash (HMAC with a secret key) in a separate index column supports exact lookup while
  the real value stays randomized. Plain SHA-256 is the wrong choice: the input space of an SSN
  or a phone number is small enough to brute force.
- Neither supports range queries or `LIKE`. If the feature needs those, encryption at that layer
  is not the answer - narrow who can read the column instead.

Rotate by wrapping a per-record data key with a KMS key. Re-wrapping keys is cheap;
re-encrypting a table is not.

## Backups and replicas

`A04:2025` · ASVS V14 · `CWE-311`

A backup is the data with none of the access control.

- Encrypt with a key not stored alongside the backup.
- Restrict who can take a dump or start a replica. `pg_dump` with a broad credential is a
  legitimate-looking exfiltration path that leaves no application audit trail.
- Restrict restores. Restoring production into staging copies the data somewhere with weaker
  controls, and that is the leak most often found after the fact.
- Test restores on a schedule. An unverified backup is a plan, not a control.
- Redact or tokenise before any non-production copy.
- Log backup and restore to a destination the database credential cannot modify.

## Audit

`A09:2025` · ASVS V16 · `CWE-778`

Application audit answers "who read what" with business context. Native audit (`pgaudit`, MySQL
audit log, provider-native) answers it in a way the application cannot bypass. Sensitive data
needs both; say which one you have.

The cost is real: per-statement logging on a read-heavy workload multiplies write volume and
storage. Auditing everything is how auditing gets turned off. Scope it to DDL, grant changes,
logins, and reads of regulated tables, and route the output away from the application account.

## Migration safety

`A08:2025` · ASVS V13, V15

Review a migration as a security change.

- A dropped column destroys data no rollback restores. Two-phase it: stop writing, deploy, drop
  later.
- Require a `WHERE` and a row-count assertion on any data `UPDATE`. `UPDATE ... SET` with no
  predicate rewrites the table.
- A new table needs its grants, which `ALTER DEFAULT PRIVILEGES` handles. Otherwise someone
  unblocks the deploy with `GRANT ALL` and it outlives the deploy.
- Migrations that create roles or change grants need a second reviewer.
- Never run migrations with the runtime credential. If it works, the runtime credential has DDL,
  and that is the finding.

## Sources

- <https://owasp.org/Top10/2025/>
- <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html>
- <https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html>
- <https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html>
- <https://www.postgresql.org/docs/17/sql-createpolicy.html>
