# Database Security Examples

Eight vulnerable/fixed pairs. Each names its OWASP Top 10 2025 category, ASVS 5.0 chapter, and
CWE. The code is deliberately small; adapt error handling and types to the project.

## Contents

1. [PHP PDO value injection](#1-php-pdo-value-injection)
2. [Psycopg identifier and IN-list injection](#2-psycopg-identifier-and-in-list-injection)
3. [Prisma raw escape hatch](#3-prisma-raw-escape-hatch)
4. [Second-order injection](#4-second-order-injection)
5. [MongoDB operator injection](#5-mongodb-operator-injection)
6. [ORM mass assignment](#6-orm-mass-assignment)
7. [Tenant isolation with RLS](#7-tenant-isolation-with-rls)
8. [N+1 as resource consumption](#8-n1-as-resource-consumption)

---

## 1. PHP PDO value injection

`A05:2025` · ASVS V1 · `CWE-89`

Vulnerable:

```php
$email = $_GET['email'];
$row = $pdo->query("SELECT id, email FROM users WHERE email = '$email'")->fetch();
```

`' OR 1=1--` becomes SQL. Adding `addslashes()` is the tempting wrong fix: it is not aware of
the server encoding or SQL mode.

Fixed:

```php
$pdo = new PDO($dsn, $user, $pass, [PDO::ATTR_EMULATE_PREPARES => false]);
$stmt = $pdo->prepare('SELECT id, email FROM users WHERE email = :email');
$stmt->execute([':email' => $_GET['email']]);
$row = $stmt->fetch(PDO::FETCH_ASSOC);
```

Why this works: PDO sends SQL and data separately to the server. Disabling emulation avoids
client-side interpolation and its charset-dependent assumptions.

---

## 2. Psycopg identifier and IN-list injection

`A05:2025`, `A06:2025` · ASVS V1, V2 · `CWE-89`, `CWE-770`

Vulnerable:

```python
def list_orders(sort: str, ids: list[str]):
    sql = f"SELECT * FROM orders WHERE id IN ({','.join(ids)}) ORDER BY {sort}"
    return conn.execute(sql).fetchall()
```

A crafted list element or sort expression becomes SQL. A list of 100,000 valid IDs is also a
cheap resource-exhaustion request.

Fixed:

```python
SORT_COLUMNS = {"created": "created_at", "total": "total_cents"}

def list_orders(sort: str, ids: list[int]):
    column = SORT_COLUMNS.get(sort)
    if column is None or len(ids) > 200 or not all(type(i) is int for i in ids):
        raise ValueError("invalid_query")
    if not ids:
        return []
    return conn.execute(
        f"SELECT * FROM orders WHERE id = ANY(%s) ORDER BY {column}", (ids,)
    ).fetchall()
```

Why this works: PostgreSQL binds the array as one value. User input only selects a fixed column
from a map, and the list cap limits query cost. Returning `[]` for an empty list avoids the wrong
fix of dropping the predicate and reading every order.

---

## 3. Prisma raw escape hatch

`A05:2025` · ASVS V1 · `CWE-89`

Vulnerable:

```typescript
const users = await prisma.$queryRawUnsafe(
  `SELECT * FROM "User" WHERE email = '${req.query.email}'`
);
```

Prisma's model API is parameterized, but `$queryRawUnsafe` is an explicit escape hatch.

Fixed:

```typescript
if (typeof req.query.email !== "string") throw new BadRequestError();
const email = req.query.email;
const users = await prisma.$queryRaw`
  SELECT id, email FROM "User" WHERE email = ${email}
`;
```

Why this works: Prisma's tagged template turns interpolations into bind parameters. Calling a
normal function with an already-built template string would not; the tag is the control.

---

## 4. Second-order injection

`A05:2025` · ASVS V1 · `CWE-89`

Vulnerable:

```python
# Stored safely today.
conn.execute("INSERT INTO reports (group_by) VALUES (%s)", (request.form["group_by"],))

# Interpreted as SQL by tomorrow's scheduled job.
group_by = conn.execute("SELECT group_by FROM reports WHERE id = %s", (report_id,)).fetchone()[0]
conn.execute(f"SELECT {group_by}, count(*) FROM events GROUP BY {group_by}")
```

The insert is parameterized, so first-order tests pass. The stored payload reaches a later sink.

Fixed:

```python
GROUPS = {"country": "country", "plan": "plan", "day": "date_trunc('day', created_at)"}

def run_report(report_id: int):
    key = conn.execute("SELECT group_by FROM reports WHERE id = %s", (report_id,)).fetchone()[0]
    expression = GROUPS.get(key)
    if expression is None:
        raise ValueError("invalid_stored_report")
    return conn.execute(
        f"SELECT {expression} AS bucket, count(*) FROM events GROUP BY bucket"
    ).fetchall()
```

Why this works: the later sink revalidates the row against a server-owned map. Write-time checks
alone miss old imports, migrations, admin edits, and another service writing the same table.

---

## 5. MongoDB operator injection

`A05:2025` · ASVS V2 · `CWE-943`

Vulnerable:

```typescript
const user = await users.findOne({
  email: req.body.email,
  password: req.body.password,
});
```

`{"email":{"$gt":""},"password":{"$gt":""}}` changes both equality tests into operators and
matches the first account. Quotes never need escaping because the attack changes object shape.

Fixed:

```typescript
const Login = z.object({
  email: z.string().email().max(254),
  password: z.string().min(8).max(200),
}).strict();
const { email, password } = Login.parse(req.body);
const user = await users.findOne({ email });
if (!user || !(await argon2.verify(user.passwordHash, password))) {
  throw new UnauthorizedError("invalid_credentials");
}
```

Why this works: only strings survive parsing, so an operator object cannot reach the query. The
password is checked against a hash outside the query. Recursively stripping `$` keys is weaker:
it must correctly sanitize every nested shape and still leaves the value typed as an object.

---

## 6. ORM mass assignment

`A01:2025` · ASVS V2 · `CWE-915`

Vulnerable:

```typescript
await prisma.user.update({ where: { id: req.user.id }, data: req.body });
```

The client sets `role`, `tenantId`, `emailVerified`, or the next sensitive column a migration
adds. A denylist becomes stale at that migration.

Fixed:

```typescript
const Patch = z.object({
  displayName: z.string().min(1).max(64).optional(),
  locale: z.enum(["en-US", "vi-VN"]).optional(),
}).strict();
const patch = Patch.parse(req.body);
await prisma.user.update({
  where: { id: req.user.id },
  data: { displayName: patch.displayName, locale: patch.locale },
});
```

Why this works: the closed schema rejects unknown fields, and the explicit mapping makes the set
of writable columns visible in review.

---

## 7. Tenant isolation with RLS

`A01:2025` · ASVS V8 · `CWE-566`

Vulnerable:

```sql
-- Every application query must remember this predicate.
SELECT id, total_cents FROM invoices WHERE id = $1 AND tenant_id = $2;
```

The query shown is safe. The design is not: the next handler can omit `tenant_id`, and no compiler
or database error catches it. A UUID primary key only makes discovery harder.

Fixed:

```sql
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoices FORCE ROW LEVEL SECURITY;
CREATE POLICY invoice_tenant ON invoices
  USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
  WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);
```

```python
with conn.transaction():
    conn.execute("SELECT set_config('app.tenant_id', %s, true)", (str(tenant_id),))
    invoice = conn.execute("SELECT id, total_cents FROM invoices WHERE id = %s", (id,)).fetchone()
```

Why this works: the engine applies the scope even when SQL omits it. `FORCE` covers the table
owner, `WITH CHECK` covers writes, and transaction-local context prevents pool reuse leaking a
previous tenant. Limitation: PostgreSQL superusers and `BYPASSRLS` roles still bypass the policy;
the runtime role must have neither.

---

## 8. N+1 as resource consumption

`A06:2025` · API4:2023 · ASVS V2 · `CWE-770`

Vulnerable:

```python
orders = session.scalars(select(Order).limit(500)).all()
return [{"id": o.id, "customer": o.customer.name} for o in orders]
```

With a lazy `customer` relation, this runs up to 501 queries per request. Repeating the endpoint
exhausts the pool. It is an availability finding, not just slow code.

Fixed:

```python
from sqlalchemy.orm import selectinload

limit = min(max(int(request.args.get("limit", 50)), 1), 100)
orders = session.scalars(
    select(Order).options(selectinload(Order.customer)).limit(limit)
).all()
return [{"id": o.id, "customer": o.customer.name} for o in orders]
```

Why this works: `selectinload` fetches the relation in a bounded additional query and the page cap
limits cardinality. Blindly joining every collection is the wrong fix: multiple one-to-many joins
can create a Cartesian result larger than the original N+1. Assert query count in tests.

## Sources

- <https://owasp.org/Top10/2025/>
- <https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html>
- <https://cwe.mitre.org/data/definitions/89.html>
- <https://cwe.mitre.org/data/definitions/943.html>
- <https://cwe.mitre.org/data/definitions/564.html>
