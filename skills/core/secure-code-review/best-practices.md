# Review Practices

Patterns for reviewing code, not for writing it. Each one names the standard it serves.
Controls for new code are in `core/owasp/best-practices.md`.

## Hunt by sink, walk back to the source

OWASP Code Review Guide 2.0, section on transactional analysis

Source-first review means reading every handler and following every variable. Sink-first
review means grepping a fixed list of dangerous calls and walking backwards. The second
finishes, because the sink list is short and stable while the source list is the whole app.

```bash
# Sinks first, across the whole tree, then narrow to the diff
rg -n 'execute\(|executemany\(|\.raw\(' --type py
rg -n 'shell=True|os\.system|child_process\.exec[^F]' -g '!test*'
rg -n 'innerHTML|dangerouslySetInnerHTML|v-html|\|\s*safe' -g '*.{ts,tsx,vue,html}'
rg -n 'pickle\.loads|yaml\.load\(|ObjectInputStream|unserialize\(' 
```

For each hit, answer one question: what value reaches this, and who chose it? If the answer is
a server constant, close it and move on. That single question eliminates most hits in under a
minute, which is why the review finishes.

Where sink-first misses things: authorization. There is no dangerous call to grep for when the
weakness is an absent check. For A01 you must enumerate handlers and check each one, which is
why the map in step 2 exists.

## Read authorization at the data layer, not the route

`A01:2025` · `API1:2023` · `CWE-639` · ASVS V8

A route decorator answers "is someone logged in". Review it, then ignore it, and go find where
the row is fetched. That is where the actual decision lives or does not.

```python
# Vulnerable: the guard is real, the authorization is missing
@router.get("/invoices/{invoice_id}")
@require_login
def get_invoice(invoice_id: int, actor: User = Depends(current_user)):
    return db.query(Invoice).get(invoice_id)
```

```python
# Fixed: the actor is part of the lookup
@router.get("/invoices/{invoice_id}")
@require_login
def get_invoice(invoice_id: int, actor: User = Depends(current_user)):
    invoice = (
        db.query(Invoice)
        .filter(Invoice.id == invoice_id, Invoice.owner_id == actor.id)
        .one_or_none()
    )
    if invoice is None:
        raise HTTPException(404)
    return invoice
```

Why this closes it: there is no branch to forget, and a missing row and someone else's row
produce the same response, so the endpoint stops confirming which IDs exist.

Review habit that catches the variant nobody catches: check update and delete separately. Teams
scope the read query and leave `DELETE FROM invoices WHERE id = ?` unscoped, because the delete
handler was written a month later.

## Check the sink's real behaviour before believing it

`A05:2025` · ASVS V1

The same-looking call is safe or unsafe depending on the argument shape. Verify, do not
pattern-match on the function name.

| Looks similar | Safe | Unsafe |
|---|---|---|
| psycopg | `cur.execute(sql, params)` | `cur.execute(sql % params)` |
| Django ORM | `.filter(name=x)` | `.extra(where=[f"name='{x}'"])` |
| Node pg | `client.query(text, values)` | `client.query(\`...${x}\`)` |
| React | `{value}` | `dangerouslySetInnerHTML={{__html: value}}` |
| Jinja | `{{ value }}` | `{{ value|safe }}`, `render_template_string` |
| subprocess | `run([cmd, arg])` | `run(f"{cmd} {arg}", shell=True)` |
| JJWT / jsonwebtoken | `verify(t, key, {algorithms:[...]})` | `decode(t)` with no verify |

A finding that says "uses `execute`, therefore SQL injection" is wrong more often than right.
Read the second argument.

## Do not accept a framework default on reputation

`A02:2025` · ASVS V13

"Django escapes templates" and "the ORM parameterizes" are true until someone turns them off,
and off is one keyword away. Confirm three things: the version in the lockfile, the setting in
the config, and the call site.

```bash
rg -n 'autoescape\s*=\s*False|MarkupSafe|\{%\s*autoescape\s+off' 
rg -n 'csrf_exempt|@CrossOrigin|cors\(\{.*origin:\s*true|rejectUnauthorized:\s*false'
rg -n '"(django|express|spring-boot|laravel/framework)"' package.json requirements*.txt
```

If you cannot confirm it from the code or from the pinned version's documentation, the finding
says "unverified" rather than either "safe" or "vulnerable". Guessing in the safe direction is
how a real bug ships.

## Separate a vulnerability from a smell, explicitly

`A06:2025` · OWASP Code Review Guide 2.0

A vulnerability needs a path: an attacker-controllable source, a reachable sink, and an impact
you can name. Remove any one of the three and you have a smell. Both are worth saying; only one
belongs in the findings list.

| Property | Vulnerability | Smell |
|---|---|---|
| Source | Attacker controls it | Server constant, enum, or already-typed value |
| Reachability | A request gets there | Dead code, test fixture, unrouted handler |
| Impact | Nameable and bounded | "Could be a problem if someone later..." |
| Evidence | A concrete input | A keyword match |

The report format that keeps this honest:

```text
## Findings
1. [High] Unscoped invoice lookup — CWE-639 — src/api/invoices.py:41
   Exploit: GET /invoices/8123 as any logged-in user returns another tenant's invoice.

## Observations (no exploitation path found)
- src/util/legacy.py:12 builds SQL with % formatting. Only caller passes a module-level
  constant; no request path reaches it. Worth deleting, not a finding today.
```

The second block is the point of the skill. Padding the findings list with the first block's
formatting applied to the second block's evidence is what makes authors ignore reviews.

## Refactor narrowly, and prove it with a test

`A08:2025` · ASVS V15

A security fix that also renames three functions cannot be reviewed, cannot be reverted
cleanly, and will not get merged today. Change the vulnerable behaviour and stop.

Order of preference, most to least contained:

1. Add the missing constraint or parameter at the sink.
2. Replace the unsafe API with the safe one from the same library.
3. Introduce a small helper and route the one call site through it.
4. Move the check to another layer. This is a design change — say so and get agreement.

The proof is a test that fails on the pre-fix code:

```python
# Regression test for CWE-639. Fails before the ownership filter is added.
def test_invoice_of_another_user_is_not_readable(client, alice, bob, invoice_of_bob):
    resp = client.get(f"/invoices/{invoice_of_bob.id}", headers=auth(alice))
    assert resp.status_code == 404          # not 403: no existence disclosure
    assert "total" not in resp.text          # no partial leak in the error body
```

```python
# Regression test for CWE-22. Encoded traversal, because the plain form is the one
# everybody remembers to block.
@pytest.mark.parametrize("name", [
    "../../etc/passwd",
    "..%2f..%2fetc%2fpasswd",
    "....//....//etc/passwd",
    "/etc/passwd",
    "uploads/../../etc/passwd",
])
def test_download_rejects_traversal(client, name):
    assert client.get("/download", params={"name": name}).status_code == 404
```

Assert the security property, not the absence of a crash. `assert resp.status_code != 500` is
satisfied by a handler that returns the file with a 200.

Run the test against the unfixed code first. A regression test that passes before the fix is
testing something else, and this happens often enough to be worth the extra minute.

## Reviewing AI-generated code

`A06:2025` · ASVS V15

Generated code fails from plausibility rather than haste. It compiles, names things well, and
puts the control one layer away from where it would work. Reviewers relax on well-formatted
code, which is exactly the wrong reflex here.

### Auth check in the wrong layer

`A01:2025` · `CWE-862`

```tsx
// Vulnerable: this is a redirect, not an access control
export default function AdminPanel() {
  const { user } = useSession();
  useEffect(() => {
    if (!user?.isAdmin) router.push("/login");
  }, [user]);
  return <UserTable />;
}
```

The check runs in the browser. `curl` on the API route that `UserTable` calls skips it
entirely. When you see a client-side guard, your next action is to open the API route and look
for the server-side check. If it is absent, the finding is on the route, not on the component.

```ts
// Fixed: the server route decides, and the client guard is cosmetic
export async function GET(req: Request) {
  const session = await getServerSession();
  if (!session?.user?.isAdmin) {
    return Response.json({ error: "not_found" }, { status: 404 });
  }
  return Response.json(await listUsers());
}
```

### Validation standing in for encoding

`A05:2025` · `CWE-89`

```python
# Vulnerable: the schema is real and the query is still injectable
class ReportQuery(BaseModel):
    table: str
    since: date

def run(q: ReportQuery):
    return db.execute(f"SELECT * FROM {q.table} WHERE created_at > '{q.since}'")
```

`str` is not a constraint. The schema makes the diff read as validated, which is why this
survives review. Validation shrinks the input space; encoding at the sink is what makes the
sink safe.

```python
# Fixed: identifier through an allowlist, value through a parameter
TABLES = {"orders": "orders", "invoices": "invoices"}

class ReportQuery(BaseModel):
    table: Literal["orders", "invoices"]
    since: date

def run(q: ReportQuery):
    return db.execute(f"SELECT * FROM {TABLES[q.table]} WHERE created_at > %s", (q.since,))
```

### Fail-open error handling with a resilience comment

`A10:2025` · `CWE-636`

```javascript
// Vulnerable: the comment explains why, and the effect is a bypass
async function canAccess(user, doc) {
  try {
    return await policy.check(user.id, doc.id);
  } catch (err) {
    // Fail open so a policy service outage does not break the app
    return true;
  }
}
```

Making the policy service unreachable becomes the cheapest bypass. Grep for `return true`,
`= true`, and `?? true` inside a `catch` in any file that mentions permission, policy, role, or
tenant.

```javascript
// Fixed: unavailable is not permitted, and it is loud
async function canAccess(user, doc) {
  try {
    return await policy.check(user.id, doc.id);
  } catch (err) {
    logger.error("policy_check_failed", { userId: user.id, docId: doc.id, err });
    throw new ServiceUnavailableError("authorization_unavailable");
  }
}
```

### Invented or version-wrong API surface

`A03:2025` · `CWE-1104`

Generated code cites options that do not exist in the installed version, so the control is a
no-op with no error. Two examples that show up: a `verify_signature` style flag passed to a
library that spells it differently, and a middleware option added in a major version newer than
the lockfile.

The check is mechanical: for every security-relevant option in the diff, confirm the exact
spelling in the version from the lockfile.

```bash
rg -n '"jsonwebtoken"|"jose"|PyJWT|jjwt' package.json package-lock.json requirements*.txt pom.xml
```

A silently ignored keyword argument is worse than a missing one, because the diff looks like
the control is present.

### Copy-shaped duplication

`A01:2025` · `CWE-863`

Generated handlers get produced in batches from one template. When the template's check was
wrong, it is wrong in all of them; when one handler was written by hand later, it is the one
missing the check. Review the set, not the file: list every handler for a resource and compare
their authorization lines side by side. The outlier is the finding.

## Sources

- <https://owasp.org/www-project-code-review-guide/>
- <https://owasp.org/Top10/2025/>
- <https://owasp.org/www-project-application-security-verification-standard/>
- <https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html>
- <https://cheatsheetseries.owasp.org/>
