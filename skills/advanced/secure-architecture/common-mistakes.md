# Common Architecture Mistakes

Design failures that pass code review because no single file is wrong. Each entry: what it looks
like, why it fails, the fix, and why the fix holds.

## The perimeter as the authorization boundary

```yaml
# The gateway is the only place authorization happens
routes:
  - path: /api/*
    require_auth: true
    upstream: http://app-svc:8080
```

`app-svc` is reachable from anything on the pod network, and it trusts whatever arrives. The
gateway answered "is this a valid user" and the design treated that as "this user may read this
row". One SSRF in an unrelated service turns into full data access.

Fix: authorization next to the data, keyed on a verified principal. The gateway stays as one more
layer. `A01:2025`, `CWE-1220`.

Why it works: the enforcement point moves inside the process that owns the row, so no network path
reaches the data without passing it. NIST SP 800-207 phrases the goal as shrinking the implicit
trust zone; a gateway makes that zone the entire cluster.

## Internal means trusted

```python
# Any caller inside the VPC is treated as the platform itself
if request.headers.get("X-Internal-Key") == INTERNAL_SHARED_SECRET:
    actor = Actor(id=request.headers["X-User-Id"], role="admin")
```

Two failures compound. The shared secret proves network position, which is the property you should
stop trusting, and it carries no principal, so the caller names its own user and role.

Fix: mTLS for the channel plus a signed, audience-scoped token for the principal. `A01:2025`,
`CWE-602` where the caller supplies its own role.

Why it works: the caller can no longer assert identity, only present something signed by an issuer
it does not control. Audience scoping means a token for one service does not work at another.

## Tenant filtering in the request path only

```python
# The handler is correct
def list_orders(actor):
    return Order.query.filter_by(tenant_id=actor.tenant).all()

# The nightly job is not
def rebuild_search_index():
    for order in Order.query.all():
        index.upsert(order)
```

The handler is right and the system still leaks, because the index is shared and the job wrote
every tenant's rows into it. The same shape appears in exports, cache warmers, admin tools, and
reports.

Fix: enforce in the database with row-level security, so the predicate cannot be omitted by any
caller. Partition derived stores per tenant. `A01:2025`, `CWE-653`. Working SQL in
[examples/tenant-isolation.sql](examples/tenant-isolation.sql).

Why it works: RLS moves the predicate below every code path. A forgotten filter returns zero rows
instead of another tenant's rows — a visible bug rather than a silent breach.

## Cache keys without a tenant prefix

```python
cache.set(f"user:{user_id}:profile", profile, ttl=300)
```

Correct only while user IDs are globally unique. The moment IDs are per-tenant sequences, or a
tenant is migrated, tenant A's user 7 reads tenant B's user 7.

Fix: put the tenant in the key, and derive it from the verified token rather than a parameter.

```python
cache.set(f"t:{actor.tenant}:user:{user_id}:profile", profile, ttl=300)
```

Why it works: collisions become impossible rather than unlikely. The same rule applies to object
storage prefixes, search index names, and message queue topics.

## Wildcard IAM because the error message asked for it

```hcl
statement {
  actions   = ["s3:*", "dynamodb:*"]
  resources = ["*"]
}
```

This is what an `AccessDenied` at 2am produces. It ships, and now an SSRF in the service can read
the audit bucket and delete the Terraform state.

Fix: enumerate the API calls the code makes, scope resources to ARNs with a prefix, add conditions.
`A01:2025`, `CWE-250`. See [examples/iam-least-privilege.tf](examples/iam-least-privilege.tf).

Why it works: the grant matches the operations that exist in the code, so operations that do not
exist in the code are unavailable to an attacker who owns the process.

The tempting wrong fix is a deny statement listing dangerous actions. Denylists enumerate what you
thought of; new services ship new actions monthly.

## Unset configuration means permissive

```javascript
const requireMfa = process.env.REQUIRE_MFA === "true";
const allowedOrigins = (process.env.CORS_ORIGINS || "*").split(",");
```

A typo in the variable name disables MFA and opens CORS, with no error and no log line. Staging
sets it correctly, so tests pass.

Fix: default to the secure value, name the opt-out so it cannot be enabled by accident, and refuse
to start when a required value is missing. `A02:2025`, `CWE-1188`. Pattern in
[best-practices.md](best-practices.md#secure-defaults).

Why it works: absence of configuration produces a denial or a crash. Both are visible; a silent
wildcard is not.

## Cached allow that outlives the outage

```python
try:
    return policy.check(actor, resource)
except PolicyUnavailable:
    return last_known_decision.get(actor, True)
```

Written to keep the product working during an outage. The result is that an attacker who can keep
the policy service unreachable keeps their access indefinitely, and a revoked user stays permitted.

Fix: bound the cache, deny past the bound, and make the denial loud. `A10:2025`.

Why it works: the bound converts an indefinite grant into a short one. Without a maximum age,
"last known" is a permanent grant with extra steps.

## Layers that fail for the same reason

"We have a WAF, a gateway rule, and input validation — three layers." All three inspect the same
attacker-controlled string with pattern matching. One encoding trick bypasses all three at once.

Fix: choose layers with independent failure modes — traffic shape, signature verification, business
rule on the actor, database predicate, append-only audit. `A06:2025`.

Why it works: independence is the property that makes depth meaningful. Counting correlated
controls overstates coverage, which is worse than knowing you have one layer.

## Admin functionality in the public process

```python
app.include_router(public_router)
app.include_router(admin_router, prefix="/admin")   # same process, same DB credential
```

One authorization bug in a public route reaches admin handlers running with a credential that can
alter schemas and rewrite audit rows.

Fix: separate deployment, separate database role, separate network reachability behind an
identity-aware proxy. `A01:2025`, `CWE-653`.

Why it works: compromising the public process no longer grants admin capability, because the
capability is not present in that process or its credential.

## A shared table used as an API

Service A writes `orders`, service B reads and updates it directly. No schema contract, no
versioning, and B's writes bypass every invariant A enforces.

Fix: one owner per table. Others call an endpoint or consume an event. `A06:2025`.

Why it works: invariants and authorization live with the owner, so there is no path that applies
one without the other. Schema changes stop being a cross-team outage.

## Audit log in the same store, writable by the same role

```sql
GRANT INSERT, UPDATE, DELETE ON audit_log TO app_rw;
```

Whoever compromises the application deletes the evidence. The audit trail exists to survive exactly
that event.

Fix: append-only. Separate role with insert-only grant, no update or delete, and ship to a store the
application cannot reach.

```sql
REVOKE ALL ON audit_log FROM app_rw;
GRANT INSERT ON audit_log TO audit_append;
REVOKE UPDATE, DELETE ON audit_log FROM audit_append;
```

Why it works: the capability to alter history is not held by any identity the application process
can use. `A09:2025`.

## Bypassable audit path

The service records an audit row in the API handler. Background jobs, migrations, and the admin
console mutate the same tables directly and record nothing.

Fix: emit the audit record where the mutation happens — a repository method, a domain event, or a
database trigger — not in the handler. `A09:2025`.

Why it works: coupling the record to the write means a new caller cannot mutate without recording.
Handler-level auditing records only the callers someone remembered.

## One environment's credential works in another

The staging service account has production database access because the connection string was copied
during setup. Staging has weaker access controls and more people in it.

Fix: separate accounts or projects per environment, distinct credentials, and network paths that do
not cross. Verify by attempting a staging-to-production connection and confirming it fails.

Why it works: separation makes lateral movement a new attack rather than a configuration lookup.

## Threat model as a one-off document

Written before the first release, filed, never updated. Six months and four features later it
describes a system that no longer exists.

Fix: model per change, small. The Threat Modeling Manifesto's value is continuous refinement over a
single delivery; the practical version is a paragraph per boundary change in the PR description.

Why it works: a current sketch beats a stale document, because people act on the current one.

## The heroic threat modeler

One security engineer models everything. It does not scale, and it produces models missing the
knowledge held by the people who built the thing.

Fix: the team models, with a specialist consulted on the hard crossings. The Manifesto names Hero
Threat Modeler as an anti-pattern and Varied Viewpoints as the pattern that replaces it.

Why it works: the person who knows the retry logic is the person who knows how it can be abused.

## Privacy left to the last sprint

Personal data spread across the primary database, warehouse, logs, error tracker, and analytics
because nothing said not to. A deletion request now needs a discovery project.

Fix: separate by sensitivity at design time, minimise at every boundary, and set retention per
store. `A02:2025`, `CWE-359`. See
[best-practices.md](best-practices.md#privacy-by-design).

Why it works: identifiers never reach the downstream systems, so deletion touches one store plus a
hash rotation rather than every copy that was ever made.

## A design decision with no record

Someone decided six months ago that support agents can read any account. Nobody remembers whether
that was reasoned or accidental, so nobody will change it.

Fix: an ADR naming the threat, the options, the choice, and the residual risk, with an owner and a
review trigger. Template in [best-practices.md](best-practices.md#security-adrs).

Why it works: it converts an unexamined default into an owned decision with a date on it. Reviews
can then ask whether the context still holds instead of re-deriving the reasoning.

## Sources

- <https://owasp.org/Top10/2025/>
- <https://csrc.nist.gov/pubs/sp/800/207/final>
- <https://www.threatmodelingmanifesto.org/>
- <https://cwe.mitre.org/>
