# Cache and Distributed Limit Controls

Caching and quotas are shared security boundaries. A cache key is an authorization decision about
which callers may see a value. A distributed limiter is an actor quota that must remain atomic while
requests move between replicas.

## Cache Controls

1. Authorize the origin lookup using the verified tenant/actor.
2. Construct a canonical key with tenant, resource, representation version, locale, and every
   authorization-relevant variation.
3. Cache only allowlisted successful representations and content types.
4. Reject oversized values and enforce total byte/entry caps plus TTL.
5. Use negative caching only for domain-safe not-found results and a shorter TTL.
6. Treat TTL as stale authorization/data time, not as invalidation proof.
7. Use a bounded single-flight lock with expiry for expensive fills.
8. Purge old namespaces when changing key semantics or after poisoning.
9. Measure hit/miss, fill calls, fill wait, entries, bytes, evictions, stale serves, and errors.

Never put secrets, session tokens, or rapidly revoked entitlements in a broad shared cache. Encryption
protects storage confidentiality; it does not stop a correct-looking but cross-tenant key from serving
the wrong plaintext after decryption.

## Key Review

```text
v3:tenant:{tenant_id}:actor-scope:{scope_hash}:invoice:{invoice_id}:view:{summary|detail}
```

Use opaque, bounded identifiers. Do not concatenate arbitrary JSON or raw query strings. If a user
can choose a filter, parse it into an allowlisted ordered structure and cap dimensions before hashing.
Log only a key fingerprint and policy scope, not sensitive values.

## Distributed Rate-Limit Controls

- Actor identity comes from verified authentication. Pre-auth keys use a trusted edge-observed IP.
- The edge strips incoming `X-Forwarded-*`, identity, and quota headers before adding its own values.
- Use an atomic increment plus expiry. Set expiry on the first increment and handle clock/window
  semantics explicitly.
- Key by operation as well as actor. A cheap read and a paid export do not share one budget.
- Test traffic distributed over every replica and region. Report aggregate accepted requests.
- Decide limiter-store failure: fail closed for expensive or sensitive actions; bounded local fallback
  only for low-risk paths, with an alert and short TTL.
- Bound key cardinality, retention, and store memory. An attacker-controlled key is a resource input.

## Runtime Cost and When Not to Use

A shared cache costs serialization, memory, eviction work, and possibly network latency; it can reduce
origin load and increase staleness. A distributed limiter costs a network call, shared-store capacity,
and a new failure dependency. Do not add either without a measured bottleneck. Do not use a shared
cache where authorization must reflect revocation immediately. Do not use a distributed limiter for
an offline fixed-size job with no shared caller population; use a local semaphore.

## Sources

- OWASP API Security Top 10 2023, API4 — <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- OWASP ASVS 5.0 project — <https://owasp.org/www-project-application-security-verification-standard/>
- OWASP Top 10 2025 — <https://owasp.org/Top10/2025/>
- CWE-400 — <https://cwe.mitre.org/data/definitions/400.html>
- CWE-770 — <https://cwe.mitre.org/data/definitions/770.html>
