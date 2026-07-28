# Redis Security Best Practices

Controls map to OWASP Top 10 2025, ASVS 5.0 chapters, and CWE where applicable. Replace example names and secret references; do not copy the values.

## Make the listener private first

`A01:2025` · `A02:2025` · ASVS V12/V13 · CWE-284

```yaml
# Vulnerable: Docker publishes Redis on every host interface
services:
  redis:
    image: redis:8.0
    ports: ["6379:6379"]
```

```yaml
# Fixed: application and Redis share an internal network; no host port exists
services:
  redis:
    image: redis:8.0
    networks: [backend]
    expose: ["6379"]
networks:
  backend:
    internal: true
```

Why this works: only workloads on `backend` can initiate a connection. For local-only diagnostics, bind `127.0.0.1:6379:6379`, never `0.0.0.0`. Protected mode and authentication remain defence in depth.

## Give each role a named ACL user

`A01:2025` · `A02:2025` · ASVS V2/V13 · CWE-284/CWE-306

```conf
# Vulnerable: every client enters as a powerful shared default user
user default on nopass ~* &* +@all
```

```conf
# Fixed: start deny-by-default; create identities around their key/channel contracts
user default off resetkeys resetchannels -@all
user web-cache on #<sha256-from-secret-manager> resetkeys ~cache:* resetchannels -@all +@read +@write -@dangerous -@admin
user worker on #<sha256-from-secret-manager> resetkeys ~jobs:* &jobs:* -@all +@list +@stream +@pubsub +ping
```

Why this works: a cache client cannot read queue keys or alter server configuration. Use `ACL CAT` against the running version, then reduce categories to individual commands if a category is broader than the contract. `+@all` includes future module commands; do not use it for runtime identities.

## Encrypt every non-local connection and verify the peer

`A02:2025` · `A04:2025` · ASVS V12/V14 · CWE-295/CWE-319

```php
// Vulnerable: plaintext URL; an observer can recover AUTH and data
'url' => env('REDIS_URL', 'tcp://cache.internal:6379'),
```

```php
// Fixed: secret value is supplied at deployment, TLS remains verified
'url' => env('REDIS_URL'), // tls://cache.internal:6380?database=1
'scheme' => 'tls',
'username' => env('REDIS_USERNAME'),
'password' => env('REDIS_PASSWORD'),
'context' => ['ssl' => ['verify_peer' => true, 'verify_peer_name' => true]],
```

Why this works: encryption without certificate and hostname validation is still vulnerable to an active network attacker. Keep credentials out of source and route their delivery/rotation through `secrets-management`.

## Separate security state from disposable cache

`A06:2025` · `A10:2025` · ASVS V8/V11/V13 · CWE-400/CWE-770

```conf
# Vulnerable: sessions and image cache share LRU eviction
maxmemory 2gb
maxmemory-policy allkeys-lru
```

```text
# Fixed design
cache Redis/Valkey: `cache:*`, bounded `allkeys-lru`, misses rebuild from source
security-state Redis/Valkey: `sess:*`, `revoke:*`, `limit:*`, `otp:*`, `idem:*`, bounded capacity and explicit no-eviction/fail-closed behavior
```

Why this works: cache pressure cannot silently delete a revocation marker or limiter counter. `maxmemory` must still be set; for security state, a rejected write is a visible failure to handle, not a reason to evict a control.

## Persist and back up according to the data value

`A04:2025` · `A10:2025` · ASVS V11/V14/V16 · CWE-312/CWE-778

```conf
# Vulnerable: sensitive state has snapshots readable by broad host users
save 900 1
# data directory and backup bucket use shared broad access
```

```text
# Fixed operating rule
- restrict Redis data/AOF/ACL/TLS files to the service account and controlled administrators
- encrypt backup storage and transfers; retain and test off-host restores
- select RDB/AOF and fsync policy from tolerated data loss
- document that RDB is point-in-time, while default AOF everysec can lose roughly one second on disaster
```

Why this works: snapshots and AOF are copies of application state. An encrypted disk alone does not restrict backup readers or prove recovery works.

## Treat modules and scripts as code surfaces

`A02:2025` · `A03:2025` · `A08:2025` · ASVS V13/V15 · CWE-94/CWE-829

```typescript
// Vulnerable: request data becomes server-side program text
await redis.eval(`return redis.call('GET', '${req.query.key}')`, 0);
```

```typescript
// Fixed: reviewed immutable script; keys/arguments are passed separately
const script = "return redis.call('GET', KEYS[1])";
await redis.eval(script, 1, `cache:${validatedCacheId}`);
```

Why this works: no request bytes change the Lua program. Allow `@scripting` only to the user that needs it. Inventory RedisJSON, Redis Search, RedisBloom, and RedisTimeSeries; patch them, use their ACL categories, scope keys/index prefixes, and re-review ACLs after Redis 8 integration.

## Bound retries and use role-specific failure policy

`A06:2025` · `A10:2025` · ASVS V7/V8/V16 · CWE-400/CWE-770

```typescript
// Vulnerable: outage becomes an unbounded retry storm or an authentication bypass
while (true) {
  try { return await limiter.consume(key); }
  catch { /* try again */ }
}
```

```typescript
// Fixed: short deadline, bounded retries, and explicit caller policy
const result = await withTimeout(limiter.consume(key), 150);
if (!result.ok) return denyRequest(); // limiter/session/revocation decision: fail closed
// A separately classified disposable cache may return a cache miss instead.
```

Why this works: one dependency failure cannot exhaust application resources or remove an authentication control. `brute-force-defense` owns counter policy; this skill owns the backing-store behavior.

## Framework integration: narrow connections, prefixes, and TTLs

`A01:2025` · `A02:2025` · ASVS V2/V13/V14 · CWE-284

- **Laravel:** configure separate named connections/prefixes for cache and queues; use the documented `username`, `password`, `scheme: tls`, timeout/retry/backoff options. Do not let the dynamic `Redis` facade use an administrative ACL user.
- **ASP.NET Core:** give `IDistributedCache` and session an ACL identity restricted to their prefixes. Do not put an authorization decision solely in an evictable cache entry.
- **Spring Boot:** configure the active Lettuce/Jedis client with verified TLS, ACL credentials, bounded timeout/pool/retry settings, and per-role key prefixes. Keep a session or queue identity separate from cache.
- **NestJS:** identify the actual cache/queue adapter; supply TLS/ACL/prefix/TTL/timeout options there. The generic `cache-manager` abstraction does not secure the remote store for you.
