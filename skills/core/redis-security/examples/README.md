# Redis Security Examples

Eight defensive pairs. Each vulnerable block is labelled and paired with a fix. Hosts, identities, and values are synthetic. A completed [Redis-backed authentication/limiter threat model and security design review](redis-auth-limiter-design-review.md) shows how Redis, authentication, limiter, secrets, logging, and architecture ownership work together.

## Exposed Docker listener

`A01:2025` · `A02:2025` · ASVS V12/V13 · CWE-284

```yaml
# Vulnerable: publishes Redis to every host interface
services:
  redis:
    image: redis:8.0
    ports: ["6379:6379"]
```

```yaml
# Fixed: no public port; application reaches an internal network only
services:
  redis:
    image: redis:8.0
    networks: [app-private]
networks:
  app-private:
    internal: true
```

An internet-reachable Redis service can disclose data or accept destructive commands. Docker port publishing is not needed for service-to-service traffic.

## Shared default user

`A01:2025` · `A02:2025` · ASVS V2/V13 · CWE-284/CWE-306

```conf
# Vulnerable: any client receives all keys, channels, and commands
user default on nopass ~* &* +@all
```

```conf
# Fixed: cache role cannot administer Redis or reach non-cache keys
user default off resetkeys resetchannels -@all
user cache on #<managed-sha256-secret> resetkeys ~cache:* resetchannels -@all +get +set +del +expire +ttl +ping
```

A generated secret and narrow contract limit a stolen cache credential to cache keys and ordinary operations.

## Plaintext connection and disabled verification

`A02:2025` · `A04:2025` · ASVS V12/V14 · CWE-295/CWE-319

```php
// Vulnerable: credentials and data travel as plaintext
'url' => 'tcp://cache.internal:6379',
```

```php
// Fixed: secret reference resolves at deploy time; TLS peer checks stay enabled
'url' => env('REDIS_URL'),
'scheme' => 'tls',
'context' => ['ssl' => ['verify_peer' => true, 'verify_peer_name' => true]],
```

TLS is only a control when the client rejects the wrong certificate and hostname.

## Security state evicted by cache traffic

`A06:2025` · `A10:2025` · ASVS V8/V11/V13 · CWE-400/CWE-770

```conf
# Vulnerable: image-cache churn can remove limiter/session/revocation keys
maxmemory 512mb
maxmemory-policy allkeys-lru
```

```text
# Fixed: use separate capacity and eviction decisions
cache: allkeys-lru, rebuildable `cache:*`
security state: noeviction/bounded writes, `sess:*`, `limit:*`, `revoke:*`, `otp:*`, `idem:*`
```

The secure form makes control failure observable rather than silently forgetting state that blocks abuse.

## Application role can reconfigure the server

`A02:2025` · ASVS V13 · CWE-269

```conf
# Vulnerable: web identity includes every administrative operation
user web on #<managed-sha256-secret> ~app:* +@all
```

```conf
# Fixed: deny all first; add only the named data operations needed
user web on #<managed-sha256-secret> resetkeys ~app:* resetchannels -@all +get +set +del +expire +ttl +ping
```

`+@all` includes admin and module commands. A web request path has no reason to change configuration, load a module, alter replication, or flush data.

## Request-built Lua script

`A05:2025` · `A08:2025` · ASVS V5/V15 · CWE-94

```typescript
// Vulnerable: request bytes become executable Redis script text
await client.eval(`return redis.call('GET', '${request.query.key}')`, 0);
```

```typescript
// Fixed: a reviewed script uses declared key/argument positions
const script = "return redis.call('GET', KEYS[1])";
await client.eval(script, 1, `cache:${allowlistedId}`);
```

The fixed form prevents input from changing the program. The ACL still restricts the script's user to its intended key namespace.

## Sensitive Redis observability exported raw

`A04:2025` · `A09:2025` · ASVS V7/V16 · CWE-532

```typescript
// Vulnerable: MONITOR/slow-log command arguments reach central logs
logger.info(await admin.monitor());
```

```typescript
// Fixed: restrict diagnostic ACLs and emit redacted aggregate telemetry
metrics.increment("redis_acl_denied", { role: "cache" });
metrics.gauge("redis_evicted_keys", info.evicted_keys);
```

Command arguments can contain tokens, user identifiers, and queue payloads. Aggregate telemetry preserves detection value without copying sensitive state.

## Redis 8 module/category upgrade

`A01:2025` · `A02:2025` · ASVS V2/V13 · CWE-284

```conf
# Vulnerable: an inherited ACL becomes broader after Redis 8 integrates modules
user search-reader on ~tenant-a:* +@read
```

```conf
# Fixed: re-review categories and scope keys/index prefixes for the deployed version
user search-reader on resetkeys ~tenant-a:* resetchannels -@all +@search +@read
```

Redis 8 changed existing ACL category membership for integrated Search, JSON, TimeSeries, and probabilistic commands. Test the real query/index contract and restrict the user to its tenant prefix.

## Real incident lessons

1. **Public listener:** Redis documentation warns that an outside client able to reach the port can erase a whole dataset with `FLUSHALL`. Private reachability is the first control.
2. **Configuration/file-write path:** Redis documents that `CONFIG` can change the working directory and dump filename; runtime identities must not hold it, and the service account must be unprivileged.
3. **Destructive deletion:** broad credentials turn deletion into a recovery event. Restrict destructive operations, alert, keep encrypted off-host backups, and rehearse restoration.
4. **Docker publication:** `6379:6379` is a deployment error when only containers need Redis. Use internal networks and avoid host ports.
5. **Managed-cache exposure:** provider encryption does not repair a broad access group. Verify the effective private network and authorized principals.
