# Redis Security Prompts

## Beginner

```text
Explain whether this Redis setup is private enough for production. Check who can reach it, whether it needs a username/password and TLS, whether its backups contain user data, and what happens when memory fills. Explain each risk in plain language and mark unknowns.
```

## Developer

```text
Review config/database.php, compose.yaml, redis.conf, and users.acl for a Laravel app that uses Redis for sessions, cache, and queues. Design separate ACL users/prefixes, TLS-verified connections, Docker internal networking, TTLs, eviction policies, retry limits, and a safe session/queue failure policy. Preserve session policy ownership in authentication and queue semantics in event-driven.
```

## Review

```text
Review every Redis/Valkey connection, redis.conf/ACL file, Helm value, Docker port mapping, and managed-cache definition. For each finding give file:line, key family, reachable client, ACL/transport/persistence evidence, OWASP Top 10 2025 category, ASVS chapter, CWE, concrete attacker outcome, severity, and a fixed block. Start with public listeners and runtime admin permissions.
```

## Audit

```text
Audit our Redis OSS 8 and Valkey 8 estates. Produce evidence for private reachability, TLS verification, named least-privilege ACLs, Redis 8 module-category review, RDB/AOF/backup protection, maxmemory/eviction separation, Sentinel/Cluster authentication, and monitoring. Mark every item pass, fail, or N/A with evidence and owner. Do not claim live settings from source code alone.
```

## Framework integration

```text
We use Spring Boot RedisTemplate for cache, Spring Session, and a Redis-backed queue. Propose separate ACL identities/key prefixes, TLS and certificate validation, connection timeout/pool/retry caps, TTL/eviction choices, and failure behavior for each. Show which choices belong to Redis Security versus Authentication, Scalability, and Event-Driven.
```

## Anti-patterns

| Prompt | Problem | Better prompt |
|---|---|---|
| "Is Redis secure?" | No deployment, role, or evidence | Name listener, clients, key families, provider, and required evidence |
| "Add requirepass" | Creates one shared powerful identity | Ask for named ACL users, keys, channels, and command contracts |
| "Expose 6379 for the app" | Treats a datastore as an edge API | Ask for private service discovery/network policy and justified diagnostics access |
| "Use Redis for sessions and cache" | Hides contradictory eviction/failure needs | Ask for separate security-state/cache capacity and outage policies |
| "Enable TLS, ignore certificate errors" | Encrypts while accepting an impostor | Ask for CA, hostname validation, and rollout testing |
| "Fix every Redis CVE" | Ignores reachability and version | Ask for deployed version, enabled modules, exposure, patch, and compensating control |
