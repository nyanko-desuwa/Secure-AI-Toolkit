---
name: redis-security
description: 'Secure Redis OSS 7.x/8.x and Valkey 8.x at the service boundary. Covers exposure, ACLs, TLS, persistence, modules, Sentinel/Cluster, sessions, cache, queues, and monitoring. Triggers: "Redis", "Valkey", "redis.conf", "redis ACL", "requirepass", "rediss", "ElastiCache", "Memorystore", "RedisJSON", "bảo mật Redis", "Redis ACL".'
allowed-tools: Read, Glob, Grep, WebSearch, WebFetch
---

# Redis Security

Redis is trusted infrastructure, not a public API. A listener that accepts an untrusted client can disclose sessions and tokens, erase the dataset, or alter service configuration. This skill owns the Redis/Valkey **service boundary**, not the application policy that uses it.

## When to Use

- Writing or reviewing `redis.conf`, ACL files, TLS, Docker Compose, Helm values, or managed-cache configuration
- Adding a Redis/Valkey session store, cache, queue, Streams/Pub/Sub, idempotency store, OTP store, or rate-limit backend
- Reviewing `REDIS_URL`, `rediss://`, ACL credentials, port `6379`, Sentinel, Cluster, replicas, RDB, or AOF
- Enabling RedisJSON, Redis Search, RedisBloom, or RedisTimeSeries
- Investigating evictions, unexpected `FLUSH*`, ACL failures, failover, persistence failures, or exposed snapshots

## When NOT to Use

| Request shape | Use instead |
|---|---|
| Cookie flags, session rotation, OAuth/JWT or token lifecycle | `authentication` |
| What to count, thresholds, lockout, or friction for guessing | `brute-force-defense` |
| Cache authorization semantics, cache poisoning, or capacity architecture | `architecture/scalability` |
| Message delivery design, consumer topology, or event contracts | `architecture/event-driven` |
| Container image/runtime hardening | `docker-security` |
| VPC/IAM/Terraform policy beyond the Redis service | `cloud-security` |
| Secret storage, rotation, or leak response | `secrets-management` |
| Log retention/SIEM design | `logging-audit` |

## Standards This Skill Maps To

| Standard | Use it for | Version here |
|---|---|---|
| OWASP Top 10 | Misconfiguration, authorization, data protection, resource limits, logging, and safe failure | 2025 |
| OWASP ASVS | Configuration, authentication, data protection, availability, and logging verification | 5.0.0 |
| MITRE CWE | Concrete access-control, secret, backup, resource, and logging weaknesses | Web catalogue, checked 2026-07-28 |

Source-specific facts are pinned in [references/](references/).

## Workflow

### 1. Classify the Redis role and data

List every key family and what a hit is worth: disposable cache, session, revocation marker, OTP replay marker, limiter, idempotency claim, queue payload, Stream, or Pub/Sub message. A cache can tolerate a miss; a limiter, session, or revocation store often cannot. Do not place them in the same eviction domain without an explicit risk decision.

### 2. Establish reachability

Trace every listener, socket, service, Security Group/firewall, port publication, and private endpoint. Redis and Valkey are designed for trusted clients. `bind`, protected mode, and `requirepass` are defence in depth; they do not make a public listener safe. See [best-practices.md](best-practices.md#make-the-listener-private-first).

### 3. Authorize the exact client

Use named ACL users, a service-specific key prefix, necessary command categories, and channel patterns. Disable or avoid the broad `default` user for applications. Runtime users do not receive `@admin`, `@dangerous`, `ACL`, `CONFIG`, `MODULE`, `MONITOR`, `SHUTDOWN`, replication control, or `FLUSH*`. `requirepass` only sets a password for the shared `default` user; it is not least privilege.

Re-review ACLs during a Redis 8 upgrade: integrated Search, JSON, TimeSeries, and probabilistic commands changed the meaning of existing categories. See [references/redis-valkey.md](references/redis-valkey.md#redis-8-modules-and-acls).

### 4. Protect data and failure behavior

Require verified TLS over any network not wholly confined to the same host. Protect ACL files, RDB/AOF files, snapshots, replica traffic, and backups as sensitive data. Set TTLs for security state. Choose durable storage and failover behavior from the data role, not cache folklore. Redis replication is asynchronous; acknowledged writes can still be lost at failover.

### 5. Bound and observe

Set memory, client, retry, timeout, value, key-growth, Stream-retention, and connection-pool limits. `maxmemory` without an eviction decision moves the failure into production. Monitor ACL failures, destructive/admin activity, replication changes, persistence errors, evictions, latency, and script failures. Never ship Redis URLs, `AUTH` material, `MONITOR`, or sensitive command values to logs.

### 6. Verify and report

Run [checklist.md](checklist.md). For each finding state the key family affected, reachability, ACL/user, attacker outcome, standards mapping, and what live configuration remains unverified.

## Security Levels

- **Critical** — public or unauthorized listener; accessible administrator/destructive path; unauthorized replication/configuration change; exposed sensitive snapshot or backup
- **High** — shared/default broad user, missing ACL isolation, plaintext across a shared network, security-state eviction, no persistence/failover plan for security state
- **Medium** — certificate validation not proven, broad module permissions, unbounded data/key growth, missing alerts for ACL/persistence/evictions
- **Low** — defence-in-depth gap such as overly broad slow-log visibility with no route to sensitive values

Exploitability and blast radius override the ladder. A loopback-only cache without persistence is not High merely because persistence is absent.

## Related Skills

- `authentication` — session and token policy; this skill secures its Redis store
- `brute-force-defense` — limiter policy; this skill secures the counter store
- `secrets-management` — credentials, certificates, rotation, and exposure response
- `docker-security`, `cloud-security`, `advanced/network-security` — deployment boundary controls
- `logging-audit`, `advanced/incident-response` — telemetry and response
- `architecture/scalability`, `architecture/event-driven` — cache and broker semantics

## Supporting Files

- [README.md](README.md) — scope, platforms, framework integration, limitations
- [checklist.md](checklist.md) — deployment and role-specific verification
- [best-practices.md](best-practices.md) — secure patterns
- [common-mistakes.md](common-mistakes.md) — tempting but unsafe fixes
- [troubleshooting.md](troubleshooting.md) — migration and operational tradeoffs
- [prompts.md](prompts.md) — scoped prompts and anti-patterns
- [references/](references/) — source summaries and version pins
- [examples/README.md](examples/README.md) — eight vulnerable/fixed pairs and incidents
