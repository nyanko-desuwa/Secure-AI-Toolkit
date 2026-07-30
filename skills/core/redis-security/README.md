# Redis Security Skill

## Purpose

Secure **Redis OSS 7.x/8.x** and **Valkey 8.x** where applications meet the datastore: network reachability, ACL identities, transport, persistence, modules, replication, eviction, and operational telemetry. Redis is often called a cache while holding sessions, reset state, queue payloads, and rate-limit counters. This skill makes that distinction visible.

## How It Works

Read [SKILL.md](SKILL.md), identify each key family and deployment boundary, then load only the supporting material required for the review.

```text
SKILL.md                 workflow and severity
README.md                scope and framework integration
checklist.md             pass/fail/N/A verification
best-practices.md        configurations and integration patterns
common-mistakes.md       plausible failures
troubleshooting.md       safe migrations and tradeoffs
prompts.md               task-shaped prompts
references/              source-pinned guidance
examples/README.md       paired examples and incidents
```

## Standards

| Standard | Version | Use here | Verified |
|---|---|---|---|
| OWASP Top 10 | 2025 | A01, A02, A04, A06, A09, A10 risk triage | 2026-07-28 |
| OWASP ASVS | 5.0.0 | V2, V6, V7, V8, V11, V12, V13, V14, V16 verification | 2026-07-28 |
| Redis OSS documentation | Latest, including 8.0 release notes | ACLs, TLS, persistence, replication, Redis 8 ACL/module changes | 2026-07-28 |
| Valkey documentation | Current security page | compatible network, ACL, TLS, protected-mode guidance | 2026-07-28 |
| MITRE CWE | Web catalogue | CWE-200, -269, -284, -306, -312, -400, -532, -770, -778, -798 | 2026-07-28 |

## Deployment Coverage

- **Self-hosted Redis/Valkey** on Linux/VMs: listener, service account, filesystem, persistence, ACL file, TLS, backups
- **Docker Compose**: internal networks, no accidental host publication, mounted config and secret files; image/runtime controls stay in `docker-security`
- **Kubernetes**: Redis-specific ACL/TLS/persistence checks; pod, policy, and admission controls stay in `enterprise/kubernetes-security`
- **Sentinel and Redis Cluster**: separate client, replication, Sentinel, and cluster-bus reachability/authentication reviews
- **Managed services**: AWS ElastiCache/MemoryDB, Azure Managed Redis, and Google Cloud Memorystore. Provider settings differ; verify private access, TLS, encryption, backup access, and identity against the active service plan.

## Framework Integration

These are integration patterns, not a substitute for the framework's current documentation.

| Stack | Use securely | Do not assume |
|---|---|---|
| Laravel | Separate `default`/`cache` connections, unique prefixes, env-backed username/password, `scheme: tls`, bounded retry/backoff; use ACLs that match each driver's keys | Database-number separation is authorization; dynamic `Redis` facade calls are safe by default |
| ASP.NET Core | Configure `IDistributedCache`/session with a TLS-verified, ACL-scoped connection; treat cache contents as untrusted serialization input and keep session lifecycle in `authentication` | A distributed cache is appropriate for all security state or provides durable failover semantics |
| Spring Boot | Configure the current Lettuce/Jedis client with TLS verification, ACL credentials, timeouts, bounded pooling/retries; scope `RedisTemplate` keys by tenant/role | A single `RedisTemplate` identity should reach cache, session, queue, and admin keys |
| NestJS | Use a maintained Redis store/queue adapter with `rediss` or TLS options, ACL-scoped credentials, prefixes, timeout/retry caps, and explicit cache TTLs | `cache-manager` itself selects a secure Redis store or validates TLS automatically |

Laravel documents username/password, separate connections, prefixes, TLS schemes, and bounded client retry/backoff. Its facade can dispatch Redis commands dynamically, so ACLs must constrain the runtime user. The NestJS cache page is generic; verify the chosen adapter's current TLS and credential options before implementation.

## Real Incidents and Failure Shapes

These cases describe defensive lessons, not reproduction steps.

1. **Exposed port 6379** - Redis itself warns that a public listener can accept destructive commands such as `FLUSHALL`. Private network reachability is the primary control; protected mode is a fallback.
2. **Configuration/file-write abuse** - Redis documents that a client able to use `CONFIG` can change working directory and dump filename, creating a host-compromise path under the Redis service account. Deny administration to runtime ACL users and run an unprivileged service account.
3. **Destructive deletion/ransomware-style events** - a broad credential or public listener lets an attacker erase data. Separate disposable cache from durable security state, restrict destructive commands, maintain tested off-host backups, and alert on abnormal administration.
4. **Published Docker service** - `ports: ["6379:6379"]` exposes a Redis container on every host interface by default. Use internal Docker networks; only bind a justified local development port to loopback.
5. **Managed cache reachable from the wrong network** - managed encryption does not make a broad VPC/Security Group safe. Verify the actual subnet, private endpoint, access group, ACL/auth mode, and backup readers.

## Limitations

- This skill cannot prove a listener is not reachable, TLS negotiated, an ACL loaded, or a backup encrypted without live/provider evidence.
- Redis OSS, Valkey, Redis 8 integrated components, Redis Stack, and managed offerings do not expose identical commands or controls. Verify the running version and provider documentation.
- Lua/function and module guidance reduces attack surface; it does not make unpatched server code safe. Track advisories and patch promptly.
- Redis replication is asynchronous. This skill cannot turn a session/revocation design into strongly consistent storage.
- Examples cover Laravel, ASP.NET Core, Spring Boot, and NestJS by integration pattern; exact package and option names change.

## Security Notes

All hosts, credentials, certificates, URLs, ACL passwords, and data in examples are synthetic. Every vulnerable block is labelled and immediately paired with a fix. Do not copy vulnerable blocks.

## References

- Redis security - <https://redis.io/docs/latest/operate/oss_and_stack/management/security/>
- Redis ACL - <https://redis.io/docs/latest/operate/oss_and_stack/management/security/acl/>
- Redis persistence - <https://redis.io/docs/latest/operate/oss_and_stack/management/persistence/>
- Redis replication - <https://redis.io/docs/latest/operate/oss_and_stack/management/replication/>
- Redis OSS 8 release notes - <https://redis.io/docs/latest/operate/oss_and_stack/stack-with-enterprise/release-notes/redisce/redisos-8.0-release-notes/>
- Valkey security - <https://valkey.io/topics/security/>
