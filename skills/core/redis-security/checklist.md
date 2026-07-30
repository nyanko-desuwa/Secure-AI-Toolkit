# Redis Security Checklist

Mark every relevant item **pass**, **fail**, or **not applicable**. Every N/A needs a reason and evidence is a configuration line, provider setting, command output, or deployment manifest - not an assumption.

## Stop conditions

- [ ] [critical] No Redis/Valkey TCP port or Unix socket is reachable by untrusted clients (A01/A02, CWE-284)
- [ ] [critical] No runtime identity can use broad administration, replication control, module loading, or `FLUSH*` (A02, CWE-269)
- [ ] [critical] Sensitive sessions, tokens, OTPs, queues, or backups are not readable without an authorized ACL identity (A01/A04, CWE-200)
- [ ] [recommended] Redis/Valkey runs as an unprivileged dedicated account where self-hosted (A02, CWE-250)

## Reachability and transport

- [ ] [critical] `bind`, firewall/security group, private endpoint, Kubernetes Service, and Docker port mappings allow only intended clients
- [ ] [critical] Protected mode is not disabled as a substitute for network isolation
- [ ] [critical] TLS is enabled and certificate/hostname validation is configured for every non-local client path, replica/Sentinel path, and cluster bus where supported (A02/A04, CWE-295)
- [ ] [critical] Plaintext fallback, insecure TLS options, and client-side `verify_peer: false` equivalents are absent
- [ ] [recommended] Unix socket ownership/mode allows only the service principals that need it

## ACLs and administrative surfaces

- [ ] [critical] Each application role has a named ACL user, long generated secret, only required command categories, key patterns, and Pub/Sub channel patterns (A01/A02, CWE-284/306)
- [ ] [critical] The `default` user is disabled or cannot grant unintended application access; `requirepass` is not the only production authorization control
- [ ] [critical] Runtime users lack `@admin`, `@dangerous`, `ACL`, `CONFIG`, `MODULE`, `DEBUG`, `MONITOR`, `SLOWLOG`, `SHUTDOWN`, `REPLICAOF`, and destructive commands unless documented and controlled
- [ ] [critical] ACL file/config is readable only by Redis administration and secrets are delivered/rotated through `secrets-management` (A02/A04, CWE-798/732)
- [ ] [recommended] Redis 8 ACLs were re-reviewed for Search, JSON, TimeSeries, Bloom and related integrated command categories

## Modules, scripts, and commands

- [ ] [recommended] Installed modules/components are inventoried, version-patched, necessary, and sourced from an approved distribution (A03/A08)
- [ ] [recommended] RedisJSON, Redis Search, RedisBloom, and RedisTimeSeries permissions use their specific ACL categories/key patterns where applicable
- [ ] [critical] User input is never concatenated into Lua/function bodies; scripts/functions are reviewed, versioned, and not granted more keys/commands than required (A05/A08)
- [ ] [recommended] `MONITOR`, slow logs, and debugging output are restricted and redacted before export (A04/A09, CWE-532)

## Data, persistence, and backups

- [ ] [recommended] Key families are classified as cache, session, token/revocation, OTP, limiter, idempotency, queue, Stream, or Pub/Sub
- [ ] [recommended] Sensitive/security-state keys have explicit TTL, namespace, and retention decisions; identifiers in keys are minimized or HMACed where snapshots would reveal a directory (A04, CWE-312)
- [ ] [critical] RDB/AOF/replica files, snapshots, and backups have access control, encryption where stored/transferred, retention, off-host copies, and restore tests (A04, CWE-312)
- [ ] [recommended] Persistence choice and tolerated write loss match the data role; RDB-only snapshots are not presented as zero-loss durability
- [ ] [recommended] Backups are not copied from an AOF rewrite without the documented consistency procedure

## Availability and role separation

- [ ] [recommended] `maxmemory`, eviction policy, client limits, timeouts, retry/backoff, connection pools, value sizes, key growth, and Stream retention are bounded (A06, CWE-400/770)
- [ ] [recommended] Sessions, revocation, OTP, limiter, and idempotency state cannot be silently evicted by disposable cache growth; separate instance/cluster/policy is used when needed
- [ ] [critical] Outage behavior is explicit: fail closed for security decisions; cache-only degradation is limited and measured
- [ ] [recommended] Replication/failover assumptions are documented; security-critical writes account for asynchronous replication and stale replicas
- [ ] [recommended] Replicas remain read-only and are not treated as safe public read endpoints

## Sentinel, Cluster, containers, and managed service

- [ ] [recommended] Sentinel/replica identities have only the documented minimum commands and isolated transport
- [ ] [critical] Cluster node, client, replication, Sentinel, and bus addresses are reachable only to intended peers
- [ ] [critical] Docker deployment uses an internal network and omits `ports:` unless explicitly required; mounted config, ACL, TLS, and data files have restrictive ownership
- [ ] [recommended] Managed service private networking, encryption, auth/ACL mode, backups, logs, and provider IAM/access groups are verified in the active account

## Monitoring and recovery

- [ ] [recommended] Alerts cover ACL/auth failures, ACL/config/module/replication changes, persistence failures, backup failures, evictions, memory pressure, latency, blocked scripts, and failover
- [ ] [recommended] Redis URLs, ACL credentials, `AUTH`/`HELLO` data, command arguments, `MONITOR`, and sensitive slow-log fields are excluded from application/central logs
- [ ] [recommended] A tested response exists for unauthorized access, credential exposure, snapshot exposure, destructive commands, and service outage; credential rotation and backup restore are included
