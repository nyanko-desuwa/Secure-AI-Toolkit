# Redis OSS and Valkey Security Reference

> Redis OSS documentation and Redis OSS 8.0 release notes checked 2026-07-28. Valkey security page checked 2026-07-28.

## Sources

- Redis security - <https://redis.io/docs/latest/operate/oss_and_stack/management/security/>
- Redis ACL - <https://redis.io/docs/latest/operate/oss_and_stack/management/security/acl/>
- Redis persistence - <https://redis.io/docs/latest/operate/oss_and_stack/management/persistence/>
- Redis replication - <https://redis.io/docs/latest/operate/oss_and_stack/management/replication/>
- Redis OSS 8.0 release notes - <https://redis.io/docs/latest/operate/oss_and_stack/stack-with-enterprise/release-notes/redisce/redisos-8.0-release-notes/>
- Valkey security - <https://valkey.io/topics/security/>

## Reachability, authentication, and TLS

Redis and Valkey describe their security model as trusted clients inside trusted environments. Restrict the TCP port or Unix socket to trusted clients; Redis shows `bind 127.0.0.1` for a single-host case and says a public port can allow `FLUSHALL` to delete the dataset. Redis protected mode activates under documented default conditions (all-interface bind and no password) and accepts loopback requests only; it is a fallback, not a perimeter.

Redis 6+ recommends ACLs with named users and fine-grained permissions. Legacy `requirepass` applies a shared password to the `default` user. Both Redis and Valkey document optional TLS for client connections, replication links, and cluster-bus traffic; Redis notes that unencrypted `AUTH` does not protect against network eavesdropping.

## ACL rules and operational questions

Redis ACL rules can restrict commands, key patterns, and Pub/Sub channel patterns. A default Redis ACL is `user default on nopass ~* &* +@all`; new users begin restrictive. `+@all`/`allcommands` includes future commands loaded by modules. `@admin` includes configuration, replication, debug, monitoring, ACL, and shutdown operations; `@dangerous` includes operations such as FLUSHALL, CONFIG, REPLICAOF, and others that require review.

Questions:

1. Which named identity reaches each cache/session/queue/limiter namespace?
2. Does any runtime identity have an administrative, destructive, module, replication, or unrestricted command category?
3. Are key and channel patterns aligned with the actual service contract?
4. Has `ACL CAT` been checked against the deployed version rather than assumed from an older version?

Redis documents minimum ACL commands for Sentinel and replicas. Treat those as separate machine identities, never as application identities.

## Redis 8 modules and ACLs

Redis OSS 8.0.0 GA was released May 2025. Redis Search, JSON, TimeSeries, and probabilistic structures including Bloom became integrated components; standalone RediSearch, RedisJSON, RedisTimeSeries, and RedisBloom modules are no longer required for Redis 8. Redis 8 introduced `@search`, `@json`, `@timeseries`, `@bloom`, and related ACL categories, and expanded existing `@read`, `@write`, `@dangerous`, `@admin`, `@slow`, and `@fast` categories to include their commands.

Therefore a Redis 7 ACL such as `+@read` can permit new Search reads after upgrade. Re-test every custom ACL, key prefix, index/query contract, and enabled integrated component. The release notes record security fixes in 8.0.x including Lua-related vulnerabilities in 8.0.4 and output-buffer growth from an unauthenticated client in 8.0.0; patch current supported versions rather than treating version labels as a control.

## Persistence, replicas, and backups

Redis persistence choices are RDB snapshots, AOF write log, no persistence, or both. RDB is point-in-time and can lose writes since the last snapshot; default AOF `everysec` can lose about one second after a disaster. RDB files are backup artifacts and must be protected like the in-memory data. Redis recommends off-host backups and explains the Redis 7+ multi-part AOF backup procedure to avoid an invalid copy during rewrite.

Redis replication is asynchronous. `WAIT` reduces but does not eliminate write loss at failover. Redis explicitly warns that running a master without persistence and automatic restart can empty the master and replicas. Read-only replicas still retain administrative surfaces and must not be exposed to untrusted networks.

## Valkey compatibility boundary

The checked Valkey security page matches the core recommendations: trusted/private access, firewall and loopback binding where appropriate, protected mode, named ACLs over shared auth, TLS, restricted dangerous commands, and an unprivileged service account. It does not establish that every Redis OSS 8 integrated component or release-note behavior applies to Valkey 8. Treat Redis 8 module category guidance as Redis-specific until the deployed Valkey documentation confirms it.
