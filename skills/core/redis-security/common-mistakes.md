# Common Mistakes

## Calling protected mode the perimeter

Protected mode refuses remote requests only under its documented default conditions. It is a useful brake on an unconfigured server, not a reason to expose a listener or disable firewall rules. Fix reachability first, then retain protected mode and ACL authentication as independent controls.

## Treating `requirepass` as ACLs

`requirepass` assigns one password to the `default` user. It does not distinguish cache from worker, session from queue, or application from administrator. Use named identities with reset-first command, key, and channel patterns. Disable or sharply constrain `default`.

## Using database numbers as tenant security

`SELECT 0` and `SELECT 1` are organizational conveniences. They are not a tenant boundary when a credential can select databases or has broad key permissions. Use separate ACL identities plus prefixes; use separate instances/clusters where eviction, persistence, or blast radius must differ.

## Adding `+@all -@dangerous`

This feels restrictive but includes every current and future module command. Redis 8 changed category membership when Search, JSON, time series, and probabilistic structures became integrated. Start `-@all`, add the smallest named commands/categories, and review on every upgrade.

## Disabling certificate verification to complete a TLS rollout

A client that accepts any certificate protects neither credentials nor data from an active attacker. Trust the issuing CA, use the real server name, and test before switching traffic. If legacy clients cannot verify TLS, isolate the migration path and schedule replacement; do not make insecure verification permanent.

## Sharing cache eviction with sessions or rate limits

An LRU cache is intended to forget. A limiter key, revocation marker, OTP replay record, and idempotency claim often exist specifically to prevent a security failure. Separate storage/policy or reject writes explicitly; never call silent eviction a graceful degradation.

## Logging Redis observability verbatim

`MONITOR`, slow logs, client names, URLs, command arguments, and errors can contain bearer tokens, identifiers, message payloads, or credentials. Restrict access, redact at collection, and hand normal log policy to `logging-audit`.

## Assuming a read-only replica is safe to expose

Redis documents that read-only replicas can still accept administrative commands such as `DEBUG` and `CONFIG`. Replica read-only mode prevents application writes; it does not authenticate a public client or replace network isolation and ACLs.

## Copying AOF files during rewrite without a consistency procedure

Redis 7+ stores multi-part AOFs with a manifest. A casual copy during rewrite may be invalid. Follow the official backup procedure, test restores, and restore automatic rewrite settings afterward.
