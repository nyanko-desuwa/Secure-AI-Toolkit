# Troubleshooting

## ACL migration breaks a client

Do not grant `+@all` to unblock it. Capture the denied command, key, and channel from a controlled test; classify the client role; then add the smallest command and pattern. Use `ACL GETUSER` and `ACL CAT` against the running version. Redis 8 upgrades require a deliberate category review because integrated components expanded existing categories.

## TLS rollout fails

Check hostname/SAN mismatch, CA trust, TLS port, and whether every client path includes replicas, Sentinel, and cluster discovery. Fix trust distribution and server names. Do not set `verify_peer`/hostname verification false. Keep plaintext only inside a documented, isolated transition boundary with a removal date.

## A legacy client understands only `AUTH <password>`

That form authenticates as `default`. Treat it as a migration blocker, not a reason to give `default` broad access forever. Isolate the legacy workload, constrain its network/key space as far as its client allows, then move it to a username-aware client and retire the account.

## Cache-only service needs to stay available during Redis failure

A cache miss may be acceptable; silently disabling a session, revocation, idempotency, OTP, or limiter check is not. Classify the key family, set a short deadline and bounded retry count, emit an alert, and implement only the degradation allowed by the classification.

## Sentinel/Cluster failover changes behavior

Redis replication is asynchronous. Acknowledged writes can still be lost at failover, and a stale replica can be unsuitable for security decisions. Test connection discovery, ACL/TLS on every node, promotion, missed writes, and application policy. Use provider-specific features only after confirming their consistency semantics.

## Managed service lacks a self-hosted control

Do not claim it passes because the option is hidden. Record the provider/service plan, the owner, and the compensating control. For example, a service may restrict `CONFIG` itself but still require private networking, ACL/authentication, TLS, backup-reader restrictions, and application-specific eviction separation.

## Need to recover after suspected unauthorized Redis access

Contain network access, preserve audit/provider evidence, rotate every affected ACL credential and TLS material, assess RDB/AOF/replica/backup exposure, restore from a known-good tested backup when integrity is uncertain, and follow `advanced/incident-response`. Do not merely change `requirepass` and declare the dataset trustworthy.
