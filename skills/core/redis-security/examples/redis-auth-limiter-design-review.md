# Redis-Backed Authentication Limiter: Threat Model and Security Design Review

> Design example, not a claim about a deployed system. Run the relevant checklists before treating
> any assumption below as verified.

## Scope and decision

A public login, OTP, and password-reset verifier uses Redis for account, source-network, device,
and global attempt budgets. Successful authentication creates a server-side session; reset and OTP
flows store one-time-use markers separately.

**Decision:** Redis is private and TLS-protected. `limiter-runtime` and `session-runtime` are
separate named ACL identities with separate key prefixes. Security state has a protected,
non-evicting capacity domain. If the limiter cannot be evaluated, new authentication attempts fail
with a generic temporary-unavailable response; existing sessions follow their established session
policy.

| Key family | Data classification | Primary owner | Failure rule |
|---|---|---|---|
| `limit:acct:<hmac-id>` | Pseudonymous security state | `brute-force-defense` | Must not be evicted; bounded TTL |
| `limit:ipnet:<network>` | Security telemetry/state | `brute-force-defense` | Must not be evicted; bounded TTL |
| `limit:global:<route>:<window>` | Security state | `brute-force-defense` | Alert on saturation or store failure |
| `sess:<opaque-id>` | Authentication state | `authentication` | Isolated from disposable cache eviction |
| `revoke:<token-id>` / `otp:<claim>` | One-time security state | `authentication` | Explicit TTL and fail-closed consumption |

## Data flow and trust boundaries

```text
Internet => login/OTP/reset verifier => limiter atomic operation => Redis security-state instance
                                  └=> identity verifier => session store => Redis session namespace
Application events => redaction boundary => audit/metrics pipeline
Operator/break-glass identity => separate administrative Redis path
```

| Crossing | Threat | Required control | Owner | Evidence |
|---|---|---|---|---|
| Internet => verifier | Credential stuffing, enumeration, distributed spraying | Account, network, device-risk, and global dimensions; uniform responses | `brute-force-defense`, `authentication` | Route inventory and negative tests |
| Verifier => Redis | Runtime identity reads sessions or administers Redis | Named ACL users, exact prefixes, minimal commands, deny `@admin`, `@dangerous`, `CONFIG`, `ACL`, `MONITOR`, `FLUSH*` | `redis-security` | ACL review and deployed `ACL DRYRUN` evidence |
| App network => Redis | Intercepted state/credentials or an untrusted client reaches Redis | Private reachability and verified TLS across hosts | `redis-security`, platform owner | Network and certificate evidence |
| Concurrent verifiers => limiter state | GET-then-SET race loses an attempt or omits expiry | Reviewed atomic increment-plus-initial-expiry operation | `brute-force-defense` | Concurrent multi-instance test |
| Redis failover/outage => login | Timeout silently removes throttling | Short timeout, generic fail-closed result, alert, recovery runbook | identity platform owner | Fault-injection test |
| Cache capacity => security keys | Cache churn evicts session/limiter/revocation state | Separate instance or protected non-evicting resource domain | platform owner, `redis-security` | `maxmemory` and eviction-alert evidence |
| App => telemetry | Redis URLs, `AUTH`, session IDs, or command values leak | Structured redacted events and aggregate metrics only | `logging-audit` | Redaction test and alert rule IDs |
| Alternate verifier routes | GraphQL/mobile/legacy route bypasses limiter | One shared policy and atomic consume path | route owners | Route and integration tests |

## Security decisions

| Decision | Why | Verification |
|---|---|---|
| Separate `limiter-runtime` and `session-runtime` ACL users | A limiter compromise cannot read sessions; a session path cannot administer Redis | ACL export, key-prefix integration test |
| Atomic counter and expiry | Concurrent requests cannot erase attempts or leave permanent keys | 50+ concurrent attempts across two app instances |
| Protected security-state capacity | Disposable cache traffic cannot silently disable a control | Deployed eviction policy and eviction alert |
| Fail closed for new authentication | Redis unavailability must not become unlimited guessing | Timeout/failure integration test |
| Uniform external response | Avoid account existence and limiter-state disclosure | Response/status/timing comparison |
| Redacted telemetry | Detection must not copy security state into logs | Fixture scan and sample event review |

## Operational evidence and go/no-go

- [ ] Redis listener, Security Group/firewall, and service discovery prove only intended workloads can reach it.
- [ ] TLS client validation is enabled for every cross-host connection.
- [ ] Runtime ACL users cannot reach the wrong prefixes or destructive/admin commands.
- [ ] Every limiter key has a bounded TTL; key cardinality, memory, clients, and retry pools have limits.
- [ ] Limiter/session/revocation state does not share an evictable cache domain without an accepted risk.
- [ ] The verifier fails closed on limiter timeout/error and has a tested user-visible response.
- [ ] Alerts cover ACL denials, persistence/failover errors, evictions, limiter unavailability, spraying patterns, and missing expected event volume.
- [ ] Restore and failover exercises name the accountable on-call owner and the post-event review.

## Accepted residual risks

| Risk | Compensating control | Accountable owner / revisit trigger |
|---|---|---|
| Redis replication is asynchronous; a recent counter update can be lost at failover | Conservative thresholds, multi-dimensional limits, MFA, global anomaly detection | Identity platform; after topology/failover change |
| Distributed attackers rotate IP/device signals | Per-account plus network/global dimensions and detection rules | Product security; quarterly review |
| Fail-closed limiter temporarily blocks legitimate new logins | HA deployment, short timeout, clear status communication, existing-session policy | Product owner; availability-SLO review |
| HMAC key identifiers remain sensitive correlation metadata | Dedicated secret, narrow Redis access, protected backups, redacted telemetry | Secrets owner; after suspected exposure |

## Ownership hand-offs

- `authentication` owns password/reset/OTP/session/token lifecycle policy.
- `brute-force-defense` owns counted actions, thresholds, lockout, friction, and spraying policy.
- `redis-security` owns Redis reachability, ACLs, TLS, persistence, eviction, and service recovery.
- `secrets-management` owns credential/secret lifecycle and exposure response.
- `logging-audit` owns retention, SIEM rules, and audit evidence treatment.
- `advanced/secure-architecture` owns broader trust-boundary decisions and accepted-risk process.
