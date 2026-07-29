# Brute Force Defense Best Practices

Every control maps to OWASP Top 10 2025, an ASVS 5.0 chapter, and a CWE where one applies.
Code is defensive and runnable with the named runtime. Thresholds are examples, not policy.

## Limit on several dimensions at once

`A07:2025` · `A06:2025` · ASVS V6 · CWE-307

Any single dimension has a bypass. Per-IP loses to proxy rotation. Per-account loses to spraying
and can lock out a named victim. Per-device loses because the client controls it. ASN blocks harm
shared cloud and mobile networks. A global limit alone lets one attacker deny login to everyone.

```typescript
// Vulnerable: rotating addresses gets unlimited attempts against one account
const key = `login:ip:${req.ip}`;
if (await redis.incr(key) > 10) return res.sendStatus(429);
```

```typescript
// Fixed: require every dimension to remain within its own budget
const id = normalizeLogin(req.body.email);
const dimensions = [
  [`acct:${hmac(id)}`, 8, 15 * 60],
  [`ip:${trustedClientIp(req)}`, 30, 5 * 60],
  [`net:${networkBucket(trustedClientIp(req))}`, 300, 15 * 60],
  [`device:${deviceRiskId(req)}`, 20, 15 * 60],
  ["global", 20_000, 60],
] as const;
const decisions = await Promise.all(dimensions.map(([k, n, s]) => increment(k, n, s)));
if (decisions.some(d => !d.allowed)) return invalidCredentialsWithDelay();
```

Why this works: an attacker must stay under every budget at once. Account catches rotating IPs;
network catches one proxy hitting many accounts; global catches broad spraying. HMAC the account
key with a server secret so Redis snapshots do not become a directory of email addresses.

The wrong fix is adding more per-IP buckets. Botnets and residential proxy services make source
addresses disposable. Device fingerprints are also spoofable; use them to increase friction, not
to identify a person.

## Reject known breached passwords before they become credentials

`A07:2025` · ASVS V6 · CWE-521

Credential stuffing works because people reuse exposed passwords. Screening only at login is too
late: the system has already accepted the compromised value.

```python
# Vulnerable: length alone accepts known breached passwords
async def password_allowed(candidate: str) -> bool:
    return len(candidate) >= 15
```

```python
# Fixed: compare the whole prospective value to a locally synced breach corpus
import hashlib

async def password_allowed(candidate: str) -> bool:
    if len(candidate) < 15:
        return False
    digest = hashlib.sha1(candidate.encode("utf-8")).hexdigest().upper()
    return not await breached_hashes.contains(digest)
```

Why this works: a password already present in breach corpuses cannot be established or retained
at change time, so the corresponding stuffed pair does not authenticate here. SHA-1 is used only
as the corpus lookup key, not for password storage; store the accepted password with the KDF from
`advanced/cryptography`. If using a remote k-anonymity service, send only the documented hash
prefix over TLS, never the password or full digest. The wrong fix is a tiny hand-written list of
`Password1!` variants; NIST requires known commonly used, expected, or compromised values and the
whole password is compared.

## Atomic distributed counters

`A07:2025` · ASVS V6/V16 · CWE-307

Four pods mean four in-memory counters. A naive Redis `GET`, increment, `SET` loses updates under
concurrency, and a separate `INCR` then `EXPIRE` can leave a permanent key if the process dies
between commands.

```python
# Vulnerable: process-local and races between concurrent requests
attempts = {}
def allowed(key: str) -> bool:
    attempts[key] = attempts.get(key, 0) + 1
    return attempts[key] <= 5
```

```python
# Fixed: Lua makes first increment + expiry one atomic server operation
import redis
r = redis.Redis.from_url("redis://127.0.0.1:6379/0", decode_responses=True)
SCRIPT = r.register_script("""
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
return {n, redis.call('TTL', KEYS[1])}
""")

def consume(key: str, limit: int, window_s: int) -> tuple[bool, int]:
    count, ttl = SCRIPT(keys=[f"bf:{key}"], args=[window_s])
    return int(count) <= limit, max(int(ttl), 0)
```

Why this works: Redis serialises the Lua script; no increment is lost and every new key receives
an expiry in the same atomic operation. This is fixed-window limiting. It allows a burst at the
window boundary. Sliding windows or token buckets smooth that edge at greater storage/cost.

## Fail closed when the limiter is unavailable

`A07:2025` · `A10:2025` · ASVS V6/V16 · CWE-307

```typescript
// Vulnerable: Redis outage becomes unlimited password attempts
try { await limiter.consume(key); }
catch { logger.warn("limiter unavailable; continuing"); }
return verifyPassword();
```

```typescript
// Fixed: dependency failure denies the authentication attempt
try {
  const decision = await limiter.consume(key);
  if (!decision.allowed) return res.status(429).json({ error: "try_later" });
} catch (error) {
  logger.error("login_limiter_unavailable", { route: req.path, errorId: errorCode(error) });
  return res.status(503).json({ error: "authentication_temporarily_unavailable" });
}
return verifyPassword();
```

Why this works: an infrastructure failure cannot remove the security boundary. The cost is real:
Redis failure now denies login. Run it redundantly, set a short timeout, alert, and keep already
established sessions usable where policy permits. A process-local fallback looks attractive, but
an attacker still multiplies its budget by the pod count and can target restarts.

## Normalise the account key once

`A07:2025` · ASVS V6 · CWE-307/CWE-180

```typescript
// Vulnerable: three spellings create three counters for one mailbox
const key = `login:${req.body.email}`;
```

```typescript
// Fixed: canonical lookup ID is also the limiter ID
function normalizeLogin(raw: string): string {
  return raw.normalize("NFKC").trim().toLocaleLowerCase("en-US");
}
const canonical = normalizeLogin(req.body.email);
const user = await users.findByCanonicalLogin(canonical);
const limiterKey = `login:account:${hmac(canonical)}`;
```

Why this works: lookup and limiting use the same canonical form, so `User@Example.com ` and
`user@example.com` spend the same budget. Unicode policy is product-specific. NFKC can collapse
characters a project intentionally distinguishes, and lowercasing an arbitrary email local part
is not universally valid. The invariant is one canonical identity function shared by account
lookup, uniqueness, audit, and limiting - not this exact function copied blindly.

## Graduated friction, not binary lockout

`A07:2025` · `A06:2025` · ASVS V6 · CWE-645

```python
# Vulnerable: an unauthenticated attacker locks a known victim for a day
def on_failure(user):
    user.failed += 1
    if user.failed >= 5:
        user.locked_until = now() + timedelta(hours=24)
```

```python
# Fixed: short delay -> CAPTCHA -> verified step; hard lock only at extreme counts
def friction(failures: int) -> dict:
    if failures < 3:  return {"delay_ms": 250}
    if failures < 8:  return {"delay_ms": min(30_000, 500 * 2 ** (failures - 3)), "captcha": True}
    if failures < 50: return {"delay_ms": 30_000, "verified_email_step": True}
    return {"hard_lock": True, "self_service_recovery": True}
```

Why this works: the attacker pays progressively while a legitimate user has a path back. Apply
delay asynchronously or at the client/gateway; sleeping a server worker is resource exhaustion.
CAPTCHA is a cost multiplier, not a wall. Solver services are cheap, so CAPTCHA never replaces
the counters.

## The surfaces people forget

### OTP attempts and replay

`A07:2025` · ASVS V6 · CWE-307/CWE-799

```python
# Vulnerable: six digits, unlimited tries, same code accepted twice
async def verify_otp(challenge, supplied):
    return supplied == challenge.code
```

```python
# Fixed: transaction locks challenge; attempts and consumption are atomic
async def verify_otp(challenge_id: str, supplied: str) -> bool:
    async with db.transaction():
        row = await db.otp_challenges.select_for_update(challenge_id)
        if not row or row.used_at or row.expires_at <= now() or row.attempts >= 5:
            return False
        await db.otp_challenges.increment_attempts(row.id)
        if not secrets.compare_digest(supplied.encode(), row.code.encode()):
            if row.attempts + 1 >= 5: await db.otp_challenges.invalidate(row.id)
            return False
        await db.otp_challenges.mark_used(row.id, now())
        return True
```

Why this works: five candidates is the whole online search budget for this challenge; the cap
invalidates it and the row lock makes two simultaneous successes impossible. Rate limit resends
separately. Issuing a new code must not reset failed attempts. For TOTP, persist the accepted time
step/counter and reject it again within the same window.

### Reset and verification tokens

`A07:2025` · ASVS V6/V11 · CWE-330/CWE-340

```typescript
// Vulnerable: timestamp makes the token searchable around the request time
const token = createHash("sha256").update(`${user.id}:${Date.now()}`).digest("hex");
```

```typescript
// Fixed: 32 random bytes, store only a hash, scope and consume once
const token = randomBytes(32).toString("base64url");
const tokenHash = createHash("sha256").update(token).digest("hex");
await db.resetToken.create({ data: {
  userId: user.id, tokenHash, purpose: "password_reset",
  expiresAt: new Date(Date.now() + 15 * 60_000), usedAt: null,
}});
```

Why this works: the CSPRNG creates 256 bits the attacker cannot derive from time or user ID;
database readers cannot use the stored digest directly. Verification must atomically set
`usedAt`, check purpose/account/expiry, and remain rate limited. Expiry narrows exposure; it does
not make a predictable token unpredictable.

### API keys, codes, short URLs, and customer identifiers

`A06:2025` · ASVS V2/V6 · CWE-799/CWE-340

Every validation endpoint needs an attempt budget even if the value is "not authentication".
Invite codes create membership. Coupons move money. Short URLs disclose content. API keys grant
authority. Generate secrets with a CSPRNG; prefix API keys only for routing; store their hashes;
rate limit by candidate prefix, source, tenant, and globally.

Sequential object IDs are enumerable. UUIDv4 raises the cost, but it is not authorization:

```python
# Vulnerable: UUID only hides the object; any bearer who learns it reads it
invoice = db.invoices.get(request.path_params["id"])

# Fixed: authorization is in the query, regardless of identifier format
invoice = db.invoices.first(id=request.path_params["id"], owner_id=actor.id)
if invoice is None: raise NotFound()
```

Why this works: a leaked or guessed ID gives no access. Keep UUIDv4 for enumeration resistance if
useful, but report the missing owner scope under A01, not as a randomness-only issue.

### Constant-time secret comparison

`A04:2025` · ASVS V11 · CWE-208

```python
# Vulnerable: comparison may reveal the matching prefix through response time
if supplied_hmac == expected_hmac: accept()

# Fixed: compare equal-type fixed-length digests with a constant-time helper
if hmac.compare_digest(bytes.fromhex(supplied_hmac), expected_digest): accept()
```

Why this works: the helper does not stop at the first differing byte, removing the byte-by-byte
timing oracle. Validate encoding and expected length before comparison, but return one uniform
failure. Network noise makes exploitation harder, not impossible; local and repeated measurement
reduces noise.

## Count operations inside batch endpoints

`A06:2025` · API4:2023 · ASVS V4/V6 · CWE-770/CWE-307

```typescript
// Vulnerable: middleware counts one HTTP request carrying 200 login mutations
app.use("/graphql", perRequestLimiter);
```

```typescript
// Fixed: budget is consumed in the resolver for every candidate
const resolvers = {
  Mutation: {
    login: async (_: unknown, args: LoginArgs, ctx: Context) => {
      await ctx.attemptLimiter.consume({ account: normalizeLogin(args.email), ip: ctx.ip });
      return authenticate(args);
    },
  },
};
// Also reject documents over 20 operations/aliases at parse-validation time.
```

Why this works: aliases, fragments, and batching no longer multiply candidates without multiplying
the counter. A gateway operation/body-size cap is still needed to bound parsing cost before a
resolver runs. JSON-RPC arrays and gRPC streams need the same per-operation accounting.

## Cover every path that verifies the credential

`A07:2025` · ASVS V6 · CWE-307

```nginx
# Vulnerable: only browser login enters the zone; /api/v1/login remains unlimited
location = /login { limit_req zone=auth burst=5 nodelay; proxy_pass http://app; }
location /api/ { proxy_pass http://app; }
```

```nginx
# Fixed backstop: both routes use one zone; application still applies account/global counters
limit_req_zone $binary_remote_addr zone=auth:10m rate=5r/m;
location = /login { limit_req zone=auth burst=5 nodelay; proxy_pass http://app; }
location = /api/v1/login { limit_req zone=auth burst=5 nodelay; proxy_pass http://app; }
```

Why this works: the forgotten path no longer bypasses the network backstop. Nginx is per-IP only;
it cannot replace the application account/device/global policy. Inventory basic auth, mobile,
legacy, SSO callback, OAuth password grant, support tools, and internal routes.

## Detection

`A09:2025` · ASVS V16 · CWE-778

A spraying attack has low failures per account and a high aggregate failure rate. Build alerts
that combine a static guardrail with a baseline. Starting conditions to tune:

| Signal | Starting alert condition | Why it helps |
|---|---|---|
| Global failures | >500 in 5 min and >3x same weekday/hour baseline | Catches spraying spread across accounts and sources |
| Account breadth | One IP/subnet touches >50 accounts in 10 min with >80% failures | Catches stuffing and reverse brute force |
| Source breadth | One account sees >20 networks in 15 min | Catches rotating-proxy brute force |
| Success after failures | Success after >10 failures or from a source in a spray cluster | Finds a guess that worked |
| Password then MFA | Correct password followed by >=3 failed MFA challenges | High-confidence password compromise |

Fixed thresholds alone produce noise during releases, outages, and seasonal traffic. Baseline by
region, tenant, route, and hour. Alert on ratio and cardinality, not only count.

Log event type, outcome, HMACed canonical account ID, route, trusted client IP/network, device-risk
ID, limiter dimension/action, request correlation ID, and timestamp. Never log the password, OTP,
token, HMAC, API key, or a partial value. Cross-link `logging-audit`.

After a success, impossible travel and new device are post-compromise signals, not proof. NAT,
VPNs, mobile handoff, and geolocation error create false positives. Use them to require step-up
and to drive investigation.

## Respond to a successful guess

`A07:2025` · `A09:2025` · ASVS V7/V16

Successful guessing is compromise. Revoke sessions and refresh-token families; force a password
or affected-secret reset; rotate API keys and recovery codes where exposed. Audit changes to
email, MFA enrolment, recovery methods, API keys, forwarding rules, payout details, and roles.
Notify through a channel the attacker did not just change, and preserve evidence. Invoke
`advanced/incident-response`; containment is not complete when the password changes.
