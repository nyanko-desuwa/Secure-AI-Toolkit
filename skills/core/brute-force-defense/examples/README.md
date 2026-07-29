# Brute Force Defense Examples

Eight defensive vulnerable/fixed pairs. Each names the category, ASVS chapter, CWE, and the
bypass. Values are synthetic. Do not turn these into candidate-testing tools.

## Contents

- [Per-IP limiter bypassed by rotating addresses](#per-ip-limiter-bypassed-by-rotating-addresses) - A07, CWE-307
- [In-memory counter defeated by horizontal scaling](#in-memory-counter-defeated-by-horizontal-scaling) - A07, CWE-307
- [OTP with no attempt cap](#otp-with-no-attempt-cap) - A07, CWE-307
- [Guessable reset token](#guessable-reset-token) - A07/A04, CWE-330/CWE-340
- [GraphQL batch counts one request](#graphql-batch-counts-one-request) - A06/API4, CWE-770/CWE-307
- [Timing-unsafe HMAC comparison](#timing-unsafe-hmac-comparison) - A04, CWE-208
- [Lockout used to deny a victim](#lockout-used-to-deny-a-victim) - A06/A07, CWE-645
- [Redis error fails open](#redis-error-fails-open) - A10/A07, CWE-307

---

## Per-IP limiter bypassed by rotating addresses

`A07:2025` · ASVS V6 · CWE-307

```typescript
// Vulnerable: a new address creates a fresh budget against the same account
async function login(req: Request, res: Response) {
  const count = await redis.incr(`login:ip:${req.ip}`);
  if (count === 1) await redis.expire(`login:ip:${req.ip}`, 300);
  if (count > 10) return res.status(429).json({ error: "try_later" });
  return verifyAndCreateSession(req, res);
}
```

An attacker rotating residential proxies gets ten attempts per address forever. A shared NAT also
lets one attacker spend every legitimate user's budget.

```typescript
// Fixed: each attempt spends several independent budgets
async function login(req: Request, res: Response) {
  const canonical = normalizeLogin(String(req.body.email));
  const ip = trustedClientIp(req);
  const keys = [
    { key: `acct:${hmac(canonical)}`, limit: 8, seconds: 900 },
    { key: `ip:${ip}`, limit: 30, seconds: 300 },
    { key: `net:${networkBucket(ip)}`, limit: 300, seconds: 900 },
    { key: "global", limit: 20_000, seconds: 60 },
  ];
  const results = await Promise.all(keys.map(k => limiter.consume(k)));
  if (results.some(r => !r.allowed)) return uniformFailure(res);
  return verifyAndCreateSession(req, res);
}
```

Why this works: rotating IPs does not reset the account budget, while account breadth is visible
to network/global controls. Device risk can add friction but cannot serve as identity because the
client can spoof it.

A gateway still provides a burst backstop. Apply the same zone to every login path; it remains
per-IP and therefore does not replace the application counters:

```nginx
http {
    limit_req_zone $binary_remote_addr zone=auth_by_ip:10m rate=5r/m;

    server {
        location = /login {
            limit_req zone=auth_by_ip burst=5 nodelay;
            limit_req_status 429;
            proxy_pass http://app;
        }
        location = /api/v1/login {
            limit_req zone=auth_by_ip burst=5 nodelay;
            limit_req_status 429;
            proxy_pass http://app;
        }
    }
}
```

Why this backstop works: both browser and mobile routes share one address budget before reaching
the application. It still needs trusted edge-derived client addresses and the account/global
policy shown above.

---

## In-memory counter defeated by horizontal scaling

`A07:2025` · ASVS V6/V16 · CWE-307

```python
# Vulnerable: each process has its own dict; restart erases it
attempts: dict[str, int] = {}
def consume(account: str) -> bool:
    attempts[account] = attempts.get(account, 0) + 1
    return attempts[account] <= 5
```

Four workers grant twenty attempts. Rolling restarts restore the full budget. Sticky sessions do
not fix restart or failover.

```python
# Fixed: Redis Lua atomically increments and assigns the first expiry
import redis
r = redis.Redis.from_url("redis://127.0.0.1:6379/0", decode_responses=True)
consume_script = r.register_script("""
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
return {n, redis.call('TTL', KEYS[1])}
""")

def consume(account_hash: str, limit: int = 5, window_s: int = 900) -> bool:
    count, ttl = consume_script(keys=[f"bf:acct:{account_hash}"], args=[window_s])
    if int(ttl) < 0: raise RuntimeError("limiter key has no expiry")
    return int(count) <= limit
```

Why this works: every worker sees one serialised count, and increment plus first expiry cannot be
split by a process crash. The remaining fixed-window boundary burst is explicit; use a sliding
window if it violates the threat model.

---

## OTP with no attempt cap

`A07:2025` · ASVS V6 · CWE-307/CWE-799

```python
# Vulnerable: a six-digit value can be tried until its expiry
async def verify_otp(challenge_id: str, candidate: str) -> bool:
    row = await db.otp.get(challenge_id)
    return row.expires_at > now() and candidate == row.code
```

The 10^6 candidate space looks large only until the endpoint accepts unlimited concurrent tries.
The same code is also replayable inside its validity window.

```python
# Fixed: attempt cap, expiry, comparison, and single-use state are one transaction
import secrets

async def verify_otp(challenge_id: str, candidate: str) -> bool:
    async with db.transaction():
        row = await db.otp.select_for_update(challenge_id)
        if not row or row.used_at or row.expires_at <= now() or row.attempts >= 5:
            return False
        await db.otp.increment_attempts(row.id)
        valid = len(candidate) == 6 and secrets.compare_digest(candidate, row.code)
        if not valid:
            if row.attempts + 1 >= 5: await db.otp.invalidate(row.id)
            return False
        await db.otp.mark_used(row.id, now())
        return True
```

Why this works: the challenge has five total candidates and one success, even under concurrency.
Resend needs a separate cap and must not reset `attempts`; TOTP must persist the accepted time-step
counter rather than storing a reusable static challenge.

---

## Guessable reset token

`A07/A04:2025` · ASVS V6/V11 · CWE-330/CWE-340

```typescript
// Vulnerable: user ID and request time determine the token
function resetToken(userId: number): string {
  return createHash("sha256").update(`${userId}:${Math.floor(Date.now() / 1000)}`).digest("hex");
}
```

Hash output length is not entropy. The attacker brackets the request timestamp and computes the
same candidates offline.

```typescript
// Fixed: CSPRNG token; database stores only its digest and lifecycle state
async function issueReset(userId: string): Promise<string> {
  const raw = randomBytes(32).toString("base64url");
  const digest = createHash("sha256").update(raw).digest("hex");
  await db.resetToken.create({ data: {
    userId, digest, purpose: "password_reset",
    expiresAt: new Date(Date.now() + 15 * 60_000), usedAt: null,
  }});
  return raw;
}
```

Why this works: 256 unpredictable bits cannot be derived from public context, and a database read
does not reveal usable tokens. Verification still needs a source/account/global attempt budget and
an atomic `usedAt IS NULL` consumption update.

---

## GraphQL batch counts one request

`A06:2025` · API4:2023 · ASVS V4/V6 · CWE-770/CWE-307

```typescript
// Vulnerable: one HTTP envelope consumes one unit, however many operations it contains
app.use("/graphql", rateLimit({ windowMs: 60_000, limit: 10 }));
app.use("/graphql", graphqlHTTP({ schema }));
```

A single document can alias a login mutation hundreds of times. Ten requests become thousands of
password checks.

```typescript
// Fixed: reject oversized documents and consume once inside each login resolver
const validationRules = [maxOperationsRule(20), maxDepthRule(8)];
const resolvers = {
  Mutation: {
    login: async (_: unknown, args: LoginArgs, ctx: Context) => {
      const decision = await ctx.limiter.consume({
        account: normalizeLogin(args.email), ip: ctx.trustedIp,
      });
      if (!decision.allowed) throw new GraphQLError("invalid_credentials");
      return authenticate(args, ctx);
    },
  },
};
app.use("/graphql", graphqlHTTP({ schema, rootValue: resolvers, validationRules }));
```

Why this works: each credential comparison consumes a budget, while parse-time limits bound work
before resolvers run. JSON-RPC arrays and gRPC streams require the same operation-level accounting.
Disabling aliases alone is not sufficient.

---

## Timing-unsafe HMAC comparison

`A04:2025` · ASVS V11 · CWE-208

```python
# Vulnerable: ordinary equality can reveal the matching prefix
expected = hmac.new(KEY, body, hashlib.sha256).hexdigest()
if supplied_signature == expected:
    accept()
```

Repeated measurements can turn prefix-dependent work into a byte-at-a-time oracle. Network noise
raises the sample count; it does not remove the dependency.

```python
# Fixed: parse fixed-length bytes, then use a constant-time helper
expected = hmac.new(KEY, body, hashlib.sha256).digest()
try:
    supplied = bytes.fromhex(supplied_signature)
except ValueError:
    supplied = b""
valid = len(supplied) == len(expected) and hmac.compare_digest(supplied, expected)
if valid:
    accept()
else:
    reject_uniformly()
```

Why this works: comparison does not stop at the first differing byte. Random sleeps are the wrong
fix: an attacker averages out noise while every legitimate call slows down.

---

## Lockout used to deny a victim

`A06/A07:2025` · ASVS V6 · CWE-645

```python
# Vulnerable: five unauthenticated failures control a victim's next 24 hours
def record_failure(user):
    user.failed += 1
    if user.failed >= 5:
        user.locked_until = now() + timedelta(hours=24)
    db.save(user)
```

Knowing an email address is enough to deny that user service. A longer lock only makes the attack
stronger.

```python
# Fixed: graduated friction and a verified recovery path
def next_action(failures: int) -> dict:
    if failures < 3:  return {"delay_ms": 250}
    if failures < 8:  return {"delay_ms": min(30_000, 500 * 2 ** (failures - 3)), "captcha": True}
    if failures < 50: return {"delay_ms": 30_000, "email_step": True}
    return {"hard_lock": True, "self_service_recovery": True}
```

Why this works: the attacker pays more without receiving a cheap hard-lock switch. Delays must be
asynchronous/gateway enforced rather than sleeping request workers. CAPTCHA is supplementary;
solver services make it a cost multiplier, not a wall.

---

## Redis error fails open

`A10/A07:2025` · ASVS V16/V6 · CWE-307

```typescript
// Vulnerable: taking Redis offline removes the attempt limit
async function permit(key: string): Promise<boolean> {
  try { return (await limiter.consume(key)).allowed; }
  catch { return true; }
}
```

A dependency incident, network partition, timeout, or deliberate pressure turns login into an
unlimited endpoint.

```typescript
// Fixed: unavailable limiter means authentication is temporarily unavailable
async function permit(key: string, event: AuditContext): Promise<boolean> {
  try {
    return (await limiter.consume(key)).allowed;
  } catch (error) {
    audit.error("auth_limiter_unavailable", {
      route: event.route, correlationId: event.correlationId, errorId: classify(error),
    });
    throw new ServiceUnavailableError("authentication_temporarily_unavailable");
  }
}
```

Why this works: failure cannot grant additional tries. It deliberately couples login availability
to the limiter. Redundant Redis, short timeouts, monitoring, and an incident path mitigate that
cost. A local-memory fallback is not equivalent because it multiplies with pods and resets.

---

## Sources

- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>
- OWASP ASVS 5.0.0 - <https://owasp.org/www-project-application-security-verification-standard/>
- OWASP API Security Top 10 2023 - <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- NIST SP 800-63B-4 - <https://pages.nist.gov/800-63-4/sp800-63b.html>
- OWASP Credential Stuffing Prevention Cheat Sheet - <https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html>
- MITRE CWE - <https://cwe.mitre.org/data/index.html>
