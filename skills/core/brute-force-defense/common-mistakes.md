# Common Mistakes

Each failure names what goes wrong, why the tempting fix fails, and the control that closes the
actual hole.

## "We have a per-account lockout, so spraying is solved"

`A07/A06:2025` · ASVS V6 · CWE-307

A sprayer tries three common passwords against every account. A five-failure account threshold
never fires. Reverse brute force - one leaked password, many usernames - has the same shape.

Fix: keep the account counter for brute force, and add global failure-rate, account-breadth by
source/network, and common-password cluster detection. Why it works: the attack cannot stay low
per account and low in aggregate at the same time.

## Per-IP is the whole limiter

`A07:2025` · ASVS V6 · CWE-307

Residential proxy services and botnets make addresses disposable. Conversely, one bad actor
behind a carrier NAT can spend the budget for thousands of legitimate users.

Fix: account + IP + subnet/ASN + device risk + global counters. Why it works: rotating one
dimension does not reset the others. Do not "fix" this by trusting `X-Forwarded-For`; unless the
proxy overwrites that header, the attacker chooses the key.

## The counter is not shared, or not atomic

`A07:2025` · ASVS V6 · CWE-307

A four-pod deployment with a process-local dictionary creates four independent budgets, and a
restart erases them. Moving to Redis fixes the sharing and leaves the race:

```python
# Vulnerable: two concurrent requests read 4 and both write 5
count = int(redis.get(key) or 0)
redis.set(key, count + 1, ex=60)
```

Separate `INCR` and `EXPIRE` calls carry their own race: process death between them leaves a key
with no expiry. Fix: a shared transactional store, `INCR` and first-expiry assignment in one Lua
script. Why
it works: every instance reads one counter and Redis serialises the update, so each attempt spends
exactly one unit. Sticky sessions are the tempting wrong fix - routing is not storage, it fails
over, and it does not survive a restart. See
[best-practices.md](best-practices.md#atomic-distributed-counters).

## Limiter exception means continue

`A10/A07:2025` · ASVS V16/V6 · CWE-307

```typescript
// Vulnerable: dependency outage removes the control
try { await limiter.check(key); } catch (_) { /* keep login available */ }
```

Fix: return 503 or require a safe verified recovery step, log and alert the dependency failure.
Why it works: failure cannot produce an authorization-to-try. The tradeoff is authentication
availability; solve it with redundant infrastructure, not unlimited attempts.

## Hard lock after five failures

`A06/A07:2025` · ASVS V6 · CWE-645

Anyone who knows a victim's email can deny them access for a day. The more "secure" the duration,
the stronger the unauthenticated DoS lever.

Fix: graduated delay, CAPTCHA, verified-email step, then hard lock at an extreme count with
self-service recovery. Why it works: attackers pay increasing cost without granting them a cheap
binary switch over the victim. A CAPTCHA alone is wrong; solver services turn it into a small
line item.

## Different casing gets a fresh counter

`A07:2025` · ASVS V6 · CWE-307/CWE-180

`User@Example.com `, `user@example.com`, and Unicode-equivalent spellings hit the same account but
different limiter keys.

Fix: account lookup, uniqueness, audit, and the limiter share one canonical identity function.
Why it works: every spelling accepted for an account spends the same budget. A regex denylist for
"weird characters" is wrong: it misses equivalences and breaks legitimate identifiers.

## The OTP cap is cosmetic

`A07:2025` · ASVS V6 · CWE-307/CWE-799/CWE-294

Two variants of the same mistake. The code caps an OTP at five guesses, then sets `attempts = 0`
whenever the attacker requests a new code. And a mathematically valid TOTP stays valid for its
whole window, so with no accepted-counter record an observed code is replayable until the step
changes.

Fix: failed attempts belong to the account/authenticator window, not the individual code; resend
gets its own budget and invalidates the old code without resetting failures. Separately, persist
the highest accepted TOTP counter and reject that step or earlier. Why it works: reissuing creates
no new search budget (NIST SP 800-63B-4 Section 3.1.3.2), and validity and single use become two
checks. Shortening the window only narrows replay time.

## Timestamp-derived reset token

`A07/A04:2025` · ASVS V6/V11 · CWE-330/CWE-340

```python
# Vulnerable: attacker knows user ID and can bracket the request time
token = sha256(f"{user.id}:{int(time.time())}".encode()).hexdigest()
```

Hashing predictable input does not add entropy. The attacker searches timestamps offline.

Fix: at least 32 bytes from the platform CSPRNG, store a digest, bind purpose/account/expiry, and
consume atomically. Why it works: the candidate cannot be derived from public context. A longer
SHA-512 output is the tempting wrong fix; 512 predictable bits remain predictable.

## UUID as authorization

`A01:2025` · ASVS V8 · CWE-862; enumeration relates to CWE-340

Switching invoice ID `4192` to UUIDv4 raises enumeration cost, then the route still returns any
invoice whose ID the caller knows. IDs leak through logs, exports, URLs, referrers, and support.

Fix: scope every object query to the actor/tenant; keep UUIDv4 only as defence in depth. Why it
works: a leaked or guessed ID grants nothing. Do not report UUID migration as the A01 fix.

## Per-request limit on a batch API

`A06:2025` · API4:2023 · ASVS V4/V6 · CWE-770/CWE-307

One GraphQL document carries 200 aliased login mutations and HTTP middleware increments once.
JSON-RPC arrays and gRPC streams have the same bypass.

Fix: validate operation count and body size before execution, and consume the attempt budget
inside each credential-verifying operation. Why it works: candidates and increments stay
one-to-one. Disabling aliases alone is wrong; batching and repeated operations remain.

## Only `/login` is throttled

`A07:2025` · ASVS V6 · CWE-307

Mobile `/api/v1/login`, legacy `/signin`, basic auth, password grant, SSO callback, and internal
support routes verify the same authority outside the policy.

Fix: inventory every credential verifier and call one limiter service from all of them; use a
gateway rule as a backstop. Why it works: the control follows the credential, not one URL. Copying
the middleware route by route is the wrong fix because the next path will be forgotten again.

## `==` compares an HMAC

`A04:2025` · ASVS V11 · CWE-208

A short-circuit comparison leaks how many prefix bytes match. Network jitter does not guarantee
safety; repetition, local proximity, and statistics reduce it.

Fix: decode to equal-length bytes and use `hmac.compare_digest`, `crypto.timingSafeEqual`, or the
platform equivalent. Why it works: comparison time no longer depends on the matching prefix.
Adding a random sleep is wrong: averaging removes noise while making legitimate requests slower.

## Logging the candidate, alerting on a flat number

`A09:2025` · ASVS V16 · CWE-532/CWE-778

`logger.info({ body: req.body })` turns failed password, OTP, token, and API-key guesses into a
central plaintext corpus, and logging the first six token characters still shrinks the search
space. Meanwhile a single "100 global failures" alert fires on every release and sleeps through a
quiet tenant compromise.

Fix: log explicit event fields only - HMACed canonical account ID, outcome, route, source/network,
device risk, limiter action, correlation ID - and pair any hard threshold with a same-hour baseline,
failure ratio, and source/account cardinality. Why it works: defenders correlate the attack without
retaining the secret, and both bursts and low-and-slow patterns stay visible while expected peaks
explain themselves. Redaction after ingestion is too late; the value already reached collectors.
