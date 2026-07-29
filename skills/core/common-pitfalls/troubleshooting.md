# Troubleshooting

Start from the symptom. Each section gives the likely causes in the order worth checking, the
command or code to check with, and where the fix lives.

## I think I leaked a key

Assume the key is being used, not just seen. Public-repo scanners find committed credentials
within minutes, and bundled keys are found by anyone reading your JavaScript.

Order matters. Revoking first is what stops the spend.

1. Revoke and reissue at the provider. Not delete the line, not delete the commit.
2. Check the provider's usage or audit log for calls you did not make. Note the window.
3. Find how it escaped: build output, git history, a Docker layer, a mobile bundle, a chat log.
4. Fix the path so the new key cannot follow it.

```bash
npm run build
grep -rEn "sk-ant-|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|service_role|-----BEGIN" \
  dist/ build/ .next/static/ 2>/dev/null
git log --all --full-history --oneline -- .env .env.local .env.production
```

Per-stack detection, including Docker and mobile, is in
[references/secret-exposure.md](references/secret-exposure.md). Rotation design is in the
`secrets-management` skill.

## My bill jumped

Check in this order. The first two are the ones that produce a shock rather than a drift.

- A leaked key someone else is using. Compare the provider's request log against your traffic.
  Requests from regions you do not serve are the tell.
- A retry or polling loop with no ceiling. `setInterval` at one second is 2.6 million calls a
  month per client. Multiply your interval by your user count before assuming it is small.
- An LLM or metered API called once per row inside a loop. Check for `await` inside `for`.
- Egress or storage from an unpaginated endpoint returning whole tables.
- A serverless function with no concurrency cap, invoked by a queue that got backed up.

Then set a billing alert at your expected monthly figure, and a hard spend cap where the provider
offers one. Limits worth starting from are in
[references/resource-limits.md](references/resource-limits.md).

## Anyone can see or change other people's data

This is the finding to fix before anything else on this page.

Test it directly. Two accounts, or one account and none.

```bash
# Log in as user A, note an ID that belongs to A, then request it as user B
curl -s -H "Authorization: Bearer $TOKEN_B" https://your-app.example.com/api/orders/A-ORDER-ID
# And with no token at all
curl -s https://your-app.example.com/api/orders/A-ORDER-ID
```

Anything other than 401 or 404 is a finding. Likely causes:

- The check runs in React only. See
  [best-practices.md](best-practices.md#4-security-decided-in-the-client).
- The JWT is decoded, not verified, so the role is caller-supplied.
- The query filters by ID but not by owner.
- Supabase or Firebase with policies disabled. Anon key plus no Row Level Security means the
  whole table is public. Test with a second account, not by reading the policy list.

## Memory keeps growing

Three different things look identical on a memory graph, and the wrong diagnosis costs days.

| Pattern | What it is | Action |
|---|---|---|
| Rises, then flattens at a plateau | A cache warming up, or a normal working set | Nothing, unless the plateau is near the limit |
| Rises steadily, never flattens, restarts reset it | A real leak | Find what is retained |
| Sawtooth that keeps rising, RSS high while heap is stable | Allocator fragmentation, or memory held outside the heap | Not a code-level leak. Check buffers and native modules |

Measure before changing code. Send the same request repeatedly and watch whether memory returns
to a baseline.

```bash
# Node: heap over time
node --expose-gc -e "setInterval(()=>console.log(process.memoryUsage()),5000)"
```

For Node, take two heap snapshots in the Chrome DevTools memory panel with the same workload
between them, and compare with the "Objects allocated between snapshots" view. The constructor
holding the most retained size names the leak. RSS is what the operating system gave the process;
heap is what your JavaScript objects occupy. A large gap between them points away from your
objects.

Most common causes in AI-generated code, in order: a module-level `Map` used as a cache with no
bound, `useEffect` with no cleanup, `setInterval` never cleared, listeners added per request, a
Python list at module scope.

Deep diagnosis per runtime, including snapshot workflow and container limits, belongs to
`architecture/performance` - see `skills/architecture/performance/troubleshooting.md`. This page
covers recognising the shape; that one covers proving it.

## The app gets slower every week

Slowness proportional to data volume is a query problem, not a hosting problem.

- `await` inside a loop over rows. One round trip per row, run sequentially.
- Missing index on a column in a `WHERE`, `JOIN`, or `ORDER BY`. Run `EXPLAIN` on the slow query
  and look for a sequential scan on a large table.
- Counting or summing by loading rows into the application. Move it to `COUNT()` or `SUM()`.
- No pagination, so response size grows with the table.
- A cache that never expires serving stale data, or no cache on an expensive read.

Measure one slow request end to end before optimising. The line you assume is hot usually is not.

## It works locally but not in production

Almost always configuration, and the dangerous version is when it appears to work.

- A required environment variable is unset in production and the code falls back to a development
  default. That default may be your dev database, which means production writes are going
  somewhere nobody is looking. Make missing config a startup failure.
- `localhost` or `127.0.0.1` in a URL that shipped. Inside a container, `localhost` is the
  container.
- A path that exists on one machine only.
- CORS listing the dev origin and not the production one.
- The build inlined a development value at build time. Build-time and run-time variables are
  different things; changing the dashboard value does not change an already-built bundle.

```bash
# Confirm what the deployed process actually connected to, without printing the secret
node -e "console.log(new URL(process.env.DATABASE_URL).host)"
```

## Something failed but the app said it worked

An empty `catch` or an unchecked write result. The failure was discarded.

```bash
grep -rn "catch\s*{\s*}\|catch (e) {}\|except:\s*pass\|except Exception:\s*pass" src/
```

Also check for a promise with no `await` and no `.catch`, and for a write whose returned row
count is never examined. Install an unhandled-rejection handler so silent failures become loud.
Fix pattern is in [best-practices.md](best-practices.md#7-swallowed-errors-and-data-loss).

## I ran an UPDATE or DELETE without a WHERE

Stop writing to the database now. Do not run more statements hoping to correct it.

1. If you were inside an open transaction, `ROLLBACK`.
2. Otherwise restore from the most recent backup or point-in-time snapshot, into a scratch
   database first so you can compare before replacing anything.
3. If there is no backup, check whether your provider retains one automatically. Many do for a
   fixed window.

Afterwards: verify a restore actually works by doing one on purpose. An untested backup is a
belief, not a backup.

## What this page cannot tell you

Whether the production environment variable is set, whether the Row Level Security policy is
enabled on the live project, whether a leaked key has been used, and whether the CDN is caching a
private response are all facts about your running system. Source code cannot answer them. Check
each one against the deployment and the provider's own console.
