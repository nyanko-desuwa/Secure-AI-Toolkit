# Prompt Examples

Prompts that produce findings rather than advice. Each names the scope, the artefact, and the
shape of the answer. Vague prompts about performance get a lecture on caching.

## Inventory acquisitions in a diff

```
Review my staged changes with skills/architecture/performance. For every acquisition —
allocation that outlives the call, cache entry, socket, file handle, cursor, subscription,
timer, task, goroutine — list the owner and the release point. Report anything with no bound
or no release on the error path. Classify each as L1 to L8.
```

Why it works: it asks for a table of owners and release points, so the answer has to be read
out of the code. "Check for memory leaks" gets you a list of leak types instead.

## Review one long-lived structure

```
Read src/cache.py. For each module-level structure: what is the key space, what is the
maximum size, what evicts entries, and can an unauthenticated caller add one? If any of the
four has no answer in the code, say so.
```

Naming the four questions is the whole prompt. Any of them unanswered is the finding.

## Work an active leak

```
Our Node service heapUsed grows ~60 MB/hour under steady traffic and OOMs at 1.5 GB after
about a day. Give me the three-snapshot method from troubleshooting.md with the exact
commands for a container I can exec into. Then tell me what a growing retainer looks like in
the comparison view versus a warm cache.
```

Giving the rate and the ceiling matters. Without them the answer cannot tell you whether one
snapshot interval is long enough to show growth.

## Distinguish leak from working set

```
RSS is 1.2 GB, heapUsed is 300 MB, and both are stable after four hours. Is this a leak?
Tell me what would distinguish a leak from a large working set here, and which measurement
would settle it.
```

Asks for the discriminator rather than a verdict. Stable is the key word — a leak that has
stopped growing is not a leak.

## Choose limits with reasoning

```
This endpoint accepts a JSON array of IDs and fetches each one from an upstream API. Give me
the bounds it needs — array length, body size, concurrency, per-call timeout, total budget —
with the reasoning for each number and what breaks if it is set too low.
```

Asking what breaks at too-low forces a real number instead of a conservative default nobody
can defend.

## Backpressure decision

```
We have a producer writing to an unbounded asyncio.Queue consumed by a slower worker. Give
me the block, drop, and reject options with the code for each, what the client sees, and
which one fits an ingest endpoint that public clients call.
```

The three options are the answer. A prompt that asks "how do I fix the queue" gets `maxsize=`
and no policy.

## Cleanup review in a component

```
Read src/components/JobStream.tsx. For each useEffect: does it return a cleanup function,
does the dependency array match what it captures, and does anything it starts — fetch,
subscription, interval — survive unmount?
```

## Cross-request contamination

```
Find every module-level, static, or thread-local variable in src/ that is written during a
request. For each, tell me whether a later request on the same worker can read the previous
request's value, and treat any that can as A01:2025 rather than a performance bug.
```

Naming the severity reframe stops the answer from filing a data leak under performance.

## Container limit reality check

```
Our Go service is OOMKilled at its 512Mi limit while pprof inuse_space shows 180 MB. Explain
where the rest is, whether the Go runtime knows about the cgroup limit, and what to set.
```

## Challenge a proposed fix

```
A teammate wants to fix our growing RSS by calling gc.collect() every 60 seconds. Explain
what that does and does not do, and what I should ask for instead.
```

See [common-mistakes.md](common-mistakes.md#the-wrong-fixes) — the wrong fixes are worth
naming explicitly, because they look like action.

## Anti-patterns

| Prompt | Problem |
|---|---|
| "Optimise this code" | No workload, no measurement. Produces speculative rewrites and a new cache |
| "Make it faster" | Faster than what, measured how? Invites micro-optimisation of cold paths |
| "Find memory leaks" | No scope. Returns a taxonomy of leaks, not findings in your code |
| "Add caching" | Adds L1. Ask for a bounded cache with a max size, TTL, and key space |
| "Why is memory growing?" without data | Guesswork. Attach two measurements or ask for the method first |
| "Is this thread-safe and leak-free?" | Two questions, different analyses. Split them |
| "Fix the OOM" | Accepts a raised limit as the answer. Ask for the retainer |
