# Troubleshooting

Runnable leak diagnosis, plus what to do when the guidance cannot be applied.

## The Method

Every runtime uses the same sequence:

1. Warm caches, then take a baseline snapshot.
2. Apply steady, representative load.
3. Take snapshot two.
4. Repeat the same load and take snapshot three.
5. Compare snapshots two and three. Find a growing retainer, not merely a large object.

A warm cache is large in snapshot two and stable in three. A leak grows in both intervals.
One snapshot cannot distinguish them. If you only have one, report a hypothesis.

Separate RSS from heap first. RSS is what the OS charges. Heap is what the runtime tracks.
Rising RSS with a flat heap points to native allocations, thread stacks, mapped files, or an
allocator retaining free pages — not necessarily live objects.

## Python

```bash
ps -o rss=,vsz= -p "$PID"
watch -n 30 "ps -o rss= -p $PID"
```

```python
import tracemalloc
tracemalloc.start(25)
baseline = tracemalloc.take_snapshot()
run_steady_load()
current = tracemalloc.take_snapshot().filter_traces((
    tracemalloc.Filter(False, "<frozen importlib._bootstrap>"),
    tracemalloc.Filter(False, "<unknown>"),
))
for stat in current.compare_to(baseline, "lineno")[:15]:
    print(stat)
```

A large positive `count_diff` at the same allocation site across consecutive intervals is the
signal. `tracemalloc` says where allocation happened, not who retains it. Use `objgraph` for
the holder:

```python
import gc, objgraph
gc.collect()
objgraph.show_growth(limit=15)  # run twice; second output is the delta
objgraph.show_backrefs(
    objgraph.by_type("MyLeakedType")[0], max_depth=6, filename="refs.png"
)
```

Without `objgraph`, count tracked objects:

```python
import collections, gc
print(collections.Counter(type(o).__name__ for o in gc.get_objects()).most_common(20))
```

`tracemalloc` sees Python allocations, not native allocations in C extensions. More traceback
frames increase overhead; do not leave it enabled blindly in production.

## Node and Browsers

```javascript
setInterval(() => {
  const m = process.memoryUsage();
  console.log({ rss: m.rss, heapUsed: m.heapUsed, external: m.external,
                arrayBuffers: m.arrayBuffers });
}, 30_000).unref();
```

Rising `heapUsed` means JavaScript objects. Rising `external` or `arrayBuffers` with flat heap
means Buffers or native memory.

```bash
node --inspect app.js
node --heapsnapshot-signal=SIGUSR2 app.js   # then: kill -USR2 "$PID"
node --max-old-space-size=100 --heapsnapshot-near-heap-limit=3 app.js
node --trace-warnings app.js                # stack for MaxListenersExceededWarning
```

Load three snapshots in DevTools. Select snapshot three, compare with two, sort by `# Delta`,
then walk `Retainers` to a GC root. Growing detached DOM nodes indicate L5; growing closures
under one handler indicate L2. `v8.getHeapStatistics()` also exposes
`number_of_detached_contexts`.

`v8.writeHeapSnapshot()` is synchronous, blocks the event loop, and needs roughly twice the
heap while running. Use a canary. Never expose `--inspect` publicly; a reachable inspector is
remote code execution.

## JVM

```bash
jcmd "$PID" GC.heap_info
jcmd "$PID" GC.class_histogram
jcmd "$PID" GC.heap_dump /tmp/app.hprof
jcmd "$PID" VM.native_memory summary  # needs -XX:NativeMemoryTracking=summary at launch
```

Add `-XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/dumps` before the incident. In a heap
analyser, use the dominator tree: retained size is what would be freed if the object vanished;
shallow size is usually irrelevant. Compare two histograms, then find the growing class's
dominator.

If RSS greatly exceeds heap, inspect direct buffers, Metaspace, code cache, and thread stacks
with Native Memory Tracking.

## Go

Expose `net/http/pprof` on an internal port only:

```bash
curl -o base.pb.gz http://localhost:6060/debug/pprof/heap
# apply load
curl -o after.pb.gz http://localhost:6060/debug/pprof/heap
go tool pprof -base base.pb.gz after.pb.gz
go tool pprof -http=:8080 after.pb.gz
```

Use `inuse_space` for retained memory. `alloc_space` shows churn and can identify a hot path
that leaks nothing.

```bash
curl -s 'http://localhost:6060/debug/pprof/goroutine?debug=2'
GODEBUG=gctrace=1 ./app
```

A stack repeated and growing, usually parked on `chan send` or `select`, is L4. A post-GC live
heap that steps upward every cycle suggests retention; a sawtooth around a stable floor is
normal.

## Containers

```bash
cat /sys/fs/cgroup/memory.max       # cgroup v2; "max" means unlimited
cat /sys/fs/cgroup/memory.current
cat /sys/fs/cgroup/memory.events    # cumulative oom_kill counter
cat /sys/fs/cgroup/memory/memory.limit_in_bytes  # cgroup v1
```

`free` may report host memory rather than the cgroup budget. Exit code 137 is `128 + 9`,
SIGKILL. Kubernetes reports `Reason: OOMKilled`. The kernel gives no stack trace and runs no
shutdown hook, so arrange evidence before the limit: near-limit dumps or threshold alerts.

| Runtime | Container behaviour | Verify |
|---|---|---|
| JVM | Container support is normally enabled; leave room outside heap | `java -Xlog:os+container=trace -version` |
| Go | Does not derive `GOMEMLIMIT` from cgroups; set it explicitly | `debug.SetMemoryLimit(-1)` |
| Node | Do not assume the V8 ceiling | `node -e 'console.log(require("v8").getHeapStatistics().heap_size_limit)'` |
| Python | No managed heap ceiling; bound allocations in the app | Read cgroup files and application metrics |

Leave headroom. Go's soft limit excludes cgo and `mmap`; the JVM heap excludes Metaspace,
thread stacks, direct buffers, and code cache.

## Guidance Cannot Be Applied

- **Leak is in a dependency.** Reproduce against the pinned version. Upgrade, bound its use,
  isolate it in a recyclable process, or replace it. A restart is mitigation, not a fix.
- **Production only.** Instrument suspected structures: cache size, queue depth, listener and
  goroutine counts, open connections. Let the graph identify what grows.
- **Bound changes behaviour.** Report current behaviour, the new rejection or eviction, who
  breaks, and a migration path. Ask before silently converting a store into a cache.
- **Backpressure adds latency.** Present block, drop, and reject with numbers. An unbounded
  queue hides the same cost until the process dies.
- **Limit is unknown.** Derive it from measured p99 entry size, concurrent users, memory
  budget, or a dependency quota. A monitored, justified initial value beats no limit.
- **Framework default is uncertain.** Verify the pinned version. If you cannot, state the
  value as unverified instead of recalling it.

## Sources

- <https://docs.python.org/3/library/tracemalloc.html>
- <https://nodejs.org/api/cli.html>
- <https://nodejs.org/api/v8.html>
- <https://pkg.go.dev/runtime/debug#SetMemoryLimit>
- <https://go.dev/doc/gc-guide>
