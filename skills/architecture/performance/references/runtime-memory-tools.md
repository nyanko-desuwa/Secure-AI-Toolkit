# Runtime Memory Tools and Flags

Version-pinned facts about the tools in [troubleshooting.md](../troubleshooting.md). Checked
2026-07-28 against the sources at the bottom.

Where a value depends on the build or the deployment, this file says to print it rather than
quoting a number. That is deliberate - a recalled default is the most common wrong statement
in a memory investigation.

## Python

| Item | Detail | Since |
|---|---|---|
| `tracemalloc.start(nframe=1)` | `nframe` must be >= 1. Values above 1 are required for `'traceback'` grouping and cumulative statistics | stdlib |
| `tracemalloc.take_snapshot()` | Raises if tracing is not active. Excludes blocks allocated before `start()` | stdlib |
| `Snapshot.compare_to(old, key_type, cumulative=False)` | `key_type` is `'filename'`, `'lineno'`, or `'traceback'`. Sorted by absolute `size_diff` | stdlib |
| `Snapshot.filter_traces(filters)` | Inclusive filters apply together; a trace matching any exclusive filter is dropped | stdlib |
| `Filter.all_frames` | No effect when the traceback limit is 1 | stdlib |
| `asyncio.TaskGroup` | Structured concurrency; a scope that cannot exit while its tasks run | Python 3.11 |
| `asyncio.timeout()` / `timeout_at()` | Cancellation scope for a deadline | Python 3.11 |
| `asyncio.create_task()` | The loop keeps only a weak reference. An unreferenced task may be collected before it finishes | 3.7 |

The `create_task` weak-reference warning is unversioned in the CPython documentation, so treat
it as applying to every version that has the function. The documented workaround, when a task
genuinely must outlive the caller:

```python
background_tasks = set()

task = asyncio.create_task(some_coro())
background_tasks.add(task)
task.add_done_callback(background_tasks.discard)
```

Without the `add_done_callback`, that set is an unbounded cache of completed tasks. Prefer
`TaskGroup` where 3.11 is available.

`tracemalloc` sees Python-level allocations only, and roughly doubles allocation cost while
active. A leak inside a C extension does not appear in it.

## Node.js

Flags, with the version each was added. Print the current heap limit rather than assuming it.

| Flag | Effect | Since |
|---|---|---|
| `--inspect[=host:port]` | V8 inspector, default `127.0.0.1:9229`. Attach DevTools for interactive snapshots | 6.3.0 |
| `--heapsnapshot-signal=SIGUSR2` | Writes a `.heapsnapshot` when that signal arrives. Off by default | 12.0.0 |
| `--heapsnapshot-near-heap-limit=N` | Writes up to N snapshots as the heap approaches its limit | 15.1.0, 14.18.0 |
| `--heap-prof` | V8 sampling allocation profiler, writes `.heapprofile` at exit | 12.4.0 |
| `--heap-prof-interval` | Average sampling interval in bytes. Default 512 KiB | 12.4.0 |
| `--max-old-space-size=MiB` | V8 old-space maximum | V8 option |
| `--max-old-space-size-percentage=P` | Percentage of available system memory. Takes precedence over the absolute flag when both are given | recent |
| `--trace-warnings` | Prints the stack for warnings, including `MaxListenersExceededWarning` | - |

`node:v8` API:

```javascript
v8.writeHeapSnapshot([filename[, options]])   // 11.13.0, returns the path
v8.getHeapStatistics()                        // 1.0.0
v8.setHeapSnapshotNearHeapLimit(limit)        // 18.10.0, 16.18.0
```

`writeHeapSnapshot` is synchronous, blocks the event loop for a time proportional to heap
size, and needs roughly twice the heap in memory while running. On a large heap it can cause
the OOM kill you are investigating. It is per-isolate: a main-thread snapshot contains nothing
about worker threads.

Two leak signals in `getHeapStatistics()`: `number_of_detached_contexts` non-zero, and
`number_of_native_contexts` growing over time. `heap_size_limit` is what V8 actually chose:

```bash
node -e 'console.log(require("v8").getHeapStatistics().heap_size_limit)'
```

Security: an inspector bound to a public interface is remote code execution. Never
`--inspect=0.0.0.0` on a reachable host.

## JVM

Container awareness is on by default on Linux. Verify on your build rather than trusting a
recalled default - the flags print themselves:

```bash
java -Xlog:os+container=trace -version
java -XX:+PrintFlagsFinal -version | grep -E 'MaxHeapSize|MaxRAMPercentage|UseContainerSupport'
```

| Flag | Notes |
|---|---|
| `-XX:+UseContainerSupport` | Reads cgroup memory and CPU limits instead of host-wide values. Enabled by default |
| `-XX:MaxRAMPercentage` | Max heap as a percentage of available memory. Consulted only when `-Xmx` is unset - an explicit `-Xmx` always wins |
| `-XX:NativeMemoryTracking=summary` | Required at launch for `jcmd VM.native_memory` to work |
| `-XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=/dumps` | Produces the dump you will want, at the moment you need it |

`jcmd` commands used in the diagnosis:

```bash
jcmd "$PID" GC.heap_info
jcmd "$PID" GC.class_histogram
jcmd "$PID" GC.heap_dump /tmp/app.hprof
jcmd "$PID" VM.native_memory summary
```

The default heap percentage is conservative because non-heap memory - Metaspace, code cache,
thread stacks, direct byte buffers - also comes out of the container limit. Raising the
percentage without budgeting for that native overhead gets the process killed by the kernel
with no `OutOfMemoryError` and no heap dump.

## Go

| Item | Detail | Since |
|---|---|---|
| `debug.SetMemoryLimit(n int64)` | Soft memory limit. Returns the previous value. A negative argument reads without modifying | Go 1.19 |
| `GOMEMLIMIT` | Provides the initial value. Byte count with an optional `B`/`KiB`/`MiB`/`GiB`/`TiB` suffix | Go 1.19 |
| `GODEBUG=gctrace=1` | One line per GC cycle with heap sizes around it | - |
| `net/http/pprof` | Registers `/debug/pprof/*` handlers. Serve on an internal port only | - |

```go
current := debug.SetMemoryLimit(-1)   // read
debug.SetMemoryLimit(2 << 30)         // 2 GiB soft limit
```

Two things to plan around. The default is effectively unlimited unless `GOMEMLIMIT` is set or
`SetMemoryLimit` is called - the Go runtime does not read cgroup limits, so in a container you
plumb the value through yourself, from the orchestrator or by reading `/sys/fs/cgroup/memory.max`.
And the limit only covers runtime-managed memory: it tracks `MemStats.Sys - MemStats.HeapReleased`
and excludes kernel memory held for the process, allocations made by C code, and
`syscall.Mmap` regions. A cgroup limit counts all of those, so matching `GOMEMLIMIT` to the
cgroup limit still leaves you exposed. Leave headroom.

It is a soft limit: the runtime responds by collecting more often and releasing more
aggressively, not by failing allocations, and it applies even with `GOGC=off`. Set too low, the
GC runs nearly continuously and the application still makes progress, just slowly.

pprof views worth distinguishing: `inuse_space` is the leak view, `alloc_space` is the churn
view. `-base` compares two profiles and shows only growth.

## Containers

```bash
cat /sys/fs/cgroup/memory.max                     # v2, "max" means unlimited
cat /sys/fs/cgroup/memory.current                 # v2
cat /sys/fs/cgroup/memory.events                  # v2, cumulative oom_kill count
cat /sys/fs/cgroup/memory/memory.limit_in_bytes   # v1
```

`free` and `/proc/meminfo` report the host inside a container. A runtime that sizes itself from
"total system memory" is reading the wrong number unless it explicitly reads cgroups.

Exit code 137 is `128 + 9`: SIGKILL from the kernel OOM killer. No stack trace, no
`OutOfMemoryError`, no shutdown hook, no chance to write a dump. Any evidence you want has to
be arranged before the kill.

## Sources

- Python `tracemalloc` - <https://docs.python.org/3/library/tracemalloc.html>
- Python `asyncio` tasks - <https://docs.python.org/3/library/asyncio-task.html>
- Node CLI options - <https://nodejs.org/api/cli.html>
- Node `v8` module - <https://nodejs.org/api/v8.html>
- Go `runtime/debug` - <https://pkg.go.dev/runtime/debug#SetMemoryLimit>
- Go GC guide - <https://go.dev/doc/gc-guide>
- JVM troubleshooting guide - <https://docs.oracle.com/en/java/javase/21/troubleshoot/>
