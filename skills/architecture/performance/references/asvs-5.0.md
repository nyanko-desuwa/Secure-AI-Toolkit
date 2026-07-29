# OWASP ASVS 5.0.0 for Resource Lifetime

Version 5.0.0, released 2025-05-30. Verified 2026-07-28 against
<https://owasp.org/www-project-application-security-verification-standard/>.

Citations in this skill are chapter-level only. ASVS 5.0 substantially reorganized the
standard; do not copy requirement IDs from 4.x. For a requirement-level assessment, use the
official 5.0 source at <https://github.com/OWASP/ASVS>.

## V2 - Validation and Business Logic

Use V2 for input-derived work and allocation:

- Array length and page size
- Numeric ranges used for allocation
- Query depth and complexity
- Batch and export size
- Concurrency or fan-out requested by a caller
- Compressed and decompressed payload bounds

Validate at the server boundary. A client-side limit changes the user interface, not the
attacker's request. Reject unknown fields where they can introduce an unbudgeted operation.

A limit needs a unit. "Maximum upload 10" is incomplete; 10 bytes, MiB, files, and entries are
different controls. Enforce bytes actually consumed rather than trusting a declared length.

## V13 - Configuration

Use V13 where the platform exposes the resource policy:

- Connection pool maximum and acquire timeout
- Reverse-proxy request body limit
- Runtime memory ceiling below the cgroup limit
- Worker and concurrency count
- Outbound connect, read, and total timeout
- Retry attempts and total budget
- Diagnostic profiler or inspector exposure

Defaults are not evidence. Read effective values from the pinned runtime or deployment. Go SQL
open connections are unlimited until configured. Node's effective V8 heap limit should be
printed, not guessed. JVM heap must leave room for non-heap memory.

Configuration belongs in source-controlled deployment manifests where possible. A production
hotfix made only in a console is not a durable control.

## V16 - Security Logging and Error Handling

Use V16 for release and observability:

- Cleanup runs on exceptions, cancellation, timeout, and disconnect
- Pool saturation and queue rejection are visible
- Cache, queue, listener, goroutine, and connection counts are measured
- OOMKill and near-limit memory events alert an operator
- Background task exceptions are observed rather than dropped
- Client errors do not expose heap contents or internal paths

The success path is not enough. Verify malformed input, client disconnect, dependency timeout,
and process shutdown. Scope guards - `with`, `try/finally`, `defer`, `using` - attach release to
all exits.

Heap dumps and profiles contain live secrets. Protect them as sensitive production data, limit
access, and delete them after diagnosis.

## Related Chapters

| Chapter | Use in this skill |
|---|---|
| V5 File Handling | Upload bytes, archive entry count, decompressed output, file-handle release |
| V8 Authorization | Tenant/user identity in shared cache keys and request context |
| V4 API and Web Service | API-specific request and response bounds |
| V15 Secure Coding and Architecture | Ownership and structured-concurrency design |

The scope addendum requires V2, V13, and V16. The related chapters are cited only where the
control directly touches them.

## Verification Procedure

For a resource-affecting change:

1. List every acquired object and external handle.
2. Name its owner and release point.
3. Identify every input that affects count, size, or lifetime.
4. Read the effective configured limit; do not infer it from a default.
5. Exercise success, exception, cancellation, and saturation.
6. Confirm metrics reveal growth before the process reaches its ceiling.

Record pass, fail, or not applicable with a reason. A chapter citation is not a claim of ASVS
Level 1, 2, or 3 compliance. Formal level claims require checking the official requirement set
one by one.

## Known Gaps

ASVS does not choose capacity values for a particular system. A 10,000-entry cache can be safe
or fatal depending on entry size and process budget. Derive limits from measured p99 size,
concurrency, dependency quota, and available headroom, then monitor them.

Source review cannot prove deployment state. Verify the running process sees the intended
cgroup limit, pool settings, and timeouts.

## Source

- OWASP ASVS project -
  <https://owasp.org/www-project-application-security-verification-standard/>
- OWASP ASVS repository - <https://github.com/OWASP/ASVS>
