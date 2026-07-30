# Design Patterns Checklist

Run the applicable sections before returning a design or code change. Mark each item pass, fail, or
not applicable; explain every not-applicable choice.

## Justification and Scope

- [ ] [recommended] The change names one real coupling or one control that callers can currently bypass
- [ ] [optional] The selected pattern is smaller than a function, parameter, module, or explicit call would be
- [ ] [recommended] The boundary has a named owner and one responsibility
- [ ] [recommended] The scope is one bounded context or module, not a repository-wide folder exercise
- [ ] [recommended] Alternatives considered include no pattern, a direct function, and a data/config change
- [ ] [recommended] The cost is recorded: types, calls, allocations, queries, latency, and retained state
- [ ] [optional] Pattern language is not being used to conceal an unresolved business decision

## Entry Points and Authorization

- [ ] [recommended] Controllers, jobs, scripts, tests, DI registrations, factories, and direct constructors were searched
- [ ] [critical] Every entry point reaches the same policy boundary
- [ ] [critical] Concrete implementations are not publicly constructible when the abstraction is a security boundary
- [ ] [critical] Actor and tenant identity come from authenticated context, not a request body or client selector
- [ ] [critical] Repository methods require tenant scope and cannot issue an unscoped read
- [ ] [critical] Strategy, plugin, and registry selection uses an allowlist owned by the server
- [ ] [critical] Authorization is enforced server-side, not by a client-selected pattern or UI path
- [ ] [recommended] An authorization failure does not reveal whether another tenant's object exists
- [ ] [optional] A01:2025, ASVS V8, CWE-602, CWE-653, or CWE-1220 is cited only when the mechanism fits

## Input and Data Boundaries

- [ ] [recommended] Adapters validate and normalize external data before it reaches domain code
- [ ] [critical] SQL, shell, template, and expression construction is parameterized or allowlisted
- [ ] [recommended] Unknown fields and unknown discriminators are rejected
- [ ] [recommended] DTOs are explicit; domain entities and internal fields are not serialized by accident
- [ ] [optional] A05:2025 and ASVS V15 are cited for verified injection or unsafe dynamic construction

## Lifetime and Ownership

- [ ] [recommended] Every listener, observer, timer, task, cache entry, pool lease, and queue item has an owner
- [ ] [recommended] Every acquisition has release on success, exception, cancellation, timeout, disconnect, and shutdown
- [ ] [recommended] A singleton is immutable or stateless and never captures request data
- [ ] [recommended] Observer callbacks have a matching unsubscribe using the same function reference
- [ ] [recommended] Memoization and caches have a maximum size or bytes, TTL, and identity-safe key
- [ ] [recommended] Object pools have maximum capacity, acquire timeout, lease timeout where needed, and reset-on-release
- [ ] [recommended] Queue depth is bounded and full behavior is explicitly block, drop, or reject
- [ ] [recommended] No callback or task failure is silently swallowed
- [ ] [optional] CWE-401, CWE-770, or CWE-772 is cited only for verified retention, missing bounds, or missing release
- [ ] [optional] `skills/architecture/performance/` was consulted for detailed leak diagnosis where relevant

## Behavior and Tests

- [ ] [recommended] The happy path and negative path exercise the boundary
- [ ] [recommended] A bypass attempt is rejected or cannot compile
- [ ] [recommended] Two tenants cannot read each other's cached or repository data
- [ ] [critical] Unknown strategy or adapter input fails closed
- [ ] [recommended] An exception returns a pool lease and removes an observer
- [ ] [recommended] Duplicate decoration, duplicate subscription, and repeated construction have defined behavior
- [ ] [recommended] Queue saturation and pool exhaustion produce bounded, observable behavior
- [ ] [optional] Tests do not prove deployment-only claims such as actual listener counts or effective pool size
- [ ] [critical] Build and relevant tests were run, and results are reported honestly

## Before Returning

- [ ] [recommended] The recommendation says when not to use the pattern
- [ ] [recommended] The implementation path and rollback/removal path are clear
- [ ] [critical] Residual gaps and unverified runtime assumptions are stated
- [ ] [critical] No credentials, personal data, attack tooling, placeholders, or invented standard IDs appear
