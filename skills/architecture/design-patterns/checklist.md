# Design Patterns Checklist

Run the applicable sections before returning a design or code change. Mark each item pass, fail, or
not applicable; explain every not-applicable choice.

## Justification and Scope

- [ ] The change names one real coupling or one control that callers can currently bypass
- [ ] The selected pattern is smaller than a function, parameter, module, or explicit call would be
- [ ] The boundary has a named owner and one responsibility
- [ ] The scope is one bounded context or module, not a repository-wide folder exercise
- [ ] Alternatives considered include no pattern, a direct function, and a data/config change
- [ ] The cost is recorded: types, calls, allocations, queries, latency, and retained state
- [ ] Pattern language is not being used to conceal an unresolved business decision

## Entry Points and Authorization

- [ ] Controllers, jobs, scripts, tests, DI registrations, factories, and direct constructors were searched
- [ ] Every entry point reaches the same policy boundary
- [ ] Concrete implementations are not publicly constructible when the abstraction is a security boundary
- [ ] Actor and tenant identity come from authenticated context, not a request body or client selector
- [ ] Repository methods require tenant scope and cannot issue an unscoped read
- [ ] Strategy, plugin, and registry selection uses an allowlist owned by the server
- [ ] Authorization is enforced server-side, not by a client-selected pattern or UI path
- [ ] An authorization failure does not reveal whether another tenant's object exists
- [ ] A01:2025, ASVS V8, CWE-602, CWE-653, or CWE-1220 is cited only when the mechanism fits

## Input and Data Boundaries

- [ ] Adapters validate and normalize external data before it reaches domain code
- [ ] SQL, shell, template, and expression construction is parameterized or allowlisted
- [ ] Unknown fields and unknown discriminators are rejected
- [ ] DTOs are explicit; domain entities and internal fields are not serialized by accident
- [ ] A05:2025 and ASVS V15 are cited for verified injection or unsafe dynamic construction

## Lifetime and Ownership

- [ ] Every listener, observer, timer, task, cache entry, pool lease, and queue item has an owner
- [ ] Every acquisition has release on success, exception, cancellation, timeout, disconnect, and shutdown
- [ ] A singleton is immutable or stateless and never captures request data
- [ ] Observer callbacks have a matching unsubscribe using the same function reference
- [ ] Memoization and caches have a maximum size or bytes, TTL, and identity-safe key
- [ ] Object pools have maximum capacity, acquire timeout, lease timeout where needed, and reset-on-release
- [ ] Queue depth is bounded and full behavior is explicitly block, drop, or reject
- [ ] No callback or task failure is silently swallowed
- [ ] CWE-401, CWE-770, or CWE-772 is cited only for verified retention, missing bounds, or missing release
- [ ] `skills/architecture/performance/` was consulted for detailed leak diagnosis where relevant

## Behavior and Tests

- [ ] The happy path and negative path exercise the boundary
- [ ] A bypass attempt is rejected or cannot compile
- [ ] Two tenants cannot read each other's cached or repository data
- [ ] Unknown strategy or adapter input fails closed
- [ ] An exception returns a pool lease and removes an observer
- [ ] Duplicate decoration, duplicate subscription, and repeated construction have defined behavior
- [ ] Queue saturation and pool exhaustion produce bounded, observable behavior
- [ ] Tests do not prove deployment-only claims such as actual listener counts or effective pool size
- [ ] Build and relevant tests were run, and results are reported honestly

## Before Returning

- [ ] The recommendation says when not to use the pattern
- [ ] The implementation path and rollback/removal path are clear
- [ ] Residual gaps and unverified runtime assumptions are stated
- [ ] No credentials, personal data, attack tooling, placeholders, or invented standard IDs appear
