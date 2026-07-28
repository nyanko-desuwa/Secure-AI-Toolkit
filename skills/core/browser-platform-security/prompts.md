# Browser Platform Security Prompts

## Beginner

```text
Explain what this service worker or extension can keep doing after I leave the page, which websites
can invoke it, and what permission is unnecessary. Show the file and setting for each answer.
```

## Developer

```text
Review manifest.json, service-worker registration/fetch handlers, content scripts, and runtime
messages. List scope, host permissions, cacheable paths, web-accessible resources, and sender checks.
Findings need file:line, attacker origin, CWE, fix, and browser-specific assumption.
```

## Review

```text
Build a capability matrix: platform feature, invoking origin/sender, accessible data/action, lifetime,
and revocation path. Flag any all-origin permission, unbounded worker scope, cache of private data,
or unvalidated extension message.
```

## Audit

```text
Assess PWA/extension controls against ASVS V1/V3/V13/V14. Provide manifest/config evidence, negative
test evidence, owner, CWE, and facts that require browser-store or deployed-header verification.
```

## Anti-patterns

| Weak prompt | Finding prompt |
|---|---|
| "Is this extension safe?" | "Show every origin allowed by manifest and every message sender that can reach privileged APIs." |
| "Check PWA cache." | "Identify each fetch route that can be cached and prove authenticated responses are excluded." |
