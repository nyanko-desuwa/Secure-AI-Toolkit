# HTTP Client Security Prompts

## Beginner

```text
Explain where this service can send HTTP requests, what an attacker can influence, and what happens
if it follows a redirect to an internal address.
```

## Developer

```text
Review src/integrations/provider_client.py for URL parsing, destination allowlists, redirects, DNS,
TLS verification, timeouts, retries, response-size limits, credentials, and safe logging.
```

## Review

```text
Review all outbound HTTP clients against skills/core/http-client-security/checklist.md. Report only
proven paths with file:line, target, exploit precondition, fix, and residual egress/DNS gaps.
```

## Audit

```text
Provide evidence for every outbound destination policy: host/address/redirect/proxy/TLS/credential
rules, timeout/retry limits, response bounds, and network egress controls. Mark runtime evidence
that source code cannot prove.
```

## Anti-patterns

| Prompt | Why it fails |
|---|---|
| “Block localhost” | Misses IPv6, metadata, redirects, DNS, and private ranges |
| “Turn off TLS verification for internal APIs” | Converts a trust problem into interception risk |
| “Add retries” | Omits idempotency, budget, backoff, and failure semantics |
