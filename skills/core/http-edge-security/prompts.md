# HTTP Edge Security Prompts

## Beginner

```text
Explain whether this app can trust the client IP and host it receives. Show the exact headers an
attacker could send, which deployment component must remove them, and what I should verify in the
CDN or load balancer. Do not say it is safe unless you found the trusted-proxy configuration.
```

## Developer

```text
Review src/server for Host, Forwarded, X-Forwarded-For, X-Forwarded-Host, X-Real-IP, and method
override reads. For each, trace the value to its security decision. Report file:line, spoofed
request shape, ASVS 4.1.3/4.1.4 or CWE, and the smallest fix.
```

## Review

```text
Review the reverse-proxy, CDN, and app configuration for HTTP edge failures. Build a hop diagram,
identify header strip/append behavior, allowed Host names, cache key inputs, cache eligibility, and
request framing behavior. Findings require a concrete attacker-controlled header or request line,
CWE, severity, fix, and deployment precondition.
```

## Audit

```text
Assess HTTP edge controls against OWASP ASVS 5.0 V4, V11, V13, and V14. For each control provide
the config/code evidence, the deployed component that enforces it, the test evidence, and anything
not verifiable from this repository. Do not replace absent evidence with a vendor default claim.
```

## Anti-patterns

| Reassuring non-answer | Prompt that produces a finding |
|---|---|
| "Is nginx secure?" | "Show every header nginx accepts from clients and whether it strips or overwrites it before proxying." |
| "Check for request smuggling." | "Map HTTP version and framing parser at each hop; identify any TE/CL ambiguity and state whether it is confirmed or needs staging proof." |
| "Does the CDN cache safely?" | "List cache-key fields and cacheable response classes. Test whether a personalized response can be stored under a public-looking path." |
