# HTTP Edge Security Skill

Controls for the HTTP edge: reverse proxies, load balancers, CDNs, and the application
code that trusts what those hops claim about the client.

## Purpose

Most "client IP", "request host", and "HTTPS was used" values in application logs and
auth decisions did not come from the socket. They came from headers. If any untrusted hop
can set those headers, the app authenticates the attacker, rate-limits the wrong person,
sends password resets to the attacker's domain, or stores one user's response under
another's cache key.

This skill owns that trust boundary. Application authorization (BOLA, mass assignment)
belongs to `api-security`. Browser XSS and CSP belong to `frontend-security`. SSH is
`ssh-server`.

## How It Works

Plain Markdown. Nothing executes. An assistant reads `SKILL.md`, follows the five steps
(map hops, decide trust, apply controls, verify, report), and opens the supporting file it
needs.

```text
SKILL.md                   workflow, severity, failure table, entry point
README.md                  this file
checklist.md               pre-return verification, grouped by edge surface
best-practices.md          patterns, each with a vulnerable/fixed pair
common-mistakes.md         wrong fixes and why they fail
troubleshooting.md         when guidance conflicts (XFF vs trust, multi-proxy)
prompts.md                 Beginner / Developer / Review / Audit prompts
references/
  README.md                index of standard pins
  owasp-edge.md            Top 10 2025 A02/A04/A05 edge mapping
  asvs-edge.md             ASVS 5.0 V4 / V11 / V13 / V14 pins
  cwe-edge.md              CWE-444, CWE-441, CWE-346, CWE-20, and related
examples/
  README.md                seven vulnerable/fixed pairs with category and CWE
```

## Standards Covered

| Standard | Version | Verified |
|---|---|---|
| OWASP Top 10 | 2025 | 2026-07-28, against <https://owasp.org/Top10/2025/> |
| OWASP ASVS | 5.0.0 (released May 2025) | 2026-07-28, V4 / V11 / V13 / V14 themes from `OWASP/ASVS` `5.0/en/` |
| CWE | MITRE classes cited below | 2026-07-28 |
| HTTP semantics | RFC 9110 / 9112 / 9113 / 9114 | Framing and Host rules as cited in references |

ASVS requirement IDs are not stable across major versions. Do not carry 4.0.3 IDs into a
5.0 report without re-reading the requirement text.

## Configuration

None. No build step, no dependency, no environment variable.

Keep this repository in the working directory so
`skills/core/http-edge-security/SKILL.md` is readable, or copy the `http-edge-security`
directory into `~/.claude/skills/`. The frontmatter `allowed-tools` limits it to read,
search, and web lookup.

## Example Usage

Scope a review to one trust decision:

```text
Find every read of X-Forwarded-For, X-Real-IP, and Forwarded in this repo. For each,
show whether a trusted-proxy allowlist exists, which hop is selected, and what security
decision uses the value (auth, rate limit, audit, geo). Give the spoofed request for each
unsafe use.
```

Host-driven URL generation:

```text
Trace password-reset and email-verification link construction. If Host or X-Forwarded-Host
influences the URL, show the poisoned request and the allowlisted fix.
```

More in [prompts.md](prompts.md).

## Limitations

- CDN, WAF, and load-balancer configuration is often invisible in an application code
  review. You cannot prove edge strip-and-append behaviour from app code alone.
- Platform defaults move. A cloud load balancer that once overwrote `X-Forwarded-For` may
  append instead after a product change. Re-verify on the deployed stack.
- Request smuggling proof needs two disagreeing parsers. Code review finds risky patterns;
  confirmation needs controlled lab traffic, not a production exploit.
- Examples are didactic. Smuggling sketches are educational desync awareness, not live
  exploit PoCs and not copy-paste attack tooling.
- Cache behaviour depends on vendor key algorithms (Cloudflare, Fastly, CloudFront, nginx
  proxy_cache). Treat vendor docs as primary for key composition.
- No coverage of non-HTTP edges (gRPC without HTTP/2 gateway quirks beyond framing notes,
  raw TCP LB L4).

## Security Notes

This skill contains deliberately vulnerable code in `best-practices.md`,
`common-mistakes.md`, and `examples/`. Every such block is labelled `Vulnerable:` on the
first line and paired with a fixed version. Do not copy a labelled-vulnerable block into a
project.

All hostnames, IPs, tokens, and identifiers are placeholders.
`203.0.113.10`, `reset.attacker.example`, and similar values are documentation addresses
(RFC 5737 / example domains), not real targets.

## References

- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>
- OWASP ASVS - <https://owasp.org/www-project-application-security-verification-standard/>
- HTTP Request Smuggling (PortSwigger research overview) - conceptual framing only
- RFC 9110 HTTP Semantics - <https://www.rfc-editor.org/rfc/rfc9110>
- CWE-444 HTTP Request Smuggling - <https://cwe.mitre.org/data/definitions/444.html>
