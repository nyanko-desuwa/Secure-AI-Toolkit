# Browser Platform Security Skill

## Purpose

Browser platform features outlive a page and cross origin boundaries in ways normal frontend code
does not. A broad service worker can intercept requests long after a deploy. An extension permission
or message listener can turn any visited page into a privileged caller.

## How It Works

```text
SKILL.md                   platform workflow
README.md                  purpose and limits
checklist.md               SW, cache, extension, update checks
best-practices.md          vulnerable/fixed patterns
common-mistakes.md         wrong fixes
troubleshooting.md         platform conflicts
prompts.md                 four review tiers
references/                platform source pins
examples/README.md         seven vulnerable/fixed pairs
```

## Standards Covered

| Standard | Version | Verified |
|---|---|---|
| OWASP Top 10 | 2025 A01/A02/A06/A08 | 2026-07-28, <https://owasp.org/Top10/2025/> |
| OWASP ASVS | 5.0.0 V1/V3/V13/V14 | 2026-07-28 |
| Browser platform docs | Service Worker, WebExtensions | 2026-07-28, MDN and vendor documentation |
| CWE | CWE-284, CWE-346, CWE-494, CWE-200 | 2026-07-28 |

## Configuration

None. The skill is Markdown with research-only tool access.

## Example Usage

```text
Review manifest.json, service-worker registration, cache rules, content scripts, and runtime message
listeners. For each permission or sender, identify who can invoke it, what data/action it reaches,
and the smallest least-privilege change. Include file:line, CWE, exploit path, and limitation.
```

## Limitations

- Code review cannot prove store review settings, enterprise extension policy, browser-version
  behavior, or CDN update headers.
- Browser APIs differ. Chromium extension examples transfer by analogy to Firefox; manifest field
  support needs vendor verification.
- This skill does not replace DOM XSS/CSP review or backend authorization.
- Client-side storage is not a safe place for a credential that grants server-side power.

## Security Notes

Examples use placeholder origins and identifiers. Every vulnerable block is labelled and paired with
a safer pattern; no example is a production manifest.
