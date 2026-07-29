---
name: browser-platform-security
description: 'Service workers, extensions, and PWAs - update/cache attacks, permission least privilege, web accessible resources, SW scope. Triggers: "service worker", "browser extension", "PWA", "chrome.runtime", "web_accessible_resources", "bảo mật extension", "service worker".'
allowed-tools: Read, Glob, Grep, WebSearch, WebFetch
---

# Browser Platform Security

A service worker persists after the page changes. An extension can see more than a page ever can.
This skill owns service-worker scope and cache policy, extension permissions and messages,
web-accessible resources, PWA update trust, and browser-platform storage boundaries.

## When to Use

- Adding a service worker, PWA manifest, offline cache, or push feature
- Reviewing Chrome/Firefox/Edge extension manifests, content scripts, or message handlers
- Designing extension permissions, update delivery, or web-accessible assets

## When NOT to Use

| Concern | Route to |
|---|---|
| DOM XSS, CSP, cookies, postMessage basics | `frontend-security` |
| API/session/token issuance | `authentication`, `api-security` |
| Secrets in a published extension/store bundle | `publish-safety` |

## The Standard

| Failure | Mapping |
|---|---|
| Overbroad service-worker scope/cache | A02/A06 · CWE-284 |
| Extension broad host permissions | A01/A02 · CWE-250 |
| Unchecked extension message sender | A01 · CWE-346 |
| Exposed web-accessible resources | A02 · CWE-200 |
| Insecure update path | A08 · CWE-494 |

Uses OWASP Top 10 2025, ASVS 5.0 V1/V3/V13/V14, and CWE. See [references/](references/).

## Workflow

1. Inventory manifests, service-worker registrations, scopes, cache rules, content scripts, and
   runtime message listeners.
2. Ask which origins, pages, users, and extensions may invoke each capability.
3. Remove unused permissions, constrain scope, validate senders and message schemas, and cache only
   safe public assets.
4. Run [checklist.md](checklist.md), then report file:line, capability, attacker path, CWE, fix,
   and deployment facts unavailable from code.

## Severity

- Critical - arbitrary webpage triggers privileged extension action or malicious update executes
- High - broad host permission plus unsafe content-script/message bridge; service worker exposes private data
- Medium - stale cache, open web-accessible asset, excess permission without demonstrated abuse
- Low - unused manifest capability or missing defense-in-depth control

## Related Skills

- `frontend-security` - DOM and browser document controls
- `publish-safety` - extension bundles and store release
- `api-security` - backend authorization reached by the platform

## Supporting Files

[README.md](README.md) · [checklist.md](checklist.md) · [best-practices.md](best-practices.md) ·
[common-mistakes.md](common-mistakes.md) · [troubleshooting.md](troubleshooting.md) ·
[prompts.md](prompts.md) · [references/](references/) · [examples/README.md](examples/README.md)
