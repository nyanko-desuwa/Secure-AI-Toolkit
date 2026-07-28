# Service Worker Controls

Sources: MDN Service Worker API and Cache API; OWASP Top 10 2025; ASVS 5.0. Checked: 2026-07-28.

A service worker controls fetches within its scope and persists across navigations. Keep scope narrow,
serve script/update over HTTPS and controlled origin, cache an allowlist of public immutable assets,
and remove account-scoped data at logout/activation. Treat update and cache policy as security
configuration, not a performance-only choice.
