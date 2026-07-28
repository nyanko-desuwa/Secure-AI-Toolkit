# Browser Platform Security Checklist

## Service workers and caches

- [ ] Registration scope is the minimum path required.
- [ ] Worker script and update path use HTTPS and controlled origins.
- [ ] Cache rules store only public assets; authenticated HTML/API responses are not offline/shared cache entries.
- [ ] Cache versioning removes obsolete privileged data on activation.
- [ ] Fetch handler does not turn arbitrary path/query into cached private content.

## Extensions

- [ ] `permissions`, `host_permissions`, and content-script matches are least privilege.
- [ ] No broad all-URL host grant exists without a documented user-visible need.
- [ ] Runtime/external messages validate sender extension ID/origin and a strict schema.
- [ ] `web_accessible_resources` lists only assets intentionally reachable by pages.
- [ ] Content scripts do not trust page DOM/messages as extension authority.
- [ ] Sensitive values are not stored in extension storage as a substitute for server controls.

## PWA/update and return

- [ ] Manifest, worker, update, and install assets are same-origin HTTPS.
- [ ] Push and notification actions require an authenticated, authorized backend operation.
- [ ] Browser/version/store policy assumptions are stated as limitations.
- [ ] Negative tests cover foreign sender, foreign origin, old cache, and broad route scope.
