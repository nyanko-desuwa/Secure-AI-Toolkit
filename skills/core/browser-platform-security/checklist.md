# Browser Platform Security Checklist

## Service workers and caches

- [ ] [recommended] Registration scope is the minimum path required.
- [ ] [critical] Worker script and update path use HTTPS and controlled origins.
- [ ] [critical] Cache rules store only public assets; authenticated HTML/API responses are not offline/shared cache entries.
- [ ] [recommended] Cache versioning removes obsolete privileged data on activation.
- [ ] [critical] Fetch handler does not turn arbitrary path/query into cached private content.

## Extensions

- [ ] [critical] `permissions`, `host_permissions`, and content-script matches are least privilege.
- [ ] [recommended] No broad all-URL host grant exists without a documented user-visible need.
- [ ] [critical] Runtime/external messages validate sender extension ID/origin and a strict schema.
- [ ] [recommended] `web_accessible_resources` lists only assets intentionally reachable by pages.
- [ ] [critical] Content scripts do not trust page DOM/messages as extension authority.
- [ ] [critical] Sensitive values are not stored in extension storage as a substitute for server controls.

## PWA/update and return

- [ ] [critical] Manifest, worker, update, and install assets are same-origin HTTPS.
- [ ] [critical] Push and notification actions require an authenticated, authorized backend operation.
- [ ] [recommended] Browser/version/store policy assumptions are stated as limitations.
- [ ] [recommended] Negative tests cover foreign sender, foreign origin, old cache, and broad route scope.
