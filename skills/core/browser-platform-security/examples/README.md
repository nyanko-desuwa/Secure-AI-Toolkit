# Browser Platform Security Examples

## Broad worker scope — CWE-284

```javascript
// Vulnerable: worker controls every origin path
navigator.serviceWorker.register("/sw.js", { scope: "/" });
```

```javascript
// Fixed: worker controls only public application shell
navigator.serviceWorker.register("/app/sw.js", { scope: "/app/" });
```

## Stale private HTML cache — CWE-200

```text
Vulnerable: cache-first handler stores /account HTML after a successful response.
Fixed: cache only reviewed public assets; private routes use network and no-store responses.
```

## All-host extension permission — CWE-250

```json
// Vulnerable: "host_permissions": ["<all_urls>"]
```

```json
// Fixed: "host_permissions": ["https://app.example.com/*"]
```

## Open web-accessible resources — CWE-200

```text
Vulnerable: all extension scripts/assets are reachable from every web page.
Fixed: expose only a static asset required by explicit origin matches.
```

## Reusable token in storage — CWE-522

```javascript
// Vulnerable: chrome.storage.local.set({ adminToken: token })
```

```text
Fixed: keep server authority on the backend; issue short-lived, scoped tokens only when required.
```

## Insecure update — CWE-494

```text
Vulnerable: worker or update manifest is obtained over HTTP or an uncontrolled origin.
Fixed: HTTPS, same-origin update path, and controlled store/publication policy.
```

## Unchecked extension message — CWE-346

```javascript
// Vulnerable: chrome.runtime.onMessage.addListener((m) => perform(m));
```

```javascript
// Fixed: verify sender.id/origin and parse an allowlisted message schema before dispatch.
```
