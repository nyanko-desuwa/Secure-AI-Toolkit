# Browser Platform Best Practices

## Narrow service-worker scope - CWE-284

```javascript
// Vulnerable: controls the entire origin
navigator.serviceWorker.register("/sw.js", { scope: "/" });
```

```javascript
// Fixed: controls only the public app shell
navigator.serviceWorker.register("/app/sw.js", { scope: "/app/" });
```

## Do not cache private documents - CWE-200

```javascript
// Vulnerable: caches every successful fetch, including /account
self.addEventListener("fetch", event => event.respondWith(caches.match(event.request).then(r => r || fetch(event.request).then(save))));
```

```javascript
// Fixed: cache a reviewed allowlist of immutable public assets only
const PUBLIC_ASSETS = new Set(["/app/main.js", "/app/main.css"]);
```

## Minimize extension hosts - CWE-250

```json
// Vulnerable: "host_permissions": ["<all_urls>"]
```

```json
// Fixed: "host_permissions": ["https://app.example.com/*"]
```

## Validate extension senders - CWE-346

```javascript
// Vulnerable: any page message triggers a privileged action
chrome.runtime.onMessage.addListener((msg) => perform(msg));
```

```javascript
// Fixed: verify sender and schema before dispatch
chrome.runtime.onMessage.addListener((msg, sender) => { if (sender.id === chrome.runtime.id) perform(parse(msg)); });
```

## Keep web resources private by default - CWE-200

```json
// Vulnerable: every extension asset is web accessible
```

```json
// Fixed: list only a static image needed by a named origin match
```

Why: platform capabilities are authority. Narrow the origin, scope, and caller before writing code.
