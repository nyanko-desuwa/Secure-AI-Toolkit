# Browser Platform Common Mistakes

## "The worker only caches static files"

Check the fetch matcher, not the intent. A catch-all cache-first handler will cache HTML, redirects,
or authenticated API responses when a route changes.

## "Users approve the extension permission"

Consent is not least privilege. Broad host permission expands the impact of a compromised extension,
unsafe content script, or confused message handler.

## "Only our page sends messages"

Any page can construct data that a content script reads. Treat page DOM and postMessage input as
untrusted; validate sender identity at the extension boundary.

## "chrome.storage is encrypted"

It is storage, not a server-side authorization boundary. Do not persist reusable server credentials
there; use a backend and short-lived, scoped tokens.