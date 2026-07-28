# Realtime Security Common Mistakes

## "The socket authenticated at connection time"

That proves who opened it, not whether each later subscribe, publish, or admin event is allowed.
Authorize each action against the actor and target resource.

## "CORS protects WebSockets"

CORS is not a WebSocket authorization mechanism. For browser connections using ambient cookies,
validate `Origin` with an allowlist and use session CSRF defenses appropriate to the connection.

## "A random room ID is authorization"

An unguessable ID reduces discovery, but URLs leak through logs, screenshots, browser history, and
referrers. Room membership needs a server-side policy check.

## "Rate-limit the upgrade only"

A single established connection can send unbounded frames, subscribe to thousands of channels, or
trigger a broadcast. Bound message size, rate, subscription count, and fan-out.

## "Reconnect restores the old state"

Reconnecting after logout, tenant removal, or role change must not restore previous subscriptions.
Bind a short ticket to the session and re-authorize every restored subscription.
