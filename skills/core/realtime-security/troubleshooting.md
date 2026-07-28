# Realtime Security Troubleshooting

## Native clients do not send Origin

Do not weaken the browser Origin policy for every client. Separate the credential path: bearer token
or mTLS for native clients, Origin allowlist plus session protection for browser clients.

## EventSource cannot set Authorization headers in the target browser

Do not put a long-lived bearer token in a query string. Use a short-lived, one-time stream ticket,
set a restrictive referrer policy, avoid logging query strings, or proxy through a backend that can
safely attach credentials.

## Product needs public rooms and private rooms

Make publicness a server-owned room attribute. Do not infer it from a `public:` name prefix supplied
by the client.

## Pub/sub transport crosses nodes

The broker does not replace application authorization. Check before publishing and subscribing, and
ensure channel names are tenant-scoped. Verify broker ACLs and sticky-session behavior separately.

## WebRTC requires TURN credentials

Issue short-lived, scoped credentials from an authenticated endpoint. Do not broadcast a reusable
TURN password in signaling messages. TURN deployment configuration remains an infrastructure check.
