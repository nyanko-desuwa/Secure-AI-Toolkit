# Common HTTP Client Security Mistakes

## Regex is treated as URL authorization

String checks miss userinfo, alternate IP notation, IPv6, IDNA, redirects, and DNS changes. Parse,
apply a destination policy, and pair application controls with egress restrictions.

## Only IPv4 private ranges are blocked

Loopback, link-local, multicast, IPv6, IPv4-mapped IPv6, and provider metadata endpoints all matter.
A denylist that remembers only `127.0.0.1` and `10.0.0.0/8` is not a boundary.

## Retry every exception

Retries can repeat payments, sends, and state changes. Bound attempts, add jitter, require
idempotency where a mutation can be replayed, and expose the final failure.

## Service mesh replaces client policy

A mesh or proxy is defence in depth. The application still decides whether an attacker-controlled
URL, redirect, credential, or response is acceptable.
