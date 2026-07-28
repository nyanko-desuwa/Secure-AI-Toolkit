# HTTP Edge Common Mistakes

## "The CDN adds X-Forwarded-For, so it is trusted"

A client can add the header before the CDN sees it. The edge must strip or replace it, and the app
must trust only the known edge peer. Appending a value is not proof that every earlier value is safe.

## "Use the first address in X-Forwarded-For"

The first address is often the original client only after every proxy has stripped forged input.
Without that guarantee it is attacker data. A fixed number of trusted hops or explicit proxy CIDRs
is the decision, not a string split.

## "A UUID Host is harmless"

Host affects password resets, redirects, cache keys, links in emails, tenant selection, and virtual
hosts. A random-looking hostname is still a routing input. Allowlist canonical hosts and configure
public origins.

## "TLS prevents request smuggling"

TLS protects a hop from passive network observers. Smuggling is a disagreement between parsers after
TLS terminates. Verify HTTP versions, framing, and proxy/backend behavior together.

## "Vary: Cookie fixes personalized caching"

It may create one cache entry per cookie and leak through another unkeyed input. Sensitive responses
should normally be `private, no-store`; cache only deliberately public representations.

## "We only use method override for old clients"

Then it is part of the effective API. Apply authorization after normalization, document the allowed
routes, and reject overrides elsewhere. A global middleware silently changes every route.
