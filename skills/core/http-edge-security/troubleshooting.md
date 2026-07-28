# HTTP Edge Troubleshooting

## Rate limiting needs client IP but forwarded headers are unsafe

Do not abandon rate limiting or trust all headers. Configure the edge to strip and append its own
header, then configure the app with the exact trusted proxy CIDRs. Prefer authenticated actor keys
for post-login limits; IP is a pre-auth and abuse-signal dimension.

## There are several proxy layers

Draw the chain and test each hop. Decide whether the application trusts a fixed count or named CIDR
ranges. A fixed count breaks when a deployment path skips a layer; CIDRs break when proxy networks
are shared too broadly. Re-check after topology changes.

## Legacy clients need HTTP method override

Restrict it to a small route allowlist, normalize before authorization and audit logging, and reject
it for administrative or money-moving routes. Do not enable global middleware and assume handlers
will notice.

## CDN documentation says a header is sanitized

Treat vendor documentation as a hypothesis. Capture a staging request at the origin or inspect the
edge policy. Versioned platform behavior and custom worker code can change the default.

## A suspected desync has no reproducible exploit

Report the ambiguity and its prerequisites, not a confirmed exploit. Patch proxy/backend versions,
remove conflicting framing acceptance, and test only in an authorized controlled environment. Do not
send desync probes to production.

## Product wants authenticated pages cached

Cache a representation that cannot contain private data, or use a cache design keyed and authorized
at the application layer. Do not solve performance by making a session page `public`.
