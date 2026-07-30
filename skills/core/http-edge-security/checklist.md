# HTTP Edge Verification Checklist

Mark every item pass, fail, or not verifiable. Edge configuration outside the repository is not a pass.

## Proxy and forwarded-header trust - ASVS 4.1.3 · CWE-441/CWE-290

- [ ] [recommended] Every proxy, CDN, load balancer, and application hop is documented with its protocol.
- [ ] [critical] The first trusted edge strips client-supplied `Forwarded`, `X-Forwarded-*`, and `X-Real-IP` before setting its own.
- [ ] [critical] Application trusted-proxy configuration uses explicit peer CIDRs or identities, never `trust proxy = true` for an Internet-facing app.
- [ ] [critical] Client IP selection has a documented hop rule; it does not accept a caller-controlled leftmost value.
- [ ] [critical] Forwarded headers are not used as an authentication or authorization assertion unless the injecting gateway is authenticated.

## Host and canonical URL - CWE-644 · ASVS V13

- [ ] [critical] Accepted `Host` values are allowlisted at the edge and application.
- [ ] [critical] Reset, invitation, and callback links use configured public origins, not request headers.
- [ ] [critical] `X-Forwarded-Host` and `X-Forwarded-Proto` are trusted only from configured proxies.
- [ ] [critical] Tenant routing cannot select a tenant or backend from an arbitrary Host header.
- [ ] [critical] Error pages and redirects never reflect an unvalidated host.

## Desync and framing - CWE-444 · ASVS V4

- [ ] [recommended] Each hop's HTTP version and request framing behavior is known.
- [ ] [critical] The edge rejects ambiguous `Content-Length` / `Transfer-Encoding` combinations and duplicate conflicting lengths.
- [ ] [recommended] Proxy and backend use supported, patched HTTP implementations.
- [ ] [critical] Header names, whitespace, absolute-form targets, and methods are normalized once before routing.
- [ ] [recommended] Header/request-line/body limits apply before application buffering.

## Shared cache - CWE-525/CWE-444

- [ ] [critical] Cache key fields are explicit and reviewed; unkeyed inputs cannot influence cached output.
- [ ] [critical] Authenticated, personalized, error, and reset responses are not shared-cacheable.
- [ ] [recommended] Cache rules normalize path encoding and extension-like suffixes before eligibility.
- [ ] [recommended] Vary behavior is intentional and does not create unbounded cache partitions.
- [ ] [recommended] CDN/WAF cache configuration is verified in the deployed control plane.

## Methods and return

- [ ] [recommended] Unsupported verbs and method-override headers are rejected before handlers.
- [ ] [recommended] `OPTIONS`, `TRACE`, `CONNECT`, and WebDAV methods are enabled only when required.
- [ ] [recommended] Negative tests cover forged forwarded headers, foreign Host, and a cacheable-looking private URL.
- [ ] [critical] Findings name the hop, a concrete request shape, the CWE, and what could not be verified.
