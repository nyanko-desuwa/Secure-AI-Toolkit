# HTTP Edge Verification Checklist

Mark every item pass, fail, or not verifiable. Edge configuration outside the repository is not a pass.

## Proxy and forwarded-header trust - ASVS 4.1.3 · CWE-441/CWE-290

- [ ] Every proxy, CDN, load balancer, and application hop is documented with its protocol.
- [ ] The first trusted edge strips client-supplied `Forwarded`, `X-Forwarded-*`, and `X-Real-IP` before setting its own.
- [ ] Application trusted-proxy configuration uses explicit peer CIDRs or identities, never `trust proxy = true` for an Internet-facing app.
- [ ] Client IP selection has a documented hop rule; it does not accept a caller-controlled leftmost value.
- [ ] Forwarded headers are not used as an authentication or authorization assertion unless the injecting gateway is authenticated.

## Host and canonical URL - CWE-644 · ASVS V13

- [ ] Accepted `Host` values are allowlisted at the edge and application.
- [ ] Reset, invitation, and callback links use configured public origins, not request headers.
- [ ] `X-Forwarded-Host` and `X-Forwarded-Proto` are trusted only from configured proxies.
- [ ] Tenant routing cannot select a tenant or backend from an arbitrary Host header.
- [ ] Error pages and redirects never reflect an unvalidated host.

## Desync and framing - CWE-444 · ASVS V4

- [ ] Each hop's HTTP version and request framing behavior is known.
- [ ] The edge rejects ambiguous `Content-Length` / `Transfer-Encoding` combinations and duplicate conflicting lengths.
- [ ] Proxy and backend use supported, patched HTTP implementations.
- [ ] Header names, whitespace, absolute-form targets, and methods are normalized once before routing.
- [ ] Header/request-line/body limits apply before application buffering.

## Shared cache - CWE-525/CWE-444

- [ ] Cache key fields are explicit and reviewed; unkeyed inputs cannot influence cached output.
- [ ] Authenticated, personalized, error, and reset responses are not shared-cacheable.
- [ ] Cache rules normalize path encoding and extension-like suffixes before eligibility.
- [ ] Vary behavior is intentional and does not create unbounded cache partitions.
- [ ] CDN/WAF cache configuration is verified in the deployed control plane.

## Methods and return

- [ ] Unsupported verbs and method-override headers are rejected before handlers.
- [ ] `OPTIONS`, `TRACE`, `CONNECT`, and WebDAV methods are enabled only when required.
- [ ] Negative tests cover forged forwarded headers, foreign Host, and a cacheable-looking private URL.
- [ ] Findings name the hop, a concrete request shape, the CWE, and what could not be verified.
