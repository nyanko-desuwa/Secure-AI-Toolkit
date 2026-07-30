---
name: http-client-security
description: 'Secure outbound HTTP(S) clients - SSRF, URL parsing, redirects, DNS/private targets, TLS verification, proxies, timeouts, retries, credentials, and response limits. Triggers: "HTTP client", "outbound HTTP", "SSRF", "fetch URL", "redirect", "HttpClient", "requests", "bảo mật HTTP client".'
allowed-tools: Read, Glob, Grep, WebSearch, WebFetch
---

# HTTP Client Security

Outbound HTTP is a trust boundary. A URL, redirect, resolver, proxy, certificate, retry, and
response body decide where the workload can act and what it can disclose.

## When to Use

- Creating or reviewing `fetch`, `requests`, `httpx`, `HttpClient`, `WebClient`, `net/http`, or SDK calls
- Fetching user- or tenant-configured destinations, callbacks, webhooks, or third-party APIs
- Configuring redirects, proxies, TLS/mTLS, timeouts, pools, retries, or response streaming
- Reviewing SSRF, metadata-service exposure, or outbound credential forwarding

## When NOT to Use

| Concern | Route to |
|---|---|
| Inbound endpoint authorization or webhook registration policy | `api-security` |
| Reverse proxy, Host, forwarded headers, framing, CDN cache | `http-edge-security` |
| VPC/egress proxy/network segmentation deployment | `network-security`, `cloud-security` |
| Cryptographic primitive or PKI lifecycle | `cryptography`, `secrets-management` |
| Agent authority over HTTP tools | `ai-security` |
| Hostile XML/YAML/object parsing after response receipt | `deserialization-security` |

## Ownership Boundary

**Owns:** Application workload <-> DNS/proxy/network <-> outbound HTTP(S) destination selection,
transport behavior, credentials, response bounds, and safe telemetry.

**Does not own:**

| Concern | Route to |
|---|---|
| Inbound API authorization and user-controlled destination policy | `api-security` |
| Reverse-proxy and Host/header trust | `http-edge-security` |
| Egress network deployment and segmentation | `network-security` |
| Client secret lifecycle | `secrets-management` |
| Agent tool authority | `ai-security` |

## Workflow

1. Inventory every outbound client, destination source, credential, proxy, and response consumer.
2. Classify destination as fixed dependency, configured integration, or attacker-influenced input.
3. Define scheme/host/port/address/redirect/credential/response policy before sending a request.
4. Enforce parsed URL and resolved-address checks, TLS hostname verification, bounded deadlines,
   size/decompression limits, idempotency-aware retries, and response schema checks.
5. Run [checklist.md](checklist.md); report live egress/DNS/proxy configuration as unverified unless proven.

## Severity

- **Critical** - SSRF reaches metadata/control plane, credentials follow an attacker destination, or TLS bypass exposes secrets
- **High** - redirect/proxy bypass, private-target reachability, unbounded retry/download causing material impact
- **Medium** - missing bounds or weak logging hygiene without a demonstrated sensitive destination
- **Low** - defence-in-depth telemetry/configuration gap with no reachable path

## Related Skills

- `api-security`, `http-edge-security`, `network-security`, `cloud-security`
- `secrets-management`, `logging-audit`, `cryptography`, `ai-security`

## Supporting Files

- [README.md](README.md), [checklist.md](checklist.md), [best-practices.md](best-practices.md)
- [common-mistakes.md](common-mistakes.md), [troubleshooting.md](troubleshooting.md), [prompts.md](prompts.md)
- [references/](references/) and [examples/README.md](examples/README.md)
