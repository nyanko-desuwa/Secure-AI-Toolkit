# Model Context Protocol Security Reference

Source: <https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices>
Authorization source: <https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization>
Specification revision: `2025-11-25`.
Verified: 2026-07-28.

MCP is a protocol, not a trust boundary. The specification says tools represent arbitrary
code execution, tool descriptions and annotations are untrusted unless obtained from a
trusted server, and hosts should obtain explicit user consent before tool invocation.

## Transport and authorization requirements

- HTTP authorization is optional for an MCP implementation, but an HTTP implementation
  should conform to the MCP authorization specification.
- An HTTP authorization server uses OAuth 2.1; an MCP server must implement Protected
  Resource Metadata (RFC 9728) when using this flow.
- STDIO implementations should not follow the HTTP OAuth specification; credentials come
  from the environment. STDIO is appropriate for local servers because access is limited to
  the client process, but the spawned process still has the client's privileges.
- For local HTTP, require an authorization token or use restricted IPC. A server open on
  localhost with no auth is reachable by other local processes and can be exposed through
  browser/DNS-rebinding paths.
- MCP clients must include the RFC 8707 `resource` parameter in both authorization and token
  requests, identifying the canonical MCP server URI.
- MCP servers must validate that an access token was issued specifically for them as the
  intended audience. They must reject tokens for another resource.
- MCP servers must not accept or transit other tokens. If they call an upstream API, they
  obtain a separate token for that API; they must not pass through the token received from the
  client.
- Request the minimum scopes. Use step-up authorization for privileged operations rather
  than an omnibus `*` or `full-access` scope.
- Proxy servers using static client IDs must obtain per-client consent before forwarding to a
  third-party authorization server. Validate redirect URIs with exact string matching,
  protect state, and make state single-use.

## Attack patterns covered by the source

The Security Best Practices page documents confused deputy attacks, token passthrough, SSRF
through OAuth metadata discovery, session hijacking and event injection, local MCP server
compromise, unsafe OAuth URL handling, proxy/STDIO escalation, and scope inflation.

The page also warns about DNS rebinding and redirect chains. IP checks performed once before a
second DNS lookup are still TOCTOU-vulnerable; an egress proxy is the stronger production
control.

This reference deliberately does not assign OWASP Agentic Security Initiative IDs. The ASI's
threat taxonomy and Agentic Top 10 category identifiers are in downloadable documents, not
on the HTML source verified here. Use a risk name and mechanism rather than fabricate an ID.
