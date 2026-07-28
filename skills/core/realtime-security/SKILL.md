---
name: realtime-security
description: 'Secure WebSocket, SSE, and WebRTC signaling — connect authz, Origin checks, message injection, fan-out abuse, reconnect binding. Triggers: "WebSocket security", "SSE", "WebRTC", "realtime", "socket.io", "Origin check", "bảo mật WebSocket", "thời gian thực".'
allowed-tools: Read, Glob, Grep, WebSearch, WebFetch
---

# Realtime Security

A long-lived connection is not a browser page and not a one-shot REST call. Auth on the upgrade
is only the start. Every subsequent message is a new authorization decision, Origin is the CSRF
boundary, and one bad subscription can fan out to every peer.

This skill owns WebSocket, Server-Sent Events, and WebRTC signaling security.

## When to Use

- Adding or reviewing a WebSocket, Socket.IO, SockJS, or native `ws` endpoint
- Designing or auditing Server-Sent Events (SSE) streams
- Reviewing WebRTC signaling rooms, offers, answers, and ICE candidate exchange
- Checking Origin validation, reconnect tokens, or channel subscription scoping
- Hunting message injection, cross-user channel join, or fan-out / broadcast abuse

## When NOT to Use

| Concern | Route to |
|---|---|
| REST, GraphQL, gRPC, webhook request/response surfaces | `api-security` |
| Login, session minting, password, MFA, OAuth token issuance | `authentication` |
| DOM XSS, client-side message rendering, CSP in the browser | `frontend-security` |
| TURN/STUN infrastructure hardening beyond app-visible config | Infrastructure review (state the limit) |
| Load-balancer sticky sessions and edge TLS termination | Infrastructure review (state the limit) |

## The Standard

OWASP API Security Top 10 2023 maps cleanly to realtime failures: connect without auth is API2;
cross-user channel is API1; subscribe to admin events is API5; unbounded broadcast is API4. ASVS
5.0 V4 (API and Web Service), V8 (Authorization), V6/V7 (Authentication/Session), and V13
(Configuration) supply the testable requirements. CWE-306, CWE-352 (Origin as CSRF-class),
CWE-639, CWE-770, and CWE-285 name the defects.

| Failure class | The failure, in one line |
|---|---|
| Connect without authz | Upgrade succeeds for anonymous or wrong principal · API2 · CWE-306 |
| Missing Origin check | Cross-site page opens a socket with the victim cookie · CWE-352-class |
| Per-message authz gap | Auth on connect only; any later `subscribe` or `send` is free · API1/API5 |
| Cross-user channel | Actor joins `room:user:4192` that is not theirs · API1 · CWE-639 |
| Message schema injection | Untyped payload drives code paths, SQL, or DOM sinks · CWE-74 / CWE-915 |
| Fan-out / resource abuse | One client broadcasts or subscribes without bound · API4 · CWE-770 |
| Reconnect session drift | Stale or stolen reconnect token rebinds as another user · API2 · CWE-384 |
| SSE cookie / CSRF gap | Event stream relies on cookie without SameSite or token binding · CWE-352 |
| Signaling room free-join | WebRTC room ID is the only gate · API1/API5 · CWE-306 |

Full mapping in [references/realtime-threats.md](references/realtime-threats.md). ASVS text in
[references/asvs-realtime.md](references/asvs-realtime.md).

## Workflow

### 1. Enumerate the realtime surface

List every upgrade path, SSE route, Socket.IO namespace, and signaling endpoint that is actually
reachable — including legacy namespaces and admin dashboards.

```bash
grep -rnE "WebSocket|ws\.Server|socket\.io|EventSource|text/event-stream|RTCPeerConnection|signaling" src/
```

### 2. For each connection, answer five questions

- Who may open this connection at all? (API2, CWE-306)
- Which Origin values are accepted, and is the check server-enforced? (CWE-352-class)
- For each message type, which objects and channels may this actor touch? (API1, API5)
- What bounds the cost of one message and of ten thousand? (API4, CWE-770)
- On reconnect, what re-binds identity, and can an old ticket be replayed? (API2, CWE-384)

A channel you cannot answer all five for is not reviewed.

### 3. Apply controls in this order

1. Authenticate and authorize on the upgrade (or first SSE request). Reject before the socket is
   accepted when possible.
2. Enforce Origin (or equivalent CSRF defence for cookie-auth connections) with an explicit
   allowlist. Do not reflect the request Origin.
3. Authorize every message and every subscription against the actor and the target resource —
   not only the connect handshake.
4. Validate message shape with a strict schema. Cap size, rate, and fan-out degree.
5. Bind reconnect tickets to actor, connection purpose, and short TTL. One-time use where the
   protocol allows.
6. Prefer end-to-end or transport encryption appropriate to the channel: `wss://`, TLS for SSE,
   DTLS-SRTP for media; never put long-lived secrets in signaling payloads.

### 4. Verify

Run [checklist.md](checklist.md). An unchecked box is a fix or a stated limitation, never a
silent skip.

### 5. Report

Per finding: failure class, endpoint or message type, the frame or request that exploits it, the
fix. Include the concrete payload — `{"type":"subscribe","channel":"user:4192"}` from actor
7 is a finding; "possible broken channel auth" is a guess.

## Severity

Rank by who can reach it and what they get.

- Critical — unauthenticated connect to a privileged channel; cross-tenant message read/write;
  signaling that joins any call
- High — authenticated cross-user subscribe or send; missing Origin on a cookie-authenticated
  socket; reconnect token that rebinds as another user
- Medium — unbounded fan-out or message rate; schema-less payloads that reach a dangerous sink;
  SSE without SameSite consideration where cookies authenticate
- Low — verbose close reasons, missing compression bomb guard with low practical impact, missing
  header with no direct path

A public stock-ticker socket with no PII is Low for missing auth and still High for unbounded
server-side fan-in if one client can force the server to push to millions of peers.

## Related Skills

- `api-security` — REST/HTTP APIs, GraphQL, gRPC, webhooks (not long-lived sockets)
- `authentication` — how sessions and tokens are issued; this skill consumes them at connect
- `frontend-security` — rendering realtime payloads into the DOM safely
- `owasp` — Top 10 2025 and ASVS chapter map
- `logging-audit` — connect denials, authz failures, and abuse signals
- `secure-code-review` — whole-codebase review workflow

## Supporting Files

- [README.md](README.md) — purpose, standards table, limitations
- [checklist.md](checklist.md) — pre-return verification
- [best-practices.md](best-practices.md) — patterns with vulnerable/fixed pairs
- [common-mistakes.md](common-mistakes.md) — what goes wrong and why the fix works
- [troubleshooting.md](troubleshooting.md) — when guidance conflicts or cannot be applied
- [prompts.md](prompts.md) — prompts that produce findings
- [references/README.md](references/README.md) — reference index
- [references/realtime-threats.md](references/realtime-threats.md) — threat map to API Top 10 / CWE
- [references/asvs-realtime.md](references/asvs-realtime.md) — ASVS 5.0 chapters for realtime
- [examples/README.md](examples/README.md) — eight vulnerable/fixed pairs
