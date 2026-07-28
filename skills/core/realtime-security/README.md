# Realtime Security Skill

Controls for long-lived client connections: WebSocket, Server-Sent Events (SSE), and WebRTC
signaling.

## Purpose

Realtime channels fail differently from request/response APIs. The handshake can look authenticated
while every later frame is free. Origin is the CSRF boundary the browser will not enforce for you
the way it does for classic form posts. One subscription can fan out to every connected peer. A
reconnect ticket that outlives the session rebinds identity after logout.

This skill owns those failures. `api-security` owns REST, GraphQL, gRPC, and webhooks.
`authentication` owns how credentials are issued. `frontend-security` owns what happens when a
payload hits the DOM.

## How It Works

Plain Markdown. Nothing executes. An assistant reads `SKILL.md`, follows the five steps
(enumerate the surface, ask five questions per connection, apply controls in order, verify,
report), and opens the supporting file it needs.

```text
SKILL.md                   workflow, severity, failure table, entry point
README.md                  this file
checklist.md               pre-return verification
best-practices.md          patterns, each with a vulnerable/fixed pair
common-mistakes.md         what goes wrong and why the fix works
troubleshooting.md         when the guidance conflicts or cannot be applied
prompts.md                 prompts that produce findings, plus anti-patterns
references/
  README.md                index of reference docs
  realtime-threats.md      threat classes mapped to API Top 10 / CWE
  asvs-realtime.md         ASVS 5.0 chapters relevant to realtime
examples/
  README.md                eight vulnerable/fixed pairs with category and CWE
```

## Standards Covered

| Standard | Version | Verified |
|---|---|---|
| OWASP API Security Top 10 | 2023 | 2026-07-28 — API1, API2, API4, API5 applied to realtime |
| OWASP ASVS | 5.0.0 (released May 2025) | 2026-07-28 — V4, V6, V7, V8, V13 chapters cited |
| OWASP Top 10 | 2025 | Cross-reporting only (A01, A04, A05, A07) |
| CWE | MITRE | 2026-07-28 — CWE-306, CWE-352, CWE-384, CWE-639, CWE-770, CWE-285, CWE-74, CWE-915 |

ASVS requirement IDs were read against the 5.0 chapter structure used elsewhere in this pack, not
recalled from ASVS 4.0.3. A `4.1.1` from an old report is a different requirement.

## Configuration

None. No build step, no dependency, no environment variable.

Keep this repository in the working directory so `skills/core/realtime-security/SKILL.md` is
readable, or copy the `realtime-security` directory into `~/.claude/skills/`. The frontmatter
`allowed-tools` limits it to read, search, and web lookup.

## Example Usage

Scope a review to connect and per-message authz:

```text
Read the WebSocket upgrade handler and every message router. For each message type, show where
the actor is bound and where channel or object authorization runs. Give the exact frame a second
user would send to join someone else's room. Cite API1:2023 or API5:2023 and CWE.
```

Check Origin and cookie-authenticated SSE:

```text
Find every SSE and WebSocket entry that authenticates with cookies. Show the Origin (or CSRF)
check, the allowlist source, and what happens when Origin is absent or spoofed from a non-browser
client. Flag reflected Origin and missing SameSite on the session cookie.
```

More in [prompts.md](prompts.md).

## Limitations

- Guidance, not a scanner. No protocol fuzzing. It cannot prove a race on reconnect without a
  test that removes the one-time ticket claim.
- Cannot see load balancer sticky sessions. Whether reconnects land on the same node, whether
  the pub/sub fabric isolates tenants, and whether the edge strips forged `Origin` or
  `X-Forwarded-*` are infrastructure facts. If they are not in application code, report
  "not verifiable from application code".
- Cannot prove TURN/STUN configuration from app code. Credential TTL, UDP allowlists, and
  whether TURN is mandatory for relay are deployment concerns. This skill covers signaling
  authorization and what the application puts on the wire; media-plane infra is out of scope
  beyond stating the gap.
- Business product rules (who may join a call) cannot be derived from code alone. The skill can
  tell you the room ID is the only gate; it cannot tell you whether that is acceptable for a
  public webinar versus a clinical consult.
- Examples are TypeScript, Python, and conceptual signaling frames. Socket.IO, raw `ws`, and
  SSE are covered; obscure brokers get the same principles without idiomatic samples.
- ASVS citations are chapter-level except where a specific pattern is named. For a formal ASVS
  assessment, work from the official 5.0 requirement set.
- No coverage of WebTransport, MQTT over WebSocket product config, or proprietary game-net
  stacks beyond the shared connect / message / fan-out model.

## Security Notes

This skill contains deliberately vulnerable code in `best-practices.md`, `common-mistakes.md`,
and `examples/`. Every such block is labelled `Vulnerable:` and paired with a fixed version. Do
not copy a labelled-vulnerable block into a project.

All hostnames, tokens, and identifiers are placeholders. `wss://realtime.example.com`,
`reconnect_ticket_test_...`, and similar values are not real and are not valid anywhere.

## References

- OWASP API Security Top 10 2023 — <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- OWASP ASVS — <https://owasp.org/www-project-application-security-verification-standard/>
- HTML Living Standard — WebSocket and EventSource
- RFC 6455 — The WebSocket Protocol
- RFC 8441 — Bootstrapping WebSockets with HTTP/2 (where applicable)
- W3C WebRTC — <https://www.w3.org/TR/webrtc/>
- OWASP HTML5 Security Cheat Sheet (WebSocket section) — <https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html>
- Cross-Site WebSocket Hijacking discussions (CWE-352-class Origin failures)
