# Realtime Security Prompts

## Beginner

```text
Explain who can open each live connection and who can read or send every kind of message. Show the
exact frame a different user could send if a check is missing, and say what the server must check.
```

## Developer

```text
Review src/realtime for WebSocket, SSE, and signaling handlers. Trace identity from connection to
every subscribe, join, send, and reconnect path. Flag missing Origin checks, object authorization,
strict schemas, and limits with file:line, API category, CWE, exploit frame, and fix.
```

## Review

```text
Build a matrix of endpoint/message type against required identity, Origin/CSRF condition, target
resource authorization, rate/size/fan-out limit, and reconnect behavior. Do not accept a handshake
check as evidence for later frames.
```

## Audit

```text
Assess WebSocket/SSE/WebRTC signaling controls against OWASP API Top 10 2023 and ASVS 5.0 V4/V6/V7/V8.
For each control provide code/config evidence, a negative test, applicable CWE, and deployment facts
that are not verifiable from this repository.
```

## Anti-patterns

| Weak prompt | Finding prompt |
|---|---|
| "Is this WebSocket secure?" | "For every message type, show the authorization decision and the object/channel it scopes." |
| "Check socket auth." | "Test a cookie-authenticated connection from an unapproved Origin and a second user subscribing to a known room." |
| "Review WebRTC." | "Trace room join, offer, answer, and ICE routing; prove each participant is authorized for the call." |
