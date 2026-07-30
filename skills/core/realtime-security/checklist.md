# Realtime Verification Checklist

Run before returning WebSocket, SSE, or WebRTC signaling code. Mark each item pass, fail, or not
applicable. "Not applicable" needs a one-line reason - an unexplained skip reads the same as an
oversight.

Only run the sections the change touches. An SSE-only change does not need the WebRTC section.

## Connect Authentication and Authorization (API2 · CWE-306 · ASVS V6, V7, V8)

- [ ] [critical] Upgrade / first SSE request authenticates before the channel is considered established
- [ ] [critical] Anonymous connects are either impossible or explicitly limited to public, non-sensitive feeds
- [ ] [critical] Identity comes from a verified session or bearer token, not from a query-string user id
- [ ] [recommended] Tokens in query strings (if unavoidable for legacy EventSource) are single-use, short-TTL,
      and not logged by the access layer
- [ ] [critical] Authorization for the *connection purpose* is checked (e.g. may open `/ws/admin`), not only
      "is logged in"
- [ ] [recommended] Failed auth closes with a generic reason; no stack traces or internal hostnames in close
      payloads

## Per-Message and Per-Subscription Authorization (API1, API5 · CWE-639, CWE-285 · ASVS V8)

- [ ] [critical] Every message type has an explicit allowlist of roles or permissions
- [ ] [critical] Subscribe / join / room enter checks object-level access for that channel
- [ ] [critical] Send / publish checks whether the actor may write that channel or target user
- [ ] [recommended] Presence, typing, and "who is online" events are scoped - not a global directory leak
- [ ] [critical] Admin-only message types cannot be invoked by a normal member of the same socket
- [ ] [recommended] Denial returns a generic error frame; does not confirm that a private channel exists when
      existence is sensitive
- [ ] [recommended] A test fails if the channel ownership check is removed

## Origin and CSRF-Class Controls (CWE-352-class · ASVS V13, V4)

- [ ] [critical] Server enforces an explicit Origin allowlist on WebSocket upgrade when cookies or ambient
      credentials authenticate the connection
- [ ] [critical] Origin is not reflected; wildcard with credentials is rejected
- [ ] [recommended] SameSite cookie attribute reviewed for cookie-authenticated SSE and WebSocket
- [ ] [critical] Non-browser clients that cannot send Origin are authenticated with bearer tokens or mTLS,
      not by skipping the Origin check for everyone
- [ ] [recommended] `Sec-WebSocket-Protocol` is not treated as an authentication secret by itself

## Rate, Size, and Fan-Out Limits (API4 · CWE-770 · ASVS V2, V4)

- [ ] [recommended] Max message size enforced before full parse or broadcast
- [ ] [recommended] Per-connection message rate limited
- [ ] [recommended] Per-actor subscription count capped
- [ ] [recommended] Broadcast / fan-out degree capped (who a single publish can reach)
- [ ] [recommended] Server-side push loops (ticker, presence) cannot be multiplied unboundedly by one client
- [ ] [recommended] Compression bombs considered if permessage-deflate is enabled
- [ ] [recommended] Idle timeout and max connection lifetime set
- [ ] [recommended] Total concurrent connections per actor (and per IP pre-auth) bounded

## Reconnect and Session Binding (API2 · CWE-384 · ASVS V7)

- [ ] [critical] Reconnect ticket bound to actor id, purpose, and expiry
- [ ] [recommended] Ticket is single-use or rotated on each successful reconnect where protocol allows
- [ ] [critical] Logout / password change / session revoke invalidates outstanding reconnect tickets
- [ ] [critical] Reconnect does not silently upgrade privileges from a stale ticket
- [ ] [optional] Ticket is not accepted from a different client fingerprint class if that is a stated policy
- [ ] [critical] After reconnect, subscriptions are re-authorized, not restored blindly from client state

## Encryption and Transport (ASVS V13, V9, V14)

- [ ] [critical] WebSocket is `wss://` in every non-local environment
- [ ] [critical] SSE is served over HTTPS
- [ ] [critical] WebRTC media uses DTLS-SRTP; signaling itself is over TLS
- [ ] [critical] Long-lived secrets (refresh tokens, TURN long-term creds) are not placed in signaling
      payloads that peers can read
- [ ] [recommended] TURN credentials are short-lived and scoped when issued by the app

## Message Schema and Injection (CWE-74, CWE-915 · ASVS V5, V1)

- [ ] [critical] Every inbound message type has a strict schema (unknown keys rejected)
- [ ] [critical] Message `type` / event name is allowlisted; free-form event names cannot invoke internals
- [ ] [critical] Payloads that will be rendered are encoded at the DOM sink (see `frontend-security`)
- [ ] [critical] Payloads that reach SQL, ORM, shell, or deserializer are parameterized / typed
- [ ] [recommended] Binary frames have an explicit content type and size cap if accepted at all

## SSE-Specific

- [ ] [critical] Stream endpoint requires auth equivalent to the data it emits
- [ ] [recommended] Cookie-authenticated streams consider CSRF / SameSite; prefer Authorization header where
      the client stack allows it
- [ ] [critical] `Last-Event-ID` replay cannot skip authz or read another actor's events
- [ ] [recommended] Event names and data fields are controlled; client cannot inject event boundaries through
      unsanitized upstream data

## WebRTC Signaling-Specific

- [ ] [critical] Room / call join requires authorization for that call resource
- [ ] [critical] Offer, answer, and ICE candidate messages are only routed between authorized participants
- [ ] [recommended] Room IDs are not the sole capability (unpredictable IDs help; they do not replace authz)
- [ ] [recommended] Screen-share or recording start is a separate privileged action if product requires it
- [ ] [critical] Signaling does not embed long-term TURN passwords in broadcast messages

## Socket.IO / Library-Specific (when used)

- [ ] [critical] Namespaces are authorized independently
- [ ] [critical] `socket.join(room)` is only called server-side after authz - never from a raw client room
      name without a check
- [ ] [critical] `socket.handshake` auth runs before event handlers are registered
- [ ] [critical] Admin namespaces are not reachable with a user-scoped token

## Before Returning

- [ ] [critical] Build or compile step run
- [ ] [critical] Cross-actor subscribe/send negative tests run
- [ ] [recommended] Origin allowlist tested with a disallowed origin
- [ ] [recommended] Reconnect-after-logout tested
- [ ] [recommended] Temporary files removed
- [ ] [critical] Anything unverifiable (sticky sessions, TURN infra, edge TLS) stated plainly
