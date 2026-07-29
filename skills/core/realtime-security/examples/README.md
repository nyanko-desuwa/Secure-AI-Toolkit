# Realtime Security Examples

## Upgrade without authentication - API2 · CWE-306

```typescript
// Vulnerable: any client gets a socket
wss.on("connection", socket => register(socket));
```

```typescript
// Fixed: verify session before handlers exist
wss.on("connection", (socket, req) => register(socket, requireSession(req)));
```

## Missing Origin check - CWE-352

```typescript
// Vulnerable: a hostile site can open a cookie-authenticated socket
acceptUpgrade(req);
```

```typescript
// Fixed: only product origins may use ambient cookies
if (req.headers.origin !== "https://app.example.com") reject();
```

## Cross-user subscription - API1 · CWE-639

```typescript
// Vulnerable: caller selects another user's channel
socket.join(`user:${frame.userId}`);
```

```typescript
// Fixed: server scopes the channel to the authenticated actor
socket.join(`user:${actor.id}`);
```

## Schema-free message - CWE-915

```typescript
// Vulnerable: unknown properties reach dispatcher
handlers[frame.type](frame);
```

```typescript
// Fixed: strict schema parses a known message union
dispatch(MessageSchema.parse(frame), actor);
```

## Unbounded fan-out - API4 · CWE-770

```typescript
// Vulnerable: client chooses unlimited audience
broadcast(frame.room, frame.data);
```

```typescript
// Fixed: policy identifies an authorized, bounded audience
publishToAuthorizedRoom(actor, frame, { maxRecipients: 500 });
```

## Reconnect replay - API2 · CWE-384

```text
Vulnerable: a reconnect ticket remains valid after logout and can restore old subscriptions.
```

```text
Fixed: short-lived, single-use ticket is bound to session and every subscription is re-authorized.
```

## WebRTC room join - API1/API5 · CWE-285

```text
Vulnerable: knowing a signaling room ID is enough to receive offers and ICE candidates.
```

```text
Fixed: the server authorizes call membership before routing every signaling message.
```
