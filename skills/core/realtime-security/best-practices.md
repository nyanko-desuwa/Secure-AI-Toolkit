# Realtime Security Best Practices

## Authenticate and authorize the upgrade - API2 · CWE-306

```typescript
// Vulnerable: anyone opens a privileged socket
wss.on("connection", socket => socket.send("connected"));
```

```typescript
// Fixed: verify identity and permission before registering handlers
wss.on("connection", (socket, request) => {
  const actor = requireSession(request);
  requirePermission(actor, "realtime.connect");
  registerHandlers(socket, actor);
});
```

## Enforce an Origin allowlist - CWE-352

```typescript
// Vulnerable: cookies make a cross-site WebSocket possible
if (request.headers.origin) accept();
```

```typescript
// Fixed: browser origins are explicit; non-browser clients use another credential path
if (request.headers.origin !== "https://app.example.com") reject();
```

## Authorize every subscription - API1 · CWE-639

```typescript
// Vulnerable: room name is the capability
socket.on("subscribe", ({ room }) => socket.join(room));
```

```typescript
// Fixed: server derives and checks the resource before joining
socket.on("subscribe", ({ orderId }) => {
  requireOrderRead(actor, orderId);
  socket.join(`order:${orderId}`);
});
```

## Use strict message schemas - CWE-915

```typescript
// Vulnerable: arbitrary event reaches internal dispatch
socket.on("message", frame => handlers[frame.type](frame));
```

```typescript
// Fixed: allowlisted discriminated union rejects unknown keys and types
socket.on("message", frame => dispatch(MessageSchema.parse(frame), actor));
```

## Bound fan-out and reconnects - API4 · CWE-770

```typescript
// Vulnerable: client chooses audience and reconnect ticket never expires
broadcast(frame.room, frame.payload);
```

```typescript
// Fixed: authorize target, cap recipients, and use short actor-bound tickets
publishToAuthorizedRoom(actor, frame, { maxRecipients: 500 });
```

Why: authentication at connect cannot authorize arbitrary future messages.
