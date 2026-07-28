# Email Security Best Practices

## Construct security links from configured origin

```python
# Vulnerable: request Host can poison a reset link
link = f"https://{request.headers['host']}/reset?token={token}"
```

```python
# Fixed: deployment configuration owns the public origin
link = f"{settings.PUBLIC_APP_ORIGIN}/reset?token={token}"
```

`http-edge-security` owns trusted Host/proxy configuration. This code must not turn an inbound
header into an account-recovery destination.

## Use structured recipient and header fields

```javascript
// Vulnerable: untrusted text becomes RFC headers
rawMessage = `To: ${request.body.email}\r\nSubject: ${request.body.subject}\r\n\r\nHello`;
```

```javascript
// Fixed: validate address and use a mail library's structured fields
await transporter.sendMail({ to: validatedAddress, subject: "Account notice", text: "Hello" });
```

Reject CR/LF in display values and never concatenate raw RFC headers.

## Verify provider events before changing state

```typescript
// Vulnerable: any JSON body marks a delivery successful
app.post("/mail/events", express.json(), async (req, res) => updateDelivery(req.body));
```

```typescript
// Fixed: verify provider signature over raw bytes, then process event ID once
app.post("/mail/events", express.raw({ type: "*/*" }), async (req, res) => {
  const event = verifyProviderEvent(req.body, req.headers["provider-signature"]);
  await processOnce(event.id, event);
  res.sendStatus(204);
});
```

`api-security` owns endpoint authorization mechanics; delivery state must still be idempotent.
