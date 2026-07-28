# Email Security Examples

Eight defensive pairs. Vulnerable blocks are labelled and paired with fixes. Domains and tokens are
synthetic.

## Host-header-poisoned reset link

`A01:2025` · CWE-601

```python
# Vulnerable: attacker Host becomes the recovery destination
url = f"https://{request.headers['host']}/reset?token={token}"
```

```python
# Fixed: configured public origin only
url = f"{settings.PUBLIC_APP_ORIGIN}/reset?token={token}"
```

## Reusable verification token in mail

`A07:2025` · CWE-640

```python
# Vulnerable: long-lived raw token is emailed and stored
token = user.id
store.save(user.id, token)
```

```python
# Fixed: opaque single-use token; authentication owns lifecycle
token = secrets.token_urlsafe(32)
store.save(user.id, hash(token), expires_in=900, single_use=True)
```

## Unbounded resend

`A07:2025` · API4 · CWE-307

```python
# Vulnerable: any email can request unlimited resets
send_reset(request.json["email"])
```

```python
# Fixed: uniform response and budgeted resend
limiter.consume(account_or_ip)
send_if_exists(request.json["email"])
return generic_accepted()
```

## Header injection

`A05:2025` · CWE-93

```python
# Vulnerable: CR/LF in subject becomes additional headers
message = f"Subject: {user_subject}\r\n\r\nBody"
```

```python
# Fixed: structured fields and CR/LF rejection
send_mail(subject=sanitize_one_line(user_subject), body=body, to=[recipient])
```

## Unsafe HTML template

`A05:2025` · CWE-79

```html
<!-- Vulnerable: untrusted name rendered as HTML -->
<p>Hello {{ user.name }}</p>
```

```html
<!-- Fixed: contextual encoding or text-only security mail -->
<p>Hello {{ user.name | escape }}</p>
```

## Tenant-chosen From domain

`A01:2025` · CWE-284

```python
# Vulnerable: tenant sets arbitrary From
mail.from_ = request.json["from"]
```

```python
# Fixed: allowlisted sender identity bound to tenant authorization
mail.from_ = tenant_sender_identity(actor.tenant_id)
```

## Unsigned provider webhook

`A08:2025` · CWE-345

```python
# Vulnerable: delivery event is trusted by presence
mark_delivered(request.json["message_id"])
```

```python
# Fixed: verify signature, freshness, and process once
event = verify_provider(request.body, request.headers)
process_once(event["id"], event)
```

## Real incident shape

A public reset link builder used request Host and a shared SMTP credential in application config.
Attackers redirected recovery mail and later rotated the exposed credential across environments.
Configured origin, secret-managed credentials, and provider event verification would have limited
both paths.
