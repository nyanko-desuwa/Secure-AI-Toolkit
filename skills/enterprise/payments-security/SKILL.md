---
name: payments-security
description: 'Secure payment flows and cardholder data - tokenization, PCI scope reduction, payment-webhook integrity, ACS interface protection, fraud hygiene, 3DS, Stripe/Adyen/Braintree. Triggers: "payment", "Stripe", "Adyen", "Braintree", "card data", "PCI", "tokenization", "webhook signature", "CVC2", "CVV", "PAN", "payment intent", "PCI DSS", "PCI SAQ", "thanh toan", "the thanh toan".'
allowed-tools: Read, Glob, Grep, WebSearch, WebFetch
---

# Payments Security

Owns the boundary where cardholder data enters, moves through, and exits your system: tokenization correctness, PCI scope reduction, payment-webhook integrity, ACS-interface hardening, and 3-D Secure flows. Supported stacks are Stripe, Adyen, and Braintree explicitly; other gateways transfer by analogy only.

## What This Skill Is NOT

It does not cover PCI DSS audit methodology (that belongs to `enterprise/compliance`). Hardcoded credentials are `core/secrets-management`. Shipping payment config to the browser is `core/publish-safety` and `core/frontend-security`. Authorization on the order a payment backs is `api-security`.

## Ownership Boundary

**Owns:** code paths that could contain, derive, or forward PAN, CVC2/CVV, expiry, or magnetic-stripe equivalent. If the variable could appear inside an assessor's CDE diagram, this skill owns it.

**Does not own:**

| Concern                                              | Route to                   |
|------------------------------------------------------|-----------------------------|
| PCI DSS scope determination and audit evidence        | `enterprise/compliance`     |
| Credential and signing-key storage                    | `core/secrets-management`   |
| Cardholder data leaked to logs or analytics           | `core/logging-audit`        |
| Payment endpoint authorization and BOLA               | `api-security`              |
| Payment endpoint brute-force or replay               | `brute-force-defense`       |

## Standards This Skill Maps To

| Standard                                          | Use it for                               | Version here |
|---------------------------------------------------|------------------------------------------|--------------|
| PCI DSS v4.0                                      | Cardholder data storage, CDE scope       | 4.0          |
| OWASP ASVS 5.0 V3/V4/V11/V12/V14/V15/V16        | General application controls             | 5.0.0        |
| OWASP Top 10 2025 A01/A02/A04/A08                | Risk triage                              | 2025         |

## Workflow

### 1. Scope the CDE first

Answer before writing: which functions, hosts, and data stores will touch full PAN, CVC2/CVV, or expiry? PCI DSS boundary is not "the database that also holds users" -- it is the specific function that receives or derives the Sensitive Authentication Value (SAV). Everything kept out of that function has a simpler SAQ path.

### 2. Validate the tokenization boundary

The only cardholder data your server should ever receive is a `payment_method` or `source` reference from the gateway SDK. If you parse a card number from an unsanitized payment form on your side, claim SAQ-A only if the field is immediately forwarded whole and never persisted.

### 3. Harden the 3DS path

The ACS redirect is owned by the browser, not your server. Your job: `methodUrl`/`app` handlers return quickly; `cvc` requested only when issuer returns `request_cvc2`; the `/complete` handler validates server-side against the original intent; completion failure returns a structured error, never a silent retry. A 3DS failure that leaves the client to retry without a fresh `client_secret` leaves the intent in-flight and reusable.

### 4. Verify webhook integrity by signature, not payload

Always verify the signature first, then parse. Reject with 400/401 on bad or expired signatures. Signature failure is not a 500; the client should not retry automatically. Never trust `event.id` alone; the body is signed, not the id.

### 5. Enforce idempotency scoping

Idempotency keys scope to the gateway account, not your application. Tie the key to (merchant_account, payment_intent_id, source). Store the server-side decision separately from the gateway response.

### 6. Verify

Run [checklist.md](checklist.md).

## Severity

Rank by whether full PAN, expiry, or CVC2/CVV can be extracted, or whether an attacker can confirm or charge without the legitimate customer's presence.

- **Critical** - webhook accepted without signature; PAN or CVC2 logged or returned to client; 3DS completed by unrelated actor
- **High** - replayed webhook mutates state; idempotency key not scoped; CVC2 stored server-side even briefly
- **Medium** - TLS pinning skipped; client_secret in a URL fragment; idempotency key from client without hashing
- **Low** - masked cardholder data with zero-width characters; stale payment_method reference not rotated

## Related Skills

- `core/secrets-management` - webhook signing secrets, WH_SECRETs, API keys
- `core/logging-audit` - masking mechanics, append-only trails
- `api-security` - order authorization, BOLA, idempotency
- `brute-force-defense` - retry, refund, and reset limits
- `enterprise/compliance` - PCI DSS scope evidence and SAQ path
- `enterprise/kubernetes-security` - CDE pod/network isolation in-cluster

## Supporting Files

- [checklist.md](checklist.md) - pre-return verification
- [best-practices.md](best-practices.md) - vulnerable and fixed pairs
- [common-mistakes.md](common-mistakes.md) - what goes wrong
- [troubleshooting.md](troubleshooting.md) - when guidance cannot be applied
- [prompts.md](prompts.md) - prompt tiers
- [references/](references/) - standard summaries, version-pinned
- [examples/](examples/) - vulnerable and fixed side by side
