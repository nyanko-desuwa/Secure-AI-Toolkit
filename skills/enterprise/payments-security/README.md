# Payments Security

Secures code paths that touch cardholder data (PAN, CVC2/CVV, expiry) in payment
integrations with Stripe, Adyen, or Braintree. Covers tokenization correctness, PCI scope
reduction, payment-webhook integrity verification, ACS interface hardening, and 3-D Secure
flow pitfalls.

## What this skill decides

- Whether your server touches full PAN or only a token/payment_method reference
- Whether your 3DS return handler correctly scopes client_secret and validates server-side
- Whether webhook signatures are verified before body parsing, and the reject path is correct
- Whether idempotency keys are scoped to (merchant, intent, source) rather than client-controlled

## Configuration

No additional libraries required. Stripe.js / Adyen Web / Braintree Drop-in handle the
browser-side tokenization out of scope of this skill.

## Limitations

- Does not cover PCI DSS audit scoping methodology: use `enterprise/compliance` for evidence,
  SAQ selection, and control mapping.
- Does not verify gateway network connectivity or DNS pinning.
- Does not model issuer risk-scoring logic; fraud signal interpretation belongs to
  `advanced/incident-response`.
- Gateway-specific quirks (Adyen HMAC v2 vs v3, Braintree webhook notification format) are
  documented in references/ but not exhaustively tested.

## Related standards

| Standard          | Pinned version | Reference file                                |
|-------------------|----------------|-----------------------------------------------|
| PCI DSS           | 4.0            | references/pci-dss.md                         |
| OWASP ASVS        | 5.0.0          | references/asvs-v14-payments.md               |
| Stripe API        | 2024-12-18     | references/stripe-payments-api.md             |
| 3-D Secure 2.x    | 2.3.1          | references/3ds-2.md                           |
