Reference: Stripe Payments API
Source: https://docs.stripe.com
Date verified: 2026-07-30

Server-side lessons:
- client_secret must never log or store; derive from PaymentIntent + API key at runtime.
- Stripe-Idempotent-Key header scope limits collisions to the same Stripe account.
- CVC2/CVV is never stored server-side; use the Stripe Verify window only.
- Webhook endpoint must verify t body - timestamp - signature using the endpoint wh_secret.
