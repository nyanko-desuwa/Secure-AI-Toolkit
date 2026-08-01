# Payments Security Troubleshooting

## "We are SAQ-A because we use Stripe.js" but PCI scope still expands

SAQ-A eligibility requires that your pages are fully outsourced to the gateway's hosted
form (Stripe Checkout, Adyen Hosted Payment Pages) OR that you use an iFrame served
entirely by the gateway with no JS access to the card elements. If your page loads
Stripe.js and constructs a CardElement, you are SAQ-A-EP, not SAQ-A. Confirm with
your QSA which SAQ applies before making scope-reduction claims.

## Webhook events arriving out of order

Stripe and Adyen do not guarantee delivery order. A payment_intent.succeeded event
may arrive before payment_intent.payment_failed for the same intent in a retried flow.
Design your fulfillment handler as idempotent: if the order is already fulfilled, return
200 without re-processing. Use the event's created timestamp to decide which event wins,
not arrival order.

## 3DS challenge loop: browser keeps redirecting back

This usually means the completion handler is returning a 3DS-required error because it
is calling confirmPayment with an expired or already-confirmed client_secret. Fix:
generate a fresh PaymentIntent when the previous confirm attempt fails with
requires_action and 3DS has already been completed. Do not retry with the same intent.

## Adyen HMAC validation fails intermittently

Adyen v2 HMAC sorts keys alphabetically before signing. Adyen v3 does not. Confirm
which HMAC version your webhook endpoint is configured for in the Adyen Customer Area
and match your verification logic accordingly. Mismatch causes 50% failure on fields
that happen to be in a different sort position.

## Stripe test vs live key confusion in staging

The stripe-signature timestamp check will pass for both test and live events if the
same WH_SECRET is accidentally shared. Add a check that the intent ID prefix
matches the expected environment: pi_test_ vs pi_ (no prefix for live).
Reject and alert on prefix mismatch.

## CVC2 appearing in payment-intent metadata

Never put CVC2, card number, or expiry in PaymentIntent metadata or description fields.
These fields are logged by Stripe's dashboard and may appear in your own audit logs via
the Events API. PCI DSS Req 3.3.2 prohibits storage of SAD post-authorisation.
If you need to annotate intents, use opaque order IDs only.
