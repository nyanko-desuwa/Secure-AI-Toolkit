# Payments Security Common Mistakes

## 1. Trusting the redirect instead of the API

A 3DS return to `/complete?payment_intent=pi_xxx` looks authoritative. It is not. The query
parameter is client-visible. An attacker who obtains any PaymentIntent ID -- including one
for a different order or a failed charge -- can replay the redirect.

Fix: retrieve the intent from the Stripe/Adyen API using the ID stored *server-side* when
the order was created, not the one from the query string.

## 2. Webhook endpoint returns 200 on signature failure

Returning 200 on a bad signature silently drops the event. The gateway marks it delivered;
your server never processed it. The right response is 400. Never swallow SignatureVerificationError.

## 3. client_secret in a URL fragment

JavaScript on the page can read `location.hash`. Browser history stores it.
Server access logs capture it in the Referrer header. Return client_secret in the
JSON body of a POST response only.

## 4. Idempotency key from the client

A client-supplied idempotency key can be reused across different orders by an attacker who
knows the key format. Generate it server-side. Tie it to the order and attempt count.

## 5. CVC2 stored even briefly

Some integrations log the full request body for debugging. CVC2/CVV appears in the log.
Even a /tmp rotation that purges after 24 hours is a PCI DSS failure: SAV must not be stored
post-authorisation at all. Mask sensitive fields before they touch any logging pipeline.

## 6. sk_live_* key shipped in a frontend bundle

A Vite/webpack build that imports process.env.STRIPE_SECRET_KEY will bundle the secret in
the JS artifact. Only publishable keys (pk_live_*) belong in the browser. Secret keys
belong in server-side secrets managers only.

## 7. Missing replay protection on webhooks

Stripe embeds a timestamp in the stripe-signature header (t=). Adyen provides a timestamp
in the HMAC payload. Check that the event is within an acceptable window (typically +/- 300 s).
Without this check, a captured webhook can be replayed after the WH_SECRET is rotated.

## 8. Single shared webhook endpoint for multiple environments

If the same endpoint accepts both test (sk_test_*) and live (sk_live_*) events, a test
event can trigger production fulfillment. Use separate endpoints and separate WH_SECRETs per
environment.
