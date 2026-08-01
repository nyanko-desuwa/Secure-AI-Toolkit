# Payments Security Checklist

Run this before returning any code that touches a payment integration.

## Tokenization boundary

- [ ] [critical] Server never receives full PAN; only a payment_method/source token from the gateway SDK
- [ ] [critical] Client-side form posts directly to the gateway (Stripe.js, Adyen Web, Braintree Drop-in); your server receives the resulting token only
- [ ] [critical] No card-number field exists in your application's request body or model

## Webhook integrity

- [ ] [critical] Signature header verified (Stripe: stripe-signature, Adyen: HMAC-SHA256, Braintree: bt_signature) before body is parsed or acted on
- [ ] [critical] Replay protection: timestamp in the signature envelope checked; events older than 300 s rejected
- [ ] [critical] Webhook endpoint returns 400/401 on bad signature, not 200 (which silently drops events) or 500 (which causes the gateway to retry)
- [ ] [recommended] Webhook secret stored in a secrets manager, not in environment variable literals or source code

## 3-D Secure flow

- [ ] [critical] /complete (or equivalent) handler validates the returned PaymentIntent server-side against the original order before capturing
- [ ] [critical] Completion of one intent cannot be replayed to authorize a different order
- [ ] [critical] 3DS failure path returns a structured error to the UI; it does not silently succeed or leave a dangling intent open
- [ ] [critical] client_secret never written to a URL fragment, log, or analytics event

## Idempotency

- [ ] [recommended] Idempotency key is generated server-side and scoped to (merchant_account, payment_intent_id, source_hash)
- [ ] [recommended] Key is not derived from or accepted directly from a client-controlled parameter
- [ ] [recommended] Server-side decision stored independently from the gateway response so replayed webhooks are detected

## CVC2/CVV handling

- [ ] [critical] CVC2/CVV never persisted, cached, or logged; used only in the authorize request and discarded
- [ ] [critical] CVC2/CVV not echoed back in any API response

## Secrets

- [ ] [critical] WH_SECRET (webhook signing key) is rotated on exposure; prior version invalidated within 5 minutes
- [ ] [critical] API secret key (sk_live_...) is never included in client-side code, browser-visible config, or logs

## Error messages

- [ ] [recommended] Declined-card errors do not reveal the last-four digits of the PAN outside a checkout UI context
- [ ] [recommended] Gateway error codes logged for operations teams, not returned verbatim to the browser
