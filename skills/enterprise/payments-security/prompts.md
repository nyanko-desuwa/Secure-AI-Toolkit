# Payments Security Prompts

## Beginner

"I am adding Stripe to my Laravel app. Where does the card number go and what does my server
actually need to receive?"

"What is the difference between a publishable key and a secret key in Stripe, and which one
goes where?"

## Developer

"Review this Stripe webhook handler and tell me if the signature verification is correct:
[paste code]. Flag any replay-attack surfaces."

"I am building a 3DS return handler. What must I verify server-side before I fulfill the order?"

"My idempotency key is built from the order ID sent by the client. What is the risk and
how do I fix it?"

## Review

"Audit this payment integration for PCI scope. Identify every code path that could put us
outside SAQ-A-EP. Flag any CVC2/CVV handling, any place the PAN touches server memory,
and any log line that could capture card data."

"Find all places in this codebase where a payment webhook is received. For each one, confirm:
(1) signature is verified before body is parsed, (2) a bad signature returns 4xx not 200 or
500, (3) replay protection uses the timestamp in the signature envelope."

## Audit

"Map every finding in this payment integration to PCI DSS v4.0 requirements. For each gap,
cite the specific Requirement number, the control objective, and the remediation."

"Run a full 3DS flow review: check the PaymentIntent creation, the methodUrl handler, the
confirmPayment call, the return handler, and the order fulfillment gate. Report each
deviation from the Stripe documentation as a severity-ranked finding with an exploitation
path."

## Anti-patterns (prompts that produce misleading results)

Anti-pattern: "Is our integration PCI compliant?" -- this is a legal/audit conclusion, not
a technical finding. Report the technical fact instead: "CVC2 is stored in the request log"
or "webhook signature is not verified before body is parsed."

Anti-pattern: "Does Stripe handle PCI for us?" -- Stripe reduces scope but does not eliminate
it. Scope depends on which integration method you use. Never assert SAQ-A without a QSA
sign-off.
