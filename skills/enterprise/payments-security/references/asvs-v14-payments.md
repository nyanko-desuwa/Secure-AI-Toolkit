Reference: ASVS 5.0.0 (Application Security Verification Standard)
Chapters used: V3, V4, V11, V12, V14
Source: https://asvs.readthedocs.io/en/latest/index.html
Date verified: 2026-07-30

V3: Session Management - idempotency tokens should not be reusable across intents.
V4: Access Control - server-side verification that the actor owns the payment intent.
V11: Business Logic - payment state machine must enforce transitions (authorized -> captured -> refunded).
V12: Files and Resources - captured payment evidence stored with least-privilege access.
V14: Privacy - cardholder details never appear in logs, error messages, or metrics tags.
