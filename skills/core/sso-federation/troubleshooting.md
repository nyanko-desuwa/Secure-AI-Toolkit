# SSO Federation Troubleshooting

## Multiple tenants share an ACS endpoint

Resolve tenant from a verified state/request binding or a configured domain policy. Do not select an
IdP from an untrusted query parameter or assertion claim before validation.

## IdP-initiated SSO is required

It lacks an SP request to bind with InResponseTo. Compensate with strict issuer/audience/recipient/
destination/time validation, replay controls, and an explicit tenant IdP allowlist.

## Certificate rotation caused login failures

Do not disable signature validation. Load the old and new key only during a documented overlap,
verify metadata provenance, set an expiry, and remove the old key after the window.

## Vendor library hides validation details

Find its documented validation API and security advisories. If the application only calls decode or
parse, it has not proven signature validation.