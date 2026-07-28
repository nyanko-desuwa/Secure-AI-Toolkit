# HTTP Client Security Troubleshooting

## A private provider endpoint is legitimate

Use a named dependency and explicit private-network/eDNS policy. Do not relax the shared arbitrary
URL client for one integration.

## An upstream uses a private CA or mTLS

Install the scoped CA bundle and client certificate through secret management. Do not disable
hostname/certificate verification globally.

## Redirects are required for OAuth or object storage

Validate every permitted host transition and strip/reapply credentials only for the explicit target.
Document the redirect contract and maximum hop count.

## DNS rebinding cannot be ruled out in code

State the limitation. Enforce egress at network/proxy level and use connection-level policy where
the platform supports it.
