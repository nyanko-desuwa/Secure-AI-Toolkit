# Browser Platform Troubleshooting

## App needs offline account pages

Cache a shell and encrypted/local state only after a product threat model. Do not make authenticated
HTML shared cacheable. On logout, delete account-scoped cache entries and revalidate on reconnect.

## Extension needs many customer domains

Use optional permissions requested at the moment of a user action, or an enterprise-managed allowlist.
Do not default to all URLs because onboarding is simpler.

## Content script must communicate with page

Use a narrow, versioned message schema, include an operation allowlist, and treat page-provided data
as untrusted. Never let it name an extension API method directly.

## Browser API differs by vendor

Name the target browser/version and verify its manifest/service-worker behavior from vendor docs.
The security model transfers; field names and support do not.