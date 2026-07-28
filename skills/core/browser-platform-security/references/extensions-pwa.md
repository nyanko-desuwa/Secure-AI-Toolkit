# Extension and PWA Controls

Sources: Chrome Extensions documentation, MDN WebExtensions, OWASP Top 10 2025. Checked: 2026-07-28.

Permissions and host matches are authority. Use minimum host permissions and optional permissions
where possible. Validate extension message sender ID/origin and strict payload schemas. Make
web-accessible resources explicit. Do not use extension storage for reusable server secrets. Update
manifests/scripts require HTTPS and controlled publication channels.
