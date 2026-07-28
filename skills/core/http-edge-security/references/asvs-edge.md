# OWASP ASVS 5.0 Edge Controls

Version: OWASP ASVS 5.0.0, released 2025-05-30. Source: <https://github.com/OWASP/ASVS>. Checked: 2026-07-28.

- **V4 API and Web Service**: 4.1.3 says intermediary headers such as `X-Real-IP`, `X-Forwarded-*`, and `X-User-ID` cannot be overridden by an end user. 4.1.4 requires only explicitly supported methods.
- **V11 Business Logic**: use it when cache or routing behavior crosses tenant/business boundaries.
- **V13 Configuration**: host allowlists, deployment defaults, and edge policy are configuration controls.
- **V14 Data Protection**: cache storage and transport decisions must not disclose protected data.

Requirement numbering changes across ASVS editions. Re-read the official 5.0 requirement before using a requirement-level audit claim.
