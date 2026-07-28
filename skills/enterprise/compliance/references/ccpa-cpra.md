# CCPA / CPRA Implementation Notes

Checked: 2026-07-28

Primary source fetched: <https://oag.ca.gov/privacy/ccpa>

The California Attorney General page points to Title 11, Division 6, Section 7001 et seq. of the
California Code of Regulations for implementing rules. It describes a user-enabled global privacy
control such as GPC as a valid request to stop the sale or sharing of personal information, and
states that covered businesses must honor it.

## Technical mapping

A browser signal is not a control until the server receives, authenticates as appropriate, stores,
and applies it to processing decisions. Evidence should include:

1. request parsing and supported-signal test;
2. preference event with subject or browser scope, timestamp, policy version, and source;
3. server-side suppression test for sale/share flows;
4. processor or ad-tech propagation result;
5. withdrawal or change history and retention;
6. synthetic end-to-end test artifact.

Do not treat a cookie banner, hidden UI choice, or client-only flag as enforcement. The technical
mapping is to opt-out preference handling; whether a business, data use, or consumer is legally
covered is a legal and scope determination.

## Date caution

The page states that CPRA protections began January 1, 2023 and that CPPA-updated regulations were
effective March 29, 2023. Re-check current law, regulations, and applicable amendments before
using either date in a formal report.

## Deliberate omissions

No individual CCPA/CPRA regulation subsection or statutory requirement ID beyond the verified
Title 11, Division 6, Section 7001 et seq. citation is used. The source page's plain-language
summary is not a substitute for the regulations or counsel.
