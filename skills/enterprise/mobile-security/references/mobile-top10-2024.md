> Verified 2026-07-28 against the OWASP Mobile Top 10 project page, which presents the
> "Top 10 Mobile Risks - Final release 2024" as the current list.
> Source: <https://owasp.org/www-project-mobile-top-10/>

# OWASP Mobile Top 10 2024

A risk ranking, not a requirement set. Use it to explain priority to people who do not read
MASVS. Use MASVS to decide what to fix.

One quirk worth knowing before you link anything: the individual risk pages still sit under
`2023-risks/` URLs, a holdover from the initial 2023 release that the 2024 final list carries
forward. The edition is 2024; the URLs say 2023. Both are correct.

| Rank | Title |
|---|---|
| M1 | Improper Credential Usage |
| M2 | Inadequate Supply Chain Security |
| M3 | Insecure Authentication/Authorization |
| M4 | Insufficient Input/Output Validation |
| M5 | Insecure Communication |
| M6 | Inadequate Privacy Controls |
| M7 | Insufficient Binary Protections |
| M8 | Security Misconfiguration |
| M9 | Insecure Data Storage |
| M10 | Insufficient Cryptography |

Earlier editions are 2016 and 2014. The 2016 list is still widely quoted in tooling output and
does not match this one — 2016 led with M1 Improper Platform Usage, which has no direct 2024
equivalent. If a scanner report cites M1 and means platform misuse, it is running a 2016 mapping.

## Mapping to the other standards in this skill

Rough, and intentionally so — the lists are cut on different axes.

| Mobile Top 10 2024 | MASVS group | OWASP Top 10 2025 | ASVS 5.0 |
|---|---|---|---|
| M1 Improper Credential Usage | STORAGE, CRYPTO | A04 | V14 |
| M2 Inadequate Supply Chain Security | CODE | A03 | V15 |
| M3 Insecure Authentication/Authorization | AUTH | A01, A07 | V6, V7, V10 |
| M4 Insufficient Input/Output Validation | CODE, PLATFORM | A05 | V1, V2 |
| M5 Insecure Communication | NETWORK | A02, A04 | V12 |
| M6 Inadequate Privacy Controls | PRIVACY | A01 | V14 |
| M7 Insufficient Binary Protections | RESILIENCE | — | — |
| M8 Security Misconfiguration | PLATFORM, CODE | A02 | V13 |
| M9 Insecure Data Storage | STORAGE | A04 | V14 |
| M10 Insufficient Cryptography | CRYPTO | A04 | V11 |

M7 has no clean web equivalent, which is the point: binary protection is a mobile-only concern
because on the web the code stays on your server. It is also the one most likely to be
over-weighted in a report, because it is the easiest to detect automatically.

## Using it in a report

Lead with the MASVS control and add the Mobile Top 10 rank in brackets for the summary. "Token
readable in `SharedPreferences` — MASVS-STORAGE-1, Mobile Top 10 2024 M9" reads well in both
directions.

Do not claim a rank you have not checked against this table. The ordering changed between 2016
and 2024 and recalled ranks are usually the old ones.
