# OWASP Top 10 2025 Reference

Source: <https://owasp.org/Top10/2025/>
Verified: 2026-07-28 (repository brief and OWASP source).

The 2025 edition is not a renumbering of 2021. Injection is `A05`, not `A03`; `A03` and
`A10` are new categories in this edition.

| ID | Name | Relevance here |
|---|---|---|
| A01:2025 | Broken Access Control | Per-user tool authorization, tenant-scoped RAG, confused deputies |
| A02:2025 | Security Misconfiguration | Open local HTTP MCP servers, unsafe renderers and egress |
| A03:2025 | Software Supply Chain Failures | MCP dependencies, model files, adapters, unpinned artefacts |
| A04:2025 | Cryptographic Failures | Secrets in prompts/logs, token protection |
| A05:2025 | Injection | Shell, SQL, HTML, and LLM output sinks |
| A06:2025 | Insecure Design | Lethal trifecta, excessive agency, missing approval and limits |
| A07:2025 | Authentication Failures | MCP OAuth and token handling |
| A08:2025 | Software or Data Integrity Failures | Model poisoning, MCP rug pulls, unsafe deserialization |
| A09:2025 | Security Logging and Alerting Failures | Tool-call logging and masked outcomes |
| A10:2025 | Mishandling of Exceptional Conditions | Fail-closed authorization and budget checks |

Use the category to communicate the risk; use ASVS for verifiable controls. Do not report
"OWASP-compliant" as a status - the Top 10 is a risk taxonomy, not a certification.
