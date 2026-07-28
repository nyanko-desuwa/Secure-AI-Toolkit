# OWASP Top 10 for LLM Applications 2025

Source: <https://genai.owasp.org/llm-top-10/>
Verified: 2026-07-28, fetched from the OWASP GenAI Security Project site.

This list is maintained by the OWASP GenAI Security Project (formerly the OWASP Top 10 for
LLM Applications project). The IDs changed between the 2023–24 edition and 2025 — do not
carry an ID over from an older document without re-checking it.

## Categories

| ID | Name | The question it forces |
|---|---|---|
| `LLM01:2025` | Prompt Injection | Where does untrusted text enter the context, and what can the model do once it controls the output? |
| `LLM02:2025` | Sensitive Information Disclosure | What is in the context, the system prompt, the logs, and the retrieval index that this caller should not see? |
| `LLM03:2025` | Supply Chain | Where did the model weights, adapters, prompts, plugins, and MCP servers come from, and who can change them? |
| `LLM04:2025` | Data and Model Poisoning | Who can write to the training set, the fine-tune data, the retrieval corpus, or the agent's persistent memory? |
| `LLM05:2025` | Improper Output Handling | Which sink consumes model output — shell, SQL, `eval`, HTML, a file path, a URL — and is it encoded for that sink? |
| `LLM06:2025` | Excessive Agency | What can the agent's tools do, with whose permissions, and which actions are irreversible? |
| `LLM07:2025` | System Prompt Leakage | Does anything in the system prompt need to stay secret? (If yes, that is the bug.) |
| `LLM08:2025` | Vector and Embedding Weaknesses | Is retrieval authorized per user, and can embeddings be inverted or the index poisoned? |
| `LLM09:2025` | Misinformation | What does the application do when the model is confidently wrong, and is that output load-bearing? |
| `LLM10:2025` | Unbounded Consumption | What caps iteration, tokens, and per-user cost? |

## Mapping to the general standards

The LLM list does not replace the general Top 10 — most LLM findings have a matching
classic category, and reporting both is what makes a finding actionable for a reviewer who
does not work on AI.

| LLM category | General mapping |
|---|---|
| LLM01 Prompt Injection | OWASP Top 10 2025 A05 (Injection) · ASVS V2 · CWE-1427 |
| LLM02 Sensitive Information Disclosure | A01 · ASVS V8, V14 |
| LLM03 Supply Chain | A03 (Software Supply Chain Failures) · ASVS V15 |
| LLM04 Data and Model Poisoning | A08 (Software or Data Integrity Failures) |
| LLM05 Improper Output Handling | A05 · ASVS V1 · CWE-1426, plus the sink's own CWE (CWE-78, CWE-89, CWE-79, CWE-94) |
| LLM06 Excessive Agency | A01, A06 (Insecure Design) · ASVS V8 |
| LLM07 System Prompt Leakage | A06 · report without a CWE unless a specific verified weakness applies |
| LLM08 Vector and Embedding Weaknesses | A01 · ASVS V8 |
| LLM09 Misinformation | A06 |
| LLM10 Unbounded Consumption | A06 · OWASP API Security Top 10 2023 API4 (Unrestricted Resource Consumption) |

## Related CWEs

Verified individually against <https://cwe.mitre.org/> on 2026-07-28.

| CWE | Name | Notes |
|---|---|---|
| CWE-1427 | Improper Neutralization of Input Used for LLM Prompting | Base weakness. Alternate term: "prompt injection". ChildOf CWE-77 under Research Concepts. Allowed for real-world vulnerability mapping. |
| CWE-1426 | Improper Validation of Generative AI Output | Base weakness. Use for model output reaching a sink unvalidated. |
| CWE-441 | Unintended Proxy or Intermediary ('Confused Deputy') | Use for an agent or MCP proxy acting with its own authority on a caller's behalf. |
| CWE-918 | Server-Side Request Forgery | Use for a fetch tool the model can point anywhere. |
| CWE-502 | Deserialization of Untrusted Data | Use for pickle-based model files. |

## OWASP Agentic Security Initiative

The same project runs an Agentic Security Initiative
(<https://genai.owasp.org/initiatives/agentic-security-initiative/>) which has published,
as of 2026-07-28:

- *OWASP Top 10 for Agentic Applications for 2026* (posted 2025-12-09)
- *Agentic AI – Threats and Mitigations* (threat taxonomy, with sample implementations in the project's GitHub repo)
- *A Practical Guide for Secure MCP Server Development* (2026-02)
- *CheatSheet – A Practical Guide for Securely Using Third-Party MCP Servers 1.0* (2025-11)
- *State of Agentic AI Security and Governance 2.01* (2026-06)

Honest limitation: the category IDs and names inside the Agentic Top 10, and the
`T`-numbered IDs in the Threats and Mitigations taxonomy, are published only inside the
downloadable PDFs. They are not on any HTML page that could be verified on 2026-07-28.
This skill therefore describes agentic risks — memory poisoning, tool misuse, cascading
failure, identity spoofing — by name and mechanism, with no ID attached. If you need to
cite an Agentic Top 10 ID, download the PDF and read the ID off it. Do not infer one from
the risk name, and do not let an assistant generate one.

## Also cited by this skill

- OWASP Top 10 2025 — <https://owasp.org/Top10/2025/> (A01 Broken Access Control, A05 Injection, A06 Insecure Design; 2025 is not a renumbering of 2021)
- OWASP ASVS 5.0.0, released 2025-05-30 — <https://owasp.org/www-project-application-security-verification-standard/> (V2 Validation and Business Logic, V8 Authorization, V15 Secure Coding and Architecture)
- Model Context Protocol specification, revision `2025-11-25` — <https://modelcontextprotocol.io/specification/2025-11-25/> and its Security Best Practices page
