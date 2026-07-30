# OWASP AISVS 1.0 Reference

Source: <https://github.com/OWASP/AISVS>
Project page: <https://owasp.org/www-project-artificial-intelligence-security-verification-standard/>
Version: 1.0. No explicit calendar release date is published on the source; do not invent one.
Verified: 2026-07-30, against `github.com/OWASP/AISVS`.

AISVS is the AI Security Verification Standard: a community-driven catalogue of
testable security requirements for AI-enabled systems, modeled on OWASP ASVS.
Version 1.0 spans 191 requirements across 12 chapters. Its philosophy is that
every requirement is verifiable, testable, and implementable across the full
lifecycle - data collection and training through deployment, monitoring, and
retirement.

What it is not: not a governance framework and not a risk-management framework.
It supplies the technical controls that frameworks like NIST AI RMF and
ISO/IEC 42001 point to, and complements the OWASP Top 10 for LLM Applications
and the Agentic Applications Top 10. Licensed CC BY-SA 4.0.

## Verification levels

- **Level 1** - essential baseline controls for all AI systems.
- **Level 2** - standard controls for sensitive data or consequential decisions.
- **Level 3** - advanced controls for high-assurance environments.

Most production systems should target at least Level 2.

## Requirement ID format

`C<chapter>.<section>.<requirement>` (numbers only), for example `C9.4.3`. When
citing across versions the preferred form carries a lowercase version prefix:
`v1.0-C9.4.3`. Quote an ID only when copied verbatim from the source - do not
derive one from a chapter name.

## Chapter mapping

Chapter titles are quoted verbatim; the `&` is cp1252-safe and kept as-is. The
"Application here" column ties each chapter to this skill's boundary and, where
natural, to the LLM Top 10 category it reinforces.

| Chapter | Name | Application here |
|---|---|---|
| C1 | Training Data Integrity & Traceability | Who can write the training or fine-tune set; provenance of corpus - LLM04 Data and Model Poisoning |
| C2 | Input Validation | Untrusted text entering the context window; the prompt-injection surface - LLM01 Prompt Injection |
| C3 | Model Lifecycle Management & Change Control | Change control over the deployed model, adapters, and prompts |
| C4 | Infrastructure, Configuration & Deployment Security | Egress, transport, and deployment config for the model-serving surface |
| C5 | Access Control & Identity for AI Components & Users | Per-user tool authority; the confused-deputy boundary - LLM06 Excessive Agency |
| C6 | Supply Chain Security for Models | Model weights, adapters, and MCP-server provenance - route to `supply-chain-security` |
| C7 | Model Behavior, Output Control & Safety Assurance | Model output as untrusted input to its sink - LLM05 Improper Output Handling |
| C8 | Memory, Embeddings & Vector Database Security | Per-user retrieval authorization; index poisoning and inversion - LLM08 Vector and Embedding Weaknesses |
| C9 | Orchestration & Agentic Security | Tool design, loop bounds, and agent authority - LLM06 Excessive Agency, LLM10 Unbounded Consumption |
| C10 | Model Context Protocol (MCP) Security | MCP server and client hardening - see [mcp-security.md](mcp-security.md) |
| C11 | Adversarial Robustness | Evasion and adversarial input against the model - a model-level concern this skill bounds, not solves |
| C12 | Monitoring, Logging & Anomaly Detection | Tool-call audit records and anomaly signals for agent activity |

AISVS also ships three appendices: a Glossary, an AI Security Controls
Inventory, and AI-Assisted Secure Coding.

## Citing AISVS in a finding

Cite chapter-level mappings (`AISVS C9`, `AISVS C10`) the same way this skill
cites ASVS chapters. Reach for a full requirement ID only when you have read it
off the source and are quoting it verbatim. Do not fabricate a requirement
number because a chapter mapping feels too broad - the numbered requirement may
say something narrower than the chapter title implies.
