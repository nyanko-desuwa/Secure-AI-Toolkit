# OWASP ASVS 5.0 Reference

Source: <https://owasp.org/www-project-application-security-verification-standard/>
Version: 5.0.0, released 2025-05-30.
Verified: 2026-07-28 (repository brief and project source).

ASVS is the verification standard. It does not have LLM-specific chapters; apply the chapter
that owns the boundary being secured.

| Chapter | Name | Application here |
|---|---|---|
| V1 | Encoding and Sanitization | Model output into HTML and other sinks |
| V2 | Validation and Business Logic | Tool argument validation, loop and budget rules |
| V5 | File Handling | MCP file tools and model-supplied paths |
| V8 | Authorization | Per-user tools, tenant-scoped RAG, confused deputies |
| V10 | OAuth and OIDC | MCP HTTP authorization and scoped credentials |
| V11 | Cryptography | Token and secret protection |
| V13 | Configuration | Egress, CSP, local MCP transport configuration |
| V14 | Data Protection | Prompts, embeddings, conversation logs |
| V15 | Secure Coding and Architecture | Trust boundaries, supply chain, tool design |
| V16 | Security Logging and Error Handling | Tool-call audit records, masking, fail-closed errors |

This skill cites chapter-level mappings, not individual requirement IDs. For formal ASVS
verification, use the official version-pinned requirements spreadsheet or checklist. Do not
invent a requirement number because a chapter mapping feels too broad.
