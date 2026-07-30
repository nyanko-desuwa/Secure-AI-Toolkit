# AI Security Skill

Security for applications that use LLMs: agents, tool calling, MCP servers and clients, and
retrieval pipelines.

## Purpose

This skill matters more than most in this repository, because its reader is an AI assistant
building AI systems. The failure mode it exists to prevent is an assistant that generates an
agent with a shell tool, a broad service credential, and a fetch tool, and then adds
"ignore malicious instructions" to the system prompt and calls it secured.

The position it takes: prompt injection is not solved and cannot be solved with prompting.
Every control here is architectural - at the tool, at the sink, at the credential, at the
retrieval query. Prompt-level measures are documented as rate reducers and labelled as such.

## How It Works

Plain Markdown. Nothing executes. An assistant reads `SKILL.md`, maps the agent against the
lethal trifecta, works the six-step workflow, and pulls in the supporting file for each step.

```text
SKILL.md                        entry point: trifecta, workflow, severity
README.md                       this file
checklist.md                    pre-return verification, grouped
best-practices.md               patterns with vulnerable/fixed pairs
common-mistakes.md              what goes wrong and why the fix works
troubleshooting.md              when the guidance cannot be applied
prompts.md                      prompts that produce findings
references/
  README.md                    standards index
  llm-top10.md                  OWASP LLM Top 10 2025, verified against the source
  injection-taxonomy.md         direct vs indirect, channels, exfil paths, controls
  owasp-top10-2025.md           general OWASP category map
  asvs-5.0.md                   ASVS 5.0 chapter map
  mcp-security.md               MCP 2025-11-25 security requirements
examples/
  README.md                     eight vulnerable/fixed pairs with category + CWE
```

## Standards Covered

| Standard | Version | Verified |
|---|---|---|
| OWASP Top 10 for LLM Applications | 2025 | 2026-07-28, against `genai.owasp.org/llm-top-10/` |
| OWASP Top 10 | 2025 (A01, A05, A06 mainly) | 2026-07-28, pinned by this repository |
| OWASP ASVS | 5.0.0 (released 2025-05-30) | 2026-07-28, pinned by this repository |
| CWE | CWE-1427, CWE-1426, CWE-441 and others | 2026-07-28, against `cwe.mitre.org` |
| MCP specification | 2025-11-25 revision | 2026-07-28, against `modelcontextprotocol.io` |

The LLM Top 10 changed between the 2023-24 and 2025 editions - categories were added,
renamed, and renumbered. Quote IDs from `references/llm-top10.md` or re-fetch; do not quote
them from memory.

## Configuration

None. No build step, no dependency, no environment variable.

To use it in Claude Code, keep this repository in the working directory so
`skills/core/ai-security/SKILL.md` is readable, or copy the `ai-security` directory into
`~/.claude/skills/`. The frontmatter `allowed-tools` restricts it to read, search, and web
lookup plus `ls`/`cat`.

## Example Usage

Map an agent's attack surface before reviewing code:

```text
Read the tool definitions in src/agent/tools.py. For each tool, tell me whether it gives
access to private data, exposure to untrusted content, or an outbound channel. Then tell me
whether all three are present in one context.
```

Review a tool-calling loop:

```text
Review src/agent/loop.py against OWASP LLM Top 10 2025. Assume prompt injection succeeds -
an attacker is writing the model's output. For each finding give the category, the location,
what the attacker reaches, and the fix.
```

Check a third-party MCP server before installing:

```text
Read the tool definitions this MCP server exposes. Flag any description containing
instructions to the model, any tool that runs shell commands, and any tool that fetches a
model-supplied URL. Tell me what this server can reach if it is malicious.
```

More in [prompts.md](prompts.md).

## Limitations

- Markdown guidance, not a scanner. No dataflow analysis, so an untrusted-content path that
  crosses several files will be missed. Pair with a review of the actual data flow.
- The core problem is open. Nothing here closes prompt injection. The controls limit what
  a compromised model reaches. Any claim that a system is "protected against prompt
  injection" is wrong, including one derived from this skill.
- Egress guidance does not close the DNS channel from application code. That needs network
  controls this skill cannot verify.
- Guardrails and injection classifiers reduce attack rate. They are not in the checklist as a
  control that satisfies a requirement, because they do not.
- MCP guidance tracks the 2025-11-25 specification revision. MCP is moving fast; re-read the
  security-best-practices page before relying on a specific requirement.
- Examples are Python and TypeScript with the Anthropic SDK shape. The patterns generalise
  across providers; the exact field names (`input_schema`, `tool_use`, `tool_result`,
  `stop_reason`) do not.
- Says nothing about model alignment, red-teaming methodology, or evaluating a model's own
  refusal behaviour. Those are model-level concerns; this skill is about the application.
- No compliance mapping. The EU AI Act, ISO 42001, and NIST AI RMF are not covered.

## Security Notes

This skill contains deliberately vulnerable code in `best-practices.md`,
`common-mistakes.md`, and `examples/`. Every such block is labelled `Vulnerable:` and paired
with a fixed version. Do not copy a labelled-vulnerable block into a project.

Injection payloads appear as illustrations - in tool descriptions, document bodies, and issue
text. They are deliberately mild and exist so a reader recognises the shape. They are not a
payload library.

All values are placeholders. There are no real credentials, hostnames, or personal data.
`attacker.example` and `example.com` are reserved documentation domains.

## References

- OWASP Top 10 for LLM Applications 2025 - <https://genai.owasp.org/llm-top-10/>
- OWASP GenAI Security Project - <https://genai.owasp.org/>
- OWASP Agentic Security Initiative - <https://genai.owasp.org/initiatives/agentic-security-initiative/>
- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>
- OWASP ASVS - <https://owasp.org/www-project-application-security-verification-standard/>
- MCP security best practices - <https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices>
- MCP authorization - <https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization>
- CWE-1427, Improper Neutralization of Input Used for LLM Prompting - <https://cwe.mitre.org/data/definitions/1427.html>
- CWE-1426, Improper Validation of Generative AI Output - <https://cwe.mitre.org/data/definitions/1426.html>
