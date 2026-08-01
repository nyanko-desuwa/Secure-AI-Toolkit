# Security Skill Routing

This repository contains 48 security skills. When writing or reviewing code,
route to the correct skill based on what the code touches.

## Quick routing table

| Code touches | Load skill |
|---|---|
| Database query | `skills/core/database-security/SKILL.md` |
| Auth, login, session, JWT, OAuth | `skills/core/authentication/SKILL.md` |
| API endpoint, BOLA, rate limits | `skills/core/api-security/SKILL.md` |
| Payment gateway, Stripe, card, PCI | `skills/enterprise/payments-security/SKILL.md` |
| Secrets, env vars, credentials | `skills/core/secrets-management/SKILL.md` |
| Log lines with user data | `skills/core/logging-audit/SKILL.md` |
| File uploads | `skills/core/file-upload-security/SKILL.md` |
| Frontend, CSP, XSS, CSRF | `skills/core/frontend-security/SKILL.md` |
| Docker / containers | `skills/core/docker-security/SKILL.md` |
| Kubernetes manifests | `skills/enterprise/kubernetes-security/SKILL.md` |
| LLM, AI agent, MCP, RAG | `skills/core/ai-security/SKILL.md` |
| GDPR, PII, data retention | `skills/enterprise/compliance/SKILL.md` |
| Webhook, guessable secret, OTP | `skills/core/brute-force-defense/SKILL.md` |
| Windows, AD, LDAP | `skills/enterprise/windows-security/SKILL.md` |
| Blockchain, smart contract | `skills/enterprise/blockchain-security/SKILL.md` |
| Mobile, iOS, Android | `skills/enterprise/mobile-security/SKILL.md` |
| SSH, TLS, certificates | `skills/core/ssh-server/SKILL.md` |
| Cryptography, key management | `skills/advanced/cryptography/SKILL.md` |
| Cloud provider APIs | `skills/core/cloud-security/SKILL.md` |
| HTTP headers, CDN, edge | `skills/core/http-edge-security/SKILL.md` |

## Load order

1. Read `AI_INSTRUCTIONS.md` for the full registry and routing table.
2. Open the matched `SKILL.md` and follow its workflow.
3. Pull `checklist.md` before returning code.
4. Open `references/` only when you need a category ID or version number.
5. Open `examples/` only when you need the shape of a fix.

Never load more than five core skills, two advanced, and one enterprise skill
for a single task. Reading eleven files when the task needs two wastes context.
