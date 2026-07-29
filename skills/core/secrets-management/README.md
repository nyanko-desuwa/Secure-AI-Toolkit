# Secrets Management Skill

How credentials are stored, delivered to a running process, rotated, and revoked.

## Purpose

Most secret handling advice stops at "use environment variables". That is one rung on a
seven-rung ladder, and it leaks in four places people do not expect. This skill gives an AI
assistant a defensible position on each rung, the access pattern for the four common secret
managers, and an ordered response for the hour after a credential leaks.

Every control names its OWASP Top 10 2025 category, ASVS 5.0 chapter, and CWE, so a finding
can be defended in review rather than argued about.

## How It Works

Plain Markdown. Nothing executes. An assistant reads `SKILL.md`, follows the six-step
workflow (inventory, place on hierarchy, deliver, design rotation, close leak paths, verify),
and pulls the supporting file it needs at each step.

```text
SKILL.md                            hierarchy, workflow, severity, exposure order
README.md                           this file
checklist.md                        pre-return verification
best-practices.md                   patterns with vulnerable/fixed pairs
common-mistakes.md                  what goes wrong and why the fix works
troubleshooting.md                  when the guidance cannot be applied
prompts.md                          prompts that produce findings
references/
  owasp-top10-2025.md               A02 and A04 as they apply to secrets
  asvs-5.0.md                       V13 and V14 chapter scope
  cwe-secrets.md                    CWE-798, 259, 522, 532, 214, 208
  secret-manager-comparison.md      Vault, AWS, Azure, GCP side by side
  exposure-response.md              revoke, rotate, investigate
examples/
  README.md                         eight vulnerable/fixed pairs
```

## Standards Covered

| Standard | Version | Verified |
|---|---|---|
| OWASP Top 10 | 2025 - A02 Security Misconfiguration, A04 Cryptographic Failures | 2026-07-28, against `owasp.org/Top10/2025/` |
| OWASP ASVS | 5.0.0 (released 2025-05-30) - V13 Configuration, V14 Data Protection | 2026-07-28, against the ASVS project page |
| CWE | CWE-798, CWE-259, CWE-522, CWE-532, CWE-214, CWE-208 | 2026-07-28, against `cwe.mitre.org` |

Version numbers are pinned in `references/` with the date checked. Update the reference file
and this table together.

## Configuration

None. No build step, no dependency, no environment variable.

To use the skill in Claude Code, keep this repository in the working directory so
`skills/core/secrets-management/SKILL.md` is readable, or copy the `secrets-management`
directory into `~/.claude/skills/`. The frontmatter `allowed-tools` restricts it to read,
search, and web lookup plus `ls`/`cat`; it cannot run arbitrary commands, and in particular it
cannot read a real secret store.

## Example Usage

Audit what exists before changing anything:

```text
Inventory every credential in this repo. For each one give the source (hardcoded, .env,
env var, manager), the scope it grants, and whether it can be revoked in one action.
Rank by severity using skills/core/secrets-management/SKILL.md.
```

Review the delivery path, not just the code:

```text
Check the Dockerfile, the CI workflow, and the Kubernetes manifests against
skills/core/secrets-management/checklist.md. I care most about secrets surviving in image
layers and build args.
```

Plan a rotation that is not an outage:

```text
Our webhook signing secret has never been rotated. Design the rotation with a dual-secret
window. Tell me what breaks at each step and how long the overlap should be open.
```

More in [prompts.md](prompts.md).

## Limitations

- Markdown guidance, not a scanner. It has no entropy analysis and no git history walk. Pair
  it with `gitleaks` or `trufflehog`; the skill tells you what to do with a hit, not how to
  find one.
- Cannot confirm runtime state. Reading a manifest cannot tell you whether the IRSA trust
  policy is actually scoped, whether etcd encryption at rest is on, or whether a rotation
  Lambda has ever succeeded. Those need a live check against the platform.
- Cannot verify that a secret was actually revoked. Only the provider's console or API can.
- Code is Python, JavaScript/TypeScript, YAML, HCL, Dockerfile, and shell. The patterns
  generalise; Go, Rust, C#, Java, and Ruby appear only in passing.
- ASVS mapping is at chapter level (V13, V14), not individual requirement IDs. For formal
  ASVS verification, work from the official CSV.
- Provider APIs move. The SDK calls shown were correct against the pinned documentation on
  2026-07-28. Check the current SDK reference before shipping.
- No HSM, KMS envelope encryption, or key ceremony coverage. Key management as a discipline
  belongs to the `cryptography` skill. This skill stops at the credential.
- No mobile or desktop client coverage. A secret shipped to a device the user controls is not
  a secret, and that argument is out of scope here.

## Security Notes

This skill contains deliberately insecure configuration and code in `best-practices.md`,
`common-mistakes.md`, and `examples/`. Every such block is labelled `Vulnerable:` and paired
with a fixed version. Do not copy a labelled-vulnerable block into a project.

Every credential, key, ARN, account ID, project ID, and hostname in this skill is an obvious
placeholder. Nothing here is a live value, and nothing is formatted to look live without
saying so. Account IDs use the AWS documentation range (`111122223333`), and key-shaped
strings carry the word `PLACEHOLDER` or `EXAMPLE`.

If you paste a real secret into a prompt while using this skill, treat it as exposed and run
[references/exposure-response.md](references/exposure-response.md). Model providers log
requests.

## References

- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>
- OWASP ASVS - <https://owasp.org/www-project-application-security-verification-standard/>
- OWASP Secrets Management Cheat Sheet - <https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html>
- CWE-798 Use of Hard-coded Credentials - <https://cwe.mitre.org/data/definitions/798.html>
- CWE-532 Insertion of Sensitive Information into Log File - <https://cwe.mitre.org/data/definitions/532.html>
- NIST SP 800-57 Part 1 Rev. 5, key management - <https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final>
