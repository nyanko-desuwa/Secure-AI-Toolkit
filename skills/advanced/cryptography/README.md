# Cryptography Skill

Applied cryptography for people building products, not for people designing ciphers.

## Purpose

Most cryptographic failures in real code are not broken maths. They are a fast hash on a password,
a static IV, a key in an environment variable that nobody can rotate, a JWT library asked to pick
its own algorithm, or `verify=False` added during a debugging session and never removed. This skill
gives an assistant the parameters and the patterns for those decisions, each tied to a published
standard so a reviewer can check the work.

The scope is deliberately narrow: choose a primitive, use it the one safe way, and manage the key
through its whole life. Anything that requires designing a new construction is out of scope by
policy, not by omission.

## How It Works

Plain Markdown. Nothing executes, nothing is fetched at runtime. An assistant reads `SKILL.md`,
answers the three threat-model questions, picks a primitive from the table, then pulls the file it
needs.

```text
SKILL.md                            entry point: threat model, primitive table, workflow, severity
README.md                           this file
checklist.md                        pre-return verification
best-practices.md                   patterns with vulnerable/fixed pairs
common-mistakes.md                  what goes wrong and why the fix works
troubleshooting.md                  when the guidance cannot be applied cleanly
prompts.md                          prompts that produce findings
references/
  password-storage.md               Argon2id, scrypt, bcrypt, PBKDF2 parameters
  nist-crypto-standards.md          FIPS 203/204/205, SP 800-38D, SP 800-57, PQC status
  owasp-crypto-mapping.md           category, chapter, and CWE lookup for a finding
examples/
  README.md                         eight vulnerable/fixed pairs across Python, JS, Go, Java
```

## Standards Covered

| Standard | Version | Verified |
|---|---|---|
| OWASP Top 10 | 2025 (A04 primary, A02 and A07 adjacent) | 2026-07-28, `owasp.org/Top10/2025/` |
| OWASP ASVS | 5.0.0 (released 2025-05-30) | 2026-07-28, ASVS project page |
| OWASP Password Storage Cheat Sheet | current | 2026-07-28, `cheatsheetseries.owasp.org` |
| FIPS 203 / 204 / 205 | final, published 2024-08-13 | 2026-07-28, `csrc.nist.gov` |
| NIST SP 800-38D (GCM) | November 2007, revision announced | 2026-07-28, `csrc.nist.gov` |
| NIST SP 800-57 Part 1 | Revision 5, May 2020 | 2026-07-28, `csrc.nist.gov` |
| NIST IR 8547 (PQC transition) | Initial Public Draft, 2024-11-12 | 2026-07-28, `csrc.nist.gov` |

Where a number lives inside a PDF that could not be read from the landing page - GCM invocation
limits, SP 800-57 cryptoperiod tables, the IR 8547 deprecation years - the reference file says so
rather than quoting a plausible figure. Check those in the source before writing them into policy.

## Configuration

None. No build step, no dependency, no environment variable.

To use it in Claude Code, keep this repository in the working directory so
`skills/advanced/cryptography/SKILL.md` is readable, or copy the `cryptography` directory into
`~/.claude/skills/`. The frontmatter `allowed-tools` restricts the skill to read, search, and web
lookup plus `ls`/`cat`; it cannot run arbitrary commands, which means it cannot generate a key, test
a cipher, or verify a certificate for you.

## Example Usage

```text
Review src/billing/tokens.py against OWASP A04:2025. For each finding give the CWE, what an
attacker gets, and the fix. Flag any nonce that is not per-message random.
```

```text
I need to encrypt a customer's bank account number in Postgres. Walk me through the threat model
questions in skills/advanced/cryptography/SKILL.md before proposing an algorithm, and tell me
whether application-layer encryption buys anything over database TDE here.
```

```text
Run skills/advanced/cryptography/checklist.md against this diff. Mark each item pass, fail, or
not applicable with a reason. Do not mark pass on anything you have not read.
```

More in [prompts.md](prompts.md).

## Limitations

- Markdown guidance, not a cryptographic review. It cannot run a test vector, measure timing
  variance, or confirm that a library version does what its documentation says.
- No formal analysis. If your design needs a security proof, this skill's advice to adopt an
  existing protocol is the whole answer it has.
- Parameter numbers age. Argon2id costs and RSA key sizes shift as hardware does; the check dates
  are in the reference files so staleness is visible.
- Some source figures are unverified and marked as such. Notably the GCM per-key invocation limit
  and the SP 800-57 cryptoperiod tables. Do not treat their absence as permission to guess.
- Side-channel coverage is shallow. Constant-time comparison is covered; cache-timing,
  power analysis, and speculative execution attacks are not, and cannot be addressed in application
  code alone.
- Post-quantum guidance is limited to "adopt hybrid key exchange where your stack offers it".
  Migration planning for long-lived signing keys needs the IR 8547 document and a specialist.
- Nothing here covers key ceremony procedure, FIPS 140 validation paperwork, or HSM operational
  runbooks. It says when you need an HSM, not how to run one.

## Security Notes

This skill contains deliberately vulnerable code in `best-practices.md`, `common-mistakes.md`, and
`examples/`. Every such block is labelled `Vulnerable:` and paired with a fix. Do not copy a
labelled-vulnerable block into a project.

All keys, tokens, and hashes in examples are placeholders. There are no real credentials, and no
key material in this skill is safe to use - anything appearing in a public repository is public.

Rotating a key is cheap; discovering you cannot rotate it is not. If a pattern here has no rotation
path, that is a finding about the pattern.

## References

- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>
- OWASP ASVS - <https://owasp.org/www-project-application-security-verification-standard/>
- OWASP Cryptographic Storage Cheat Sheet -
  <https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html>
- OWASP Password Storage Cheat Sheet -
  <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>
- NIST CSRC publications - <https://csrc.nist.gov/publications>
- CWE - <https://cwe.mitre.org/>
