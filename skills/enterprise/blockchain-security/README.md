# Blockchain Security Skill

Smart contract and web3 integration security, mapped to published standards.

## Purpose

Give an AI assistant a way to reason about on-chain code the way an auditor does: value
flows first, trust boundaries second, cryptography last. Every control names the OWASP Smart
Contract Top 10 2026 category, the general OWASP Top 10 2025 category for cross-reporting,
the ASVS chapter where the off-chain side is involved, and a CWE.

The scope deliberately spans both sides of the boundary. A protocol with flawless Solidity
and a deployer private key in a CI environment variable is not secure, and neither is one
whose indexer credits a deposit on a single confirmation.

## How It Works

Plain Markdown. Nothing executes. An assistant reads `SKILL.md`, follows the seven-step
workflow, and pulls the supporting file it needs at each step.

```text
SKILL.md                          workflow, severity, entry point
README.md                         this file
checklist.md                      pre-return verification, grouped
best-practices.md                 patterns with vulnerable/fixed pairs
common-mistakes.md                what goes wrong and why the fix works
troubleshooting.md                when the guidance cannot be applied
prompts.md                        prompts that produce findings
references/
  owasp-smart-contract-top10-2026.md   SC01-SC10 with the question each implies
  owasp-top10-2025-mapping.md          on-chain finding to general category
  asvs-5.0-offchain.md                 chapters that apply to the backend
  swc-and-successors.md                why SWC IDs are not cited here
  eips-and-solidity.md                 EIP numbers and Solidity behaviour, verified
  cwe-mapping.md                       CWE IDs with abstraction level
examples/
  README.md                       8 Solidity pairs + 1 TypeScript backend example
```

## Standards Covered

| Standard | Version | Verified |
|---|---|---|
| OWASP Smart Contract Top 10 | 2026 (project version 2.0.0) | 2026-07-28, against `scs.owasp.org` |
| OWASP Top 10 | 2025 | 2026-07-28, against `owasp.org/Top10/2025/` |
| OWASP ASVS | 5.0.0 (released 2025-05-30) | 2026-07-28, against the ASVS project page |
| Solidity | 0.8.36, released 2026-07-09 | 2026-07-28, against the release changelog |
| CWE | current entries, abstraction levels noted | 2026-07-28, against `cwe.mitre.org` |
| SWC Registry | unmaintained since 2020, not cited | 2026-07-28, against `swcregistry.io` |

Every reference file carries its source URL and the date checked. EIP numbers and Solidity
version behaviour in this skill were fetched, not recalled — see
[references/eips-and-solidity.md](references/eips-and-solidity.md) for the list and the
sources.

## Configuration

None. No build step, no dependency, no environment variable.

To use it in Claude Code, keep this repository in the working directory so
`skills/enterprise/blockchain-security/SKILL.md` is readable, or copy the
`blockchain-security` directory into `~/.claude/skills/`. The `allowed-tools` frontmatter
restricts it to read, search, and web lookup plus `ls`/`cat`.

The Solidity examples pin `pragma solidity 0.8.36;`. They compile with solc 0.8.36. If your
project is on an older 0.8.x, the examples still hold — nothing in them depends on a feature
newer than 0.8.0 checked arithmetic — but change the pragma to match your toolchain rather
than floating it with `^`.

## Example Usage

Review one contract against the on-chain standard:

```text
Read contracts/Vault.sol and review it against the OWASP Smart Contract Top 10 2026.
For each finding give the SC category, the function, the concrete profit path, and the fix.
Skip anything with no profit path and no denial-of-service path.
```

Check the ordering property specifically:

```text
For every external call in contracts/, tell me whether state is written before or after the
call, and which other function reads that same state. I am looking for cross-function
reentrancy, not just single-function.
```

Review the backend, not the contract:

```text
Our indexer credits a user balance from a Transfer event at 1 confirmation. Review
services/indexer/ against ASVS 5.0 V2 and the reorg handling guidance in this skill.
```

More in [prompts.md](prompts.md).

## Limitations

Name these when using the skill. Silence about a gap reads as a guarantee.

- Markdown guidance, not an analyser. No symbolic execution, no dataflow, no path
  exploration. It will miss bugs that need cross-contract taint tracking. Pair it with
  Slither or a similar static analyser and with a fuzzer.
- Solidity and TypeScript only. Nothing here is Vyper, Rust (Solana, ink!, CosmWasm), Move,
  or Cairo specific. The trust-boundary reasoning transfers; the syntax and the concurrency
  model do not. Solana's account model in particular changes what "reentrancy" means.
- Economic security is out of scope. Whether your liquidation incentive is large enough,
  whether your collateral factor survives a 40% gap down, whether your governance token
  distribution permits a cheap takeover — those need modelling, not a code review.
- No gas optimisation advice. Where a security control costs gas, this skill takes the
  control. If your bottleneck is gas, that is a different conversation and the tradeoff
  should be explicit.
- ASVS mapping is at chapter level (V1 to V17), not requirement IDs. The 5.0 numbering is
  new enough that recalled IDs are unreliable. For formal verification, work from the
  official repository.
- Bridge and cross-chain messaging security is named but not covered in depth. Validator set
  assumptions, message replay across chains, and finality differences deserve their own
  treatment.
- Does not evaluate deployment state. Reading source cannot tell you whether the deployed
  bytecode matches, who holds the admin key right now, or whether the timelock is armed.
  Verify those on-chain.
- An audit is a point-in-time review of one commit. It is not a certificate, it does not
  cover the commit after it, and it does not cover the parts the auditors were told were out
  of scope. Say which commit was audited and what changed since.

## Security Notes

This skill contains deliberately vulnerable Solidity in `best-practices.md`,
`common-mistakes.md`, and `examples/`. Every such block is labelled `Vulnerable:` and paired
with a fixed version. Do not deploy a labelled-vulnerable block.

Two attacker-side snippets appear in `examples/README.md`. Each is the minimal illustration
of why the vulnerable pattern fails, immediately followed by the fix. They are not tuned for
any live protocol and target only the local vulnerable contract in the same example. Do not
point them at a contract you do not own.

All addresses are placeholders. There are no real keys, mnemonics, RPC URLs, contract
addresses, or personal data anywhere in this skill.

## References

- OWASP Smart Contract Top 10 2026 — <https://scs.owasp.org/sctop10/>
- OWASP Smart Contract Security project — <https://scs.owasp.org/>
- OWASP Top 10 2025 — <https://owasp.org/Top10/2025/>
- OWASP ASVS — <https://owasp.org/www-project-application-security-verification-standard/>
- Solidity documentation — <https://docs.soliditylang.org/>
- EIPs — <https://eips.ethereum.org/>
- OpenZeppelin Contracts — <https://docs.openzeppelin.com/contracts/5.x/>
- SWC Registry (unmaintained) — <https://swcregistry.io/>
- CWE — <https://cwe.mitre.org/>
