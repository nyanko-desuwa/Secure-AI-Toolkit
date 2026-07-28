---
name: blockchain-security
description: 'Apply smart contract and web3 integration security when writing, reviewing, or deploying Solidity and the off-chain services around it. Maps findings to OWASP Smart Contract Top 10 2026, OWASP Top 10 2025, and ASVS 5.0. Triggers: "smart contract", "Solidity", "reentrancy", "web3", "DeFi", "oracle", "proxy upgrade", "hợp đồng thông minh", "bảo mật blockchain".'
allowed-tools: Read, Glob, Grep, WebSearch, WebFetch
---

# Blockchain Security

Deployed contract code is public, immutable by default, and holds value directly. A bug is
not a ticket, it is a withdrawal. There is no hotfix window and no rollback.

Start from the assumption that every actor is untrusted: the caller, the calling contract,
the block producer who chooses transaction order, and any contract you call out to. That
last one matters most, because an external call hands the CPU to code the attacker wrote.

## When to Use

- Writing or reviewing Solidity, especially anything that moves value or changes permissions
- Designing a protocol: collateral, pricing, fees, governance, upgrade paths
- Integrating a third-party token, oracle, AMM, or bridge
- Building the off-chain side: a signing service, an indexer, a relayer, a wallet connection
- Preparing for or reading an audit

## The Standards, and What Each Is For

| Standard | Use it for | Version here |
|---|---|---|
| OWASP Smart Contract Top 10 | On-chain risk categories, incident-informed | 2026 (project v2.0.0) |
| OWASP Top 10 | Cross-reporting to a general security audience | 2025 |
| OWASP ASVS | Verifying the off-chain services | 5.0.0 |
| CWE | Root-cause naming in a finding | current |

The Smart Contract Top 10 names the on-chain failure. The general Top 10 and ASVS cover the
backend, the key handling, and the API in front of it — the parts an on-chain-only review
misses. See [references/](references/).

On SWC: the SWC Registry is no longer actively maintained and stopped taking new entries in
2020. Do not cite SWC IDs as current classification. Describe the weakness and cite the
Smart Contract Top 10 category instead. Details in
[references/swc-and-successors.md](references/swc-and-successors.md).

## Workflow

### 1. Map the value and the trust boundaries

Three questions, in this order:

- Where does value enter and leave? Every one of those paths is a target.
- Which addresses hold privilege, and who controls those keys today?
- Which external contracts does this call, and what happens if one of them is hostile?

If a contract calls an address supplied by a caller, or read from mutable storage, you have
already found the most important thing in the file. Read that path first.

### 2. Order the state machine

Most on-chain exploits are ordering bugs, not cryptography bugs. For every function that
makes an external call, confirm the sequence is checks, then effects, then interactions.
State updated after the call is state an attacker can observe twice.

Then widen the question: if this function is re-entered, which *other* function becomes
wrong? A per-function guard does nothing about a shared balance read by a second entry
point. See [best-practices.md](best-practices.md#reentrancy).

### 3. Price nothing from a single manipulable source

Any value read from a pool inside one transaction can be moved inside that same transaction,
with borrowed capital that never leaves the block. Treat spot price as attacker input.

### 4. Assume the mempool is public

A pending transaction is a proposal that anyone can read and react to before it lands.
Slippage limits, deadlines, and commit-reveal are design requirements, not polish.

### 5. Treat upgradeability as a permission, not a feature

An upgradeable contract is a contract that someone can rewrite. Ask who, on what timelock,
and what the users' exit is if they disagree.

### 6. Verify

Run [checklist.md](checklist.md). Then compile, run the property tests, and run a static
analyser. Manual reading finds intent bugs; a fuzzer finds the arithmetic ones.

### 7. Report

Per finding: category, contract and function, the concrete profit path, and the fix. A
finding with no profit path and no denial-of-service path is a code smell — label it as one.

## Severity

Rank by what an attacker walks away with, and what precondition they need.

- **Critical** — direct theft or permanent freeze of user funds, or seizure of admin rights,
  reachable by anyone
- **High** — theft or freeze that needs capital (a flash loan counts as available capital),
  a specific market state, or one privileged key
- **Medium** — value leakage bounded by fees or rounding, griefing that costs the attacker
  more than the victim, or a bug behind a trusted multisig
- **Low** — defence in depth missing, gas waste, no value path

Say "a flash loan is available capital" out loud when it applies. Reviews that rate an
oracle bug medium because "you'd need $50M" are wrong; the attacker borrows it and repays it
in the same transaction.

## Related Skills

- `core/owasp` — the general Top 10 and ASVS baseline this builds on
- `core/api-security` — the API in front of a signing or indexing service
- `core/secrets-management` — deployer keys, signer keys, and HSM boundaries

## Supporting Files

- [README.md](README.md) — purpose, layout, standards table, limitations
- [checklist.md](checklist.md) — pre-return verification, grouped
- [best-practices.md](best-practices.md) — patterns with vulnerable/fixed pairs
- [common-mistakes.md](common-mistakes.md) — what goes wrong and why the fix works
- [troubleshooting.md](troubleshooting.md) — when the guidance cannot be applied
- [prompts.md](prompts.md) — prompts that produce findings
- [references/](references/) — standards, version-pinned with check dates
- [examples/](examples/) — eight vulnerable/fixed contract pairs plus one backend example
