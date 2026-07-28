# Prompt Examples

Prompts that produce findings rather than category recitals. Scope the code, name the trust
assumption, and ask for the concrete value or denial-of-service path.

## Review a withdrawal

```text
Read contracts/Vault.sol. For every function that can pay ETH or tokens, identify the state
read, the state write, the external call, and whether a callback can spend the same value twice.
Map each finding to SC08:2026, A06:2025, ASVS chapter, and CWE. Show the vulnerable path and fix.
```

## Review access control

```text
Review every state-changing function in contracts/. List the caller allowed today, the caller
that should be allowed, and the exact check enforcing it. Search for tx.origin, missing
modifiers, unprotected initializers, one-step ownership transfer, and hook functions callable by
any address. Map findings to SC01:2026, A01:2025, ASVS V8, and CWE.
```

## Review an oracle

```text
Trace every price, exchange rate, collateral value, and share price in contracts/. For each
source, say whether it is a same-transaction spot observation, a TWAP, or an independent feed.
Assume flash-loan capital is available. Give the manipulation path, stale-data behavior, and
whether deviation checks halt sensitive actions. Map to SC03:2026 and SC04:2026.
```

## Review upgradeability

```text
Review the proxy and implementation together. Draw the storage layout in declaration order,
locate the initializer and upgrade authorization, and tell me what happens if an attacker calls
initialize or upgradeTo first. Check constructor versus initializer, ERC-1967 slots, storage gaps,
and timelock / exit assumptions. Map to SC10:2026, A08:2025, ASVS V8, V13, V15, and CWE-284.
```

## Review signatures

```text
Read contracts/Permit.sol and the backend verifier. Decode the signed fields. Check domain
separation by chain id and verifying contract, nonce consumption, deadline, zero-address
recovery, lower-half s, v range, and ERC-1271 support. Try replay across two chain IDs and two
contract addresses in a test. Map to A04:2025, ASVS V11, and CWE-347.
```

## Review token integration

```text
Review every IERC20, ERC-777, ERC-721, ERC-1155, and callback interaction. Assume the token can
return false, return no data, charge a fee, rebase, or invoke a hook. Identify where requested
amount differs from received amount and where state is written after the hook. Map to SC06:2026,
SC08:2026, ASVS V2 and V15, and CWE-252 or CWE-841.
```

## Review the indexer

```text
Read services/indexer/. The service currently credits deposits after one confirmation. Design a
reorg-safe state machine with pending and available balances. Include block hash, parent hash,
transaction hash, log index, duplicate handling, removed logs, and an idempotent replay test.
Map to A08:2025 and A10:2025, ASVS V2, V4, V14, and CWE-703.
```

## Verify properties

```text
Write invariant and property-based tests for this vault. Include: total assets cover shares;
no user withdraws more than their shares; a failed recipient cannot block another user; an
external callback cannot increase a balance; and the oracle rejects stale or deviating data.
Use a handler to constrain valid calls, target the handler, and explain what a fork test adds.
```

## Pre-return checklist

```text
Run skills/enterprise/blockchain-security/checklist.md against the diff. Mark every applicable
item pass, fail, or not applicable with a reason. Compile with the pinned compiler and report the
actual command output. Do not mark an audit, a simulator, or a passing unit test as proof that
an economic invariant holds.
```

## Anti-patterns

| Prompt | Problem |
|---|---|
| "Is this contract secure?" | No contract, value path, actor, or standard scope. Produces a recital. |
| "Make this DeFi protocol safe" | Invites an unbounded rewrite and hides the threat model. |
| "Fix reentrancy with a mutex" | A single lock can miss cross-function and cross-contract paths. |
| "Use an oracle" | Does not say freshness, manipulation cost, source independence, or fallback. |
| "Use EIP-712" | Typed data is not nonce consumption or replay protection by itself. |
| "Use SafeERC20" | A wrapper handles return conventions, not fee-on-transfer, rebasing, or hooks. |
| "Wait one confirmation" | Confirmation depth depends on chain finality and the value at stake. |
| "The audit passed" | An audit is one point-in-time review of one commit and scope. |
| "Cite the SWC number" | The SWC Registry is unmaintained; use a current category and describe the mechanism. |
