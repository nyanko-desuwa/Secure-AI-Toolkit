# Troubleshooting

What to do when smart contract security guidance does not resolve cleanly.

## Checks-effects-interactions is impossible in this flow

Split the flow. Record an intention or debt first, let the external interaction happen, then
finalize in a separate call. If atomicity is required, use an explicit state-machine phase and
make every public function reject intermediate states it cannot safely observe.

Do not quietly move the state update after the call. That recreates the vulnerability. State the
migration and compatibility cost before changing the interface. `SC08:2026`, `A06:2025`,
`CWE-841`, ASVS V2 and V15.

## A reentrancy guard breaks composability

First find whether the composability is intentional or accidental. A callback that must re-enter
one function does not justify exposing all functions during half-written state.

Options, in preference order:

1. Make state correct before the callback.
2. Separate callback-safe and callback-unsafe state.
3. Use a scoped state-machine phase instead of one global lock.
4. Document the exact allowed callback and write a property test for it.

A narrower guard with stale state is not a fix. `SC08:2026`, `CWE-841`.

## The token has fee-on-transfer or rebasing behavior

Do not patch the arithmetic until the token policy is explicit:

- Unsupported: reject the token with an allowlist.
- Fee-on-transfer: credit the measured balance delta, not the requested amount.
- Rebasing: use shares rather than fixed nominal balances, or isolate the token in an adapter.
- Hook-capable: assume transfer can re-enter and update state first.

Measuring a balance delta still trusts the token to report `balanceOf` honestly and can be wrong
under an asynchronous rebase. State that limitation. `SC06:2026`, `SC08:2026`, `A06:2025`,
`CWE-252`, ASVS V2 and V15.

## No second independent oracle exists

Do not silently downgrade to spot price. Bound the damage:

1. Use the deepest available TWAP over a window justified by manipulation cost.
2. Add stale-data and maximum-change circuit breakers.
3. Cap position size so maximum extractable value remains below manipulation cost.
4. Halt new borrowing or minting when the source is unhealthy; allow safe repayments and exits.
5. Report the single-source trust assumption as a design limitation.

A one-block delay is not independence. `SC03:2026`, `SC04:2026`, `A06:2025`, `CWE-682`,
ASVS V2.

## Users require unlimited slippage

That is equivalent to authorizing any execution price. Do not set `minOutput = 0` on their behalf.
Offer a clear user-selected tolerance, show the expected and worst-case output, and require a
short deadline. If a liquidation or arbitrage flow must accept any price, cap the economic loss
in the protocol and explain why searchers cannot externalize it to users. `SC02:2026`,
`A06:2025`, ASVS V2.

## Upgrade storage layout is already incompatible

Do not deploy the upgrade. Reordering or changing a variable type corrupts live state. Options:

- Create a new implementation that restores the old layout and appends new fields.
- Deploy a new proxy and migrate through an audited, bounded path.
- Use a one-time migration function with an explicit version and invariant checks.

Back up storage values and test the exact migration against a fork of deployed state. A storage
snapshot generated from source is not enough if deployed bytecode differs. `SC10:2026`,
`A08:2025`, `CWE-284`, ASVS V13 and V15.

## The proxy is already deployed uninitialized

Treat it as an active takeover window. Do not announce the address publicly and wait for a normal
change process. If you control deployment ordering, initialize in the proxy constructor's data so
creation and initialization are one transaction. If already public, determine on-chain whether
anyone initialized it; if not, initialize through the authorized deployment process immediately.
If taken, do not interact or deposit value. `SC01:2026`, `SC10:2026`, `A01:2025`, `CWE-284`,
ASVS V8.

## The backend saw a reorganisation after crediting a user

Mark credits provisional until confirmation depth is reached. Store block number, block hash,
transaction hash, and log index. On parent-hash mismatch, find the common ancestor, reverse every
derived credit from orphaned blocks, then replay canonical blocks idempotently.

If the user can withdraw provisional credit, a database rollback is too late. Separate pending
and available balance. `A08:2025`, `A10:2025`, `CWE-703`, ASVS V2, V4 and V14.

## Simulation succeeds but the transaction reverts on-chain

Simulation is an observation at one state and ordering. Between simulation and inclusion, prices,
nonces, balances, allowances, and access state can change. Include slippage and deadlines,
resimulate at the latest block before submission, and handle a revert as normal rather than
retrying with wider limits automatically. Private order flow reduces visibility; it does not make
state static. `A06:2025`, `A10:2025`, ASVS V2 and V16, `CWE-703`.

## Static analysis and manual review disagree

Trace the concrete path. A tool warning without a reachable attacker-controlled path may be a
false positive; a manual assertion that "the framework handles it" is not evidence.

For each disagreement, record:

1. The entry point and attacker-controlled values.
2. The state read and written.
3. Every external call and callback.
4. The invariant that would fail.
5. A test that proves or refutes the path.

Suppress only with that reason attached. `A06:2025`, ASVS V15.

## A required property is hard to fuzz

Use a handler that constrains the fuzzer to valid actions and tracks ghost state. Target the
handler, not the protocol directly. Keep `fail_on_revert` false only when reverts are expected and
the invariant still gets meaningful sequences; otherwise a campaign can spend its time bouncing
off preconditions.

Fork tests prove compatibility with one real state snapshot, not every future state. Keep unit,
fuzz, invariant, fork, and static analysis as separate layers. `A06:2025`, ASVS V2 and V15.

## The standard has moved on

This skill pins OWASP Smart Contract Top 10 2026, OWASP Top 10 2025, ASVS 5.0.0, and Solidity
0.8.36, verified 2026-07-28. Re-fetch before quoting an identifier or compiler behavior in a
formal report. The SWC Registry is unmaintained; do not add an SWC ID from memory.
