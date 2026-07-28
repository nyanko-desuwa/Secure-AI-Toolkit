# Blockchain Verification Checklist

Run before returning Solidity or web3 integration code. Mark each item pass, fail, or not
applicable. "Not applicable" needs a one-line reason — an unexplained skip is a gap.

Only the sections the change touches need running. A pure view function does not need the
oracle section.

## External Calls and Ordering (SC06, SC08 · A06:2025 · CWE-841, CWE-252)

- [ ] Every function making an external call writes its state changes before the call
- [ ] For each guarded function, the state it touches is not readable or writable through an
      unguarded second entry point (cross-function reentrancy)
- [ ] For each external call, the callee cannot re-enter a *different* contract in the system
      and observe half-updated state (cross-contract reentrancy)
- [ ] View functions used by other protocols as a price or share source are correct mid-call,
      or documented as not safe to read during a callback (read-only reentrancy)
- [ ] Low-level `call`, `send`, `staticcall`, and `delegatecall` return values are checked
- [ ] No `delegatecall` to an address that a caller supplies or that non-admin code can change
- [ ] Payouts to arbitrary addresses use pull, not push, or tolerate a reverting recipient
- [ ] No unbounded loop over an array that any user can append to
- [ ] External calls inside a loop cannot be made to consume the whole gas limit by one entry

## Access Control (SC01 · A01:2025 · CWE-284, CWE-863)

- [ ] Every state-changing function has an intentional caller restriction, or is intentionally
      public and that is stated
- [ ] No authorization uses `tx.origin`
- [ ] `msg.sender` is the right identity for this check even when reached through a proxy,
      a multicall, a hook, or a meta-transaction forwarder
- [ ] Hook and callback entry points verify the caller is the expected pool, vault, or manager
- [ ] Ownership transfer is two-step, or transferring to a wrong address is otherwise
      recoverable
- [ ] Privileged roles are separated: configuration, emergency pause, and upgrade are not one
      role
- [ ] Privileged addresses are a multisig or governance contract, not a single hot EOA
- [ ] Every privilege change and upgrade emits an event

## Initialization and Upgradeability (SC10 · A08:2025 · CWE-284)

- [ ] Initializer cannot run twice, and cannot be called by an arbitrary address first
- [ ] Implementation contract behind a proxy disables initializers in its constructor
- [ ] `upgradeTo` / `_authorizeUpgrade` is restricted to the upgrade role
- [ ] Storage layout of the new implementation appends only. No reordering, no type changes,
      no removal of an existing variable
- [ ] Inherited contracts have a storage gap, or the inheritance order is frozen
- [ ] No `constructor` state initialization in a contract used behind a proxy
- [ ] `immutable` and `constant` values in an implementation are correct for every proxy that
      points at it
- [ ] Upgrade path has a timelock, and the delay is long enough for a user to exit

## Arithmetic (SC07, SC09 · CWE-682)

- [ ] Compiler is 0.8.x, so arithmetic is checked by default
- [ ] Every `unchecked` block has a comment stating why overflow is impossible there
- [ ] Multiplication happens before division in every ratio
- [ ] Rounding direction is chosen deliberately and favours the protocol on both deposit and
      withdrawal
- [ ] First-depositor, zero-supply, and zero-amount cases are handled explicitly
- [ ] No sequence of deposit and withdraw returns more than it put in. Prove this with a test,
      not by reading
- [ ] Token decimals are read or configured, not assumed to be 18
- [ ] Casts to a narrower type cannot silently truncate. `SafeCast` or an explicit bound check

## Oracles and Pricing (SC03, SC04 · A06:2025 · CWE-682)

- [ ] No AMM spot price, `getReserves`, or `balanceOf`-derived ratio used as a valuation source
- [ ] Feed answer is validated: positive where negative is impossible, and the round is
      complete
- [ ] Feed timestamp is checked against a staleness window sized to the feed's own update
      cadence
- [ ] Two independent sources with a deviation bound, or a TWAP over a window long enough that
      moving it costs more than the position is worth
- [ ] Sensitive operations halt on missing or out-of-band data rather than using a default
- [ ] Sequencer or L2 liveness is checked where the chain has one
- [ ] Behaviour on a depegged or paused asset is defined

## Ordering and MEV (SC02 · A06:2025)

- [ ] User-facing swaps and mints take a minimum-output or maximum-input parameter that the
      caller sets, not a contract-computed default
- [ ] Deadline parameter present, and not `block.timestamp` supplied by the same transaction
- [ ] No mechanism where being first in the block is free money without cost to the attacker
- [ ] Auctions, liquidations, and reveals do not depend on a secret that is visible in
      calldata before it is used
- [ ] No on-chain randomness from `block.timestamp`, `block.prevrandao`, or `blockhash` for
      anything with value attached (CWE-330)

## Signatures (A04:2025 · ASVS V11 · CWE-347)

- [ ] Signed payload includes a domain separator binding chain id and verifying contract
- [ ] Signed payload includes a nonce or a hash that is marked used, and it is consumed before
      the effect
- [ ] Deadline or expiry in the signed payload
- [ ] `ecrecover` result compared against zero, or a library used that reverts on failure
- [ ] Malleable signatures rejected — `s` in the lower half order, `v` in {27, 28}
- [ ] Signature is not used as a unique identifier. Replay protection is a nonce or hash
      invalidation
- [ ] Contract signers supported through ERC-1271 where relevant, or explicitly unsupported

## Token Integration (SC06 · A08:2025 · CWE-252)

- [ ] ERC-20 return value checked, or a safe-transfer wrapper used
- [ ] Amount received measured as balance-after minus balance-before where a fee-on-transfer
      or rebasing token is possible
- [ ] Internal accounting does not assume `balanceOf(this)` only changes through your own
      functions
- [ ] Token allowlist, or the design tolerates an arbitrary token with hooks and reentrancy
- [ ] Approval race handled: set to zero first, or use an increase/decrease pattern
- [ ] No assumption that `transfer` reverts on failure

## Denial of Service and Exceptional Conditions (A10:2025 · CWE-400, CWE-703)

- [ ] No batch operation where one reverting participant blocks everyone else
- [ ] No function whose gas cost grows with a value an attacker controls
- [ ] Nothing critical depends on a specific gas stipend, `.transfer`, or `.send`
- [ ] Pausing cannot lock user funds permanently with no withdrawal path
- [ ] A failed external call leaves no partially applied state

## Off-Chain Services (A01, A04, A08:2025 · ASVS V2, V11, V14)

- [ ] Signing keys in a KMS, HSM, or hardware wallet. Not in an env var, a repo, or a
      container image
- [ ] Deployer key separate from the operational signer key, and both separate from an admin
      key
- [ ] Transaction simulated before submission, and the simulation result is checked
- [ ] Deposits credited only after a confirmation depth appropriate to the chain
- [ ] Reorg handling exists: events are keyed by block hash, and a credit is reversible
- [ ] Indexer treats a missing or duplicate event as expected, not impossible
- [ ] Chain id validated on every signature the backend verifies or produces
- [ ] Frontend shows the user what they are signing. No blind `eth_sign` over opaque bytes
- [ ] Approval requests are bounded in amount and scoped to a known spender

## Testing and Verification

- [ ] Contracts compile with the pinned compiler version, warnings read not skipped
- [ ] Property or invariant tests exist for the value-conservation properties, not just unit
      tests of the happy path
- [ ] Reentrancy has a test with an actual re-entering mock, not just a guard in place
- [ ] Fork test against real state for anything that integrates a live protocol
- [ ] Static analyser run, findings triaged with a reason for each dismissal
- [ ] Deployment scripts reviewed. The deploy transaction is part of the attack surface
- [ ] If an audit exists, the commit it covered is stated, and the diff since is reviewed
