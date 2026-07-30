# Blockchain Verification Checklist

Run before returning Solidity or web3 integration code. Mark each item pass, fail, or not
applicable. "Not applicable" needs a one-line reason - an unexplained skip is a gap.

Only the sections the change touches need running. A pure view function does not need the
oracle section.

## External Calls and Ordering (SC06, SC08 · A06:2025 · CWE-841, CWE-252)

- [ ] [critical] Every function making an external call writes its state changes before the call
- [ ] [critical] For each guarded function, the state it touches is not readable or writable through an
      unguarded second entry point (cross-function reentrancy)
- [ ] [critical] For each external call, the callee cannot re-enter a *different* contract in the system
      and observe half-updated state (cross-contract reentrancy)
- [ ] [critical] View functions used by other protocols as a price or share source are correct mid-call,
      or documented as not safe to read during a callback (read-only reentrancy)
- [ ] [critical] Low-level `call`, `send`, `staticcall`, and `delegatecall` return values are checked
- [ ] [critical] No `delegatecall` to an address that a caller supplies or that non-admin code can change
- [ ] [recommended] Payouts to arbitrary addresses use pull, not push, or tolerate a reverting recipient
- [ ] [recommended] No unbounded loop over an array that any user can append to
- [ ] [recommended] External calls inside a loop cannot be made to consume the whole gas limit by one entry

## Access Control (SC01 · A01:2025 · CWE-284, CWE-863)

- [ ] [critical] Every state-changing function has an intentional caller restriction, or is intentionally
      public and that is stated
- [ ] [critical] No authorization uses `tx.origin`
- [ ] [critical] `msg.sender` is the right identity for this check even when reached through a proxy,
      a multicall, a hook, or a meta-transaction forwarder
- [ ] [critical] Hook and callback entry points verify the caller is the expected pool, vault, or manager
- [ ] [recommended] Ownership transfer is two-step, or transferring to a wrong address is otherwise
      recoverable
- [ ] [recommended] Privileged roles are separated: configuration, emergency pause, and upgrade are not one
      role
- [ ] [recommended] Privileged addresses are a multisig or governance contract, not a single hot EOA
- [ ] [recommended] Every privilege change and upgrade emits an event

## Initialization and Upgradeability (SC10 · A08:2025 · CWE-284)

- [ ] [critical] Initializer cannot run twice, and cannot be called by an arbitrary address first
- [ ] [critical] Implementation contract behind a proxy disables initializers in its constructor
- [ ] [critical] `upgradeTo` / `_authorizeUpgrade` is restricted to the upgrade role
- [ ] [critical] Storage layout of the new implementation appends only. No reordering, no type changes,
      no removal of an existing variable
- [ ] [recommended] Inherited contracts have a storage gap, or the inheritance order is frozen
- [ ] [recommended] No `constructor` state initialization in a contract used behind a proxy
- [ ] [recommended] `immutable` and `constant` values in an implementation are correct for every proxy that
      points at it
- [ ] [recommended] Upgrade path has a timelock, and the delay is long enough for a user to exit

## Arithmetic (SC07, SC09 · CWE-682)

- [ ] [critical] Compiler is 0.8.x, so arithmetic is checked by default
- [ ] [recommended] Every `unchecked` block has a comment stating why overflow is impossible there
- [ ] [recommended] Multiplication happens before division in every ratio
- [ ] [recommended] Rounding direction is chosen deliberately and favours the protocol on both deposit and
      withdrawal
- [ ] [critical] First-depositor, zero-supply, and zero-amount cases are handled explicitly
- [ ] [critical] No sequence of deposit and withdraw returns more than it put in. Prove this with a test,
      not by reading
- [ ] [recommended] Token decimals are read or configured, not assumed to be 18
- [ ] [recommended] Casts to a narrower type cannot silently truncate. `SafeCast` or an explicit bound check

## Oracles and Pricing (SC03, SC04 · A06:2025 · CWE-682)

- [ ] [critical] No AMM spot price, `getReserves`, or `balanceOf`-derived ratio used as a valuation source
- [ ] [critical] Feed answer is validated: positive where negative is impossible, and the round is
      complete
- [ ] [critical] Feed timestamp is checked against a staleness window sized to the feed's own update
      cadence
- [ ] [recommended] Two independent sources with a deviation bound, or a TWAP over a window long enough that
      moving it costs more than the position is worth
- [ ] [critical] Sensitive operations halt on missing or out-of-band data rather than using a default
- [ ] [recommended] Sequencer or L2 liveness is checked where the chain has one
- [ ] [recommended] Behaviour on a depegged or paused asset is defined

## Ordering and MEV (SC02 · A06:2025)

- [ ] [critical] User-facing swaps and mints take a minimum-output or maximum-input parameter that the
      caller sets, not a contract-computed default
- [ ] [recommended] Deadline parameter present, and not `block.timestamp` supplied by the same transaction
- [ ] [recommended] No mechanism where being first in the block is free money without cost to the attacker
- [ ] [recommended] Auctions, liquidations, and reveals do not depend on a secret that is visible in
      calldata before it is used
- [ ] [critical] No on-chain randomness from `block.timestamp`, `block.prevrandao`, or `blockhash` for
      anything with value attached (CWE-330)

## Signatures (A04:2025 · ASVS V11 · CWE-347)

- [ ] [critical] Signed payload includes a domain separator binding chain id and verifying contract
- [ ] [critical] Signed payload includes a nonce or a hash that is marked used, and it is consumed before
      the effect
- [ ] [recommended] Deadline or expiry in the signed payload
- [ ] [critical] `ecrecover` result compared against zero, or a library used that reverts on failure
- [ ] [critical] Malleable signatures rejected - `s` in the lower half order, `v` in {27, 28}
- [ ] [critical] Signature is not used as a unique identifier. Replay protection is a nonce or hash
      invalidation
- [ ] [optional] Contract signers supported through ERC-1271 where relevant, or explicitly unsupported

## Token Integration (SC06 · A08:2025 · CWE-252)

- [ ] [critical] ERC-20 return value checked, or a safe-transfer wrapper used
- [ ] [recommended] Amount received measured as balance-after minus balance-before where a fee-on-transfer
      or rebasing token is possible
- [ ] [recommended] Internal accounting does not assume `balanceOf(this)` only changes through your own
      functions
- [ ] [recommended] Token allowlist, or the design tolerates an arbitrary token with hooks and reentrancy
- [ ] [recommended] Approval race handled: set to zero first, or use an increase/decrease pattern
- [ ] [recommended] No assumption that `transfer` reverts on failure

## Denial of Service and Exceptional Conditions (A10:2025 · CWE-400, CWE-703)

- [ ] [recommended] No batch operation where one reverting participant blocks everyone else
- [ ] [recommended] No function whose gas cost grows with a value an attacker controls
- [ ] [recommended] Nothing critical depends on a specific gas stipend, `.transfer`, or `.send`
- [ ] [critical] Pausing cannot lock user funds permanently with no withdrawal path
- [ ] [recommended] A failed external call leaves no partially applied state

## Off-Chain Services (A01, A04, A08:2025 · ASVS V2, V11, V14)

- [ ] [critical] Signing keys in a KMS, HSM, or hardware wallet. Not in an env var, a repo, or a
      container image
- [ ] [recommended] Deployer key separate from the operational signer key, and both separate from an admin
      key
- [ ] [recommended] Transaction simulated before submission, and the simulation result is checked
- [ ] [critical] Deposits credited only after a confirmation depth appropriate to the chain
- [ ] [recommended] Reorg handling exists: events are keyed by block hash, and a credit is reversible
- [ ] [recommended] Indexer treats a missing or duplicate event as expected, not impossible
- [ ] [critical] Chain id validated on every signature the backend verifies or produces
- [ ] [recommended] Frontend shows the user what they are signing. No blind `eth_sign` over opaque bytes
- [ ] [recommended] Approval requests are bounded in amount and scoped to a known spender

## Testing and Verification

- [ ] [recommended] Contracts compile with the pinned compiler version, warnings read not skipped
- [ ] [recommended] Property or invariant tests exist for the value-conservation properties, not just unit
      tests of the happy path
- [ ] [recommended] Reentrancy has a test with an actual re-entering mock, not just a guard in place
- [ ] [recommended] Fork test against real state for anything that integrates a live protocol
- [ ] [recommended] Static analyser run, findings triaged with a reason for each dismissal
- [ ] [recommended] Deployment scripts reviewed. The deploy transaction is part of the attack surface
- [ ] [optional] If an audit exists, the commit it covered is stated, and the diff since is reviewed
