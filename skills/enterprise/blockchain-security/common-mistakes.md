# Common Mistakes

These are failure patterns seen in generated and hand-written Solidity and web3 code. Each
entry says what goes wrong, why it is exploitable, and the fix.

## A reentrancy guard used as the design

```solidity
// Vulnerable: a guard on withdraw does not protect claim(), which reads the same balance.
function withdraw(uint256 amount) external nonReentrant {
    require(balances[msg.sender] >= amount, "balance");
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok, "send");
    balances[msg.sender] -= amount;
}

function claim() external {
    uint256 amount = balances[msg.sender];
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok, "send");
    balances[msg.sender] = 0;
}
```

A callback can enter through the unguarded function or another contract that shares the state.
The guard is not a substitute for checks-effects-interactions across the whole call graph.

Fix: commit every shared accounting change before any external call, guard all stateful entry
points that need a lock, and test cross-function and cross-contract callbacks. This is
`SC08:2026`, `A06:2025`, `CWE-841`, ASVS V2 and V15.

## `tx.origin` mistaken for the caller

```solidity
// Vulnerable: an intermediary called by the owner passes the check.
require(tx.origin == owner, "owner");
```

`tx.origin` identifies the EOA that started the transaction. An attacker can induce that EOA
to call an intermediary, which then invokes the privileged function. Use `msg.sender` and an
explicit contract-wallet or forwarder policy. This is `SC01:2026`, `A01:2025`, `CWE-284`,
ASVS V8.

## The constructor initialized a proxy

```solidity
// Vulnerable behind a proxy: this writes the implementation's storage, not the proxy's.
constructor(address admin) {
    owner = admin;
}
```

A proxy executes the implementation with `delegatecall`; its constructor ran only when the
implementation was deployed. The proxy's owner remains unset. Use a one-shot initializer,
pass its encoded call during proxy deployment, and lock the implementation with
`_disableInitializers()`. This is `SC10:2026`, `A08:2025`, `CWE-284`, ASVS V8, V13 and V15.

## A one-step ownership transfer

```solidity
// Vulnerable: one typo sends ownership to an address that cannot accept it.
function transferOwnership(address next) external onlyOwner {
    owner = next;
}
```

The new address may be a wrong account or a contract that cannot operate the admin path. Use a
pending owner and require that address to call `acceptOwnership`, or use a reviewed two-step
primitive. This is `SC01:2026`, `A01:2025`, `CWE-863`, ASVS V8.

## Division before multiplication

```solidity
// Vulnerable: values smaller than 10,000 become zero before rate is applied.
uint256 fee = amount / 10000 * rate;
```

Integer division truncates. The lost remainder is not recovered by later multiplication. Use a
full-precision multiplication-then-division library, define who receives rounding, and fuzz
small values and repeated calls. Solidity 0.8 checked arithmetic does not prevent precision
loss. This is `SC07:2026`, `A06:2025`, `CWE-682`, ASVS V2.

## `unchecked` added for gas without a proof

```solidity
// Vulnerable: wraparound can turn a subtraction into a huge balance.
unchecked {
    balances[user] -= amount;
}
```

`unchecked` restores wrapping behavior for arithmetic in its block. It does not merely disable a
warning. Keep the default checked arithmetic unless a local proof and a boundary check make
wraparound impossible. This is `SC09:2026`, `A06:2025`, `CWE-682`, ASVS V15.

## A spot price called an oracle

```solidity
// Vulnerable: a same-transaction trade can move the ratio before it is read.
(uint112 reserve0, uint112 reserve1, ) = pair.getReserves();
uint256 price = uint256(reserve1) * 1e18 / reserve0;
```

A flash loan supplies temporary capital to skew a shallow pool, borrow against the false price,
and repay before the transaction ends. Use a sufficiently long TWAP or independent sources
with a deviation check, freshness checks, and a halt path. This is `SC03:2026` and `SC04:2026`,
`A06:2025`, `CWE-682`, ASVS V2.

## A safe-looking low-level call whose result is ignored

```solidity
// Vulnerable: state claims payment happened even when the call failed.
recipient.call{value: amount}("");
paid[recipient] = true;
```

Low-level calls return a success flag. Ignoring it creates accounting drift, and handing over
control before the state write also opens reentrancy. Check the result, write effects first,
and prefer a pull queue for arbitrary recipients. This is `SC06:2026`, `A10:2025`, `CWE-252`,
ASVS V2 and V16.

## A loop over a user-growable array

```solidity
// Vulnerable: one user can grow recipients until this can never fit in the block gas limit.
address[] public recipients;
function payAll() external {
    for (uint256 i; i < recipients.length; ++i) {
        (bool ok, ) = payable(recipients[i]).call{value: 1 wei}("");
        require(ok, "recipient");
    }
}
```

The array grows without a fixed gas bound. One reverting recipient also blocks all later
payouts. Use indexed, paginated claims and isolate each recipient's withdrawal. This is
`A10:2025`, `CWE-400`, `CWE-703`, ASVS V2 and V16.

## Signature without a domain or nonce

```solidity
// Vulnerable: the signed digest is valid on every chain and can be submitted repeatedly.
bytes32 digest = keccak256(abi.encode(user, amount));
address signer = ecrecover(digest, v, r, s);
```

Bind typed data to the chain and verifying contract, include a nonce and deadline, reject a zero
recovery address and malleable signatures, then consume the nonce before the effect. This is
`A04:2025`, ASVS V11, `CWE-347`.

## ERC-20 assumed to be standard

```solidity
// Vulnerable: credits amount requested, not amount received.
token.transferFrom(msg.sender, address(this), amount);
credit[msg.sender] += amount;
```

Fee-on-transfer tokens make the contract undercollateralized. Tokens can also return `false`,
return no data, rebase, or invoke hooks. Use a safe wrapper, measure balance deltas where the
token policy permits it, and allowlist or isolate tokens. This is `SC06:2026`, `SC08:2026`,
`A06:2025`, `CWE-252`, ASVS V2 and V15.

## The indexer trusted one confirmation

```typescript
// Vulnerable: an event from a block that is later orphaned becomes permanent credit.
provider.on("Deposit", async (user, amount) => {
  await db.credit(user, amount);
});
```

A chain reorganisation can remove that event. Key credits by transaction hash, log index, and
block hash; wait for a policy-appropriate confirmation depth; reconcile removed logs and replay
canonical blocks. This is `A08:2025`, `A10:2025`, ASVS V2, V4, V14 and CWE-703.

## Audit treated as a guarantee

An audit is a point-in-time review of one commit and one stated scope. It does not prove the
next upgrade safe, does not prove deployment matches source, and does not model every economic
attack. Record the commit, exclusions, compiler settings, and changes since the audit. This
is `A06:2025`, ASVS V15.
