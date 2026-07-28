# Blockchain Best Practices

Each pattern names the on-chain and cross-reporting standards. Vulnerable blocks are
intentionally unsafe. They are paired with fixes and an explanation of why the fix closes the
path.

## Reentrancy

`SC08:2026` · `A06:2025` · ASVS V2, V15 · `CWE-841`

The classic bug reads a balance, calls out, then writes the balance. The callback reads the
same old balance again. A lock is useful, but it is not the structural fix: cross-function and
cross-contract paths can share state that a naive per-function lock does not cover.

```solidity
// Vulnerable: state is committed after control leaves the contract.
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "balance");
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok, "send");
    balances[msg.sender] -= amount;
}
```

A malicious recipient can call `withdraw` again before the first call subtracts its balance.

```solidity
// Fixed: checks, effects, interactions. The guard is a belt, not the ordering fix.
uint256 private constant NOT_ENTERED = 1;
uint256 private constant ENTERED = 2;
uint256 private status = NOT_ENTERED;

modifier nonReentrant() {
    require(status == NOT_ENTERED, "reentrant");
    status = ENTERED;
    _;
    status = NOT_ENTERED;
}

function withdraw(uint256 amount) external nonReentrant {
    uint256 available = balances[msg.sender];
    require(available >= amount, "balance");
    balances[msg.sender] = available - amount;
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok, "send");
}
```

The balance is no longer spendable during the callback. The guard blocks the same entry point,
but the effects-before-interaction order also makes the state correct when another function or
another contract observes it. A guard does not automatically cover every contract in a call
graph; audit shared state and read-only views too.

The tempting wrong fix is `.transfer`: relying on a small gas stipend is brittle as gas costs
and recipient behavior change. Use a checked low-level call with correct ordering, or a pull
queue where the recipient chooses when to withdraw.

## Access control and `tx.origin`

`SC01:2026` · `A01:2025` · ASVS V8 · `CWE-284`, `CWE-863`

```solidity
// Vulnerable: an intermediary contract can make tx.origin look like the owner.
address public owner;

function sweep(address payable recipient) external {
    require(tx.origin == owner, "owner");
    recipient.transfer(address(this).balance);
}
```

If the owner is induced to call an intermediary, the intermediary can call `sweep` and pass the
check. `tx.origin` is the transaction's original EOA, not the immediate caller. Authorize the
immediate caller with `msg.sender`; for a multisig or contract wallet, authorize that contract
explicitly or use the project's account-abstraction validation.

```solidity
// Fixed: the authority is the immediate caller and ownership transfer is two-step.
address public owner;
address public pendingOwner;

modifier onlyOwner() {
    require(msg.sender == owner, "owner");
    _;
}

function transferOwnership(address next) external onlyOwner {
    require(next != address(0), "zero");
    pendingOwner = next;
}

function acceptOwnership() external {
    require(msg.sender == pendingOwner, "pending owner");
    owner = pendingOwner;
    pendingOwner = address(0);
}

function sweep(address payable recipient) external onlyOwner {
    (bool ok, ) = recipient.call{value: address(this).balance}("");
    require(ok, "send");
}
```

The check cannot be satisfied by a caller merely acting on the owner's transaction, and a
mistyped new owner cannot silently take ownership. The wrong fix is a client-side role check or
an obscure address: the contract must enforce the rule on every state-changing path.

## Arithmetic, precision, and rounding

`SC07:2026`, `SC09:2026` · `A06:2025` · ASVS V2, V15 · `CWE-682`

Solidity 0.8.0 and later revert on arithmetic overflow and underflow by default. `unchecked`
restores wrapping only inside its lexical block. Division truncates, so operation order and
rounding direction are part of the value model.

```solidity
// Vulnerable: division first loses precision; unchecked hides an overflow assumption.
function fee(uint256 amount, uint256 rate) external pure returns (uint256) {
    unchecked {
        return (amount / 10000) * rate;
    }
}
```

```solidity
// Fixed: multiply before division, checked by default, and make the direction explicit.
function fee(uint256 amount, uint256 rate) external pure returns (uint256) {
    require(rate <= 10000, "rate");
    return (amount * rate + 9999) / 10000; // round up: protocol never under-collects
}
```

The fixed form preserves sub-unit fees and uses checked multiplication. The bound is not a
proof for every possible amount; if `amount * rate` can exceed the type, use a full-precision
math library or prove a tighter bound. Do not add `unchecked` just to save gas. It trades a
revert for silent wraparound.

For shares, round deposits down and withdrawals up against the user where the protocol's
invariant requires it; write the policy down and fuzz repeated small operations. A rounding
choice that looks harmless once can mint value after thousands of calls.

## External calls, return values, and pull payments

`SC06:2026` · `A10:2025` · ASVS V2, V15, V16 · `CWE-252`, `CWE-400`

```solidity
// Vulnerable: failure is ignored, and a caller controls the code executed.
function pay(address token, address payable recipient, uint256 amount) external {
    token.call(abi.encodeWithSignature("transfer(address,uint256)", recipient, amount));
    recipient.call{value: amount}("");
}
```

A token can return `false` without reverting. A low-level call can also fail while execution
continues. `delegatecall` is worse when its target is attacker-influenced: the callee runs with
this contract's storage and balance.

```solidity
// Fixed: validate the target, check the result, and make recipients pull.
mapping(address => uint256) public owed;

function queue(address payable recipient, uint256 amount) external {
    owed[recipient] += amount;
}

function withdrawPayment() external {
    uint256 amount = owed[msg.sender];
    require(amount != 0, "nothing");
    owed[msg.sender] = 0;
    (bool ok, ) = payable(msg.sender).call{value: amount}("");
    require(ok, "send");
}
```

The queue avoids one reverting recipient blocking a batch and sets the owed amount to zero
before handing over control. In a real token integration, use a maintained safe-transfer
wrapper and measure balance deltas for fee-on-transfer tokens. No generic wrapper can make a
rebasing token behave like a fixed-balance token; state the token assumptions.

## Oracle and price manipulation

`SC03:2026`, `SC04:2026` · `A06:2025` · ASVS V2 · `CWE-682`

```solidity
// Vulnerable: reserves are attacker-controlled within the transaction.
interface IPair {
    function getReserves() external view returns (uint112, uint112, uint32);
}

function collateralValue(address pair, uint256 amount) external view returns (uint256) {
    (uint112 cash, uint112 asset, ) = IPair(pair).getReserves();
    return amount * uint256(cash) / uint256(asset);
}
```

A large trade, often funded by a flash loan, changes the reserve ratio before this function
reads it. A TWAP over a meaningful window raises the manipulation cost. Two independent feeds
with a deviation bound and a stale-data circuit breaker are stronger than one source.

The wrong fix is a longer spot-price variable or a one-block delay. A delay does not make a
manipulable observation independent. Use a cumulative-price TWAP, an independent feed, or halt
when sources disagree. Validate positive answers, complete rounds, and `updatedAt` freshness.

## MEV and ordering

`SC02:2026` · `A06:2025` · ASVS V2 · `CWE-841`

```solidity
// Vulnerable: the contract computes an output after the transaction is visible.
function swap(uint256 input) external {
    uint256 output = quote(input);
    tokenOut.transfer(msg.sender, output);
}
```

A searcher can buy before the transaction and sell after it, or sandwich it so the user receives
less. The mempool is public and ordering is a design constraint.

```solidity
// Fixed: the user commits to a bound and expiry.
function swap(uint256 input, uint256 minOutput, uint256 deadline) external {
    require(block.timestamp <= deadline, "expired");
    uint256 output = quote(input);
    require(output >= minOutput, "slippage");
    require(tokenOut.transfer(msg.sender, output), "transfer");
}
```

Slippage and deadlines limit the user's loss; they do not eliminate MEV. For hidden bids or
reveals, commit-reveal binds a later action to a prior commitment without exposing the value
before the reveal. Do not use block timestamp or block hash as randomness for value-bearing
choices.

## Upgradeability and initialization

`SC10:2026` · `A08:2025` · ASVS V8, V13, V15 · `CWE-284`

```solidity
// Vulnerable: anyone can rewrite the implementation.
address public implementation;

function upgradeTo(address next) external {
    implementation = next;
}
```

An unprotected upgrade is an admin bypass. A proxy also skips the implementation constructor;
an initializer left open can be called by the first stranger. Storage variables must not be
reordered or repurposed across implementations. A storage gap reserves room for inherited state.

```solidity
// Fixed: authorization is explicit, and initialization is one-shot.
address public implementation;
address public owner;
bool private initialized;

modifier onlyOwner() {
    require(msg.sender == owner, "owner");
    _;
}

function initialize(address firstOwner, address firstImplementation) external {
    require(!initialized, "initialized");
    require(firstOwner != address(0) && firstImplementation.code.length != 0, "bad init");
    initialized = true;
    owner = firstOwner;
    implementation = firstImplementation;
}

function upgradeTo(address next) external onlyOwner {
    require(next.code.length != 0, "not contract");
    implementation = next;
}
```

This closes the open initializer and upgrade paths, but it is not a production proxy by itself.
Use a reviewed proxy implementation, fixed storage slots such as ERC-1967, an upgrade
 timelock, and a governance-controlled authorization hook. The code is intentionally small to
show the failure, not to replace a proxy library.

## Signature domain and replay protection

`A04:2025` · ASVS V11 · `CWE-347`

```solidity
// Vulnerable: the same signature works on every chain and every contract, forever.
function claim(bytes32 digest, uint8 v, bytes32 r, bytes32 s) external {
    address signer = ecrecover(digest, v, r, s);
    require(signer == owner, "signer");
    claimed[msg.sender] = true;
}
```

There is no domain separator, nonce, expiry, or zero-address failure check. A signature can be
replayed on another deployment or chain, and a failed `ecrecover` returns the zero address.
Use EIP-712 typed data with a domain that binds name, version, chain id, and verifying contract;
track a nonce per signer; reject malleable signatures; and use a checked recovery library.

```solidity
// Fixed: the digest is domain-bound and consumed once.
bytes32 private constant TYPE_HASH = keccak256("Claim(address account,uint256 nonce,uint256 deadline)");
mapping(address => uint256) public nonces;

function claim(address account, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
    require(block.timestamp <= deadline, "expired");
    uint256 nonce = nonces[account]++;
    bytes32 domain = keccak256(abi.encode(
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
        keccak256(bytes("Example")), keccak256(bytes("1")), block.chainid, address(this)
    ));
    bytes32 structHash = keccak256(abi.encode(TYPE_HASH, account, nonce, deadline));
    bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domain, structHash));
    address signer = ecrecover(digest, v, r, s);
    require(signer != address(0) && signer == owner, "signer");
    claimed[account] = true;
}
```

The nonce is incremented before the effect, and the digest cannot cross the chain or contract
domain. A production implementation must also enforce the lower-half `s` range and `v` range,
or use a library that does. EIP-712 does not itself solve replay; the nonce does.

## Token hooks and non-standard ERC-20s

`SC06:2026`, `SC08:2026` · `A06:2025` · ASVS V2, V15 · `CWE-252`, `CWE-841`

A token may charge a fee, rebase balances, return `false` rather than revert, return no value,
or invoke recipient hooks. ERC-777 hooks can reintroduce reentrancy through an apparently simple
transfer. A fixed-value internal accounting model that assumes vanilla ERC-20 behavior will
become insolvent or re-entered.

```solidity
// Vulnerable: credits the requested amount, not the amount actually received.
function deposit(address token, uint256 amount) external {
    require(IERC20(token).transferFrom(msg.sender, address(this), amount), "transfer");
    credit[msg.sender] += amount;
}
```

```solidity
// Fixed: measure the delta and use a safe wrapper in production.
function deposit(address token, uint256 amount) external {
    uint256 beforeBalance = IERC20(token).balanceOf(address(this));
    require(IERC20(token).transferFrom(msg.sender, address(this), amount), "transfer");
    uint256 received = IERC20(token).balanceOf(address(this)) - beforeBalance;
    credit[msg.sender] += received;
}
```

The delta prevents a fee-on-transfer token from creating unbacked credit. It does not solve
rebases between the two reads, malicious tokens that lie about `balanceOf`, or ERC-777 hooks.
Allowlist tokens or isolate their accounting and test with adversarial mocks. A safe wrapper
handles return conventions; it cannot remove arbitrary token code execution.
