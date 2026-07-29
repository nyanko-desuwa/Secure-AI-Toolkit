# Blockchain Security Examples

Eight vulnerable/fixed pairs. Every Solidity block pins `pragma solidity 0.8.36;` and is a
complete compilation unit. Vulnerable blocks are intentionally unsafe. Do not deploy them.

## Contents

1. [Withdrawal reentrancy](#1-withdrawal-reentrancy) - SC08, CWE-841
2. [`tx.origin` authorization](#2-txorigin-authorization) - SC01, CWE-284
3. [AMM spot price oracle](#3-amm-spot-price-oracle) - SC03/SC04, CWE-682
4. [Unprotected initializer and upgrade](#4-unprotected-initializer-and-upgrade) - SC01/SC10, CWE-284
5. [Signature replay and malleability](#5-signature-replay-and-malleability) - A04, CWE-347
6. [Unbounded batch payout](#6-unbounded-batch-payout) - A10, CWE-400/CWE-703
7. [Non-standard token integration](#7-non-standard-token-integration) - SC06/SC08, CWE-252
8. [MEV without slippage or deadline](#8-mev-without-slippage-or-deadline) - SC02, CWE-841
9. [Reorg-safe TypeScript indexer](#9-reorg-safe-typescript-indexer) - A08/A10, CWE-703

---

## 1. Withdrawal reentrancy

`SC08:2026` · `A06:2025` · ASVS V2, V15 · `CWE-841`

Vulnerable: the balance is reduced after the recipient receives control.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

contract VulnerableVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "balance");
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "send");
        balances[msg.sender] -= amount;
    }
}
```

A recipient contract can call `withdraw` from its receive callback while the old balance remains.

Fixed: effects precede interaction, and the guard covers the stateful withdrawal entry point.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

contract FixedVault {
    mapping(address => uint256) public balances;
    uint256 private locked = 1;

    modifier nonReentrant() {
        require(locked == 1, "reentrant");
        locked = 2;
        _;
        locked = 1;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external nonReentrant {
        uint256 available = balances[msg.sender];
        require(available >= amount, "balance");
        balances[msg.sender] = available - amount;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "send");
    }
}
```

Why this works: the callback observes the reduced balance. The lock is defence in depth; correct
ordering is what keeps cross-function observers from seeing spendable stale state.

---

## 2. `tx.origin` authorization

`SC01:2026` · `A01:2025` · ASVS V8 · `CWE-284`, `CWE-863`

Vulnerable: an intermediary invoked by the owner inherits the owner's `tx.origin`.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

contract VulnerableOriginWallet {
    address public immutable owner;

    constructor(address initialOwner) payable {
        require(initialOwner != address(0), "zero");
        owner = initialOwner;
    }

    function sweep(address payable recipient) external {
        require(tx.origin == owner, "owner");
        (bool ok, ) = recipient.call{value: address(this).balance}("");
        require(ok, "send");
    }
}
```

A contract can persuade the owner to call it and then invoke `sweep` during that transaction.

Fixed: authorize the immediate caller and require the next owner to accept.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

contract FixedOwnerWallet {
    address public owner;
    address public pendingOwner;

    constructor(address initialOwner) payable {
        require(initialOwner != address(0), "zero");
        owner = initialOwner;
    }

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
}
```

Why this works: an intermediary is not the authorized immediate caller, and a mistyped owner
cannot finalize the handoff.

---

## 3. AMM spot price oracle

`SC03:2026`, `SC04:2026` · `A06:2025` · ASVS V2 · `CWE-682`

Vulnerable: the reserve ratio can be moved and consumed inside the same transaction.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

interface IVulnerablePair {
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 timestamp);
}

contract VulnerableSpotOracle {
    IVulnerablePair public immutable pair;

    constructor(address pairAddress) {
        require(pairAddress.code.length != 0, "pair");
        pair = IVulnerablePair(pairAddress);
    }

    function quote(uint256 token0Amount) external view returns (uint256) {
        (uint112 reserve0, uint112 reserve1, ) = pair.getReserves();
        require(reserve0 != 0, "empty");
        return token0Amount * uint256(reserve1) / uint256(reserve0);
    }
}
```

A flash-loan-funded swap can skew the reserves, use the inflated quote, then reverse the swap.

Fixed: consume a time-weighted source and an independent source, reject stale or deviating data.
The source contracts are injected so this unit is compilable and testable with mocks.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

interface ITwapSource {
    function consult(uint256 token0Amount) external view returns (uint256 quote, uint256 updatedAt);
}

interface IIndependentSource {
    function latest() external view returns (uint256 price, uint256 updatedAt);
}

contract FixedDualOracle {
    ITwapSource public immutable twap;
    IIndependentSource public immutable independent;
    uint256 public immutable maxAge;
    uint256 public immutable maxDeviationBps;

    constructor(address twapAddress, address independentAddress, uint256 age, uint256 deviationBps) {
        require(twapAddress.code.length != 0 && independentAddress.code.length != 0, "source");
        require(age != 0 && deviationBps <= 10_000, "config");
        twap = ITwapSource(twapAddress);
        independent = IIndependentSource(independentAddress);
        maxAge = age;
        maxDeviationBps = deviationBps;
    }

    function quote(uint256 token0Amount) external view returns (uint256) {
        (uint256 twapQuote, uint256 twapAt) = twap.consult(token0Amount);
        (uint256 unitPrice, uint256 independentAt) = independent.latest();
        require(twapQuote != 0 && unitPrice != 0, "bad price");
        require(block.timestamp - twapAt <= maxAge, "stale twap");
        require(block.timestamp - independentAt <= maxAge, "stale independent");

        uint256 referenceQuote = token0Amount * unitPrice / 1e18;
        require(referenceQuote != 0, "small quote");
        uint256 difference = twapQuote > referenceQuote
            ? twapQuote - referenceQuote
            : referenceQuote - twapQuote;
        require(difference * 10_000 / referenceQuote <= maxDeviationBps, "deviation");
        return twapQuote;
    }
}
```

Why this works: a one-transaction reserve move cannot rewrite an already accumulated meaningful
TWAP, and manipulating one source does not pass the independent deviation check. The remaining
assumption is that the sources are genuinely independent and the TWAP window is long enough.

---

## 4. Unprotected initializer and upgrade

`SC01:2026`, `SC10:2026` · `A01:2025`, `A08:2025` · ASVS V8, V13, V15 · `CWE-284`

Vulnerable: the first caller becomes owner, and anyone can replace the implementation.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

contract VulnerableUpgradeableLogic {
    address public owner;
    address public implementation;

    function initialize(address firstOwner) external {
        owner = firstOwner;
    }

    function upgradeTo(address next) external {
        implementation = next;
    }
}
```

A stranger can initialize an uninitialized proxy or call `upgradeTo` with hostile code.

Fixed: initialize once, authorize upgrades, validate code, and expose changes through events.
This demonstrates the authorization state; use a reviewed proxy library for production slots and
delegation.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

contract FixedUpgradeableLogic {
    address public owner;
    address public implementation;
    bool private initialized;
    uint256[47] private storageGap;

    event Initialized(address indexed owner);
    event Upgraded(address indexed implementation);

    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }

    function initialize(address firstOwner, address firstImplementation) external {
        require(!initialized, "initialized");
        require(firstOwner != address(0), "owner");
        require(firstImplementation.code.length != 0, "implementation");
        initialized = true;
        owner = firstOwner;
        implementation = firstImplementation;
        emit Initialized(firstOwner);
    }

    function upgradeTo(address next) external onlyOwner {
        require(next.code.length != 0, "implementation");
        implementation = next;
        emit Upgraded(next);
    }
}
```

Why this works: initialization is one-shot and upgrades require the recorded authority. A real
proxy must also initialize atomically at deployment, lock the implementation, preserve storage
layout, and put upgrades behind governance and a timelock.

---

## 5. Signature replay and malleability

`A04:2025` · ASVS V11 · `CWE-347`

Vulnerable: raw data has no chain, contract, nonce, or deadline, and failed recovery is not
rejected explicitly.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

contract VulnerableClaimSigner {
    address public immutable signer;
    mapping(address => uint256) public credits;

    constructor(address authorizedSigner) {
        signer = authorizedSigner;
    }

    function claim(address account, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encode(account, amount));
        require(ecrecover(digest, v, r, s) == signer, "signature");
        credits[account] += amount;
    }
}
```

The signature can be submitted repeatedly and replayed against another deployment or chain.

Fixed: EIP-712 typed data binds chain and contract; a nonce and deadline bound each authorization;
recovery rejects zero and malleable signatures.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

contract FixedClaimSigner {
    bytes32 private constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 private constant CLAIM_TYPEHASH = keccak256(
        "Claim(address account,uint256 amount,uint256 nonce,uint256 deadline)"
    );
    uint256 private constant SECP256K1_HALF_ORDER =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    address public immutable signer;
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public credits;

    constructor(address authorizedSigner) {
        require(authorizedSigner != address(0), "signer");
        signer = authorizedSigner;
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(
            DOMAIN_TYPEHASH,
            keccak256(bytes("FixedClaimSigner")),
            keccak256(bytes("1")),
            block.chainid,
            address(this)
        ));
    }

    function claim(
        address account,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(block.timestamp <= deadline, "expired");
        require(v == 27 || v == 28, "v");
        require(uint256(s) <= SECP256K1_HALF_ORDER, "s");
        uint256 nonce = nonces[account]++;
        bytes32 structHash = keccak256(abi.encode(
            CLAIM_TYPEHASH, account, amount, nonce, deadline
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0) && recovered == signer, "signature");
        credits[account] += amount;
    }
}
```

Why this works: a digest is valid only for this chain and contract, once, before its deadline.
Incrementing the nonce before the effect makes a callback unable to reuse it. A production system
should use a reviewed recovery library and support contract signers where required.

---

## 6. Unbounded batch payout

`A10:2025` · ASVS V2, V16 · `CWE-400`, `CWE-703`

Vulnerable: users grow the array, and one reverting recipient blocks every later payout.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

contract VulnerableBatchPayout {
    address payable[] public recipients;

    function register() external {
        recipients.push(payable(msg.sender));
    }

    function payAll() external payable {
        require(msg.value == recipients.length, "one wei each");
        for (uint256 i = 0; i < recipients.length; ++i) {
            (bool ok, ) = recipients[i].call{value: 1 wei}("");
            require(ok, "recipient failed");
        }
    }
}
```

Eventually the loop cannot fit in the block gas limit. A recipient that reverts freezes the batch
sooner.

Fixed: credit bounded entries and let each recipient pull independently.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

contract FixedPullPayout {
    mapping(address => uint256) public claimable;
    uint256 private locked = 1;

    modifier nonReentrant() {
        require(locked == 1, "reentrant");
        locked = 2;
        _;
        locked = 1;
    }

    function credit(address recipient) external payable {
        require(recipient != address(0) && msg.value != 0, "credit");
        claimable[recipient] += msg.value;
    }

    function withdraw() external nonReentrant {
        uint256 amount = claimable[msg.sender];
        require(amount != 0, "nothing");
        claimable[msg.sender] = 0;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "send");
    }
}
```

Why this works: no payout operation grows with attacker-controlled global state, and a recipient's
failure affects only that recipient.

---

## 7. Non-standard token integration

`SC06:2026`, `SC08:2026` · `A06:2025` · ASVS V2, V15 · `CWE-252`, `CWE-841`

Vulnerable: the requested amount is credited even if the token charges a fee, returns false, or
invokes a hook before state is settled.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

interface IVulnerableToken {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract VulnerableTokenVault {
    mapping(address => uint256) public credit;

    function deposit(address token, uint256 amount) external {
        IVulnerableToken(token).transferFrom(msg.sender, address(this), amount);
        credit[msg.sender] += amount;
    }
}
```

Fixed: allowlist the token, use a low-level safe-return adapter, measure the received balance
delta, and guard hook-capable transfers.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

interface IFixedToken {
    function balanceOf(address account) external view returns (uint256);
}

contract FixedTokenVault {
    address public immutable owner;
    mapping(address => bool) public supported;
    mapping(address => mapping(address => uint256)) public credit;
    uint256 private locked = 1;

    constructor(address initialOwner) {
        require(initialOwner != address(0), "owner");
        owner = initialOwner;
    }

    modifier nonReentrant() {
        require(locked == 1, "reentrant");
        locked = 2;
        _;
        locked = 1;
    }

    function setSupported(address token, bool value) external {
        require(msg.sender == owner, "owner");
        require(token.code.length != 0, "token");
        supported[token] = value;
    }

    function deposit(address token, uint256 amount) external nonReentrant {
        require(supported[token] && amount != 0, "deposit");
        uint256 beforeBalance = IFixedToken(token).balanceOf(address(this));
        (bool ok, bytes memory result) = token.call(
            abi.encodeWithSignature("transferFrom(address,address,uint256)", msg.sender, address(this), amount)
        );
        require(ok && (result.length == 0 || abi.decode(result, (bool))), "transfer");
        uint256 received = IFixedToken(token).balanceOf(address(this)) - beforeBalance;
        require(received != 0, "received");
        credit[token][msg.sender] += received;
    }
}
```

Why this works: false and low-level failure are rejected, fee-on-transfer credit is backed by the
measured delta, and a hook cannot re-enter the deposit. Rebasing and dishonest tokens remain a
policy question; use an adapter or reject them.

---

## 8. MEV without slippage or deadline

`SC02:2026` · `A06:2025` · ASVS V2 · `CWE-841`

Vulnerable: the user accepts whatever output exists when a block producer finally orders the
transaction.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

contract VulnerableConstantProductSwap {
    uint256 public reserveIn = 1_000_000 ether;
    uint256 public reserveOut = 1_000_000 ether;

    function swap(uint256 amountIn) external returns (uint256 amountOut) {
        require(amountIn != 0, "input");
        amountOut = reserveOut - (reserveIn * reserveOut) / (reserveIn + amountIn);
        reserveIn += amountIn;
        reserveOut -= amountOut;
    }
}
```

A searcher can trade before the user to worsen the price and reverse the trade after. There is no
bound on the user's loss and no expiry.

Fixed: the caller sets the minimum acceptable output and a deadline.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

contract FixedConstantProductSwap {
    uint256 public reserveIn = 1_000_000 ether;
    uint256 public reserveOut = 1_000_000 ether;

    function swap(
        uint256 amountIn,
        uint256 minimumOut,
        uint256 deadline
    ) external returns (uint256 amountOut) {
        require(block.timestamp <= deadline, "expired");
        require(amountIn != 0 && minimumOut != 0, "bounds");
        amountOut = reserveOut - (reserveIn * reserveOut) / (reserveIn + amountIn);
        require(amountOut >= minimumOut, "slippage");
        reserveIn += amountIn;
        reserveOut -= amountOut;
    }
}
```

Why this works: ordering can still change the execution price, but not past the loss the user
approved, and a stale transaction cannot execute indefinitely. Commit-reveal is appropriate when
the value itself must remain hidden until a later phase.

---

## 9. Reorg-safe TypeScript indexer

`A08:2025`, `A10:2025` · ASVS V2, V4, V14, V16 · `CWE-703`

Vulnerable: one observed event becomes irreversible credit.

```typescript
import { WebSocketProvider, Log } from "ethers";

type DepositDatabase = {
  creditFromLog(transactionHash: string, logIndex: number): Promise<void>;
};

declare const database: DepositDatabase;
const provider = new WebSocketProvider(process.env.RPC_URL ?? "http://127.0.0.1:8545");

provider.on({ address: "0x0000000000000000000000000000000000000001" }, async (log: Log) => {
  await database.creditFromLog(log.transactionHash, log.index);
});
```

A reorganisation can orphan the block while the database credit remains.

Fixed: process finalized-enough canonical blocks, retain block hashes, make event application
idempotent, and roll orphaned blocks back before replay. This complete module assumes the injected
store implements the transactional methods in the interface.

```typescript
import { JsonRpcProvider, Log } from "ethers";

type StoredBlock = { number: number; hash: string; parentHash: string };

type CreditStore = {
  lastCanonicalBlock(): Promise<StoredBlock | null>;
  blockAt(number: number): Promise<StoredBlock | null>;
  begin(): Promise<void>;
  commit(): Promise<void>;
  rollback(): Promise<void>;
  saveBlock(block: StoredBlock): Promise<void>;
  removeBlockAndReverseCredits(number: number): Promise<void>;
  applyDepositOnce(key: string, log: Log): Promise<void>;
};

export class ReorgSafeDepositIndexer {
  constructor(
    private readonly provider: JsonRpcProvider,
    private readonly store: CreditStore,
    private readonly depositContract: string,
    private readonly confirmations: number,
  ) {
    if (confirmations < 2) throw new Error("confirmation policy is too shallow");
  }

  async sync(): Promise<void> {
    const head = await this.provider.getBlockNumber();
    const safeHead = head - this.confirmations + 1;
    if (safeHead < 0) return;

    await this.reconcileCanonicalChain(safeHead);
    let cursor = (await this.store.lastCanonicalBlock())?.number ?? -1;

    while (cursor < safeHead) {
      const number = cursor + 1;
      const block = await this.provider.getBlock(number);
      if (!block?.hash) throw new Error(`missing block ${number}`);
      const previous = await this.store.lastCanonicalBlock();
      if (previous && block.parentHash !== previous.hash) {
        await this.reconcileCanonicalChain(safeHead);
        cursor = (await this.store.lastCanonicalBlock())?.number ?? -1;
        continue;
      }

      const logs = await this.provider.getLogs({
        address: this.depositContract,
        fromBlock: number,
        toBlock: number,
      });

      await this.store.begin();
      try {
        for (const log of logs) {
          const key = `${block.hash}:${log.transactionHash}:${log.index}`;
          await this.store.applyDepositOnce(key, log);
        }
        await this.store.saveBlock({ number, hash: block.hash, parentHash: block.parentHash });
        await this.store.commit();
        cursor = number;
      } catch (error) {
        await this.store.rollback();
        throw error;
      }
    }
  }

  private async reconcileCanonicalChain(safeHead: number): Promise<void> {
    let stored = await this.store.lastCanonicalBlock();
    while (stored && stored.number <= safeHead) {
      const chainBlock = await this.provider.getBlock(stored.number);
      if (chainBlock?.hash === stored.hash) return;
      await this.store.begin();
      try {
        await this.store.removeBlockAndReverseCredits(stored.number);
        await this.store.commit();
      } catch (error) {
        await this.store.rollback();
        throw error;
      }
      stored = await this.store.lastCanonicalBlock();
    }
  }
}
```

Why this works: only sufficiently confirmed blocks become available credit, every applied log has
an idempotency key bound to its block hash, and orphaned credits are reversed before canonical
blocks replay. Confirmation depth is a chain- and value-specific policy, not a universal number.
