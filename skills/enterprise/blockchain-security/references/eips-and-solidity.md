# EIPs and Solidity Behaviour

Checked 2026-07-28 against the official EIP pages, Solidity changelog, and documentation. The
version-sensitive claims in this skill use these sources rather than memory.

## Solidity

The latest released compiler at the check date is Solidity 0.8.36, released 2026-07-09. The
changelog lists 0.8.37 as unreleased. The examples pin exactly:

```solidity
pragma solidity 0.8.36;
```

Solidity 0.8.0 changed arithmetic so operations revert on underflow and overflow by default.
`unchecked { ... }` restores the previous wrapping behavior inside its lexical block. Division
and modulo by zero still fail. Arithmetic overflow outside `unchecked` is documented as Panic
0x11; division or modulo by zero as Panic 0x12.

Sources:

- <https://raw.githubusercontent.com/ethereum/solidity/develop/Changelog.md>
- <https://raw.githubusercontent.com/ethereum/solidity/develop/docs/080-breaking-changes.rst>
- <https://raw.githubusercontent.com/ethereum/solidity/develop/docs/control-structures.rst>

## EIP-712

EIP-712, "Typed structured data hashing and signing," is Final. It defines typed structured
data hashing, a domain separator, and the `\x19\x01` typed-data digest convention. It explicitly
does not itself provide replay protection. Bind chain and contract in the domain and consume a
nonce in the protocol.

Source: <https://eips.ethereum.org/EIPS/eip-712>

## EIP-155

EIP-155, "Simple replay attack protection," is Final. It binds Ethereum transaction signatures
to a chain ID. This concerns transaction signatures; application-level typed-data signatures
still need their own domain and nonce policy.

Source: <https://eips.ethereum.org/EIPS/eip-155>

## ERC-1967 and ERC-1822

ERC-1967, "Proxy Storage Slots," is Final. It defines fixed implementation, beacon, and admin
slots for proxy tooling and collision avoidance.

Source: <https://eips.ethereum.org/EIPS/eip-1967>

ERC-1822, "Universal Upgradeable Proxy Standard (UUPS)," is Stagnant. It defines a UUPS
compatibility slot and a `proxiableUUID` check. A standard slot does not authorize upgrades;
the authorization hook still needs protection.

Source: <https://eips.ethereum.org/EIPS/eip-1822>

## ERC-777 and hooks

ERC-777, "Token Standard," is Final. It defines `tokensToSend` and `tokensReceived` hooks via
the ERC-1820 registry. The hooks can be called for transfer and transferFrom, so token movement
is an external-call boundary and a reentrancy surface.

Source: <https://eips.ethereum.org/EIPS/eip-777>

## ERC-2612

ERC-2612, "Permit Extension for EIP-20 Signed Approvals," is Final. It adds signature-based
approval through `permit`; implementations still need EIP-712 domain separation, a nonce, and
deadline handling.

Source: <https://eips.ethereum.org/EIPS/eip-2612>

## ERC-1271

ERC-1271, "Standard Signature Validation Method for Contracts," is Final. It defines how a
contract signer validates a signature for a hash on its own behalf. Support it where smart
contract wallets or multisigs can be signers; `ecrecover` covers EOAs only.

Source: <https://eips.ethereum.org/EIPS/eip-1271>

## EIP-1153

EIP-1153, "Transient storage opcodes," is Final. `TLOAD` and `TSTORE` provide transaction-scoped
storage, which can support a reentrancy lock. A transient lock changes storage cost, not the
need for effects-before-interactions or cross-contract review.

Source: <https://eips.ethereum.org/EIPS/eip-1153>
