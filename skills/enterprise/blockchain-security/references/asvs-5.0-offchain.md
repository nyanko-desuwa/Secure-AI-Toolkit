# OWASP ASVS 5.0.0 for Web3 Integrations

Version 5.0.0, released 2025-05-30. Verified 2026-07-28 against the ASVS project page.

Source: <https://owasp.org/www-project-application-security-verification-standard/>

ASVS is a web-application verification standard, not a Solidity standard. Use it at chapter level
for the backend, wallet interface, signing service, relayer, deployment pipeline, and indexer.
Do not claim an ASVS level without verifying every requirement at that level.

## Chapters used by this skill

| Chapter | Title | Web3 application |
|---|---|---|
| V2 | Validation and Business Logic | Transaction bounds, slippage, deadlines, event state machines, confirmation policy, value conservation. |
| V4 | API and Web Service | RPC/API authorization, idempotent event ingestion, relayer endpoints, wallet session boundaries. |
| V8 | Authorization | Deployer, owner, upgrade, pauser, signer, and callback caller permissions. |
| V11 | Cryptography | Private keys, seed phrases, typed signatures, domain separation, nonce and replay handling. |
| V13 | Configuration | Chain IDs, RPC endpoints, proxy addresses, compiler settings, deployment configuration. |
| V14 | Data Protection | Private keys, seeds, pending transaction data, wallet identifiers and indexed user data. |
| V15 | Secure Coding and Architecture | Trust boundaries, proxy design, external calls, static analysis, invariant testing. |
| V16 | Security Logging and Error Handling | Failed transactions, reorg rollback, signer denial, exceptional external-call behavior. |

ASVS V2 and V11 are the baseline requested for this skill. Other chapters appear only where the
control truly crosses into that surface.

## Level guidance

A value-bearing web3 service usually merits at least an ASVS Level 2 target on its off-chain
surface. A custody or critical-infrastructure service may need Level 3. This sentence is scoping
guidance, not a compliance claim.

## Source

- <https://owasp.org/www-project-application-security-verification-standard/>
- <https://github.com/OWASP/ASVS>
