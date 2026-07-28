# OWASP Top 10 2025 Mapping

Current released edition. Verified 2026-07-28 against <https://owasp.org/Top10/2025/>.

Use these categories for cross-reporting. The Smart Contract Top 10 is the primary on-chain
classification; do not replace it with a general category that hides the mechanism.

| On-chain concern | OWASP Top 10 2025 | Why |
|---|---|---|
| Missing modifier, `tx.origin`, initializer, bad ownership | A01 Broken Access Control | A caller reaches a privileged value or code path without the intended authorization. |
| Weak signatures, replay, malleability, private key handling | A04 Cryptographic Failures | Cryptographic verification or key protection fails. |
| Protocol assumes caller, pool, token, or block ordering is honest | A06 Insecure Design | The missing control is architectural; input validation alone cannot repair it. |
| Upgrade artifact, deployment bytecode, or event-derived credit is trusted without integrity | A08 Software or Data Integrity Failures | An artifact or derived state is accepted without the required integrity boundary. |
| Swallowed call errors, partial state, reorgs, stale fallback, blocked batches | A10 Mishandling of Exceptional Conditions | Failure leaves unsafe or inconsistent state. |

The requested cross-report categories are therefore A01, A04, A06, A08, and A10. Use A05 only
when the off-chain integration has an actual interpreter injection issue; smart contract calldata
is not automatically A05.

## Sources

- <https://owasp.org/Top10/2025/>
- <https://owasp.org/www-project-top-ten/> 
