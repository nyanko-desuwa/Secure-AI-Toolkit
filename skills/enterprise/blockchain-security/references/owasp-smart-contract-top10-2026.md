# OWASP Smart Contract Top 10 (2026)

Current edition. Project version 2.0.0. Verified 2026-07-28 against the OWASP project page.

Source: <https://owasp.org/www-project-smart-contract-top-10/>

This 2026 list is forward-looking and uses 2025 incident and survey data. Do not silently use
2025 identifiers: the list and ordering changed.

## Categories

| Category | Title | Ask in a review |
|---|---|---|
| SC01:2026 | Access Control Vulnerabilities | Who can initialize, upgrade, pause, mint, withdraw, or invoke this hook? |
| SC02:2026 | Business Logic Vulnerabilities | What profitable action sequence violates the intended workflow? |
| SC03:2026 | Price Oracle Manipulation | Can the value source be moved in the same transaction or become stale? |
| SC04:2026 | Flash Loan-Facilitated Attacks | Does borrowed same-transaction capital defeat a presumed cost barrier? |
| SC05:2026 | Lack of Input Validation | Are addresses, amounts, array lengths, and callback data constrained on-chain? |
| SC06:2026 | Unchecked External Calls | What if the callee fails, re-enters, lies, or consumes the forwarded gas? |
| SC07:2026 | Arithmetic Errors | Where does truncation, scaling, or repeated rounding create value? |
| SC08:2026 | Reentrancy Attacks | Which same, different, or cross-contract entry point sees stale state? |
| SC09:2026 | Integer Overflow and Underflow | Is checked arithmetic disabled or defeated by casts and assumptions? |
| SC10:2026 | Proxy & Upgradeability Vulnerabilities | Who can rewrite the code, and will the new storage layout preserve state? |

## Scope notes

SC08 explicitly includes single-function, cross-function, cross-contract, and read-only
reentrancy. The prevention is checks-effects-interactions plus a guard where useful, with testing
across hooks and contracts.

SC03 treats oracles as trust boundaries. Same-transaction AMM spot values, stale data, short
TWAP windows, one source, and absent deviation checks are all in scope.

SC06 includes low-level calls, token return behavior, arbitrary callbacks, gas effects, and the
way external calls enable reentrancy and accounting drift.

## Use with the general standards

This is an on-chain vulnerability list. Cross-report every control to OWASP Top 10 2025 and ASVS
where the same failure extends into a backend or workflow. See
[owasp-top10-2025-mapping.md](owasp-top10-2025-mapping.md).

## Sources

- <https://owasp.org/www-project-smart-contract-top-10/>
- <https://scs.owasp.org/sctop10/>
- <https://owasp.org/www-project-smart-contract-top-10/2026/en/src/SC01-access-control-vulnerabilities.html>
- <https://owasp.org/www-project-smart-contract-top-10/2026/en/src/SC03-price-oracle-manipulation.html>
- <https://owasp.org/www-project-smart-contract-top-10/2026/en/src/SC06-unchecked-external-calls.html>
- <https://owasp.org/www-project-smart-contract-top-10/2026/en/src/SC07-arithmetic-errors.html>
- <https://owasp.org/www-project-smart-contract-top-10/2026/en/src/SC08-reentrancy-attacks.html>
