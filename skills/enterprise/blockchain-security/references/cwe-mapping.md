# CWE Mapping

Checked 2026-07-28 against the MITRE CWE entries. CWE is a weakness vocabulary, not an exploit
severity. Prefer a specific child when one fits; several requested entries are deliberately
high-level.

| CWE | Name | Abstraction | Use in this skill |
|---|---|---|---|
| CWE-841 | Improper Enforcement of Behavioral Workflow | Class | Reentrancy, workflow order, commit before callback. |
| CWE-682 | Incorrect Calculation | Pillar | Arithmetic and precision when a more specific child is unavailable. |
| CWE-284 | Improper Access Control | Pillar | Broad access-control framing; prefer CWE-863 for incorrect authorization. |
| CWE-863 | Incorrect Authorization | Class | A permission decision authorizes the wrong caller or condition. |
| CWE-330 | Use of Insufficiently Random Values | Class | Timestamp/block-derived or otherwise insufficient randomness. |
| CWE-347 | Improper Verification of Cryptographic Signature | Base | Missing domain, replay, failure, or malleability validation. |
| CWE-400 | Uncontrolled Resource Consumption | Class | Unbounded loops and gas-limit-dependent work. |
| CWE-703 | Improper Check or Handling of Exceptional Conditions | Pillar | Broad failure and reorg handling; use a specific descendant when known. |
| CWE-252 | Unchecked Return Value | Base | Ignored low-level calls and non-standard token return values. |

Sources:

- <https://cwe.mitre.org/data/definitions/841.html>
- <https://cwe.mitre.org/data/definitions/682.html>
- <https://cwe.mitre.org/data/definitions/284.html>
- <https://cwe.mitre.org/data/definitions/863.html>
- <https://cwe.mitre.org/data/definitions/330.html>
- <https://cwe.mitre.org/data/definitions/347.html>
- <https://cwe.mitre.org/data/definitions/400.html>
- <https://cwe.mitre.org/data/definitions/703.html>
- <https://cwe.mitre.org/data/definitions/252.html>
