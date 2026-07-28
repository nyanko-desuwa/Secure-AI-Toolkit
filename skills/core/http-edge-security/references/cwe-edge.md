# CWE Classes for HTTP Edge Findings

Checked: 2026-07-28 against <https://cwe.mitre.org/>.

| CWE | Use when |
|---|---|
| CWE-444 | HTTP request smuggling or inconsistent message interpretation |
| CWE-441 | Unintended proxy or intermediary trust |
| CWE-290 | Client spoofing through a claimed identity/address |
| CWE-644 | Improper HTTP Host header validation |
| CWE-525 | Information exposure through browser cache / cache policy |
| CWE-346 | Origin validation failure where the edge accepts a forged origin-like assertion |
| CWE-20 | Method, request target, or header normalization accepts an invalid input |

Choose the narrowest CWE supported by the demonstrated path. A suspicious header alone is not a confirmed smuggling finding.
