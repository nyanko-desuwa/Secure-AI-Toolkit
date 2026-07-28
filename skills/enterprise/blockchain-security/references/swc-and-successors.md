# SWC Registry and Successors

The Smart Contract Weakness Classification Registry was checked 2026-07-28 at
<https://swcregistry.io/> and its source README at
<https://raw.githubusercontent.com/SmartContractSecurity/SWC-registry/master/README.md>.

The registry states that it is no longer actively maintained and that new SWC entries have not
been added since 2020. Existing entries may help a reviewer search old reports, but they are not
a current edition. This skill therefore does not cite SWC identifiers. It describes the weakness
and uses the current OWASP Smart Contract Top 10 2026 category instead.

## Successors

The registry points readers to:

- EEA EthTrust Security Levels Specification, whose first published version incorporated the
  registry's vulnerability material. See <https://entethalliance.org/specs/>
- Smart Contract Security Verification Standard (SCSVS), a broader development and verification
  guideline. See <https://scs.owasp.org/standards/smart-contract-security-verification-standard/>

The appropriate current classification depends on the report's required taxonomy. Do not invent
an SWC number when the current source cannot be verified.

## Practical mapping without SWC IDs

| Weakness | Current wording used here |
|---|---|
| Reentrancy | SC08:2026; CWE-841 |
| Unchecked return | SC06:2026; CWE-252 |
| Authorization failure | SC01:2026; CWE-284 or CWE-863 |
| Arithmetic and precision | SC07:2026 / SC09:2026; CWE-682 |
| Signature verification | A04:2025; ASVS V11; CWE-347 |
| Resource exhaustion | A10:2025; CWE-400 |
| Exceptional condition | A10:2025; CWE-703 |

This avoids presenting an archived identifier as if it were a current standard.
