# HIPAA Security Rule Safeguards

Checked: 2026-07-28

Primary source for technical safeguards fetched: <https://www.law.cornell.edu/cfr/text/45/164.312>
The eCFR pages for administrative and privacy safeguards were blocked by an automated-access
restriction in this environment. Only the technical safeguards below are cited by exact ID.

## Verified technical safeguards

| Citation | Verified standard or specification | Status |
|---|---|---|
| 45 CFR 164.312(a)(1) | Access control | Standard |
| 45 CFR 164.312(a)(2)(i) | Unique user identification | Required |
| 45 CFR 164.312(a)(2)(ii) | Emergency access procedure | Required |
| 45 CFR 164.312(a)(2)(iii) | Automatic logoff | Addressable |
| 45 CFR 164.312(a)(2)(iv) | Encryption and decryption | Addressable |
| 45 CFR 164.312(b) | Audit controls | Standard |
| 45 CFR 164.312(c)(1) | Integrity | Standard |
| 45 CFR 164.312(c)(2) | Mechanism to authenticate electronic protected health information | Addressable |
| 45 CFR 164.312(d) | Person or entity authentication | Standard |
| 45 CFR 164.312(e)(1) | Transmission security | Standard |
| 45 CFR 164.312(e)(2)(i) | Integrity controls | Addressable |
| 45 CFR 164.312(e)(2)(ii) | Encryption | Addressable |

## Technical-control mapping

- Audit trails support § 164.312(b), but the event population, retention, review, and access to
  the audit store still need evidence.
- Server-side identity and authorization support § 164.312(a)(1) and § 164.312(d); authentication
  does not by itself prove authorization.
- Encryption at rest maps to § 164.312(a)(2)(iv); TLS and transmission integrity map to
  § 164.312(e)(1) and its specifications.
- Backups and recovery may support contingency safeguards, but this reference does not assert
  an unverified administrative-safeguard paragraph.

Addressable does not mean optional in a casual sense. Analyse, implement, document, or justify
an alternative as the Rule and covered-entity facts require. Qualified HIPAA counsel governs.

## Deliberate omissions

No § 164.308 administrative safeguard IDs, § 164.310 physical safeguard IDs, § 164.502(b) minimum
necessary citation, or § 164.504(e) business-associate citation is used here because those source
texts were not successfully fetched. Do not infer them from memory.
