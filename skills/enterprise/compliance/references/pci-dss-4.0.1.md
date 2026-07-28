# PCI DSS v4.0.1

Checked: 2026-07-28

Sources fetched:

- Document Library: <https://www.pcisecuritystandards.org/document_library/>
- Requirement-title summary: <https://en.wikipedia.org/wiki/Payment_Card_Industry_Data_Security_Standard>

The PCI SSC Document Library labels the current standard v4.0.1. The fetched summary identifies
June 2024 as the release date. Confirm the licensed PCI SSC document and the assessed scope before
using this reference in a formal assessment.

## Verified top-level requirements

| Requirement | Title |
|---|---|
| 1 | Install and maintain network security controls. |
| 2 | Apply secure configurations to all system components. |
| 3 | Protect stored account data. |
| 4 | Protect cardholder data with strong cryptography during transmission over open, public networks. |
| 5 | Protect all systems and networks from malicious software. |
| 6 | Develop and maintain secure systems and software. |
| 7 | Restrict access to system components and cardholder data by business need to know. |
| 8 | Identify users and authenticate access to system components. |
| 9 | Restrict physical access to cardholder data. |
| 10 | Log and monitor all access to system components and cardholder data. |
| 11 | Test security of systems and networks regularly. |
| 12 | Support information security with organizational policies and programs. |

## Technical-control mapping

- Audit logging supports Requirement 10.
- Access control and access reviews support Requirements 7 and 8.
- Encryption at rest and data minimisation can reduce Requirement 3 scope; encryption in transit
  supports Requirement 4.
- Secure change gates and vulnerability scanning support Requirement 6; scanning and testing may
  also support Requirement 11.
- Evidence generation supports assessment of operation but does not establish compliance.

## Deliberate omissions

PCI DSS v4.0.1 sub-requirement numbers and full requirement text were not accessible from the
fetched PCI SSC pages. This skill deliberately cites only verified top-level requirement numbers.
Do not invent sub-requirement IDs or claim that encryption alone removes payment scope.
