# PCI DSS 4.x Mapping

Checked: 2026-07-28

Current detailed reference: [PCI DSS v4.0.1](pci-dss-4.0.1.md)

Sources fetched:

- PCI SSC Document Library: <https://www.pcisecuritystandards.org/document_library/>
- Requirement-title summary: <https://en.wikipedia.org/wiki/Payment_Card_Industry_Data_Security_Standard>

The PCI SSC library labels PCI DSS v4.0.1 as the featured current standard. The fetched summary
states June 2024. Verify the PCI SSC document used by the assessor before an external citation.

## Technical-control mapping

| Implemented control | Verified top-level requirement |
|---|---|
| Encryption for stored account data | Requirement 3 — Protect stored account data. |
| Strong cryptography for transmission over open, public networks | Requirement 4 — Protect cardholder data with strong cryptography during transmission over open, public networks. |
| Secure SDLC and blocking change gates | Requirement 6 — Develop and maintain secure systems and software. |
| Business-need authorization | Requirement 7 — Restrict access to system components and cardholder data by business need to know. |
| Unique users and authentication | Requirement 8 — Identify users and authenticate access to system components. |
| Audit logging and monitoring | Requirement 10 — Log and monitor all access to system components and cardholder data. |
| Vulnerability scans and security tests | Requirement 11 — Test security of systems and networks regularly. |

A technical artifact supports assessment only for the cardholder-data environment and connected
systems it actually covers. Tokenisation, outsourcing, or encryption may reduce exposure but does
not automatically remove a system from scope.

## Deliberate omissions

No PCI DSS v4.0.1 sub-requirement number is included. The fetched PCI SSC pages did not expose the
requirement body and the linked PDF returned HTTP 403. Use the licensed standard rather than
reconstructing sub-requirement IDs from memory.
