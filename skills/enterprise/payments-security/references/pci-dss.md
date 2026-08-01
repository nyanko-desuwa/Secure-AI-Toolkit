Reference: PCI DSS v4.0
Category: Secure cardholder data storage, transmission, and scope reduction
Source: https://docs.paymentcardIndustry.com/pci-dss/requirements/4
Date verified: 2026-07-30

Top-level requirement mapping:
- Req 1: install and maintain network security controls
- Req 2: apply all configurations to all system components
- Req 3: protect stored account data (PAN/SVC/CVC logic)
- Req 4: protect cardholder data with strong cryptography during transmission over open, public networks
- Req 5: protect all systems and networks from malicious software
- Req 6: develop and maintain secure systems and software
- Req 7: restrict access to system components and cardholder data by business need-to-know
- Req 8: identify users and authenticate access to system components
- Req 9: restrict physical access to cardholder data
- Req 10: log and monitor all access to system components and cardholder data
- Req 11: regularly test security controls and systems
- Req 12: support information security with organizational policies and programs

ASVS mapping: V3 (Session Management), V4 (Access Control), V11 (Business Logic), V12 (Files and Resources), V14 (Privacy)

CWE highlights:
- CWE-312 (Cleartext Storage of Sensitive Information)
- CWE-319 (Cleartext Transmission of Sensitive Information)
- CWE-306 (Missing Authentication for Critical Function)
- CWE-345 (Insufficient Verification of Data Authenticity)
- CWE-352 (Cross-Site Request Forgery / replay of payments)
