# OWASP and CWE Mapping

Which standard a Windows finding belongs to. Verified 2026-07-28 against
<https://owasp.org/Top10/2025/> and
<https://owasp.org/www-project-application-security-verification-standard/>.

ASVS mapping here is at chapter level only (V1 to V17). This skill does not quote individual
ASVS requirement numbers. For formal verification, work from the official ASVS 5.0.0 release.

## OWASP Top 10 2025 categories used

| Category | Windows findings that land here |
|---|---|
| A01 Broken Access Control | Service running as Domain Admin, over-privileged app pool identity, writable service binary, writable registry key under a service, tier-0 credential on a tier-1 host, JEA endpoint exposing an unconstrained cmdlet |
| A02 Security Misconfiguration | IIS defaults left in place, directory browsing on, version headers, no request filtering, WinRM over HTTP, RDP without NLA, Defender exclusion over a writable path, no baseline or no drift detection |
| A04 Cryptographic Failures | Connection string with a password in a committed config, WDigest plaintext caching, unprotected Data Protection key ring, no BitLocker where the threat model needs it, cleartext management protocols |
| A09 Security Logging and Alerting Failures | No advanced audit policy, process creation without command line, no service-install or privilege-use collection, no forwarding, no alert on the events collected |

2025 is not a renumbering of 2021. Injection moved to A05, and A03 (Software Supply Chain
Failures) and A10 (Mishandling of Exceptional Conditions) are new. A stack trace returned to a
client is A02 for the configuration and A10 for the handling; pick the one that describes the
fix you are proposing and say which.

## ASVS 5.0.0 chapters used

| Chapter | Use here |
|---|---|
| V12 Secure Communication | SMB signing, LDAP channel binding, WinRM over HTTPS, TLS on the IIS binding |
| V13 Configuration | Service identity, app pool isolation, `web.config` and `appsettings.json` hardening, GPO baselines, attack surface reduction |
| V14 Data Protection | Secret storage, DPAPI and vault use, Data Protection key ring, BitLocker and TPM-backed protection |
| V16 Security Logging and Error Handling | Audit policy, event collection, `customErrors`, no stack trace to the client |

V12 appears in the table because SMB signing and channel binding genuinely belong there, even
though the assigned scope for this skill names V13, V14, and V16.

## CWE mapping

| CWE | Name | Where it applies |
|---|---|---|
| CWE-250 | Execution with Unnecessary Privileges | Service as Domain Admin or LocalSystem where a virtual account suffices |
| CWE-269 | Improper Privilege Management | `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege` granted to an account that does not need it; always-elevated interactive session |
| CWE-732 | Incorrect Permission Assignment for Critical Resource | Writable service binary, writable service directory, writable registry key, world-readable key ring |
| CWE-522 | Insufficiently Protected Credentials | Cached domain credentials on a member server, plaintext credentials in LSASS, unprotected key material |
| CWE-798 | Use of Hard-coded Credentials | Connection string password in `web.config` or `appsettings.json`, service account password in a deployment script |
| CWE-428 | Unquoted Search Path or Element | Unquoted `ImagePath` on a service |
| CWE-276 | Incorrect Default Permissions | Application directory inheriting permissive ACLs from its parent, `C:\inetpub` subdirectory writable by `Users` |
| CWE-306 | Missing Authentication for Critical Function | Unauthenticated management endpoint, anonymous SMB or LDAP bind allowed where signing is not required |
| CWE-319 | Cleartext Transmission of Sensitive Information | WinRM over HTTP, LDAP simple bind without TLS, unsigned SMB |
| CWE-778 | Insufficient Logging | Audit subcategory not enabled, events generated but never forwarded |

Two more appear in examples where they fit better than anything above: CWE-209 for an error
message that discloses internal state, and CWE-16 for configuration in general. Use the specific
one when it exists.

## How to report a finding

State the category, the location, the mechanism, and the fix. "Service `AcmeSync` runs as
`CONTOSO\svc_admin`, a member of Domain Admins (A01:2025, CWE-250). Anyone who compromises the
service process, or who is a local administrator on this host, obtains a Domain Admin credential
from LSASS. Fix: gMSA with `PrincipalsAllowedToRetrieveManagedPassword` set to this host, plus
a specific grant on the network share it reads."

A control with no exploitation path is defence in depth, not a vulnerability. Say which it is.

## Sources

- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>, checked 2026-07-28
- OWASP ASVS 5.0.0 (released 2025-05-30) -
  <https://owasp.org/www-project-application-security-verification-standard/>, checked 2026-07-28
- CWE - <https://cwe.mitre.org/>
