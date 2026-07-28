# Windows Hardening Verification Checklist

Mark each applicable item pass, fail, or not applicable with a reason. An unexplained skip is a gap.

Items marked **[host]** cannot be settled by reading configuration, a GPO backup, or a script in
source control. They need a command run on the live host or against the live domain. If you have not
run it, the answer is "unknown", not "pass".

## Service Identity (A01 · ASVS V13 · CWE-250, CWE-269)

- [ ] Every non-default service identity is inventoried with what it runs as and why
- [ ] No service, scheduled task, or app pool runs as a member of Domain Admins, Enterprise Admins,
      Schema Admins, Account Operators, or Backup Operators **[host]**
- [ ] Services needing no domain resources use a virtual account, `LocalService`, or
      `ApplicationPoolIdentity`
- [ ] Services needing domain resources use a gMSA or standalone MSA, not a domain user
- [ ] `PrincipalsAllowedToRetrieveManagedPassword` on each gMSA lists only the hosts that run it **[host]**
- [ ] `Test-ADServiceAccount` returns True on every host before the service is repointed **[host]**
- [ ] `Log on as a service` granted to the new identity before the service account is changed
- [ ] No service account is in the local Administrators group without a written justification **[host]**
- [ ] Effective privileges of each service account reviewed with `whoami /priv` in that context **[host]**
- [ ] `SeImpersonatePrivilege` and `SeAssignPrimaryTokenPrivilege` held only where the workload needs them **[host]**
- [ ] Service account passwords, where a user account is unavoidable, are 25+ random characters in a vault

## Credential Exposure (A04 · ASVS V14 · CWE-522, CWE-798)

- [ ] Credential Guard enabled on domain-joined, non-DC servers that meet the requirements **[host]**
- [ ] LSA protection confirmed running, not just configured — System log WinInit event 12 **[host]**
- [ ] CodeIntegrity operational log reviewed in audit mode before LSA protection was enforced **[host]**
- [ ] Tier-0 accounts in Protected Users, after testing for lockout
- [ ] No account for a service or computer is in Protected Users (it gives them no protection)
- [ ] RDP to servers uses Restricted Admin or Remote Credential Guard; helpdesk paths use Restricted Admin
- [ ] Local administrator passwords are unique per host and machine-managed **[host]**
- [ ] Cached domain credential count on member servers reviewed against the operational need **[host]**
- [ ] No plaintext credential in a service definition, scheduled task action, or deployment script
- [ ] No connection string with a password in a committed `web.config` or `appsettings.json`
- [ ] Production secrets come from DPAPI, a certificate, or a vault; user secrets are development-only
- [ ] Secrets are not passed as command-line arguments, especially with 4688 command-line capture on

## Local Privilege Escalation (A01 · CWE-732, CWE-428, CWE-276)

- [ ] No service `ImagePath` contains an unquoted path with a space **[host]**
- [ ] No service binary or its containing directory is writable by non-administrators **[host]**
- [ ] No registry key under a service's configuration is writable by non-administrators **[host]**
- [ ] Application code directories are not writable by the account that runs the application
- [ ] Writable state, log, and upload paths are outside the code directory and outside the web root
- [ ] No user was given local administrator rights to work around a directory ACL
- [ ] Defender exclusions reviewed; none covers a directory writable by a non-administrator **[host]**
- [ ] Scheduled tasks stored in writable directories, or with writable script targets, identified **[host]**

## Authentication Path (A04 · ASVS V12 · CWE-306, CWE-319)

- [ ] No member server or service account has unconstrained delegation **[host]**
- [ ] Constrained delegation replaced with resource-based where the resource owner should decide
- [ ] Back ends that must distinguish a real logon from a service-asserted one check `S-1-18-1` / `S-1-18-2`
- [ ] Write access to computer objects reviewed, because it can grant RBCD **[host]**
- [ ] SPNs on ordinary user accounts inventoried and either moved to a gMSA or given long random passwords **[host]**
- [ ] AES enforced and RC4 removed for SPN-bearing accounts where the service supports it
- [ ] SMB signing required on both client and server (`RequireSecuritySignature` = 1) **[host]**
- [ ] `EnableSecuritySignature` is not being relied on — it is ignored for SMB2 and later
- [ ] SMB signing audit run before fleet enforcement to find clients that cannot comply **[host]**
- [ ] LDAP signing and channel binding required
- [ ] Extended Protection for Authentication enabled on IIS sites using Windows Integrated auth
- [ ] No connection string or share path uses an IP address or CNAME where Kerberos is expected

## Remote Management (A02 · ASVS V12, V13)

- [ ] WinRM listeners use HTTPS with a valid certificate; HTTP listeners justified or removed **[host]**
- [ ] Management access restricted by source at both the network and host firewall **[host]**
- [ ] RDP requires NLA
- [ ] Administrative access is time-bound (JIT) rather than standing where the tooling allows
- [ ] JEA endpoints use `RestrictedRemoteServer`, a virtual account or gMSA, and transcription
- [ ] JEA role capability files expose no cmdlet that can add a group member, start a process, or
      invoke arbitrary code
- [ ] JEA role capability files and their containing module are writable only by trusted admins **[host]**
- [ ] Role capability filenames are unique across the module path (search order is not deterministic)
- [ ] A jump host or bastion exists for tier-0 work and tier-0 credentials are used nowhere else

## PowerShell (A02 · A09 · ASVS V13, V16)

- [ ] Execution policy is not being treated as a security boundary anywhere in the design
- [ ] Script block logging enabled, with Protected Event Logging alongside it
- [ ] Transcription enabled to a directory standard users cannot read
- [ ] Application control (AppLocker or WDAC) decided on, with Constrained Language Mode as the effect
- [ ] Scripts do not embed credentials, and do not build commands by string concatenation

## IIS and ASP.NET Core (A02 · A04 · A10 · ASVS V13, V14, V16)

- [ ] One application pool per application, each with its own identity
- [ ] `customErrors mode="RemoteOnly"` or `"On"`, with a defined error page
- [ ] ASP.NET Core developer exception page is behind an environment check
- [ ] Directory browsing off
- [ ] `Server`, `X-AspNet-Version`, and `X-Powered-By` headers removed
- [ ] Request filtering limits request size, URL length, and query string to the application's need
- [ ] Upload limits set at both IIS and application level
- [ ] Content root contains no `.git`, `.env`, backup file, or unreferenced admin page
- [ ] Data Protection keys persisted to a shared store and encrypted at rest when there is more than one node
- [ ] The key store is readable and writable only by the application identity **[host]**
- [ ] `SetApplicationName` matches across nodes of the same application, and differs between applications
- [ ] TLS on the binding; HSTS set once every subdomain supports HTTPS

## Baseline, Patching, and Attack Surface (A02 · ASVS V13)

- [ ] A named baseline applies — CIS benchmark for the exact OS version, or a Microsoft SCT baseline
- [ ] GPO precedence understood for the target OU; no conflicting GPO higher in the order **[host]**
- [ ] Drift detection runs on a schedule, not once at build **[host]**
- [ ] Unused roles and features removed, not just stopped
- [ ] Update rings defined, with reboot ownership named
- [ ] BitLocker enabled where the threat model includes physical or disposal risk, TPM-backed **[host]**

## Auditing and Detection (A09 · ASVS V16 · CWE-778)

- [ ] Advanced audit policy subcategories enabled for each event ID being collected
- [ ] "Force audit policy subcategory settings" enabled so basic policy cannot overwrite it
- [ ] `auditpol /get` confirms the effective policy on the host **[host]**
- [ ] Process creation includes the command line
- [ ] 4719 collected, so a silent audit policy replacement is visible
- [ ] Group-addition events cover global, local, and universal (4728, 4732, 4756), not just one
- [ ] Service installation collected, with an alert on a service account outside the built-in three
- [ ] Every event ID in the collection list was verified, not recalled
- [ ] Events leave the host, because a local administrator can clear the Security log
- [ ] Each collected event has a named rule; each rule has a named emitting event

## Before Returning

- [ ] Every destructive command carries a warning and a safer preview or rollback step
- [ ] Commands match the stated Windows Server version
- [ ] Unknown runtime state is reported as unknown, not implied to be fine
- [ ] No real hostname, domain, account, or credential left in the output
