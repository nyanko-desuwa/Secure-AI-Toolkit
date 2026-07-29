# Windows Hardening Examples

Eight vulnerable/fixed pairs. Every pair names its category, ASVS chapter, and CWE. Vulnerable
blocks are deliberate. Do not copy them. Hostnames, domains, and accounts are placeholders.

## 1. Domain Admin service versus gMSA or virtual account

`A01:2025` · ASVS V13 · CWE-250, CWE-269

```powershell
# Vulnerable: application service holds a tier-0 credential in LSASS
sc.exe config AcmeSync obj= 'CONTOSO\svc_domainadmin' password= 'Placeholder-only-not-a-secret'
```

The service is now the highest-leverage finding in the estate. Code execution in the service or a
local administrator on the host can expose a Domain Admin credential. A password in the service
definition or deployment script is another copy.

```powershell
# Fixed when no domain resource is needed: per-service virtual account, no password
sc.exe config AcmeSync obj= 'NT SERVICE\AcmeSync' password= ''

# Fixed when the service reads a domain share from a farm: gMSA, retrieval limited to these hosts
$hosts = Get-ADComputer -Filter 'Name -like "WEB0*"'
New-ADServiceAccount -Name 'svc_acmesync' `
    -DNSHostName 'svc_acmesync.contoso.example' `
    -PrincipalsAllowedToRetrieveManagedPassword $hosts `
    -KerberosEncryptionType AES256 -Enabled $true
Install-ADServiceAccount -Identity 'svc_acmesync'
Test-ADServiceAccount -Identity 'svc_acmesync'   # True before cutover
# WARNING: grant Log on as a service before this change or restart will fail.
sc.exe config AcmeSync obj= 'CONTOSO\svc_acmesync$' password= ''
```

Why this works: the virtual account has no password. The gMSA password is generated and rotated by
AD and retrievable only by named hosts. The share ACL still grants only the required read/write
operation; gMSA identity is not permission by itself.

The tempting wrong fix is a long password on the old account. It still sits in LSASS and still gives
the application a tier-0 token.

## 2. Unconstrained delegation versus RBCD

`A01:2025` · ASVS V13 · CWE-269

```powershell
# Vulnerable: every caller's forwardable TGT is available to the front end
Set-ADComputer 'WEB01' -TrustedForDelegation $true
```

An administrator who authenticates to `WEB01` has delegated an identity the compromised server can
use to access other services. This is a domain-wide compromise path from one front end, not a local
web setting.

```powershell
# Fixed: resource owner permits only WEB01 to act on behalf of users to SQL01
Set-ADComputer 'SQL01' -PrincipalsAllowedToDelegateToAccount (Get-ADComputer 'WEB01')

# WARNING: remove only after the RBCD path has been tested. This breaks old delegation flows.
Set-ADComputer 'WEB01' -TrustedForDelegation $false
Set-ADComputer 'WEB01' -Clear 'msDS-AllowedToDelegateTo'
```

Why this works: resource-based constrained delegation writes the trust to the back-end's
`msDS-AllowedToActOnBehalfOfOtherIdentity`; a compromised front end reaches only that resource.
Write access to the `SQL01` computer object is therefore security-critical and must be restricted.

A constrained-delegation alternative lists exact target SPNs on the front end. It is safer than
unconstrained but still gives that front end impersonation to every listed target. RBCD is the
preferred shape when the resource owner should decide.

This example deliberately contains no ticket-request or ticket-extraction tooling.

## 3. Scheduled-task password versus gMSA

`A04:2025` · ASVS V14 · CWE-522, CWE-798

```xml
<!-- Vulnerable: a scheduled task action invokes a script with a password in its arguments -->
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Principals>
    <Principal id="Author">
      <UserId>CONTOSO\svc_reports</UserId>
      <LogonType>Password</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-File C:\apps\reports\export.ps1 -Password "Placeholder-only"</Arguments>
    </Exec>
  </Actions>
</Task>
```

The password reaches the task XML, process command line, task history, and potentially event 4688.
It also gives the task's account whatever domain rights its owner later adds.

```powershell
# Fixed: task runs as a gMSA. There is no password element or password argument.
$taskAction  = New-ScheduledTaskAction -Execute 'C:\Program Files\Acme\reports.exe' `
               -Argument '--export'
$taskTrigger = New-ScheduledTaskTrigger -Daily -At 02:00
$principal   = New-ScheduledTaskPrincipal -UserId 'CONTOSO\svc_reports$' -LogonType ServiceAccount
Register-ScheduledTask -TaskName 'Acme Reports' -Action $taskAction `
    -Trigger $taskTrigger -Principal $principal -Description 'Placeholder report export'
```

Why this works: the Task Scheduler uses the managed identity and Windows obtains its password from
AD. Nothing secret is embedded in XML or arguments. The account still receives only the export
share rights it needs.

If a legacy task cannot use a gMSA, use a vault-backed short-lived credential and document the
exception. Do not pass it on the command line.

## 4. Open WinRM/RDP versus restricted management

`A02:2025` · ASVS V12, V13 · CWE-319, CWE-306

```powershell
# Vulnerable: management listener reachable from any network source, allowing password authentication
winrm quickconfig -quiet
# RDP is enabled for broad membership with no source restriction.
```

Password-bearing management reachable from a user network gives an attacker a large guessing and
credential-replay surface. A tier-0 administrator connecting from that network also leaves the
credential on the wrong tier.

```powershell
# Fixed shape: HTTPS listener with a certificate, then firewall only the bastion subnet.
# Certificate subject/SAN and thumbprint are placeholders; verify them on the host.
$thumbprint = '0000000000000000000000000000000000000000'
winrm create winrm/config/Listener?Address=*+Transport=HTTPS "@{Hostname='WEB01.contoso.example'; CertificateThumbprint='$thumbprint'}"
New-NetFirewallRule -DisplayName 'WinRM HTTPS from bastion' -Direction Inbound `
    -Protocol TCP -LocalPort 5986 -RemoteAddress '192.0.2.0/24' -Action Allow
```

```text
# Fixed RDP client mode for helpdesk support, where the client may be compromised
mstsc.exe /RestrictedAdmin

# Or enforce Remote Credential Guard by GPO:
Computer Configuration\Administrative Templates\System\Credentials Delegation
  Restrict delegation of credentials to remote servers = Require Remote Credential Guard
```

```text
# Authentication policy silo is an AD control, not a firewall rule.
# Scope tier-0 admins to hardened admin workstations and deny their logon to tier-1 OUs.
# Verify the silo and logon rights on the live domain; a policy file alone proves nothing.
```

Why this works: source restriction removes reachability; HTTPS protects the WinRM channel; Restricted
Admin and Remote Credential Guard prevent reusable credentials reaching the target. JIT membership
and an authentication policy silo make the tier boundary enforceable rather than advisory.

This pair does not prescribe a made-up WinRM registry value. The effective listener and certificate
must be verified with `winrm enumerate winrm/config/listener` on the host.

## 5. Local admin for one app versus a writable state directory

`A01:2025` · ASVS V13 · CWE-250, CWE-732

```powershell
# Vulnerable: every user is made administrator because the app cannot write its install directory
Add-LocalGroupMember -Group 'Administrators' -Member 'CONTOSO\AllEmployees'
```

Every user can now install a service, change another service, read protected files, and alter the
host. The application's write requirement was a directory ACL problem.

```powershell
# Fixed: preserve administrator/SYSTEM ownership of code; grant only the app identity Modify on state
New-Item -ItemType Directory -Path 'C:\ProgramData\Acme\state' -Force | Out-Null
icacls 'C:\ProgramData\Acme\state' /inheritance:r `
    /grant 'BUILTIN\Administrators:(OI)(CI)(F)' `
    /grant 'NT AUTHORITY\SYSTEM:(OI)(CI)(F)' `
    /grant 'IIS AppPool\AcmePool:(OI)(CI)(M)'
icacls 'C:\Program Files\Acme' /inheritance:r `
    /grant 'BUILTIN\Administrators:(OI)(CI)(F)' `
    /grant 'NT AUTHORITY\SYSTEM:(OI)(CI)(F)' `
    /grant 'IIS AppPool\AcmePool:(OI)(CI)(RX)'
```

Why this works: the app gets a write sink but not the ability to modify its code or the host. The
wrong fix of granting Modify to `C:\Program Files\Acme` leaves every user able to replace the code.

## 6. Shared local administrator password versus LAPS

`A01:2025` · ASVS V14 · CWE-522, CWE-798

```text
# Vulnerable: every machine accepts the same local administrator credential
Machine: WEB01  Local Administrator: .\Administrator  Password: Placeholder-shared-value
Machine: WEB02  Local Administrator: .\Administrator  Password: Placeholder-shared-value
```

One compromised workstation or server becomes the key to every machine that accepts the same
password. A local admin password is not a domain password, but reuse turns it into a lateral movement
credential at fleet scale.

```text
# Fixed: Windows LAPS manages a unique local administrator password per device and stores it in AD
# or Microsoft Entra ID according to the deployment. Configure through the Windows LAPS policy,
# grant retrieval to a small audited group, and set an expiration/rotation interval.
# Enumerate the installed LAPS policy and cmdlets on the target before scripting; this skill does not
# invent a cmdlet name or registry value.
```

Why this works: compromise of WEB01 yields a password that is useless on WEB02. Retrieval is an
access-controlled event that can be audited. LAPS does not protect a password while it is actively
used on a host, so use Restricted Admin or Remote Credential Guard for remote administration too.

## 7. Over-privileged IIS pool versus isolated identity

`A01:2025` · ASVS V13 · CWE-250, CWE-732, CWE-276

```powershell
# Vulnerable: pool runs as a domain administrator and writes inside its served content root
Set-ItemProperty 'IIS:\AppPools\AcmePool' -Name processModel.identityType -Value SpecificUser
Set-ItemProperty 'IIS:\AppPools\AcmePool' -Name processModel.userName -Value 'CONTOSO\svc_webadmin'
Set-ItemProperty 'IIS:\AppPools\AcmePool' -Name processModel.password -Value 'Placeholder-only'
icacls 'C:\inetpub\wwwroot\acme' /grant 'CONTOSO\svc_webadmin:(OI)(CI)(M)'
```

Code execution can modify served files, plant a persistent page, read sibling application content,
and expose the service account's domain credential.

```powershell
# Fixed: one pool, one virtual identity; content Read/Execute, uploads outside the web root
New-WebAppPool -Name 'AcmePool'
Set-ItemProperty 'IIS:\AppPools\AcmePool' -Name processModel.identityType -Value ApplicationPoolIdentity
New-WebApplication -Site 'Default Web Site' -Name 'acme' -ApplicationPool 'AcmePool' `
    -PhysicalPath 'C:\apps\acme\content'

icacls 'C:\apps\acme\content' /inheritance:r `
    /grant 'BUILTIN\Administrators:(OI)(CI)(F)' `
    /grant 'NT AUTHORITY\SYSTEM:(OI)(CI)(F)' `
    /grant 'IIS AppPool\AcmePool:(OI)(CI)(RX)'
New-Item -ItemType Directory 'C:\ProgramData\Acme\uploads' -Force | Out-Null
icacls 'C:\ProgramData\Acme\uploads' /inheritance:r `
    /grant 'IIS AppPool\AcmePool:(OI)(CI)(M)' `
    /grant 'BUILTIN\Administrators:(OI)(CI)(F)' `
    /grant 'NT AUTHORITY\SYSTEM:(OI)(CI)(F)'
```

Why this works: the pool SID is unique (`IIS AppPool\AcmePool`), code is read-only to the worker,
and writable uploads are outside the web root. If the application needs a domain resource, use a
gMSA for this one pool, not a domain administrator.

## 8. Default audit policy versus useful collection

`A09:2025` · ASVS V16 · CWE-778

```powershell
# Vulnerable: defaults leave process creation, service installation, and group changes invisible
# A GPO backup exists, but nobody checked the effective host policy.
auditpol.exe /get /category:*
```

Credential-theft preparation, a new privileged group member, or a newly installed service can occur
without a useful event reaching the collector. Reading a script or GPO cannot prove enforcement on a
live domain.

```powershell
# Fixed: enable the specific advanced audit subcategories that produce the events we need.
auditpol.exe /set /subcategory:'Logon' /success:enable /failure:enable
auditpol.exe /set /subcategory:'Special Logon' /success:enable
auditpol.exe /set /subcategory:'Process Creation' /success:enable
auditpol.exe /set /subcategory:'Security Group Management' /success:enable
auditpol.exe /set /subcategory:'User Account Management' /success:enable
auditpol.exe /set /subcategory:'Security System Extension' /success:enable

# Also enable the separate policy:
# Computer Configuration\Administrative Templates\System\Audit Process Creation
# "Include command line in process creation events" = Enabled

# Prevent basic policy from overwriting advanced subcategories:
# Computer Configuration\Windows Settings\Security Settings\Local Policies\Security Options
# "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" = Enabled

auditpol.exe /get /subcategory:'Logon','Special Logon','Process Creation','Security Group Management','User Account Management','Security System Extension'
```

Collect and alert on the verified events:

| Event | What it shows |
|---|---|
| 4624 / 4625 | Successful / failed logon |
| 4672 | Special privileges assigned to a new logon |
| 4688 | Process creation, with command line only when the separate policy is enabled |
| 4697 | Service installed in the Security log |
| 4720 | User account created |
| 4728 / 4732 / 4756 | Member added to global / local / universal security group |
| 4719 | Audit policy changed |

Why this works: the subcategory, event, forwarding path, and SIEM rule are named together. Event
4697 is attributable and records the configured service account; 4728 alone is insufficient because
local Administrators additions produce 4732. Event 4672 is noisy for SYSTEM and needs filtering.

The command-line policy has a cost: anyone who can read the Security log can read command-line
arguments, including secrets. Stop passing passwords on command lines and restrict log access.

Full verified list and source links in [references/audit-event-ids.md](../references/audit-event-ids.md).
The commonly cited System-log event 7045 was not verified against Microsoft Learn during research,
so it is deliberately not used as a required collection ID here.

## Sources

- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>
- OWASP ASVS 5.0.0 - <https://owasp.org/www-project-application-security-verification-standard/>
- Microsoft Learn sources and check dates are in `references/`.
