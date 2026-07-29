# Windows Service Account Types

Which identity a service should run as, and what each one buys. Verified 2026-07-28 against
Microsoft Learn: `New-ADServiceAccount`
(<https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adserviceaccount>),
`Add-KdsRootKey` (<https://learn.microsoft.com/en-us/powershell/module/kds/add-kdsrootkey>),
and IIS Application Pool Identities
(<https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities>).

## The options, worst to best for a given need

| Identity | Password | Domain identity | Use when |
|---|---|---|---|
| Domain user in Domain Admins | Human-managed | Yes, tier-0 | Never |
| Ordinary domain user | Human-managed, usually never rotated | Yes | Only when nothing below works, and say why |
| `LocalSystem` | None | Machine account | The service genuinely needs full local privilege (rare) |
| `NetworkService` | None | Machine account | Legacy; shared with other services in the same identity |
| `LocalService` | None | Anonymous on the network | No network resources, minimal local rights |
| Virtual account `NT SERVICE\<Name>` | None | Machine account | Per-service local isolation, network access as the machine |
| IIS `ApplicationPoolIdentity` | None | Machine account | Every IIS application pool, by default |
| Standalone MSA | AD-managed, auto-rotated | Yes, one host | Domain resources needed from exactly one server |
| gMSA | AD-managed, auto-rotated, retrievable only by named hosts | Yes, many hosts | A cluster, a load-balanced farm, or a scheduled task on several nodes |

Virtual accounts and `ApplicationPoolIdentity` have no password anywhere, so there is nothing for
an attacker to dump or replay. They still authenticate outbound as the machine account, which is
why "the service needs to read a file share" is not by itself a reason to create a domain user -
ACL the share to the computer account or to a group containing it.

## gMSA setup

Once per forest, on a domain controller. `-EffectiveImmediately` skips the default ten-day wait;
in a production forest with more than one DC, let replication settle instead.

```powershell
# Once per forest. Requires Domain Admins or Enterprise Admins.
Add-KdsRootKey -EffectiveImmediately
```

Create the account and name the hosts allowed to retrieve its password:

```powershell
$hosts = Get-ADComputer -Filter 'Name -like "WEB0*"'

$gmsa = @{
    Name                                       = 'svc_acmeweb'
    DNSHostName                                = 'svc_acmeweb.contoso.example'
    SamAccountName                             = 'svc_acmeweb'
    PrincipalsAllowedToRetrieveManagedPassword = $hosts
    KerberosEncryptionType                     = 'AES256'
    ManagedPasswordIntervalInDays              = 30
    Enabled                                    = $true
    Description                                = 'Acme web farm app pool identity. Owner: platform team.'
}
New-ADServiceAccount @gmsa
```

On each member server:

```powershell
Install-ADServiceAccount -Identity 'svc_acmeweb'
Test-ADServiceAccount   -Identity 'svc_acmeweb'   # must return True before you repoint the service
```

Point the service at it. The trailing `$` and the empty password are both required.

```powershell
# Grant "Log on as a service" to CONTOSO\svc_acmeweb$ first, or the service will not start.
sc.exe config AcmeSync obj= 'CONTOSO\svc_acmeweb$' password= ''
Restart-Service AcmeSync
```

For an IIS application pool:

```powershell
Import-Module WebAdministration
Set-ItemProperty 'IIS:\AppPools\AcmeWeb' -Name processModel.identityType   -Value SpecificUser
Set-ItemProperty 'IIS:\AppPools\AcmeWeb' -Name processModel.userName       -Value 'CONTOSO\svc_acmeweb$'
Set-ItemProperty 'IIS:\AppPools\AcmeWeb' -Name processModel.password       -Value ''
```

`ManagedPasswordIntervalInDays` can only be set at creation. It is read-only afterwards.

## Auditing what you already have

Find services not running as one of the built-in identities:

```powershell
Get-CimInstance Win32_Service |
    Where-Object { $_.StartName -notin @(
        'LocalSystem', 'NT AUTHORITY\LocalService', 'NT AUTHORITY\NetworkService', $null
    ) } |
    Select-Object Name, StartName, PathName, StartMode |
    Sort-Object StartName
```

Then check whether any of those accounts is privileged in the domain:

```powershell
'svc_admin','svc_sql','svc_backup' | ForEach-Object {
    $g = Get-ADPrincipalGroupMembership $_ -ErrorAction SilentlyContinue
    [pscustomobject]@{
        Account = $_
        Groups  = ($g.Name -join ', ')
    }
}
```

Any result containing Domain Admins, Enterprise Admins, Schema Admins, Account Operators, or
Backup Operators is a critical finding (A01:2025, CWE-250). Backup Operators is on the list
because `SeBackupPrivilege` and `SeRestorePrivilege` bypass file ACLs entirely - Microsoft's own
description of `SeBackupPrivilege` says it "causes the system to grant all read access control to
any file, regardless of the access control list".

## Privileges that matter for a service account

Verified against the event 4672 privilege table
(<https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672>).

| Privilege | Right name | Why it matters |
|---|---|---|
| `SeImpersonatePrivilege` | Impersonate a client after authentication | Lets the process act as any account that authenticates to it. The pivot in most service-to-SYSTEM escalations |
| `SeAssignPrimaryTokenPrivilege` | Replace a process-level token | Lets the process start a child under a different token |
| `SeDebugPrivilege` | Debug programs | Attach to any process, including LSASS. Administrators only |
| `SeBackupPrivilege` / `SeRestorePrivilege` | Back up / restore files and directories | Read or write any file regardless of ACL |
| `SeTcbPrivilege` | Act as part of the operating system | Impersonate any user without authentication |
| `SeEnableDelegationPrivilege` | Enable accounts to be trusted for delegation | Can mark an account trusted for delegation |

`SeImpersonatePrivilege` is held by `LocalSystem`, `NetworkService`, `LocalService`, and members
of Administrators and IIS_IUSRS by default. That is expected for a web worker process - it needs
to impersonate the authenticated caller. It is not expected on an arbitrary domain user you
created for a batch job. Check with:

```powershell
whoami /priv
```

Run it as the service account (via `PsExec`-style service context or a scheduled task under that
identity) rather than assuming from the account's group membership.

## Sources

- `New-ADServiceAccount` -
  <https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adserviceaccount>,
  checked 2026-07-28
- `Add-KdsRootKey` - <https://learn.microsoft.com/en-us/powershell/module/kds/add-kdsrootkey>,
  checked 2026-07-28
- IIS Application Pool Identities -
  <https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities>,
  checked 2026-07-28
- Event 4672 privilege table -
  <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672>,
  checked 2026-07-28
