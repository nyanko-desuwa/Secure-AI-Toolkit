# Audit Policy and Event IDs

Every ID below was checked on 2026-07-28 against Microsoft Learn. Each row names the subcategory
that has to be enabled, because an event ID with no audit subcategory behind it is a detection
rule that will never fire.

IDs marked "not verified" are commonly cited elsewhere but were not confirmed against Microsoft
documentation on the check date. Do not put those in a collection list without checking first.

## Verified event IDs

| ID | Meaning | Subcategory | Category |
|---|---|---|---|
| 4624 | An account was successfully logged on | Audit Logon | Logon/Logoff |
| 4625 | An account failed to log on | Audit Logon, Audit Account Lockout | Logon/Logoff |
| 4672 | Special privileges assigned to new logon | Audit Special Logon | Logon/Logoff |
| 4688 | A new process has been created | Audit Process Creation | Detailed Tracking |
| 4697 | A service was installed in the system | Audit Security System Extension | System |
| 4719 | System audit policy was changed | Audit Audit Policy Change | Policy Change |
| 4720 | A user account was created | Audit User Account Management | Account Management |
| 4728 | A member was added to a security-enabled global group | Audit Security Group Management | Account Management |
| 4732 | A member was added to a security-enabled local group | Audit Security Group Management | Account Management |
| 4756 | A member was added to a security-enabled universal group | Audit Security Group Management | Account Management |
| 4799 | A security-enabled local group membership was enumerated | Audit Security Group Management | Account Management |

Notes that change how you use these:

- 4728, 4732, and 4756 are the same event for global, local, and universal groups. A rule that
  only watches 4728 misses a local Administrators addition on a member server, which is the one
  you care about most on a web host.
- 4697 records the service account configured at install time. Microsoft's own monitoring guidance
  is useful as a rule: alert when `Service File Name` is outside `%windir%` or Program Files, when
  `Service Type` is `0x1`, `0x2`, or `0x8` (driver types), when `Service Start Type` is `0` or `1`
  (driver start), and when `Service Account` is not `localSystem`, `localService`, or
  `networkService`. That last one finds exactly the finding this skill opens with.
- 4697 also does not record a later change to the image path. Microsoft says that has to be
  tracked through process-creation events instead.
- 4672 fires for every SYSTEM logon, so it is noisy by default. It earns its place because the
  event body lists the privileges assigned, including `SeImpersonatePrivilege`,
  `SeAssignPrimaryTokenPrivilege`, `SeDebugPrivilege`, and `SeEnableDelegationPrivilege`. Filter
  on the subject not being LOCAL SYSTEM, NETWORK SERVICE, or LOCAL SERVICE, and on privileges you
  have decided should never appear.
- 4719 is the tell that basic audit policy overwrote your advanced audit policy. Collect it or you
  will not know your audit configuration was silently replaced.
- 4720 has a long field list. Two worth alerting on: `Allowed To Delegate To` not `-` on a new
  account, and the `Trusted For Delegation` account-control flag enabled.

## Not verified on 2026-07-28

| ID | Commonly cited as | Status |
|---|---|---|
| 7045 | Service Control Manager, "a service was installed in the system", System log | Could not confirm against Microsoft documentation. The Security-log equivalent, 4697, is verified above and is subject to audit policy, which 7045 is not. If you want the System-log source, verify it on your own host with `Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045}` before writing a rule |

Service installation is worth collecting from both logs where you can: 4697 is auditable and
attributable, and the System-log source survives audit policy being turned off.

## Legacy privilege-use IDs

The pre-Vista basic audit policy setting "Audit privilege use" produces 576, 577, and 578 rather
than the 4xxx range. If you see those IDs, the host is on basic audit policy, not advanced.

Microsoft also documents that privilege-use auditing suppresses a specific set of rights unless
the `FullPrivilegeAuditing` registry key is enabled: bypass traverse checking, debug programs,
create a token object, replace process level token, generate security audits, back up files and
directories, restore files and directories. That means `SeAssignPrimaryTokenPrivilege` use is
*not* audited by default. Enabling full privilege auditing generates a large volume of events and
Microsoft warns it can affect performance. Treat 4672 at logon as the practical signal instead.

## Enabling what these depend on

Process creation without the command line tells you `wscript.exe` ran. With the command line it
tells you which script. Two settings, both required:

| Setting | Path |
|---|---|
| Audit Process Creation | Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Configuration > Detailed Tracking |
| Include command line in process creation events | Computer Configuration > Administrative Templates > System > Audit Process Creation |

Microsoft's own warning on the second one, and it is a real tradeoff: "any user with access to
read the security events will be able to read the command line arguments for any successfully
created process. Command line arguments can contain sensitive or private information such as
passwords or user data." Enable it, and then treat the Security log as sensitive: restrict who
can read it, and stop passing secrets as command-line arguments.

Stop basic audit policy from overwriting the advanced configuration:

- Computer Configuration > Windows Settings > Security Settings > Local Policies > Security
  Options > "Audit: Force audit policy subcategory settings (Windows Vista or later) to override
  audit policy category settings" → Enabled.

Then verify what is actually effective on the host, not what the GPO says:

```powershell
auditpol.exe /get /category:*
auditpol.exe /get /subcategory:"Process Creation","Security System Extension","Special Logon"
```

Reading a GPO backup does not prove the effective setting. `auditpol /get` does.

## Related logs worth collecting

| Log | Events | Why |
|---|---|---|
| `Microsoft-Windows-PowerShell/Operational` | 4104 (script block logging) | Records the content of every script block processed, including one assembled at runtime. Windows PowerShell 5.1 provider GUID `{A0C1853B-5C40-4B15-8766-3CF1C58F985A}` |
| `PowerShellCore/Operational` | 4104 | Same for PowerShell 7.x. The provider must be registered first with `$PSHOME\RegisterManifest.ps1` |
| `...\Windows\CodeIntegrity\Operational` | 3065, 3066 (audit mode); 3033, 3063 (enforced) | LSA plug-ins and drivers that fail, or would fail, to load under LSA protection |
| `Windows Logs\System` | WinInit 12 | "LSASS.exe was started as a protected process with level: 4" confirms LSA protection is actually on |
| `...\Windows\Authentication\ProtectedUser*` | 104, 304, 100, 303 | Protected Users behaviour and failures. Disabled by default; enable per log in Event Viewer |
| `...\Windows\SMBServer\Audit` | 3021, 3022 | Clients that do not support signing or encryption (Windows 11 24H2+) |
| `...\Windows\SMBClient\Audit` | 31998, 31999 | Servers that do not support signing or encryption (Windows 11 24H2+) |

Script block logging deserves a warning of its own. Microsoft recommends enabling Protected Event
Logging alongside it, because a script's own credentials end up in the log otherwise. Protected
Event Logging encrypts the entry with a public key using CMS; the private key stays on the
collector, not on the logging host. The certificate needs Document Encryption
(`1.3.6.1.4.1.311.80.1`) as an EKU and either Data Encipherment or Key Encipherment.

## Forwarding and alerting

Collection is not detection. For each event above, name the rule; for each rule, name the event.
`core/logging-audit` covers the pipeline, retention, and the deadman rule that fires when a
stream goes quiet. Windows Event Forwarding or a SIEM agent both work; what matters is that the
events leave the host, because a local administrator can clear the Security log.

## Sources

- Advanced security audit policy settings -
  <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/advanced-security-audit-policy-settings>,
  checked 2026-07-28
- Command line process auditing -
  <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing>,
  checked 2026-07-28
- Event 4625 -
  <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625>,
  checked 2026-07-28
- Event 4672 -
  <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672>,
  checked 2026-07-28
- Event 4697 -
  <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4697>,
  checked 2026-07-28
- Event 4720 -
  <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720>,
  checked 2026-07-28
- Audit Security Group Management -
  <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-group-management>,
  checked 2026-07-28
- Audit privilege use (legacy) -
  <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/basic-audit-privilege-use>,
  checked 2026-07-28
- `about_Logging` (5.1) and `about_Logging_Windows` (7.x) -
  <https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging>,
  checked 2026-07-28
- Configure added LSA protection -
  <https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection>,
  checked 2026-07-28
- Protected Users security group -
  <https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group>,
  checked 2026-07-28
