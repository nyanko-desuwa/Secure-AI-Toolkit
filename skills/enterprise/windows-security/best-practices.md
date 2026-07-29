# Windows and .NET Best Practices

Each pattern names its Top 10 category, ASVS chapter, and CWE. Vulnerable blocks are deliberate.
Commands, event IDs, and paths were checked against the Microsoft sources in `references/`.

## Service identity

`A01:2025` · ASVS V13 · CWE-250, CWE-269

```powershell
# Vulnerable: tier-0 credential in a tier-1 service process and deployment history
sc.exe config AcmeSync obj= 'CONTOSO\svc_admin' password= 'Placeholder-only'
```

```powershell
# Fixed when no domain access is needed: no password exists
sc.exe config AcmeSync obj= 'NT SERVICE\AcmeSync' password= ''

# Fixed when a web farm needs domain access
$farm = Get-ADComputer -Filter 'Name -like "WEB0*"'
New-ADServiceAccount -Name 'svc_acmeweb' `
    -DNSHostName 'svc_acmeweb.contoso.example' `
    -PrincipalsAllowedToRetrieveManagedPassword $farm `
    -KerberosEncryptionType AES256 -Enabled $true
Install-ADServiceAccount -Identity 'svc_acmeweb'
Test-ADServiceAccount -Identity 'svc_acmeweb' # must be True before cutover
# WARNING: grant Log on as a service first or restart fails.
sc.exe config AcmeSync obj= 'CONTOSO\svc_acmeweb$' password= ''
```

The virtual account has no password. AD generates and rotates the gMSA password; only named hosts
can retrieve it. Grant either identity only the share, database, and local paths it needs. A long
password on the Domain Admin account leaves the tier-0 token in LSASS and is not a fix.

## Credential exposure

`A04:2025` · ASVS V14 · CWE-522

```powershell
# Vulnerable: configured state shows no LSA protection
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
    -Name RunAsPPL -ErrorAction SilentlyContinue
```

```powershell
# Fixed: audit incompatible LSA plug-ins, then enforce without UEFI lock on Server 2025
$audit = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe'
New-Item $audit -Force | Out-Null
Set-ItemProperty $audit -Name AuditLevel -Type DWord -Value 8
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
    -Name RunAsPPL -Type DWord -Value 2 # reboot required
```

After audit mode, inspect CodeIntegrity events 3065/3066. After reboot, confirm System-log WinInit
event 12 says LSASS started as a protected process. A registry export proves intent, not operation.

Enable Credential Guard on eligible domain-joined non-DC hosts. It moves NTLM hashes, Kerberos TGTs,
and application domain credentials into VBS isolation. It breaks DES, NTLMv1, TGT extraction, and
unconstrained delegation; fix those dependencies rather than disabling it fleet-wide.

Use Protected Users for tested privileged humans. Never add service or computer accounts. Test AES,
NTLM, delegation, CredSSP, offline-sign-in, and four-hour TGT compatibility before adding a Domain
Admin. Use Restricted Admin RDP for helpdesk paths and Remote Credential Guard for direct Kerberos
RDP where SSO is needed. Use Windows LAPS so one local-admin password does not open every host.

WDigest plaintext caching must be disabled. Protected Users prevents it for members. The commonly
cited machine-wide registry value could not be verified against Microsoft Learn during research, so
this skill does not reproduce it. Use the current Microsoft baseline or verify the value first.

## File-system and registry ACLs

`A01:2025` · ASVS V13 · CWE-428, CWE-732, CWE-276

### Unquoted path

```powershell
# Vulnerable
sc.exe create AcmeAgent binPath= 'C:\Program Files\Acme Agent\agent.exe --run' start= auto

# Fixed: quote executable; arguments remain outside
sc.exe config AcmeAgent binPath= '"C:\Program Files\Acme Agent\agent.exe" --run'
```

Microsoft documents that an unquoted `CreateProcess` path tries each whitespace break in order.
Quoting closes that ambiguity. It does not close a writable directory.

### Writable binary directory

```powershell
# Vulnerable: Users can replace code run by the service
icacls 'C:\Program Files\Acme Agent'
# BUILTIN\Users:(OI)(CI)(M)
```

```powershell
# Fixed. WARNING: confirm deploy and service identities before replacing inheritance.
icacls 'C:\Program Files\Acme Agent' /inheritance:r `
  /grant 'BUILTIN\Administrators:(OI)(CI)(F)' `
  /grant 'NT AUTHORITY\SYSTEM:(OI)(CI)(F)' `
  /grant 'NT SERVICE\AcmeAgent:(OI)(CI)(RX)'
New-Item -ItemType Directory 'C:\ProgramData\Acme\state' -Force | Out-Null
icacls 'C:\ProgramData\Acme\state' /inheritance:r `
  /grant 'BUILTIN\Administrators:(OI)(CI)(F)' `
  /grant 'NT AUTHORITY\SYSTEM:(OI)(CI)(F)' `
  /grant 'NT SERVICE\AcmeAgent:(OI)(CI)(M)'
```

Code stays read-only; required writes go to a separate state path.

### Writable service registry key

```powershell
# Vulnerable
Get-Acl 'HKLM:\SYSTEM\CurrentControlSet\Services\AcmeAgent' |
    Select-Object -ExpandProperty AccessToString
# BUILTIN\Users Allow FullControl
```

```powershell
# Fixed: use the Security Compliance Toolkit's SetObjectSecurity tool or Set-Acl to leave
# Administrators and SYSTEM FullControl and NT SERVICE\AcmeAgent ReadKey only.
# Verify the effective DACL with Get-Acl after deployment.
```

Do not publish a generic ACL-replacement script that discards service-specific ACEs. Build the DACL
from the actual service requirements. Path quoting, directory ACL, and registry ACL are independent.

## Kerberos delegation and SPNs

`A01:2025` · ASVS V13 · CWE-269, CWE-522

```powershell
# Vulnerable: every caller's forwardable TGT is available on WEB01
Set-ADComputer 'WEB01' -TrustedForDelegation $true
```

```powershell
# Fixed: the resource permits only WEB01 to act on its behalf
Set-ADComputer 'SQL01' -PrincipalsAllowedToDelegateToAccount (Get-ADComputer 'WEB01')
# WARNING: remove old trust only after the RBCD path succeeds.
Set-ADComputer 'WEB01' -TrustedForDelegation $false
Set-ADComputer 'WEB01' -Clear 'msDS-AllowedToDelegateTo'
```

RBCD limits compromise to resources whose owners opted in. Write access to the resource computer
object is therefore security-critical. If the back end must distinguish real authentication from
service assertion, check `S-1-18-1` versus `S-1-18-2` in its ACL.

```powershell
# Vulnerable inventory: SPNs on ordinary users expose weak service-account passwords offline
Get-ADUser -LDAPFilter '(servicePrincipalName=*)' `
    -Properties servicePrincipalName,PasswordLastSet

# Fixed account property after moving the service to a gMSA
Set-ADServiceAccount 'svc_acmeweb' -KerberosEncryptionType AES256
```

Move SPNs to gMSAs. If impossible, use a long random vaulted password and rotate it. Password
complexity does not defeat offline guessing of a short password. No attack tooling belongs here.

## SMB signing and NTLM relay

`A04:2025` · ASVS V12 · CWE-319, CWE-306

NTLM does not bind authentication proof to its channel. SMB signing binds messages to the session.

```powershell
# Vulnerable: ignored for SMB2 and later
Set-ItemProperty 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters' `
    -Name EnableSecuritySignature -Type DWord -Value 1
```

```powershell
# Fixed: require signing inbound and outbound
Set-ItemProperty 'HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters' `
    -Name RequireSecuritySignature -Type DWord -Value 1
Set-ItemProperty 'HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters' `
    -Name RequireSecuritySignature -Type DWord -Value 1
```

Audit incompatible peers before enforcement:

```powershell
Set-SmbServerConfiguration -AuditClientDoesNotSupportSigning $true
Set-SmbClientConfiguration -AuditServerDoesNotSupportSigning $true
```

Also require LDAP signing and channel binding, and Extended Protection on IIS Windows authentication.
Do not connect by IP or CNAME where Kerberos is expected; Microsoft notes that this falls back to
NTLM.

## PowerShell and JEA

`A02:2025` · A09:2025 · ASVS V13, V16 · CWE-269, CWE-778

Execution policy is not a security boundary. Microsoft says it is not a system that restricts user
actions and can be bypassed by typing script contents at the command line.

```powershell
# Vulnerable: ordinary operator receives domain-wide privilege for one restart
Add-ADGroupMember -Identity 'Domain Admins' -Members 'CONTOSO\dns_operator'
```

```powershell
# Fixed role capability: exact cmdlets, exact parameter values
@{
  VisibleCmdlets = @(
    @{Name='Restart-Service';Parameters=@{Name='Name';ValidateSet=@('Dns','Spooler')}}
    @{Name='Get-Service';Parameters=@{Name='Name';ValidateSet=@('Dns','Spooler')}}
  )
}
```

```powershell
$roles = @{'CONTOSO\JEA_Ops'=@{RoleCapabilities='AcmeOps'}}
New-PSSessionConfigurationFile -Path .\JEAConfig.pssc `
  -SessionType RestrictedRemoteServer -RunAsVirtualAccount `
  -TranscriptDirectory 'C:\ProgramData\JEAConfiguration\Transcripts' `
  -RoleDefinitions $roles -RequiredGroups @{Or='2FA-logon','smartcard-logon'}
Test-PSSessionConfigurationFile .\JEAConfig.pssc
Register-PSSessionConfiguration -Name 'AcmeOps' -Path .\JEAConfig.pssc -Force
```

Do not expose `Start-Process`, `New-Service`, `Invoke-Expression`, `Invoke-Command`, group-member
cmdlets, or `net.exe`. Custom function bodies run in the default language mode, not JEA's language
constraint. ACL role files to trusted administrators and use unique capability filenames.

Enable script-block logging through the verified Windows PowerShell policy path; event 4104 lands in
`Microsoft-Windows-PowerShell/Operational`. Enable Protected Event Logging too, because script
contents can contain credentials. Use AppLocker or WDAC for application control; Constrained
Language Mode is an effect of application control, not of execution policy.

## IIS configuration and errors

`A02:2025` · A10:2025 · ASVS V13, V16 · CWE-209, CWE-276

```xml
<!-- Vulnerable -->
<configuration>
  <system.web><customErrors mode="Off"/><compilation debug="true"/></system.web>
  <system.webServer><directoryBrowse enabled="true"/></system.webServer>
</configuration>
```

```xml
<!-- Fixed -->
<configuration>
  <system.web>
    <customErrors mode="On" defaultRedirect="~/error"/>
    <compilation debug="false"/>
    <httpRuntime enableVersionHeader="false" maxRequestLength="4096"/>
  </system.web>
  <system.webServer>
    <directoryBrowse enabled="false"/>
    <httpProtocol><customHeaders><remove name="X-Powered-By"/></customHeaders></httpProtocol>
    <security><requestFiltering>
      <requestLimits maxAllowedContentLength="4194304" maxUrl="2048" maxQueryString="1024"/>
    </requestFiltering></security>
  </system.webServer>
</configuration>
```

Use one `ApplicationPoolIdentity` pool per app. ACL content Read/Execute to
`IIS AppPool\<PoolName>` and writable uploads/state outside the web root. `customErrors="On"` avoids
a proxy making a remote request look local. Server-header removal varies by IIS version; verify it
for the installed version rather than copying an unverified setting.

```csharp
// Vulnerable
app.UseDeveloperExceptionPage();

// Fixed
if (app.Environment.IsDevelopment()) app.UseDeveloperExceptionPage();
else { app.UseExceptionHandler("/error"); app.UseHsts(); }
```

Confirm production `ASPNETCORE_ENVIRONMENT` on the host. Source cannot prove it.

## Secrets and Data Protection

`A04:2025` · ASVS V14 · CWE-798, CWE-522

Vulnerable `appsettings.json`:

```json
{"ConnectionStrings":{"Default":"Server=sql01;User Id=app;Password=Placeholder-only;"}}
```

Fixed with a gMSA:

```json
{"ConnectionStrings":{"Default":"Server=sql01.contoso.example;Database=Billing;Integrated Security=true;Encrypt=true;"}}
```

Use user secrets only in development. In production use integrated authentication, DPAPI, or a
vault. Rotate a committed credential; deletion does not remove git history.

```csharp
// Vulnerable: per-machine ring breaks cookies across nodes
builder.Services.AddDataProtection();

// Fixed: shared ring, stable app discriminator, certificate protection
builder.Services.AddDataProtection()
  .SetApplicationName("Billing")
  .PersistKeysToFileSystem(new DirectoryInfo(@"\\fileserver\keys\billing\"))
  .ProtectKeysWithCertificate(builder.Configuration["CertificateThumbprint"]!);
```

Give only the app identity read/write/create on the key store. Encryption at rest does not stop an
attacker who can write a new key. Use the same app name across its nodes and a different name for
other applications.

## Audit policy

`A09:2025` · ASVS V16 · CWE-778

```powershell
# Vulnerable: one intended setting, effective policy unknown
auditpol.exe /get /category:*
```

```powershell
# Fixed subcategories
AuditPol /set /subcategory:'Logon','Special Logon','Process Creation' /success:enable
AuditPol /set /subcategory:'Security Group Management','User Account Management' /success:enable
AuditPol /set /subcategory:'Security System Extension' /success:enable
AuditPol /set /subcategory:'Logon' /failure:enable
AuditPol /get /subcategory:'Logon','Special Logon','Process Creation','Security Group Management','User Account Management','Security System Extension'
```

Also enable the verified policy "Include command line in process creation events", and force
advanced subcategories to override basic audit policy. Command lines may contain secrets, so restrict
Security-log access. Forward verified 4624/4625, 4672, 4688, 4697, 4719, 4720, and
4728/4732/4756 to the SIEM. See [references/audit-event-ids.md](references/audit-event-ids.md).

## Baseline, patching, containers, and data at rest

`A02:2025` · A04:2025 · ASVS V13, V14 · CWE-276

Vulnerable: a one-time GPO import, unused roles still installed, an exclusion covering a writable
application tree, and Windows containers treated like Linux user-namespace containers.

Fixed: apply the exact CIS or SCT baseline for the OS, check effective `gpresult` and `auditpol`,
diff periodically with Policy Analyzer, use update rings with reboot ownership, remove unused roles,
and reject broad Defender exclusions. Use AppLocker or WDAC in audit mode before enforcement.

Windows containers have no Linux-style user namespace boundary. Process isolation shares the host
kernel; trust the container like another process on the host. Hyper-V isolation gives each container
a utility VM and a stronger kernel boundary. Use Hyper-V isolation when tenant or workload trust
differs from the host; neither mode makes a privileged identity safe.

```powershell
# Fixed BitLocker shape: TPM protector; escrow a recovery protector under the enterprise policy
Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -TpmProtector
```

BitLocker and TPM-backed key protection address a stolen disk, disposed server, or copied VM image.
They do not protect a mounted volume from an attacker with a live session.

## Sources

- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>
- OWASP ASVS 5.0.0 - <https://owasp.org/www-project-application-security-verification-standard/>
- Microsoft sources and check dates - [references/](references/)
