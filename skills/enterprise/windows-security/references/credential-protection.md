# Credential Protection on Windows

What each control actually stops, and what it does not. Checked 2026-07-28 against Microsoft Learn:
Credential Guard overview
(<https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/>),
Configure added LSA protection
(<https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection>),
Protected Users security group
(<https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group>),
and Remote Credential Guard
(<https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard>).

## The mechanism

LSASS validates logons and holds the secrets that make single sign-on work: NTLM hashes, Kerberos
TGTs and long-term keys, and credentials applications stored as domain credentials. A local
administrator with `SeDebugPrivilege` can open that process and read them. Nothing about that is
exotic; it is what the privilege is for.

So the question on any member server is not "can LSASS be read" but "what is worth reading in
there". Every control below reduces the answer.

## Credential Guard

Uses virtualization-based security to move NTLM hashes, Kerberos derived credentials, and
application-stored domain credentials into an isolated process (`LSAIso.exe`) that the running OS
cannot read. Microsoft states plainly that malware running in the OS with administrative privileges
cannot extract VBS-protected secrets.

Requirements: VBS, Secure Boot. TPM recommended for hardware binding, UEFI lock recommended so a
registry change cannot turn it off. Hyper-V guests must be generation 2 with an IOMMU on the host.

Default enablement: on by default in Windows 11 22H2+ and Windows Server 2025 for domain-joined,
non-DC systems meeting hardware requirements, without UEFI lock. If Credential Guard was explicitly
disabled before the upgrade, the upgrade does not re-enable it.

What breaks, per Microsoft: Kerberos DES, Kerberos unconstrained delegation, Kerberos TGT
extraction, NTLMv1. Digest, credential delegation, MS-CHAPv2, and CredSSP still work but expose
credentials. Note the second item - if unconstrained delegation is configured anywhere in the
path, Credential Guard breaks it. That is a feature; fix the delegation.

Where not to enable it: domain controllers (Microsoft says it adds no security there and causes
compatibility issues) and Exchange Server (unsupported, performance issues).

Honest limits Microsoft states: it does not protect the AD database or the SAM, and it does not
protect a VM's secrets from a privileged attack originating on the Hyper-V host.

## LSA protection (RunAsPPL)

Runs LSASS as a protected process so non-protected processes cannot read its memory or inject code.
Complementary to Credential Guard, not a replacement - enable both.

```powershell
# Enabled with UEFI lock (1) or without (2). Value 2 is enforced on Win11 22H2+ / Server 2025+.
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Type DWord -Value 1
# Reboot required.
```

Audit before enforcing. Any LSA plug-in or driver - smart card drivers, cryptographic plug-ins,
password filters - must be signed with a Microsoft signature or it will fail to load.

```powershell
# Audit mode: log what would fail, block nothing.
$ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe'
New-Item -Path $ifeo -Force | Out-Null
Set-ItemProperty -Path $ifeo -Name AuditLevel -Type DWord -Value 8
# Then read CodeIntegrity/Operational for 3065 and 3066.
```

Audit mode is on by default on Windows 11 22H2 and later. Audit events are not generated when Smart
App Control is enabled, or when a kernel debugger is attached.

Confirm it took effect from the System log, not the registry: WinInit event 12,
"LSASS.exe was started as a protected process with level: 4".

Two consequences worth knowing. With UEFI lock set, clearing the registry value does nothing - the
UEFI variable has to be removed with Microsoft's LSA Protected Process Opt-out tool. And you cannot
attach a debugger to a protected LSASS, so a custom LSA plug-in becomes undebuggable.

## WDigest

WDigest could cache plaintext credentials in LSASS. The behaviour is controlled by
`UseLogonCredential` under
`HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`. Setting it to `0` disables
plaintext caching; the value being absent or `1` on an older or tampered host means plaintext is
available.

The verification worth doing is that the value is `0` or absent-and-defaulting-safe on your OS
version, and that nothing in your configuration management sets it to `1`. Check it, do not assume:

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' `
    -Name UseLogonCredential -ErrorAction SilentlyContinue
```

If a hardening baseline sets it explicitly to `0`, leave it explicit. An explicit safe value
survives a host being rebuilt from an old image; a default does not.

Protected Users membership makes this moot for those accounts - Microsoft states Windows Digest
does not cache a Protected User's plaintext credentials even when Windows Digest is enabled.

## Protected Users group

A domain global security group, well-known RID 525. Membership triggers non-configurable
protections. Domain functional level must be Windows Server 2012 R2 or later.

On the device where a member signs in:

- CredSSP does not cache plaintext credentials, even with "Allow delegating default credentials" on
- Windows Digest does not cache plaintext credentials
- NTLM does not cache plaintext credentials or the NT one-way function
- Kerberos does not create DES or RC4 keys, and does not cache plaintext credentials or long-term
  keys after the initial TGT
- No cached verifier is created, so offline sign-in stops working for that account

At the domain controller, a Protected User cannot authenticate with NTLM, cannot use DES or RC4 in
Kerberos preauthentication, cannot delegate with unconstrained *or* constrained delegation, and
cannot renew a TGT beyond its initial four-hour lifetime. The group forces the TGT lifetime and
renewal to 240 minutes and the member cannot change it.

Two warnings from Microsoft, both worth repeating verbatim in effect:

- Never add service or computer accounts. Membership gives them no local protection because the
  password or certificate is always available on the host, and authentication fails with "the user
  name or password is incorrect".
- Do not add accounts already in Domain Admins or Enterprise Admins until you have tested. Highly
  privileged users get the same non-configurable restrictions as anyone else, and you can lock the
  account out. The built-in Administrator (RID 500) is always exempt from authentication policies.

AES keys are required. An account whose password was last set by a pre-2008 DC, or that was
migrated from another domain without a password reset, has no AES key and will be locked out of
authentication on joining the group.

Troubleshooting logs live under `Applications and Services Logs\Microsoft\Windows\Authentication`
and are disabled by default. Enable each one in Event Viewer. Relevant IDs: 104 and 304 on
ProtectedUser-Client, 100 and 104 on ProtectedUserFailures-DomainController, 303 on
ProtectedUserSuccesses-DomainController.

## RDP: Restricted Admin and Remote Credential Guard

Plain RDP sends the credential to the remote host, stores it there, and leaves it usable by an
attacker on that host after you disconnect. That is the lateral-movement path.

| Property | Plain RDP | Remote Credential Guard | Restricted Admin |
|---|---|---|---|
| Credentials sent to remote host | Yes | No | No |
| SSO to other systems as the signed-in user | Yes | Yes | No |
| Prevents use of credentials after disconnect | No | Yes | Yes |
| Prevents pass-the-hash | No | Yes | Yes |
| Supported authentication | Any negotiable | Kerberos only | Any negotiable |
| RDP access granted by | Remote Desktop Users | Remote Desktop Users | Administrators |

Remote Credential Guard redirects Kerberos requests back to the connecting device. Restricted Admin
connects as the remote host's own identity, so it cannot reach further resources as you.

Which to use: Microsoft recommends Restricted Admin (`mstsc.exe /RestrictedAdmin`) for helpdesk
support, because if the *client* is already compromised, an attacker can ride an open Remote
Credential Guard channel and act as the user for the life of the session and briefly after.

Enable on the remote host - required for both modes:

```
Computer Configuration\Administrative Templates\System\Credentials Delegation
  => "Remote host allows delegation of nonexportable credentials" = Enabled
```

Registry equivalent: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`, `DisableRestrictedAdmin`
(REG_DWORD) = `0`.

Enforce on the client:

```
Computer Configuration\Administrative Templates\System\Credentials Delegation
  => "Restrict delegation of credentials to remote servers" = Enabled
     "Restrict Credential Delegation"  (prefers RCG, falls back to Restricted Admin)
     or "Require Remote Credential Guard"
```

One-off without policy: `mstsc.exe /remoteGuard`.

Limits: Remote Credential Guard needs Kerberos and does not allow NTLM fallback, works only against
AD-joined remote hosts (not Microsoft Entra joined), does not support compound authentication, works
only for direct connections - not through Connection Broker or RD Gateway - and the Remote Desktop
UWP app does not support it. When "Restrict Credential Delegation" is enabled the
`/restrictedAdmin` switch is ignored in favour of the policy.

Also deploy Windows LAPS. Microsoft raises it in the same breath as these controls, because a shared
local administrator password across a fleet makes every one of the above irrelevant for lateral
movement.

## What none of this fixes

- A service account with a human-set password in a domain group that grants it real privilege. There
  is no memory-protection feature that helps; change the identity.
- A secret in a config file on disk. That is `core/secrets-management`, not LSASS.
- A domain controller. Credential Guard is not recommended there and the AD database is out of
  scope for it. Tier-0 hosts are protected by not letting anything else touch them.

## Sources

- Credential Guard overview -
  <https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/>,
  checked 2026-07-28
- Configure added LSA protection -
  <https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection>,
  checked 2026-07-28
- Protected Users security group -
  <https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group>,
  checked 2026-07-28
- Credentials Protection and Management -
  <https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management>,
  checked 2026-07-28
- Remote Credential Guard -
  <https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard>,
  checked 2026-07-28
- Windows LAPS - <https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview>
