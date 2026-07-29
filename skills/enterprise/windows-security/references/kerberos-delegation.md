# Kerberos Delegation, SPNs, and NTLM

Verified 2026-07-28 against Microsoft Learn: Kerberos constrained delegation overview
(<https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview>),
Kerberos authentication overview
(<https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview>),
and SMB signing overview
(<https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview>).

## The three delegation models

| Model | Where it is configured | Blast radius |
|---|---|---|
| Unconstrained | On the delegating (front-end) account: "trust this computer for delegation to any service" | Every caller's forwarded TGT is available on that host. The host can impersonate them to anything |
| Constrained (KCD) | On the delegating account, listing target SPNs. Requires domain admin to set | Only the listed services, and historically only within one domain |
| Resource-based (RBCD) | On the resource (back-end) account, listing which front-ends may act on its behalf | Only that resource, decided by the resource owner. Works across domains |

Microsoft states the problem with the older model plainly: "any front-end service that could
delegate to a resource service represented a potential attack point. If a server that hosted a
front-end service was compromised, and it was configured to delegate to resource services, the
resource services could also be compromised."

Unconstrained delegation is the one to hunt for. A server configured for it receives forwardable
TGTs from every account that authenticates to it, including any administrator who happens to
connect. Compromise the host and you inherit those identities without touching a password.

## Find it

```powershell
# Unconstrained delegation (TRUSTED_FOR_DELEGATION) on computers and users.
Get-ADObject -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' `
             -Properties samAccountName, objectClass |
    Select-Object objectClass, samAccountName

# Constrained delegation targets.
Get-ADObject -LDAPFilter '(msDS-AllowedToDelegateTo=*)' -Properties msDS-AllowedToDelegateTo |
    Select-Object Name, msDS-AllowedToDelegateTo
```

Domain controllers legitimately appear in the first result. Anything else on that list needs a
written reason.

## Replace it with RBCD

Configure on the resource, naming the front-end principals. This sets
`msDS-AllowedToActOnBehalfOfOtherIdentity`.

```powershell
$frontEnd = Get-ADComputer 'WEB01'
Set-ADComputer 'SQL01' -PrincipalsAllowedToDelegateToAccount $frontEnd

# Then remove the old trust. WARNING: this breaks any flow that depended on it.
Set-ADComputer 'WEB01' -TrustedForDelegation $false
Set-ADComputer 'WEB01' -Clear 'msDS-AllowedToDelegateTo'
```

Why this closes the hole: the KDC now issues a service ticket for the back end only when the back
end's own attribute names the front end. Compromising `WEB01` yields impersonation to `SQL01` and
nothing else, and the `SQL01` owner made that decision.

Honest limitation: the KDC always allows protocol transition under RBCD, "as though the bit were
set". Microsoft's answer is two well-known SIDs the back end can use in an ACL to tell how the
caller was authenticated:

| SID | Meaning |
|---|---|
| `S-1-18-1` | Identity asserted by an authentication authority on proof of possession of client credentials |
| `S-1-18-2` | Identity asserted by a service |

If the back end must distinguish a real user logon from a service-asserted one, it has to check
for these. RBCD alone does not do it.

A second limitation: write access to the resource's account object is enough to add yourself to
`PrincipalsAllowedToDelegateToAccount`. RBCD moves the decision to the resource owner, so the ACL
on the computer object becomes security-relevant. Audit who can write it.

## Service principal names and Kerberoasting

An SPN maps a service instance to the account that runs it. Any authenticated domain user can
request a service ticket for any SPN, and part of that ticket is encrypted with a key derived
from the service account's password. That is the exposure: a weak password on an SPN-bearing user
account can be attacked offline, without touching the service.

The controls, in order of effect:

1. Run the service under a gMSA or a machine account. The password is 240 bytes of random data,
   rotated automatically. Offline attack is not viable. This removes the problem rather than
   raising its cost.
2. If a user account must hold the SPN, give it a long random password (25+ characters) held in a
   vault, and rotate it.
3. Force AES and remove RC4 for the account: `Set-ADServiceAccount -KerberosEncryptionType AES256`
   or the equivalent on the user object. Note that domain-joined systems and clustering manage
   `msDS-SupportedEncryptionTypes` themselves and can overwrite the flag.
4. Put privileged accounts in Protected Users, which stops DES and RC4 in preauthentication
   outright.

Inventory SPNs on user accounts - machine and gMSA accounts are fine, user accounts are the risk:

```powershell
Get-ADUser -LDAPFilter '(servicePrincipalName=*)' -Properties servicePrincipalName, PasswordLastSet |
    Select-Object SamAccountName, PasswordLastSet, @{n='SPNs';e={$_.servicePrincipalName -join ', '}}
```

The tempting wrong fix is a password complexity policy. Complexity does not defeat an offline
attack on a short password; length and randomness do, and an AD-managed password gives you both
for free.

This skill does not include Kerberoasting tooling. The mechanism above is what you need to
understand the control.

## Why NTLM relay works, and what stops it

NTLM proves possession of a credential but does not bind that proof to the channel it travelled
over. A machine-in-the-middle can therefore take the challenge-response exchange from one
connection and present it on another to a different service, authenticating as the victim without
ever learning the password.

The mitigations are per-protocol, and they work by binding the authentication to the session or
the channel:

| Protocol | Control | Effect |
|---|---|---|
| SMB | Require signing, both inbound and outbound | Every message carries a signature derived from the session key. A relayed session cannot produce valid signatures |
| LDAP | Channel binding plus require signing | Ties the authentication to the TLS channel |
| HTTP (IIS) | Extended Protection for Authentication | Same idea, for Windows Integrated auth |
| All | Prefer Kerberos; restrict or disable NTLM where you can | Removes the relayable exchange |

SMB signing policy, verified against the Microsoft page:

- Client: `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManWorkstation\Parameters`,
  value `RequireSecuritySignature`, `REG_DWORD`, `1`
- Server: `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters`,
  value `RequireSecuritySignature`, `REG_DWORD`, `1`

GPO path: Computer Configuration > Windows Settings > Security Settings > Local Policies >
Security Options, "Microsoft network client/server: Digitally sign communications (always)".

`EnableSecuritySignature` is ignored for SMB2 and later. Setting it and believing you are done is
a common mistake - signing for SMB 2.02+ is controlled solely by whether it is required.

Signing happens when either side requires it. It is skipped only when both sides have
`RequireSecuritySignature` set to 0.

Before enforcing across a fleet, find the clients and servers that would break. Windows 11 24H2
and later can audit this:

```powershell
Set-SmbServerConfiguration -AuditClientDoesNotSupportSigning $true
Set-SmbClientConfiguration -AuditServerDoesNotSupportSigning $true
```

Events land in `Applications and Services Logs\Microsoft\Windows\SMBServer\Audit` (IDs 3021,
3022) and `...\SMBClient\Audit` (IDs 31998, 31999).

Two operational notes from the same Microsoft page, both worth repeating to developers:

- Connecting to a share by IP address or CNAME causes NTLM to be used instead of Kerberos. A
  hardcoded IP in a connection string quietly downgrades the authentication.
- The session key is derived from the password, so signing and encryption are only as strong as
  the account's password. Another reason for machine-managed service account passwords.

## Encryption type configuration on Windows Server 2025

Kerberos on Windows Server 2025 and later no longer honours the legacy
`SupportedEncryptionTypes` `REG_DWORD` under
`HKEY_LOCAL_MACHINE\CurrentControlSet\Control\Lsa\Kerberos\Parameters`. Use the Group Policy
setting "Network security: Configure encryption types allowed for Kerberos" instead. A script
that writes that registry value is now a no-op on 2025; if you find one, it is not doing what its
author thinks.

## Sources

- Kerberos constrained delegation overview -
  <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview>,
  checked 2026-07-28
- Kerberos authentication overview -
  <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview>,
  checked 2026-07-28
- SMB signing overview -
  <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview>,
  checked 2026-07-28
- `New-ADServiceAccount` (delegation parameters) -
  <https://learn.microsoft.com/en-us/powershell/module/activedirectory/new-adserviceaccount>,
  checked 2026-07-28
