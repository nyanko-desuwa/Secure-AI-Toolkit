---
name: windows-security
description: 'Harden Windows Server and deploy .NET applications without handing out domain admin. Covers service accounts, gMSA, Kerberos delegation, LSASS and credential theft, ACL privilege escalation, PowerShell/JEA, WinRM/RDP, IIS and ASP.NET Core configuration, auditing, and AppLocker/WDAC. Maps to OWASP Top 10 2025 A01/A02/A04/A09, ASVS 5.0 V13/V14/V16, and CIS Windows Server Benchmarks. Triggers: "Windows Server", "IIS", "gMSA", "service account", "Kerberos", "PowerShell hardening", "web.config", "appsettings.json", "Active Directory", "bảo mật Windows", "máy chủ Windows".'
allowed-tools: Read, Write, Edit, Glob, Grep, Bash(ls:*), Bash(cat:*), WebSearch, WebFetch
---

# Windows Server and .NET Hardening

The finding that matters most in a Windows estate is almost never a missing patch. It is a
service running as a Domain Admin, because the password sits in LSASS on a member server that
a helpdesk account can log into.

## When to Use

- Choosing or reviewing the identity a Windows service, scheduled task, or IIS app pool runs as
- Writing or reviewing `web.config`, `appsettings.json`, or a `Program.cs` that configures ASP.NET Core
- Setting file system, registry, or service ACLs
- Configuring remote management: WinRM, RDP, JEA, a jump host
- Reviewing Kerberos delegation, SPNs, or an NTLM fallback
- Writing PowerShell that will run with privilege, or reviewing a script someone else wrote
- Designing what a Windows host forwards to a SIEM
- Building a deployment pipeline that publishes to IIS

## The Five Surfaces

A Windows host is compromised through one of five doors. They are independent.

| Surface | The question | Standards |
|---|---|---|
| Service identity | What can this process do if its code is compromised? | A01:2025 · ASVS V13 · CWE-250, CWE-269 |
| Credential exposure | What secrets are in memory or on disk, and who can read them? | A04:2025 · ASVS V14 · CWE-522, CWE-798 |
| Local escalation | Can a non-admin on this box become SYSTEM? | A01:2025 · CWE-732, CWE-428, CWE-276 |
| Authentication path | Can an attacker relay, replay, or delegate an identity? | A04:2025 · ASVS V12 · CWE-319, CWE-306 |
| Visibility | Would anyone notice? | A09:2025 · ASVS V16 · CWE-778 |

## Workflow

### 1. Establish the identity before touching anything else

Write down, for each service and app pool: what it runs as, what network resources it needs,
and what it actually reads and writes locally. Most answers collapse.

The decision tree is short:

- Needs no domain resources → a virtual account (`NT SERVICE\<ServiceName>`) or, for IIS,
  `ApplicationPoolIdentity`. No password exists to steal.
- Needs domain resources from one host → a standalone MSA (`-RestrictToSingleComputer`).
- Needs domain resources from several hosts, or is behind a load balancer → a gMSA, with
  `PrincipalsAllowedToRetrieveManagedPassword` naming only those hosts.
- Needs a real interactive user account → almost certainly a design problem. Say so.

Details and cmdlets in [references/service-account-types.md](references/service-account-types.md).

A service account is never a member of Domain Admins, Administrators, or Backup Operators. If
it is, that is the first finding, and it outranks everything else on the page.

### 2. Assume the host will be compromised, and reduce what that yields

The attacker's goal on a member server is a credential that works somewhere else. Close the
supply: Credential Guard on, LSA protection on, WDigest plaintext caching off, tier-0 accounts
in Protected Users, RDP through Restricted Admin or Remote Credential Guard. See
[best-practices.md](best-practices.md#credential-exposure).

Tiering is the control that makes the rest matter. A Domain Admin credential that authenticates
to a tier-1 web server has been surrendered to whoever owns that web server. Enforce it with
logon-right denials and authentication policy silos, not with a policy document.

### 3. Close the local escalation primitives

Three classics, all ACL problems, all findable by reading configuration:

- An unquoted service path whose parent directory is writable
- A service binary or its directory writable by a non-admin
- A writable registry key under a service's configuration

Each one turns "any local user" into SYSTEM. The ACL that closes each is in
[best-practices.md](best-practices.md#file-system-and-registry-acls).

### 4. Fix the authentication path

Unconstrained delegation on a server means every caller's TGT is cached there — the server
can impersonate them anywhere. Replace it with resource-based constrained delegation, which
puts the decision on the resource owner. NTLM relay works because the protocol does not bind
the authentication to the channel; SMB signing and LDAP channel binding are the mitigations.
See [references/kerberos-delegation.md](references/kerberos-delegation.md).

### 5. Configure the application, not just the host

IIS and ASP.NET Core have their own set: one app pool per application, `customErrors` on,
directory browsing off, version headers gone, request filtering sized to the app, and Data
Protection keys in a shared, ACL'd, encrypted store if there is more than one node. Secrets
never live in a committed `web.config` or `appsettings.json`. See
[best-practices.md](best-practices.md#iis-and-aspnet-core).

### 6. Decide what you would see

Advanced audit policy on, command-line capture in process-creation events, and a named list of
event IDs going to a collector. Verified IDs with their subcategories are in
[references/audit-event-ids.md](references/audit-event-ids.md). Do not paste an event ID from
memory into a detection rule; the reference file says which ones were checked and against what.

### 7. Verify

Run [checklist.md](checklist.md). Reading a GPO backup does not prove the setting is effective
on the host. State what you could not confirm.

## Severity

Rank by what the attacker gains, not by which setting is missing.

- **Critical** — a service or task running as a Domain Admin or Enterprise Admin; unconstrained
  delegation on a member server; a tier-0 credential used to log into a tier-1 host; a
  production connection string with a password committed to source; an unquoted service path
  with a writable parent directory
- **High** — service account in local Administrators without justification; Credential Guard
  and LSA protection both off on a domain-joined server; SMB signing not required; a writable
  service binary path; WinRM listener on HTTP across an untrusted segment; IIS returning a full
  stack trace; Data Protection keys unshared behind a load balancer, or shared world-readable
- **Medium** — no advanced audit policy; no command-line capture in process creation; RDP
  without NLA; Defender exclusion covering a writable application directory; app pools sharing
  an identity; no drift detection against a baseline
- **Low** — server version header present; PowerShell execution policy not set to
  `RemoteSigned`; local password policy weaker than the domain's on a domain-joined box

Execution policy reported as a high finding is how a report gets ignored. Microsoft's own
documentation says it "isn't a security system that restricts user actions".

## Safety

This skill is defensive. It describes attack mechanisms so the control makes sense, and stops
there. It contains no credential-dumping, relay, or Kerberoasting tooling, and adding any would
be out of scope for the skill rather than a gap in it.

Destructive operations are marked where they appear. Three that end badly:

- Changing a service account without granting `Log on as a service` first — the service does
  not restart
- Enabling `RequireSecuritySignature` on a fleet with a non-Microsoft SMB client that does not
  support it
- Adding a Domain Admin to Protected Users without testing. Microsoft warns this can lock the
  account out, and the restrictions are not configurable

## Related Skills

- `core/ssh-server` — the same reasoning for remote access, service confinement, and reversible
  deploys on Linux. Read it for the general shape; this skill is the Windows specialisation
- `core/logging-audit` — what to do with the events once they reach a collector
- `core/secrets-management` — where the connection string actually lives
- `core/mvc-security` — ASP.NET MVC application-layer controls
- `advanced/network-security` — segmentation that makes tiering enforceable
- `enterprise/compliance` — mapping baselines to an audit

## Supporting Files

- [README.md](README.md) — purpose, standards table, limitations, security notes
- [checklist.md](checklist.md) — pre-return verification, grouped by surface
- [best-practices.md](best-practices.md) — real PowerShell, XML, JSON, and C#
- [common-mistakes.md](common-mistakes.md) — what goes wrong and why the fix works
- [troubleshooting.md](troubleshooting.md) — when the hardening breaks the application
- [prompts.md](prompts.md) — prompts that produce findings
- [references/](references/) — version-pinned standard summaries with check dates
- [examples/](examples/) — eight vulnerable/fixed pairs
