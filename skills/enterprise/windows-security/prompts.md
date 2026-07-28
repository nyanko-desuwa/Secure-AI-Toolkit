# Prompt Examples

Prompts that produce findings rather than a recital of Windows features. Each bounds the input,
states what runtime evidence is unavailable, and asks for the mechanism and the fix.

## Review service identities

```text
Read this service inventory. For every service not running as LocalSystem, LocalService,
NetworkService, a virtual account, or gMSA, identify its account and what domain resources it
appears to need. Rank any privileged-domain account first. Give the gMSA or virtual-account
migration and the exact resource ACL it would need. Mark domain group membership unknown unless
you actually queried AD.
```

Why it works: it starts with the highest-leverage Windows finding and separates what the inventory
shows from what only the domain can answer.

## Review one service for local escalation

```text
Review AcmeAgent's ImagePath, service registry ACL, binary directory ACL, and writable state
paths. Check all three privilege-escalation primitives independently: unquoted path, writable
binary/directory, and writable service registry key. Show the fixed sc.exe and icacls/Set-Acl
commands. Do not treat quoting as a fix for a writable directory.
```

## Replace Domain Admin with gMSA

```text
This service runs as a Domain Admin and reads one SMB share. Design the migration to a gMSA:
KDS prerequisite, account creation, allowed retrieval hosts, SPN if needed, share ACL, Log on as
a service, Test-ADServiceAccount, cutover, and rollback order. Use placeholder names and mark the
commands that could stop the service.
```

## Review Kerberos delegation

```text
Review this export of userAccountControl, msDS-AllowedToDelegateTo, and
PrincipalsAllowedToDelegateToAccount. Identify unconstrained delegation first. For each entry,
state what a compromise of that host can impersonate, then show the narrowest resource-based
constrained delegation replacement. Do not include ticket extraction or Kerberoasting commands.
```

## Explain an SPN finding

```text
This ordinary domain user has three SPNs and a password last changed four years ago. Explain why
that is an offline password-guessing exposure, then give the gMSA migration. No attack tooling.
Map to A04:2025, ASVS V14, and CWE-522 or CWE-798 as appropriate.
```

## Review credential exposure

```text
Review this member-server GPO for Credential Guard, LSA protection, Protected Users, RDP credential
delegation, and tiered administration. For every setting, distinguish configured from confirmed
running. Give the live-host command or event needed to verify it. Flag any tier-0 account allowed
to authenticate to this tier-1 host.
```

## Design remote management

```text
Design remote administration for 40 Windows member servers. Use WinRM over HTTPS through a
bastion, source-restricted firewall rules, JIT group membership, and a JEA endpoint for service
restart. Give the role capability and session configuration. Do not grant local admin to the
operators. Cross-reference core/ssh-server for the general bastion reasoning.
```

## Review a JEA endpoint

```text
Read this .psrc and .pssc. Find every cmdlet, parameter, provider, external command, or custom
function that can escape the intended role. Check role merging and duplicate capability filenames.
Show a constrained VisibleCmdlets replacement with ValidateSet, and mark runtime effective access
unknown until the endpoint is tested as a non-admin user.
```

## Review IIS and ASP.NET Core

```text
Read web.config, appsettings*.json, Program.cs, and the IIS app-pool export. Check: one pool per
application, pool identity, writable web-root paths, customErrors/developer exception page,
directory browsing, version headers, request and upload limits, committed secrets, and Data
Protection key storage for a three-node farm. Return vulnerable/fixed XML, JSON, C#, and ACLs.
```

## Design Data Protection for a farm

```text
This ASP.NET Core app runs on WEB01-WEB03 and users are logged out at random. Design a shared,
encrypted Data Protection key ring. State the store ACL, certificate/Key Vault protection,
SetApplicationName rule, and what remains unprotected if an attacker can write new keys. Do not
suggest disabling cookie or antiforgery validation.
```

## Design Windows auditing

```text
Use only references/audit-event-ids.md. Build a collection plan for logon, privilege assignment,
process creation with command line, account/group changes, and service installation. Name the
advanced audit subcategory for every event, the SIEM alert that consumes it, and the host-side
verification. Do not invent or use an unverified event ID.
```

## Review a baseline exception

```text
SMB signing broke one legacy appliance. Give me a compatibility investigation and the smallest
possible time-bounded exception. Keep signing required everywhere else. Include owner, expiry,
compensating controls, evidence that proves the appliance is the incompatible peer, and the test
that removes the exception.
```

## Review the staged change

```text
Review only the staged Windows deployment changes. Map findings to OWASP Top 10 2025, ASVS 5.0
chapter, and CWE. Give file:line, exploitation path, and fixed configuration. Skip anything without
an exploitation path, and mark live-domain facts unknown rather than guessing.
```

## Verify before returning

```text
Run skills/enterprise/windows-security/checklist.md against the change. Mark each applicable item
pass, fail, or not applicable with a reason. Items tagged [host] cannot pass from source alone; list
the live command or event needed and mark them unknown if it was not run.
```

## Anti-patterns

| Prompt | Problem |
|---|---|
| "Harden Windows" | No host role, OS version, domain tier, or application. Produces a baseline dump |
| "Make it CIS compliant" | Which server version, domain-joined or stand-alone, and which benchmark release? CIS numbers move |
| "Turn on every audit event" | Generates volume without a detection objective and can hide the events that matter |
| "Disable NTLM everywhere" | Breaks unknown legacy paths without first finding or owning them |
| "Use a service account" | Says nothing about whether that means virtual account, gMSA, or Domain Admin |
| "Enable Credential Guard" | Ignores delegation and legacy authentication compatibility, placement, and runtime verification |
| "Set execution policy to secure PowerShell" | Execution policy is not a security boundary |
| "Open RDP for the admins" | No source boundary, credential-delegation mode, tier, or JIT lifetime |
| "Put secrets in environment variables" | Better than source, but not automatically a vault and often visible to the process owner |
| "Fix the unquoted path" | Misses the writable binary and service registry ACL, which are independent |
| "Collect event 7045" | Commonly cited, but this skill could not verify it against Microsoft Learn. Use verified 4697 or verify 7045 yourself |
| "Is this GPO secure?" | A GPO file is intent. Ask for effective `gpresult` and `auditpol` state |
| "Give me a Kerberoasting test" | Offensive tooling is out of scope; ask for SPN inventory and gMSA migration instead |
| "Show how to dump LSASS" | Out of scope; ask whether Credential Guard and LSA protection are effective |

## A useful output contract

Add this to any review prompt:

```text
For each finding: severity, standard, file:line or policy path, precondition, what the attacker
gains, fixed code/configuration, and how to verify it. Separate source-confirmed facts from
live-host facts. Use only event IDs, registry paths, GPO paths, and cmdlet parameters you verified.
```

That last sentence prevents the most damaging failure in Windows guidance: a plausible-looking
registry path that does nothing.
