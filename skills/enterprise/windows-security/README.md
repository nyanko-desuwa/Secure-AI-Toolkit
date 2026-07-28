# Windows Server and .NET Hardening

## Purpose

Give an assistant a defensible way to decide what a Windows service runs as, what a compromise of
that service yields, and what an IIS or ASP.NET Core deployment exposes. The skill is weighted
towards identity and configuration because that is where Windows estates actually fall over: a
service running as a Domain Admin is worth more to an attacker than any unpatched CVE on the same
host.

It is defensive only. Attack mechanisms are described so the control makes sense. There is no
credential-dumping, relay, or Kerberoasting tooling here, by design.

## How It Works

Plain Markdown, nothing executes. Read `SKILL.md`, work the five surfaces, apply the concrete
configuration, then run `checklist.md`.

```text
SKILL.md                            workflow, five surfaces, severity, file index
README.md                           this file
checklist.md                        pre-return verification, grouped by surface
best-practices.md                   patterns with vulnerable/fixed pairs
common-mistakes.md                  what goes wrong and why the fix holds
troubleshooting.md                  when hardening breaks the application
prompts.md                          prompts that produce findings
references/
  owasp-mapping.md                  Top 10 2025, ASVS chapters, CWE table
  service-account-types.md          identity decision table, gMSA setup, privileges
  kerberos-delegation.md            unconstrained vs KCD vs RBCD, SPNs, NTLM relay
  credential-protection.md          Credential Guard, LSA protection, Protected Users, RDP
  audit-event-ids.md                verified event IDs with their subcategories
  cis-and-baselines.md              CIS benchmark versions, SCT, drift detection
examples/README.md                  eight vulnerable/fixed pairs
```

## Standards Covered

| Standard | Version | Use here | Verified |
|---|---|---|---|
| OWASP Top 10 | 2025 | A01 access control, A02 misconfiguration, A04 crypto/secrets, A09 logging | 2026-07-28 |
| OWASP ASVS | 5.0.0 (released 2025-05-30) | V12 communication, V13 configuration, V14 data protection, V16 logging and error handling | 2026-07-28 |
| CIS Microsoft Windows Server Benchmark | 2025 v2.0.0 · 2022 v5.0.0 · 2019 v5.0.0 · 2016 v4.0.0 | Host baseline reference | 2026-07-28, against the CIS benchmark list |
| Microsoft Security Compliance Toolkit | Windows Server 2025, 2022, 2019, 2016 baselines | GPO baselines, Policy Analyzer, LGPO | 2026-07-28, against Microsoft Learn |
| NIST SP 800-53 | Rev. 5 families, not control IDs | AC, AU, CM, IA, SC mapping at family level | 2026-07-28 |

ASVS is mapped at chapter level only. CIS is cited by benchmark version, never by control number —
the numbering moves between versions and this skill does not have the PDFs. If you need a control
ID, open the benchmark for your exact OS version and quote it from there.

CWEs used: CWE-250, CWE-269, CWE-732, CWE-522, CWE-798, CWE-428, CWE-276, CWE-306, CWE-319,
CWE-778. Full mapping in [references/owasp-mapping.md](references/owasp-mapping.md).

## Configuration

None. No build step, no dependency, no environment variable. Copy the directory into your
assistant's skill location or keep it readable in the project. Frontmatter limits tools to read,
write, search, web lookup, and `ls`/`cat`.

Every domain, hostname, account name, and thumbprint in this skill is a placeholder
(`contoso.example`, `WEB01`, `svc_acmeweb`). Replace them before applying anything.

## Example Usage

```text
Review every service on this host that does not run as LocalSystem, LocalService, NetworkService,
or a virtual account. For each, tell me what it runs as, whether that account is privileged in the
domain, and the least-privilege identity that would still work.
```

```text
Read this web.config and appsettings.json. Find anything that returns internal state to a client
or holds a secret. Map each finding to a Top 10 2025 category and a CWE, and give me the fixed
file, not a description of the fix.
```

```text
We have unconstrained delegation on WEB01. Explain the exposure, then give me the resource-based
constrained delegation commands to replace it and the order to run them in so nothing breaks.
```

```text
Design what this member server forwards to the SIEM. Use only event IDs verified in
references/audit-event-ids.md, name the audit subcategory each one needs, and name the rule that
fires on it.
```

More in [prompts.md](prompts.md).

## Limitations

- Reading configuration cannot prove enforcement. A GPO backup, an `.admx` reference, or a script
  in source control says what someone intended. Only `auditpol /get`, `gpresult`, `Get-Acl`,
  `Test-ADServiceAccount`, and the effective registry on the host say what is true. Checklist items
  that cannot be settled from source are marked as such.
- No domain access. This skill cannot enumerate your AD, so it cannot tell you whether
  `svc_backup` is in Domain Admins. It can tell you the query that answers it.
- CIS control IDs are deliberately absent. Benchmark versions are cited; individual recommendation
  numbers are not, because they were not verified against the PDFs.
- WDigest: the mechanism and the controls that neutralise it (Credential Guard, Protected Users)
  are covered. The specific `WDigest` registry value name was not verifiable from Microsoft Learn
  on the check date, so it is not stated. Verify it against current documentation before scripting
  a change.
- Windows LAPS is referenced as the control for shared local administrator passwords, but its
  PowerShell cmdlet names were not verified here. Enumerate the module on the host before
  scripting.
- WDAC and AppLocker are covered as decisions, not as policy XML. Authoring a WDAC policy is a
  project, and a half-verified policy in audit mode gives false confidence.
- Windows containers are covered only where the trust boundary differs from Linux. There is no
  Dockerfile guidance here; that is `core/docker-security`.
- Nothing here is a substitute for the benchmark tooling. Policy Analyzer and a CIS assessment find
  drift; a Markdown skill does not.

## Security Notes

This skill contains deliberately insecure configuration in `best-practices.md`,
`common-mistakes.md`, and `examples/`. Every such block is labelled `Vulnerable:`. Do not copy one.

Three changes in here can lock you out or stop a service. They are marked where they appear:

- Repointing a service to a new identity without granting `Log on as a service` first
- Requiring SMB signing on a fleet that still has a client which cannot do it
- Adding a privileged account to Protected Users. Microsoft warns this can lock the account out and
  the restrictions are not configurable

Enabling command-line capture in process-creation events makes the Security log more sensitive.
Microsoft's own note is that anyone who can read security events can then read the command line of
every process — including a password passed as an argument. Enable it, restrict who reads the log,
and stop passing secrets on command lines.

## References

- OWASP Top 10 2025 — <https://owasp.org/Top10/2025/>
- OWASP ASVS 5.0.0 — <https://owasp.org/www-project-application-security-verification-standard/>
- CIS Benchmarks — <https://www.cisecurity.org/cis-benchmarks>
- Microsoft Security Compliance Toolkit —
  <https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10>
- Windows Server security documentation — <https://learn.microsoft.com/en-us/windows-server/security/>
- Credential Guard — <https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/>
- Just Enough Administration — <https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/jea/overview>
- ASP.NET Core Data Protection —
  <https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/configuration/overview>
- NIST SP 800-53 Rev. 5 — <https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final>
