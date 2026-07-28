# CIS Benchmarks and the Microsoft Security Compliance Toolkit

Version-pinned baseline sources. Checked 2026-07-28 against the CIS Benchmarks download page
(<https://www.cisecurity.org/cis-benchmarks>) and the Microsoft Security Compliance Toolkit guide
(<https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10>).

## CIS Microsoft Windows Server Benchmark versions

Listed on the CIS catalogue page on 2026-07-28. Only currently supported releases appear there;
CIS says withdrawn versions move to Workbench.

| Benchmark | Version |
|---|---|
| Microsoft Windows Server 2025 | 2.0.0 |
| Microsoft Windows Server 2025 Stand-alone | 1.0.0 |
| Microsoft Windows Server 2022 | 5.0.0 |
| Microsoft Windows Server 2022 Stand-alone | 2.0.0 |
| Microsoft Windows Server 2022 STIG | 2.0.0 |
| Microsoft Windows Server 2019 | 5.0.0 |
| Microsoft Windows Server 2019 Stand-alone | 3.0.0 |
| Microsoft Windows Server 2016 | 4.0.0 |
| Azure Compute Microsoft Windows Server 2022 | 1.0.0 |
| Azure Compute Microsoft Windows Server 2019 | 1.0.0 |

Two things follow from that table. The domain-joined and Stand-alone benchmarks are separate
documents with different version numbers, so "CIS Windows Server 2022" is ambiguous unless you say
which. And STIG-aligned variants exist and renumber recommendations relative to the main benchmark.

### On control numbers

This skill does not quote CIS recommendation numbers. They are behind registration, they differ
between the domain-joined and Stand-alone benchmarks, and they are renumbered between major
versions — a number copied from a v4 document into a v5 audit is worse than no number at all.

Describe the control instead: "require SMB signing on both the client and server side" is
unambiguous, checkable, and does not go stale. If a project needs the recommendation ID, download
the PDF for the exact platform and version and read it from there.

CIS also ships CIS-CAT Pro for automated assessment, Build Kits as GPO backups, and Hardened
Images. Each covers a narrower subset of products than the benchmark list.

## Microsoft Security Compliance Toolkit

Free, no registration, GPO backups plus tooling. Contents as documented on 2026-07-28:

- Windows Server baselines: Windows Server 2025, 2022, 2019, 2016
- Windows 11 baselines: 24H2, 23H2, 22H2, 21H2
- Windows 10 baselines: 22H2, 21H2, 1809, 1607, 1507
- Microsoft 365 Apps for Enterprise baseline: version 2412
- Microsoft Edge baseline: version 128
- Tools: Policy Analyzer, LGPO, SetObjectSecurity, GPO to Policy Rules

Download: <https://www.microsoft.com/download/details.aspx?id=55319>

### What each tool is for

| Tool | Use |
|---|---|
| Policy Analyzer | Compare a set of GPOs against each other, against a baseline, or against current local policy and local registry. Flags redundant and internally inconsistent settings. Exports to Excel |
| LGPO.exe | Apply and export local policy. Imports `Registry.pol`, security templates, advanced audit backup files, and LGPO text format. The practical option for non-domain-joined hosts |
| SetObjectSecurity.exe | Set the security descriptor on files, directories, registry keys, event logs, services, and SMB shares |
| GPO2PolicyRules | Convert GPO backups to Policy Analyzer `.PolicyRules` files without the GUI. Ships with Policy Analyzer |

### Drift detection

Policy Analyzer's baseline-then-snapshot comparison is the drift mechanism: capture the intended
state, capture the host later, diff. It is a point-in-time comparison, not continuous monitoring —
pair it with a configuration management tool or Azure Machine Configuration if you need
continuous.

The GPO-side complement is event 4719 (see
[audit-event-ids.md](audit-event-ids.md)), which fires when basic audit policy overwrites the
advanced audit configuration. That is drift you will otherwise discover during an incident.

## GPO precedence

Local, then Site, then Domain, then OU — later wins, so an OU-linked GPO beats a domain-linked
one for objects in that OU. Within a single container, the GPO with the lowest link order wins.
`Enforced` on a link makes it survive block-inheritance and beats lower-level GPOs.
`Block Inheritance` on an OU stops higher-level GPOs except enforced ones.

Two consequences worth stating in a review:

- A security baseline linked at the domain root is overridden by any OU GPO that sets the same
  value, unless the link is enforced. Enforcing the baseline is usually correct and usually
  surprising to whoever set the OU GPO.
- Computer Configuration and User Configuration are separate trees with separate precedence.
  Microsoft documents that for the PowerShell execution policy setting specifically, Computer
  Configuration takes precedence over User Configuration.

Verify what is effective, not what is linked:

```powershell
gpresult.exe /h C:\Temp\rsop.html /f    # writes a Resultant Set of Policy report
auditpol.exe /get /category:*           # effective audit policy, which gpresult does not show well
```

## How to use a baseline without breaking the application

1. Apply the baseline to a test host that runs the real workload, not an empty VM.
2. Record what breaks. Legacy SMB clients, unsigned LDAP callers, and applications that need
   NTLM are the usual three.
3. Document each exception with an owner and a review date. An undocumented exception is
   indistinguishable from drift.
4. Re-run Policy Analyzer after each change so the exception set stays visible.

A baseline applied and then silently exempted in twelve places is not a baseline.

## Sources

- CIS Benchmarks — <https://www.cisecurity.org/cis-benchmarks>, catalogue checked 2026-07-28
- Microsoft Security Compliance Toolkit guide —
  <https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10>,
  checked 2026-07-28
- SCT download — <https://www.microsoft.com/download/details.aspx?id=55319>
- Microsoft Security Baselines blog —
  <https://techcommunity.microsoft.com/t5/microsoft-security-baselines/bg-p/Microsoft-Security-Baselines>
