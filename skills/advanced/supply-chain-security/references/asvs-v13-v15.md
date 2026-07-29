# ASVS 5.0.0 - V13 Configuration and V15 Secure Coding and Architecture

> Version 5.0.0 (released 2025-05-30), verified 2026-07-28 against
> <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x22-V13-Configuration.md> and
> <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x24-V15-Secure-Coding-and-Architecture.md>

ASVS 5.0 renumbered everything from 4.0.3. A recalled `V14.2.x` dependency ID from an older
report does not map. Only the requirements below were read from the source; cite the chapter
for anything else.

## V15 - the supply chain requirements

Requirement text summarised. Levels as published.

| # | Requirement | L |
|---|---|---|
| 15.1.1 | Documentation defines risk-based remediation time frames for third-party component versions with vulnerabilities, and for updating libraries in general | 1 |
| 15.1.2 | An inventory catalog, such as an SBOM, is maintained of all third-party libraries in use, including verifying components come from pre-defined, trusted, and continually maintained repositories | 2 |
| 15.1.4 | Documentation highlights third-party libraries considered "risky components" | 3 |
| 15.1.5 | Documentation highlights parts of the application using "dangerous functionality" | 3 |
| 15.2.1 | The application only contains components that have not breached the documented update and remediation time frames | 1 |
| 15.2.4 | Third-party components and all transitive dependencies are included from the expected repository, whether internally owned or external, with no risk of a dependency confusion attack | 3 |
| 15.2.5 | Additional protections around "dangerous functionality" and "risky components" - sandboxing, encapsulation, containerization, or network-level isolation, to delay and deter pivoting | 3 |

Also in V15 but not supply-chain-specific: 15.1.3 and 15.2.2 (availability of expensive
functionality), 15.2.3 (no test code or dev functionality in production), 15.3.x (defensive
coding: mass assignment, type juggling, prototype pollution, parameter pollution, redirect
following, original client IP), 15.4.x (concurrency, TOCTOU).

### Definitions the chapter supplies

These are load-bearing, because two L3 requirements depend on them.

A component with "dangerous functionality" - internal or third-party - performs deserialization
of untrusted data, raw file or binary parsing, dynamic code execution, or direct memory
manipulation. Vulnerabilities there risk compromising the application and its underlying
infrastructure.

A "risky component" is a third-party library with missing or poorly implemented security
controls around its development process or functionality. Named examples: poorly maintained,
unsupported, end-of-life, or a history of significant vulnerabilities.

### Reading the levels honestly

Dependency confusion (15.2.4) is Level 3. So is the risky-component inventory. That is the
standard's assessment of testing difficulty, not of exploitability - dependency confusion is
cheap to exploit and has produced real incidents at large companies. If a project targets
Level 2, 15.2.4 is still worth implementing; say that you exceeded the level rather than
citing L2 as permission to skip it.

15.1.1 and 15.2.1 are Level 1 and they pair: write the window, then hold to it. A project
with no documented window automatically fails 15.2.1, because there is nothing to breach and
nothing to enforce. Start with the document.

## V13 - the configuration requirements that matter here

| # | Requirement | L |
|---|---|---|
| 13.2.1 | Backend component communication is authenticated with individual service accounts, short-term tokens, or certificates - not unchanging credentials such as passwords, API keys, or shared privileged accounts | 2 |
| 13.2.2 | Backend communication uses accounts with the least necessary privileges | 2 |
| 13.2.4 | An allowlist defines the external resources or systems the application may communicate with, at application, web server, firewall, or combined layers | 2 |
| 13.3.1 | A secrets management solution creates, stores, controls access to, and destroys backend secrets. Secrets must not be in application source code or build artifacts. L3 requires hardware-backed, such as an HSM | 2 |
| 13.3.2 | Access to secret assets follows least privilege | 2 |
| 13.3.4 | Secrets expire and rotate per the application's documentation | 3 |
| 13.4.1 | Deployed without source control metadata (`.git`, `.svn`), or with those folders inaccessible externally and to the application | 1 |

Three of these read differently once you apply them to a pipeline rather than to a running
application:

- 13.2.1 is the case against a long-lived registry publish token. OIDC-minted short-lived
  credentials are the requirement, not an optimisation.
- 13.3.1's "not included in build artifacts" is why a leaked `.npmrc` or `.pypirc` inside a
  published tarball is an ASVS failure and not just untidy.
- 13.2.4's egress allowlist is the control that turns a malicious `postinstall` from a
  successful exfiltration into a failed connection. It is the second line after disabling
  scripts, and it is the one that still works when a script slips through.

13.1.4 asks the documentation to define which secrets are critical and a rotation schedule
based on threat model. For supply chain work, publish tokens and signing keys belong at the
top of that list.

## Citation practice

`ASVS V15 (Secure Coding and Architecture)` and `ASVS V13 (Configuration)` are correct
chapter-level citations. Use the specific numbers above only as written here. For any other
requirement, fetch the source file rather than recalling an ID.

## Sources

- V13 - <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x22-V13-Configuration.md>
- V15 - <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x24-V15-Secure-Coding-and-Architecture.md>
- Project page - <https://owasp.org/www-project-application-security-verification-standard/>
