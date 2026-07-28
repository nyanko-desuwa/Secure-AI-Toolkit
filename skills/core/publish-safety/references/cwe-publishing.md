# CWE Entries for Publishing

Verified against <https://cwe.mitre.org/> on 2026-07-28. Each title below was read on its own CWE
page and is quoted as MITRE publishes it. Do not paraphrase a CWE title in a finding, and do not
cite an ID you have not read.

## The six that carry most publish findings

| ID | Title | Abstraction | Use it when |
|---|---|---|---|
| CWE-527 | Exposure of Version-Control Repository to an Unauthorized Control Sphere | Variant | The repository itself became reachable: private flipped to public, a `.git` directory served by a web host, a repo pushed to the wrong org |
| CWE-540 | Inclusion of Sensitive Information in Source Code | Base | A credential or sensitive value inside source that is published — committed, packaged, or shipped in a bundle |
| CWE-538 | Insertion of Sensitive Information into Externally-Accessible File or Directory | Base | The value is in a file that the audience is allowed to fetch but not allowed to see the contents of: a deployed `.env`, a published tarball, a static asset |
| CWE-798 | Use of Hard-coded Credentials | Base | A credential literal in code, config, a build file, or a fixture, independent of whether it shipped |
| CWE-615 | Inclusion of Sensitive Information in Source Code Comments | Variant | A key, an internal URL, or a stale note left in a comment that ships with the file |
| CWE-532 | Insertion of Sensitive Information into Log File | Base | A credential reaching a build log, a CI log, or any log shared in an issue or a paste |

## Picking between 540, 538, and 798

These three overlap and reviewers use them interchangeably, which makes findings hard to compare.
The distinction that holds:

- 798 is about the code containing the credential. It applies the moment the literal is written,
  before anything is published.
- 540 is about that source being published. Cite it when the exposure is the source code itself
  reaching an audience — a public repo, a published package, a readable bundle.
- 538 is about a non-source file placed somewhere fetchable. A `.env` deployed next to the app, a
  config file inside a published tarball, a backup left in a public bucket. MITRE's description
  covers actors who are permitted to access the location "but not to the sensitive information."

A committed `.env` in a public repo is honestly all three: 798 for the literal, 540 for the
publication, 527 for the repository exposure. Cite the one that names the failure you are asking
someone to fix, and add a second only when it adds information.

## CWE-527 and what it actually covers

The entry is about placing a version-control repository "in a directory, archive, or other
resource that is stored, transferred, or otherwise made accessible to unauthorized actors." That
covers the two cases that matter here: a visibility change on a hosted repository, and a `.git`
directory that ends up inside deployed output or a container image.

It was renamed twice — "Exposure of CVS Repository to an Unauthorized Control Sphere" before 2020,
and "Information Leak Through CVS Repository" before 2009 — so older tooling may emit either title
for the same ID.

## CWE-200 is deliberately not in the table above

CWE-200, Exposure of Sensitive Information to an Unauthorized Actor, is the obvious-looking fit and
the wrong choice. It is a Class-level entry and MITRE marks it DISCOURAGED for vulnerability
mapping, with the reasons given as frequent misuse, frequent misinterpretation, and abstraction.
The rationale is that loss of confidentiality is a technical impact rather than a root cause, and
that more than 400 other entries can produce it. The page points to specific alternatives including
CWE-201, CWE-203, CWE-538, CWE-285, CWE-732, and CWE-287.

So: use the specific child. CWE-200 in a finding tells a reviewer nothing they did not already know
from the sentence next to it.

## CWE-798 mapping note

The CWE-798 page marks mapping as allowed only with careful review, because more specific children
exist: CWE-259 for a hard-coded password and CWE-321 for a hard-coded cryptographic key. Reach for
the child when the value's type is known. The entry also carries a High likelihood of exploit,
which is worth quoting when someone argues that a key in a private repo is theoretical.

## Related IDs you may reach for

| ID | Title | Note |
|---|---|---|
| CWE-259 | Use of Hard-coded Password | Child of 798, specific to passwords |
| CWE-321 | Use of Hard-coded Cryptographic Key | Child of 798, specific to keys |
| CWE-522 | Insufficiently Protected Credentials | The credential exists in the right place but is not protected there |
| CWE-1104 | Use of Unmaintained Third Party Components | For what you publish becoming someone else's dependency |

CWE-259, CWE-321, and CWE-522 are summarised with check dates in
[secrets-management/references/cwe-secrets.md](../../secrets-management/references/cwe-secrets.md);
CWE-1104 is cited by `core/devsecops`. They are listed here for orientation. Read the entry before
citing one — this file only verified the six in the first table plus CWE-200 and CWE-527.

## Mapping to the Top 10 and ASVS

| CWE | Top 10 2025 | ASVS 5.0 |
|---|---|---|
| 527 | A02 | V13 |
| 540 | A04, also A02 when packaging config decided it | V13, V14 |
| 538 | A02 | V13, V14 |
| 798 | A04 | V13, V14 |
| 615 | A02 | V14 |
| 532 | A09 | V16, V14 |

## Sources

- CWE list — <https://cwe.mitre.org/data/index.html>
- CWE-527 — <https://cwe.mitre.org/data/definitions/527.html>
- CWE-540 — <https://cwe.mitre.org/data/definitions/540.html>
- CWE-538 — <https://cwe.mitre.org/data/definitions/538.html>
- CWE-798 — <https://cwe.mitre.org/data/definitions/798.html>
- CWE-615 — <https://cwe.mitre.org/data/definitions/615.html>
- CWE-532 — <https://cwe.mitre.org/data/definitions/532.html>
- CWE-200 — <https://cwe.mitre.org/data/definitions/200.html>
