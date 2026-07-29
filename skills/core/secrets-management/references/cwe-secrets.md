# CWE Entries for Secrets

Verified against <https://cwe.mitre.org/> on 2026-07-28. Titles are quoted as MITRE publishes
them; do not paraphrase a CWE title in a finding, and do not invent an ID you have not read.

## The six that carry most secrets findings

| ID | Title | Use it when |
|---|---|---|
| CWE-798 | Use of Hard-coded Credentials | Any credential literal in source, config, or a build file |
| CWE-259 | Use of Hard-coded Password | Specifically a password literal. More precise than 798 when it applies |
| CWE-522 | Insufficiently Protected Credentials | Stored or transmitted without adequate protection - plaintext at rest, weak transport, over-broad read access |
| CWE-532 | Insertion of Sensitive Information into Log File | A token, key, or password reaching a log or a telemetry sink |
| CWE-214 | Invocation of Process Using Visible Sensitive Information | Secret in command-line arguments or the environment block, visible to other processes on the host |
| CWE-208 | Observable Timing Discrepancy | Secret compared with `==`, where the timing difference leaks a prefix |

## Picking between 798 and 259

798 is the parent case: any hard-coded credential, including keys, tokens, and certificates.
259 is the child for passwords specifically. Cite 259 when the value is a password and 798 when
it is anything else or when you want the broader category. Citing both is not wrong; citing
neither and saying "hardcoded secret" is a finding a reviewer cannot look up.

## Where 522 fits

522 is the catch-all for a credential that exists in the right place but is not protected there.
A Kubernetes Secret in an etcd with no encryption at rest is 522, not 798 - the design is
correct, the protection is missing. A Terraform state file with a database password in a public
bucket is 522. A `.env` file readable by every user on a shared host is 522.

If the credential should not exist in that form at all, 798 is the better fit. If it should
exist there but needs guarding, use 522.

## 214 and the environment variable question

214 is what makes "environment variables are not the end state" a citable claim rather than an
opinion. MITRE's description names command-line arguments and environment variables explicitly
as elements other processes on the operating system can view.

This is why a secret passed as `--password=...` on a command line is a distinct finding from the
same secret in a file: the argument list is world-readable in the process table on most
platforms, and it lands in shell history and CI logs.

## 532 and the scope people miss

532 is written about log files, and the same reasoning covers every downstream sink: log
aggregators, APM traces, error trackers, crash reports, and analytics events. The exposure is
usually wider than the original credential store because log read access is granted liberally.

Worth stating in a finding: who can read the sink. "Token in the application log" is different
from "token in the log, and the log ships to a third-party SaaS with 90-day retention and
read access for the whole engineering group".

## 208 and honest severity

208 is real and usually low severity on its own. The exploit needs many samples and a low-noise
network path. Report it as a defence-in-depth gap unless the compared value is guessable byte by
byte with unlimited attempts - an API key checked without rate limiting, for example. Do not
inflate it to critical because the word "timing attack" sounds severe.

## Related IDs you may reach for

| ID | Title | Note |
|---|---|---|
| CWE-256 | Plaintext Storage of a Password | Narrower than 522, specific to storage |
| CWE-321 | Use of Hard-coded Cryptographic Key | Narrower than 798, specific to keys |
| CWE-540 | Inclusion of Sensitive Information in Source Code | For secrets in files shipped to a client |
| CWE-1392 | Use of Default Credentials | Shipped defaults never changed |

Verify any of these on the CWE site before citing. The four above were checked on 2026-07-28;
they are listed for orientation, not as a substitute for reading the entry.

## Mapping to the Top 10 and ASVS

| CWE | Top 10 2025 | ASVS 5.0 |
|---|---|---|
| 798, 259 | A04, also A02 when it is a shipped default | V13, V14 |
| 522 | A04 | V14, V13 |
| 532 | A09 | V16, V14 |
| 214 | A02 | V13 |
| 208 | A04 | V11, V14 |

## Sources

- CWE list - <https://cwe.mitre.org/data/index.html>
- CWE-798 - <https://cwe.mitre.org/data/definitions/798.html>
- CWE-259 - <https://cwe.mitre.org/data/definitions/259.html>
- CWE-522 - <https://cwe.mitre.org/data/definitions/522.html>
- CWE-532 - <https://cwe.mitre.org/data/definitions/532.html>
- CWE-214 - <https://cwe.mitre.org/data/definitions/214.html>
- CWE-208 - <https://cwe.mitre.org/data/definitions/208.html>
