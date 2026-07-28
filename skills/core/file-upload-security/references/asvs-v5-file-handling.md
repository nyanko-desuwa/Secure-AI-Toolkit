# ASVS 5.0 V5 — File Handling

OWASP Application Security Verification Standard, version 5.0.0, released 30 May 2025.
Chapter V5 is the file-handling chapter: uploads, downloads, path handling, and archive
extraction.

Source: <https://owasp.org/www-project-application-security-verification-standard/> ·
requirement text: <https://github.com/OWASP/ASVS> · checked 2026-07-28.

## Why V5 and not the Top 10

The Top 10 tells you an upload endpoint is risky (A08, plus A01 and A02 depending on
storage and serving). V5 is where you go to decide whether your implementation is correct,
because it is written as statements you can pass or fail.

Requirement IDs did not carry over from ASVS 4.x. A `V12.1.1` citation from an old report
does not point at the same statement in 5.0. Cite the chapter unless you have read the
current requirement text; an invented ID is worse than a chapter-level citation.

## What the chapter covers

| Area | What to verify |
|---|---|
| Upload acceptance | Size limits enforced server-side, type determined from content, unexpected types rejected |
| Storage | Files stored outside the web root or in object storage that cannot execute them |
| Naming | The stored name is server-generated; the client name is never used as a path |
| Download | Content type fixed by the server, `Content-Disposition` set, no browser sniffing |
| Path handling | Paths canonicalised before the containment check, no traversal, no symlink escape |
| Archives | Entry names and link targets validated, expansion bounded |
| Resource limits | Decompression, pixel expansion, and entity expansion cannot exhaust memory or CPU |

## Related chapters

An upload feature never sits inside V5 alone.

| Chapter | Why it applies |
|---|---|
| V1 Encoding and Sanitization | The display filename reaching HTML, a header, or a log |
| V2 Validation and Business Logic | Allowlisting the accepted formats, per-actor quotas |
| V3 Web Frontend Security | `nosniff`, CSP, and the separate-origin decision for served files |
| V4 API and Web Service | Presigned upload endpoints, request size limits |
| V8 Authorization | Who may read a stored file; scoping the download lookup |
| V13 Configuration | Web server mapping, bucket policy, execute permissions on the directory |
| V14 Data Protection | EXIF GPS and other metadata in files that will be public |
| V16 Logging and Error Handling | Rejections logged, scanner failures failing closed |

## Levels

ASVS defines three verification levels. Level 1 is a black-box baseline, Level 2 is the
right default for an application handling user data, Level 3 is for systems where failure
is severe.

Say which level you targeted. "We followed ASVS V5 guidance" is honest. "We are ASVS
Level 2" claims a completed requirement-by-requirement assessment.

## CWEs used in this skill

| CWE | Name | Where it shows up |
|---|---|---|
| CWE-434 | Unrestricted Upload of File with Dangerous Type | Extension or `Content-Type` trusted; executable content stored in a served directory |
| CWE-22 | Improper Limitation of a Pathname to a Restricted Directory | Client filename used as a path; download endpoint joining user input; zip slip |
| CWE-409 | Improper Handling of Highly Compressed Data (Data Amplification) | Zip bombs, pixel floods, nested archives |
| CWE-611 | Improper Restriction of XML External Entity Reference | SVG and Office Open XML parsed with entity resolution enabled |

Source: <https://cwe.mitre.org/>

Related CWEs worth naming when they fit the specific defect: CWE-59 (link following),
CWE-73 (external control of filename or path), CWE-79 (stored XSS from a served SVG or
HTML file), CWE-770 (allocation without limits).
