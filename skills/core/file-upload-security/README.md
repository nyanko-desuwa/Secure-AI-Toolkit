# File Upload Security

## Purpose

A file upload crosses a trust boundary twice. The client controls the bytes, the declared
MIME type, and the original name. The download client controls the URL. Treating any of
those as trusted turns a feature into code execution, stored XSS, data exposure, or denial
of service.

This skill covers acceptance, storage, processing, archive extraction, direct-to-object-
storage uploads, and serving files back.

## How It Works

The workflow is deliberately layered:

1. Authenticate and authorize the upload and every download.
2. Limit request rate, count, declared and observed size, and processing resources.
3. Buffer to an isolated temporary location. Never use the supplied name as a path.
4. Determine type from bytes. Extension and `Content-Type` are hints for display only; both
   are client-supplied. For images, decode and re-encode to a server-chosen format.
5. Generate an opaque storage key. Store outside the web root, or in object storage with no
   execute semantics.
6. Scan and process in a sandbox. Parsers for images, PDFs, Office, XML, and archives are
   large native-code attack surfaces.
7. Serve with fixed headers from a separate origin. Resolve any filesystem path before
   checking that it remains inside the permitted root.

Magic numbers are a useful first filter, not proof. A polyglot can satisfy two parsers at
once. Re-encoding an image forces a decoder to construct pixels and a fresh encoder to write
new bytes, removing most trailing or embedded payloads. It costs CPU, memory, latency, and
can lose animation, color profiles, comments, or exact fidelity. Keep the original only if
the business need justifies the extra attack surface.

## File Layout

```text
file-upload-security/
+-- SKILL.md
+-- README.md
+-- checklist.md
+-- best-practices.md
+-- common-mistakes.md
+-- troubleshooting.md
+-- prompts.md
+-- references/
|   +-- asvs-v5-file-handling.md
|   \-- file-type-detection.md
\-- examples/
    \-- README.md
```

## Standards

| Standard | Relevant mapping | Use |
|---|---|---|
| OWASP Top 10 2025 A08 | Software or Data Integrity Failures | Untrusted file acceptance and processing |
| OWASP Top 10 2025 A01 | Broken Access Control | Ownership, download authorization, traversal |
| OWASP Top 10 2025 A02 | Security Misconfiguration | Web-root execution and unsafe response headers |
| OWASP Top 10 2025 A05 | Injection | SVG stored XSS and parser interpreters |
| OWASP Top 10 2025 A06 | Insecure Design | Resource limits, abuse cases, direct upload policy |
| OWASP Top 10 2025 A10 | Mishandling of Exceptional Conditions | Fail-closed scanning and processing errors |
| OWASP ASVS 5.0.0 V5 | File Handling | Verification chapter for upload and download controls |
| CWE-434 | Unrestricted Upload of File with Dangerous Type | Executable or active content upload |
| CWE-22 | Improper Limitation of a Pathname to a Restricted Directory | Path traversal and zip slip |
| CWE-409 | Improper Handling of Highly Compressed Data | Zip, image, and other expansion bombs |
| CWE-611 | Improper Restriction of XML External Entity Reference | XML entity expansion and external entities |

The mappings are chapter-level. Do not claim an ASVS level or invent a 5.0 requirement
number without checking the official requirements source.

## Configuration

Choose values per product and test them against real files. Example starting points:

| Setting | Example | Enforcement point |
|---|---:|---|
| Maximum request body | 10 MiB | Reverse proxy and application |
| Maximum image pixels | 25 million | Decoder, before expensive processing |
| Maximum archive entries | 1,000 | Archive inspection |
| Maximum expanded archive bytes | 100 MiB | Counting extractor |
| Upload rate | 20/hour/user | Application and edge |
| Download origin | `files.example.invalid` | Separate cookie-free origin |

These are operating defaults, not universal requirements. A direct-to-S3 POST policy must
repeat the size and type constraints because the application is not in the byte path.

## Example Usage

Ask for a bounded review:

```text
Review this upload and download flow against OWASP Top 10 2025 A01, A02, A08 and ASVS 5.0 V5.
Trace the bytes from request to storage to response. Check magic numbers, re-encoding, names,
path resolution, archive expansion, scan failure behaviour, authorization, and response headers.
For each finding give file:line, CWE, exploitation path, fix, and remaining limitation.
```

Ask for a design decision:

```text
Design an avatar upload. It must accept PNG, JPEG, and WebP, strip EXIF, reject pixel floods,
store outside the web root, and serve from a separate origin. Show Python code and the nginx
configuration, and state the CPU and quality costs of re-encoding.
```

## Limitations

- Magic-number detection does not prove a file has one safe interpretation. Polyglot files
  remain possible. Re-encoding helps only formats that can be safely decoded and encoded.
- Malware scanning is a low bar, not a verdict. ClamAV can miss novel or encrypted payloads,
  and a clean result does not make a parser safe.
- `Content-Disposition: attachment` reduces browser execution risk but is not a substitute for
  a separate origin, correct authorization, or CSP where content is intentionally previewed.
- Object storage removes server-side execute semantics, but a public bucket or broad object key
  still creates an access-control failure.
- A size limit does not stop every bomb. A small compressed archive or image can expand after
  validation; count entries, pixels, and decompressed bytes, and impose process limits.
- Code examples show the security boundary. Production code still needs framework-specific
  error handling, observability, retention, and key management.

## Security Notes

SVG is a script-bearing document, not an image. Do not allow it through an image allowlist
unless it is sanitized and served as inert data from a separate origin. Office formats are
ZIP containers containing XML and may carry macros, external relationships, and entity or
parser hazards. Do not render untrusted Office files in a privileged desktop or server
context.

Strip EXIF and other metadata before publishing photographs. GPS coordinates can reveal a
person's home or workplace even when the image pixels look harmless.

Archive extraction requires an explicit policy. Reject absolute entry names, `..` after
normalization, links outside the destination, device files, and entries exceeding counts or
expanded-byte limits. Extract into a fresh directory with restrictive permissions, then
move approved files by server-generated names.

## References

- [ASVS V5 summary](references/asvs-v5-file-handling.md)
- [File type detection](references/file-type-detection.md)
- <https://owasp.org/Top10/2025/>
- <https://owasp.org/www-project-application-security-verification-standard/>
- <https://cwe.mitre.org/data/definitions/434.html>
- <https://cwe.mitre.org/data/definitions/22.html>
- <https://cwe.mitre.org/data/definitions/409.html>
- <https://cwe.mitre.org/data/definitions/611.html>
