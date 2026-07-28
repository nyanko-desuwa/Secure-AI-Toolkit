---
name: file-upload-security
description: 'Decide how to accept files from users and serve them back without handing over code execution, stored XSS, or the filesystem. Triggers: "file upload", "multipart", "avatar", "attachment", "presigned URL", "zip slip", "SVG upload", "tải tệp lên", "kiểm tra tệp".'
allowed-tools: Read, Write, Edit, Glob, Grep, Bash(ls:*), Bash(cat:*), WebSearch, WebFetch
---

# File Upload Security

An upload endpoint takes attacker-controlled bytes, an attacker-controlled name, and an
attacker-controlled type, and writes them to your disk. This skill decides what to check,
where to put the result, and how to hand it back.

## When to Use

- Writing or reviewing any endpoint that accepts a file, including multipart forms, base64
  JSON payloads, and presigned direct-to-storage uploads
- Writing the download or preview endpoint that serves user content back
- Extracting an archive, parsing a document, or generating a thumbnail
- Reviewing storage layout, bucket policy, or the web server config in front of uploads
- Handling images, SVG, PDF, Office documents, or anything a native parser touches

## Standards This Skill Maps To

| Standard | Use it for | Version here |
|---|---|---|
| Top 10 A08 Software or Data Integrity Failures | Untrusted content accepted and trusted downstream | 2025 |
| Top 10 A01 Broken Access Control | Path traversal, reading another user's file, unscoped presigned URLs | 2025 |
| Top 10 A02 Security Misconfiguration | Storage inside the web root, sniffable responses, executable upload dirs | 2025 |
| ASVS V5 File Handling | Verification: upload, download, path handling, archive extraction | 5.0.0 |
| CWE-434, CWE-22, CWE-409, CWE-611 | Naming the specific defect in a finding | current |

Top 10 gives you the risk framing for a report. ASVS V5 is the chapter you open to check
whether the implementation is actually correct. See [references/](references/).

## Workflow

### 1. Scope

Three questions, answerable before any code:

- What does the application do with these bytes later? Serve them, parse them, execute
  them, hand them to a shell tool, or index them?
- Who is allowed to read the file once stored, and where is that decided?
- If the file is hostile, what is the worst outcome — script in a page, code on the server,
  disk exhausted, or a parser crash?

The third question sets the controls. An avatar that is only ever re-encoded and served
from a CDN needs different work than an XLSX that gets parsed by a native library.

### 2. Map

An upload endpoint is almost always A08 (accepting untrusted content), plus A02 if storage
or serving is misconfigured, plus A01 if download is not scoped to the owner. It is
frequently A10 as well, because size and expansion limits are a failure-path concern.

It is not A04. A missing checksum is an integrity failure, not a cryptographic one. And a
public bucket is A01 or A02, not "encryption".

Attach the CWE. `CWE-434` for accepting a dangerous type, `CWE-22` for traversal in the
name or the download path, `CWE-409` for decompression bombs, `CWE-611` for entity
expansion in SVG and Office XML.

### 3. Apply Controls

Ordered by what fails hardest if missing:

1. **Storage isolation.** Outside the document root, or object storage with no execute
   semantics. Nothing else on this list survives a writable, executable `uploads/`
   directory. See [best-practices.md](best-practices.md#storage-isolation).
2. **Server-generated filenames.** The client's name is a display string and nothing else.
3. **Content-based type determination, then re-encoding where the format allows it.**
   Magic numbers reject the obvious; re-encoding is what actually removes a payload.
4. **Fixed response headers on the way out.** One `Content-Type` you chose,
   `Content-Disposition: attachment`, `nosniff`, and a separate origin for anything
   rendered inline.
5. **Size, count, rate, and expansion limits.** Enforced on real bytes written, not on a
   declared length.
6. **Authorization on download.** Resolve the path first, then check it is inside the root,
   then check the actor owns the record.
7. **Sandboxed parsing and scanning.** Last, because it is the weakest layer, not the
   first.

### 4. Verify

Run [checklist.md](checklist.md) before returning code. Every unchecked box is a fix or a
stated limitation. "Magic number checked" is not a pass if the format is SVG.

### 5. Report

Per finding: the category, the file and line, the concrete exploitation path, and the fix.
"Uploads are not validated" is not a finding. "A `.php` file lands in
`public/uploads/` and PHP-FPM is mapped to that directory, so any authenticated user gets
RCE" is.

## Severity

- **Critical** — an uploaded file can be executed as code on the server, or a stored file
  runs script on your primary origin against a logged-in session
- **High** — traversal writes or reads outside the storage root, one user reads another
  user's file, or a presigned URL lets a client write anywhere in the bucket
- **Medium** — decompression or pixel bomb takes the process down, EXIF GPS leaks to every
  viewer, missing size limits fill the disk
- **Low** — metadata not stripped from a non-public file, no malware scan, no checksum

Adjust for reachability. An SVG upload restricted to admins and served from a
sandboxed origin with `Content-Disposition: attachment` is not the same finding as an
avatar rendered inline on every profile page.

## Related Skills

- `owasp` — the general Top 10 and ASVS mapping this skill specialises
- `cloud-security` — bucket policy, IAM scoping, and CDN configuration
- `frontend-security` — CSP and the separate-origin decision on the browser side
- `api-security` — resource consumption limits on the endpoint itself

## Supporting Files

- [README.md](README.md) — purpose, configuration, limitations
- [checklist.md](checklist.md) — pre-return verification
- [best-practices.md](best-practices.md) — patterns, with vulnerable/fixed pairs
- [common-mistakes.md](common-mistakes.md) — what goes wrong and why the fix works
- [troubleshooting.md](troubleshooting.md) — when the guidance cannot be applied
- [prompts.md](prompts.md) — prompts that produce findings
- [references/](references/) — ASVS V5 summary, file type detection
- [examples/](examples/) — eight vulnerable/fixed pairs
