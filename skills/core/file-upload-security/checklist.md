# File Upload Verification Checklist

Mark pass, fail, or not applicable. An N/A needs a reason. A control is not a pass because a
framework probably enables it; verify the version and runtime configuration.

## Authorization and Names — A01 · ASVS V5, V8 · CWE-22

- [ ] Upload permission is enforced server-side for the authenticated actor and tenant.
- [ ] Download permission checks the stored object owner or explicit capability.
- [ ] Client names are used only for display, encoded for the display context, and never used
      as a filesystem path, object key, command argument, or HTML markup.
- [ ] The stored name/key is generated with a CSPRNG or an opaque database identifier.
- [ ] Download paths are resolved before checking they are inside the permitted root.
- [ ] A missing object and an object the actor cannot access do not disclose its existence.

## Type and Content — A08 · A05 · ASVS V1, V2, V5 · CWE-434

- [ ] Extension and declared `Content-Type` are treated as untrusted hints, not validation.
- [ ] The server checks magic bytes and parses the format with a bounded decoder.
- [ ] Polyglot limitations are documented; high-risk image types are decoded and re-encoded.
- [ ] SVG is rejected, sanitized as a document, or served as inert attachment on a separate origin.
- [ ] Office and XML parsers disable external entities, network access, and macros where supported.
- [ ] Uploaded content is not deserialized with a code-capable deserializer.
- [ ] Image EXIF and other privacy-sensitive metadata are stripped before publication.

## Storage and Serving — A02 · A01 · ASVS V3, V5 · CWE-434

- [ ] Files are stored outside the document root, or in object storage with no execute semantics.
- [ ] No web server maps an upload directory to PHP, JSP, CGI, or another code handler.
- [ ] Download authorization occurs before opening or redirecting to the object.
- [ ] Response `Content-Type` is selected by the server from validated type, never echoed from
      the request or object metadata.
- [ ] `Content-Disposition: attachment` is set unless a narrowly justified safe preview exists.
- [ ] `X-Content-Type-Options: nosniff` is set.
- [ ] File responses come from a separate cookie-free origin; no session cookies are sent there.
- [ ] Object storage policies constrain keys and do not make the whole bucket public.

## Resource Limits — A06 · A10 · ASVS V2, V5 · CWE-409

- [ ] Edge and application enforce maximum request bytes, file bytes, file count, and upload rate.
- [ ] Limits use observed bytes, not only a client-supplied `Content-Length`.
- [ ] Image dimensions and pixel count are bounded before full processing.
- [ ] Archives cap entry count, nesting, compressed size, expanded size, and processing time.
- [ ] Archive entry names are normalized and checked for traversal; tar links and special files
      are rejected or constrained inside the destination.
- [ ] Processing runs with CPU, memory, filesystem, and network limits in a sandbox.
- [ ] Oversize, timeout, parse, or scan failures fail closed and leave no approved file.

## Scanning and Operations — A08 · A09 · A10 · ASVS V5, V16

- [ ] Malware scanning happens before release to a user-visible location.
- [ ] ClamAV or equivalent is treated as a low-bar detection layer, not proof of safety.
- [ ] Scanner errors and unavailable scanners quarantine or reject; they do not approve.
- [ ] Upload, scan, quarantine, rejection, download denial, and deletion decisions are logged.
- [ ] Logs contain actor, object ID, outcome, and correlation ID, but not file contents or secrets.
- [ ] Quarantine retention and cleanup are bounded.

## Direct-to-Object-Storage Uploads — A01 · A06 · A08 · ASVS V4, V5

- [ ] Presigned URLs are short-lived, scoped to one server-generated key and actor.
- [ ] POST policy conditions constrain exact or allowed `Content-Type` and `content-length-range`.
- [ ] The client cannot choose a bucket, prefix, ACL, metadata that changes serving behaviour, or
      overwrite another object.
- [ ] A completion callback or worker validates bytes after upload before marking the object safe.
- [ ] Unvalidated objects are private and quarantined; the public URL is issued only after checks.
