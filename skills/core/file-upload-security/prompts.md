# Prompt Examples

Prompts that produce findings instead of a recital of upload advice. Each one bounds the
input, names the standard, and asks for an exploitation path.

## Review an upload handler

```
Read src/api/uploads.py and review the upload handler against OWASP Top 10 2025 A08 and
ASVS 5.0 V5. For each finding give the CWE, the line, the concrete exploitation path, and
the fix. Tell me specifically: is the stored filename server-generated, is the storage
directory inside the document root, and is the type decided from bytes or from a header?
```

The three explicit questions are what make this useful. Without them the answer drifts into
generic advice about validating uploads.

## Trace the whole path, upload to serve

```
Follow one uploaded avatar through this codebase: the multipart handler, where the bytes
land, and the endpoint that serves it back. For the serving side, tell me the Content-Type,
whether Content-Disposition is set, whether nosniff is present, and which origin it is
served from. Map gaps to A01, A02, or A05 with a CWE.
```

Most real upload bugs live in the gap between the two halves. A handler reviewed alone looks
fine; the stored-XSS path only appears when you read the download side.

## Check the storage and serving configuration

```
Read the nginx config and the deployment manifests. Is the upload directory reachable as a
URL? Is any handler mapped to it? Does the response go through a CDN that could add back
Content-Type sniffing? Say plainly what you could not verify from the files alone.
```

Ending with the honesty clause matters. Code review cannot confirm runtime configuration,
and an assistant that claims otherwise produces a false pass.

## Archive extraction

```
This worker extracts uploaded ZIP files. Check it for zip slip (CWE-22), symlink entries,
entry-count limits, and expanded-size limits (CWE-409). Show me the containment check and
whether it happens before or after path resolution.
```

Asking where the check happens relative to resolution catches the common broken version:
rejecting strings containing `..` instead of resolving and testing containment.

## Presigned upload design review

```
I am adding direct-to-S3 uploads with presigned URLs. Before I write it: what must the
policy constrain, what still has to be validated server-side after the upload, and what
does a presigned PUT with no conditions let a client do? Map each control to a Top 10 2025
category and ASVS V5.
```

Design-time is the right moment for this one. Retrofitting post-upload validation onto a
"the client uploads and we mark it done" flow means changing the state machine.

## SVG specifically

```
This app accepts SVG logos and renders them with an <img> tag on the profile page. Explain
the stored XSS path, then give me the options ranked by residual risk: rasterise, sanitise,
or separate origin plus attachment. Say what each one costs the product.
```

Naming the rendering context (`<img>` versus inline `<svg>` versus direct navigation)
changes the answer, so state it.

## Resource limits and bombs

```
Review this image pipeline for decompression bombs. Check the request body limit, the file
size limit enforced on bytes actually written, the pixel limit before decode, and whether
Pillow's MAX_IMAGE_PIXELS is relied on as the only guard. Map to CWE-409 and A10:2025.
```

## Verify before returning code

```
Run skills/core/file-upload-security/checklist.md against this diff. Mark each item pass,
fail, or not applicable with a one-line reason. Do not mark anything pass that you have not
actually read the code for, and list anything you could only verify at runtime separately.
```

## Anti-patterns

| Prompt | Problem |
|---|---|
| "Is my file upload secure?" | No scope. Produces the generic list, not findings in your code |
| "Add file validation" | Yields an extension allowlist and nothing else. The weakest control, presented as done |
| "Sanitise the filename" | Frames the name as fixable. The fix is to stop using it as a path at all |
| "Block dangerous extensions" | A denylist. `.phtml`, `.phar`, `.pht`, case variants, and trailing dots all survive |
| "Make uploads OWASP compliant" | There is no compliance state for Top 10. Ask for specific controls |
| "Check the MIME type" | Ambiguous between the client header and byte detection, and the two are opposites |
| "Scan uploads for malware" | Treats the weakest layer as the primary control. Isolation comes first |
