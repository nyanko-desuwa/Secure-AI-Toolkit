# Troubleshooting

What to do when the guidance cannot be applied as written.

## The product requires SVG uploads

This is the most common real conflict. SVG is a script-bearing document, and "sanitise it"
is not a complete answer.

Rank the options and present them with what each costs:

1. Rasterise on upload, store PNG or WebP, discard the SVG. Loses scalability - a logo
   becomes fixed-resolution.
2. Store the SVG, never render it inline. Fixed `image/svg+xml`,
   `Content-Disposition: attachment`, `nosniff`, separate cookieless origin, restrictive
   CSP. The file stays vector, but it cannot be used as an `<img>` on your own page.
3. Sanitise with a maintained library plus the separate origin. Weakest, and it depends on
   a sanitiser keeping up with browser parsing quirks.

If the requirement is genuinely "vector logos rendered inline", say that option 3 plus a
separate origin is the only shape that satisfies it and that the residual risk is real.
Do not claim a regex denylist made it safe.

## Storage is already inside the web root and cannot move

Migrating a path breaks existing URLs, and that is often owned by another team. Interim
measures, in order of value:

1. Make the directory non-executable at the web server or handler level. In nginx, no
   `fastcgi_pass` for that location; in Apache, `php_admin_flag engine off` plus
   `RemoveHandler` for that directory.
2. Add the extension-deny location block, knowing it is defence in depth only.
3. Write all new uploads outside the root and serve old paths through a redirect.

Report the interim state as an open finding with the migration path, not as fixed. An
executable upload directory is the single control that makes every other one irrelevant.

## Re-encoding is unacceptable for this format

Photographers reject lossy re-encoding, designers need the colour profile, and animation
does not survive a naive convert. Options:

- Re-encode losslessly where the format allows it (PNG to PNG, WebP lossless), accepting
  the size cost.
- Keep the original in a private bucket that is never served to browsers, and serve only a
  re-encoded derivative. The original stays available for download-as-attachment.
- For formats with no safe re-encode (PDF, Office), accept that validation is structural
  and lean entirely on isolation: separate origin, attachment disposition, sandboxed
  parsing.

Say which one you chose and what it does not cover.

## The type-detection library returns nothing

`file-type` and libmagic return no result for text formats: SVG, CSV, plain text, JSON,
and some subtitle formats. Do not treat "no detection" as "unknown, therefore reject" if
the product accepts CSV.

For text formats, detection is not the control. Parse it as the format you expect with a
strict parser, cap the size, and serve it as an attachment. For CSV specifically, remember
that a leading `=`, `+`, `-`, or `@` in a cell is a formula-injection problem in Excel, not
an upload problem - it belongs to the export path.

## Magic bytes pass but the file is still rejected downstream

The detected container is right and the inner format is wrong. `PK\x03\x04` matches DOCX,
XLSX, JAR, and APK identically. Detecting ZIP does not tell you which.

Inspect the container: for OOXML, check for `[Content_Types].xml` and the expected part
layout; for a JAR, `META-INF/MANIFEST.MF`. Then apply the archive limits - an XLSX is a ZIP,
so entry count and expanded size limits apply to it too.

## The scanner is unavailable in the deploy environment

ClamAV is often not available in a serverless or restricted container runtime. Do not
silently drop the scan and do not fail open.

Set the record to `quarantine` and leave it there. An unscanned file is not `available`. If
the product cannot tolerate delayed availability, that is a product decision to escalate,
not a check to skip. Document that scanning is absent and that the isolation controls are
therefore carrying the whole load.

## Presigned uploads make server-side validation feel impossible

It is not impossible, it is asynchronous. The upload completing is not the file becoming
usable.

Write the object into a `quarantine/` prefix, have a worker read it, validate, re-encode,
strip metadata, scan, then copy to the served prefix and update the record. If there is no
worker infrastructure, validate on first access and cache the result - worse for latency,
but still a real check.

If the constraint is "the client needs the URL immediately after upload", return a URL that
points at your application, not at the bucket, and have it 404 until validation passes.

## You cannot tell whether the deployment is actually safe

Reading code cannot confirm that `/srv/app-data` is outside the document root, that the
bucket is private, that the CDN does not add `Content-Type` sniffing back, or that a
separate origin has no session cookies.

State it as unverified. "Storage path is outside the web root in the code, but I could not
confirm the nginx `root` directive or the bucket policy" is honest and actionable. Claiming
the control is in place because the code looks right is how these get missed.

## Two controls conflict

Fixed `Content-Disposition: attachment` breaks inline image display. Separate-origin
serving breaks a same-origin fetch that relies on cookies.

Resolve by asking what has to render inline. Images that must render inline get:
re-encoded to a raster format server-side, served from the separate origin with a fixed
image type and `nosniff`, without attachment disposition. Everything else - documents,
archives, anything unrecognised - gets attachment disposition. That split is defensible;
turning off attachment disposition globally because one avatar needed it is not.

## The standard has moved on

ASVS 5.0.0 (released 2025-05-30) and Top 10 2025 references here were checked 2026-07-28.
Chapter numbers move between major versions, and 5.0 requirement IDs do not map from 4.x.
If a report needs a precise requirement number, pull it from the ASVS repository rather
than quoting from memory. See [references/](references/) for URLs.
