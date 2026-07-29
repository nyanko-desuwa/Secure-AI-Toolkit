# File Type Detection

What each detection method actually proves, and where it stops. Checked 2026-07-28.

## The three claims a client makes

| Claim | Source | Worth |
|---|---|---|
| Filename extension | Client-supplied string in the multipart part | None. Renaming a file changes it |
| `Content-Type` in the multipart part | Client-supplied header | None. Set by the uploading code, not derived from bytes |
| The bytes | The file itself | The only thing you can inspect |

Neither of the first two is a security control. A browser fills them in from the local
file, and any HTTP client fills them in with whatever it likes. `curl -F
"file=@shell.php;type=image/png"` sets `image/png` on PHP source.

## Magic numbers

Reading the leading bytes and matching a signature table tells you what a parser will
probably see. It is a real improvement over the extension and it is where detection should
start.

| Format | Leading bytes |
|---|---|
| PNG | `89 50 4E 47 0D 0A 1A 0A` |
| JPEG | `FF D8 FF` |
| GIF | `47 49 46 38` (`GIF8`) |
| PDF | `25 50 44 46` (`%PDF`) |
| ZIP, and every ZIP-based format (DOCX, XLSX, PPTX, ODF, JAR, APK) | `50 4B 03 04` (`PK\x03\x04`) |
| GZIP | `1F 8B` |
| WebP | `52 49 46 46` at 0, `57 45 42 50` at 8 |

Two things the table shows on its own. Detecting `PK\x03\x04` does not tell you whether the
file is a spreadsheet or a JAR - you must inspect the container. And SVG has no magic
number at all, because it is text; a leading `<?xml` or `<svg` is not a signature.

## Libraries

| Language | Library | Notes |
|---|---|---|
| Python | `python-magic` (libmagic binding), or `puremagic` for a pure-Python option | libmagic is the same engine as `file(1)` |
| Node | `file-type` (npm) | Reads from a buffer or stream; returns `undefined` for text formats including SVG and CSV |
| PHP | `finfo` / `finfo_file` with `FILEINFO_MIME_TYPE` | Built in; do not use `$_FILES['x']['type']` |
| CLI (verification) | `file --mime-type -b path` | Useful when checking a stored sample by hand |

Detection returns a claim about the bytes. It is not a decision. Map the detected type
through an allowlist and derive the extension from your own table, never from the input.

## Where magic numbers stop: polyglots

A polyglot file is valid to more than one parser at once. A GIF header followed by PHP
source is still a GIF to a signature check and still executable to a PHP handler. The same
trick works with JPEG comment segments, PDF, and ZIP - ZIP is especially easy because its
central directory sits at the end of the file, so arbitrary bytes can precede it.

Magic-number detection is a necessary filter, not a sufficient one. What closes the gap
depends on the format:

- Images: decode and re-encode. The output contains only what the new encoder wrote, so a
  trailing script payload does not survive. Costs CPU and memory, and loses animation,
  colour profiles, and embedded metadata unless you deliberately carry them over.
- Archives and Office documents: parse the container and validate its parts. Do not try to
  detect a polyglot by scanning for signatures.
- PDF: no re-encode is equivalent. Treat it as active content and serve it as an
  attachment, or rasterise it in a sandbox if it must be previewed.
- SVG: not an image. See below.

Independent of format, the storage and serving controls are what keep a polyglot inert:
outside the web root, server-generated name, fixed `Content-Type`, `nosniff`, attachment
disposition, separate origin.

## SVG is a document, not an image

SVG is XML. It can carry `<script>`, event handler attributes (`onload`, `onerror`),
`<foreignObject>` with embedded HTML, `<use href="...">` referencing external content, and
XML entity declarations. Rendered inline on your origin, a stored SVG is stored XSS.
Parsed on the server, it is an XXE and entity-expansion surface (CWE-611, CWE-409).

Options, strongest first:

1. Do not accept SVG. Accept raster formats and re-encode.
2. Rasterise on upload in a sandbox, store the PNG or WebP, discard the SVG.
3. Store the SVG but never render it inline: fixed `image/svg+xml` type,
   `Content-Disposition: attachment`, `nosniff`, separate origin with no session cookies,
   and a restrictive CSP on that origin.
4. Sanitise with a maintained library and still serve it from a separate origin. A
   handwritten regex or tag denylist is not sanitisation.

If the server parses SVG or an Office part, disable DTD loading and external entity
resolution. In Python, use `defusedxml` or verify the Expat version - the 3.14 standard
library docs state that Expat below 2.7.2 may be vulnerable to billion laughs, quadratic
blowup, and large-token attacks, and point at `pyexpat.EXPAT_VERSION` to check what your
interpreter bundles.

Source: <https://docs.python.org/3/library/xml.html>

## Expansion limits are part of detection

Detection tells you the format. It says nothing about what the format expands to.

- Pillow raises `DecompressionBombWarning` above `Image.MAX_IMAGE_PIXELS` and
  `DecompressionBombError` above twice that value. The default in Pillow 12.1.0 is
  89,478,485 pixels - verified locally against `PIL.Image.MAX_IMAGE_PIXELS`. That default is
  a crash guard, not an application limit; set your own well below it.
- ZIP: check entry count and the sum of declared uncompressed sizes before extracting, and
  still count real bytes while streaming. Declared sizes are attacker-controlled.
- XML: cap entity expansion, or use a parser that refuses DTDs.

Source: <https://pillow.readthedocs.io/>

## Sources

- <https://docs.python.org/3/library/xml.html>
- <https://docs.python.org/3/library/tarfile.html>
- <https://pillow.readthedocs.io/>
- <https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html>
- <https://cwe.mitre.org/>
