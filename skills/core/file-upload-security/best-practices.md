# File Upload Best Practices

Each control is mapped to OWASP Top 10 2025, ASVS 5.0, and a CWE where one applies. The
vulnerable blocks are intentionally unsafe. Do not copy them.

## Storage isolation

`A02:2025` · ASVS V5, V13 · `CWE-434`

A writable `uploads/` under the document root becomes RCE when PHP-FPM, JSP, CGI, or another
handler executes a landed script. A random name does not change that. Store outside the web
root, or use object storage with no execute semantics.

```php
// Vulnerable: web root plus client-selected extension enables script execution
$name = $_FILES['file']['name'];
move_uploaded_file($_FILES['file']['tmp_name'], "/var/www/html/uploads/$name");
```

```php
// Fixed: opaque server name in a non-served directory
$stored = bin2hex(random_bytes(16));
move_uploaded_file($_FILES['file']['tmp_name'], "/srv/app-data/uploads/$stored");
```

The fixed path cannot be requested as a web script, and the user name never becomes a path.
Permissions and PHP/nginx mapping still need deployment verification.

## Type detection and image re-encoding

`A08:2025` · ASVS V2, V5 · `CWE-434`

The extension and multipart `Content-Type` are client supplied. Magic bytes are better, but a
polyglot may be valid to more than one parser. For images, decode and re-encode to a server-
chosen format. This costs CPU, memory, latency, and may lose animation, profiles, comments,
or exact quality.

```python
# Vulnerable: both values are attacker-controlled claims
if upload.content_type == "image/png" and upload.filename.endswith(".png"):
    save(upload.file, upload.filename)
```

```python
# Fixed: bounded byte detection followed by decode and fresh encoding
from io import BytesIO
from PIL import Image, ImageOps

MAX_BYTES = 10 * 1024 * 1024
MAX_PIXELS = 25_000_000

def normalize_avatar(stream, destination):
    raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("file_too_large")
    with Image.open(BytesIO(raw)) as source:
        source.verify()                         # structural check
    with Image.open(BytesIO(raw)) as source:
        if source.width * source.height > MAX_PIXELS:
            raise ValueError("too_many_pixels")
        image = ImageOps.exif_transpose(source).convert("RGB")
        out = BytesIO()
        image.save(out, format="WEBP", quality=85, method=6, exif=b"")
    destination.write_bytes(out.getvalue())
```

`verify()` alone does not produce safe output. The second decode and new encode remove bytes
that are not represented in the new image. A parser vulnerability can still exist, so run it
in a sandbox and keep Pillow patched. Pillow's default `MAX_IMAGE_PIXELS` is 89,478,485 in
current releases; set an application limit lower than the library default where appropriate.

## Generated names and safe display

`A01:2025` · `A05:2025` · ASVS V1, V5 · `CWE-22`, `CWE-434`

UUIDs or random names are not authorization. They prevent name collisions and reduce guessing,
but access still needs an owner check. The original name is display-only and must be encoded
for its output context.

```ts
// Vulnerable: user name becomes a path and an HTML injection
const path = join(UPLOAD_DIR, req.file.originalname);
await fs.promises.rename(req.file.path, path);
res.send(`<a href="/files/${req.file.originalname}">download</a>`);
```

```ts
// Fixed: database identity controls storage and HTML escaping stays at the sink
const id = crypto.randomUUID();
const key = `${req.user.id}/${id}`;
await objectStore.put(key, req.file.path, { contentType: "image/webp" });
await files.insert({ id, ownerId: req.user.id, key, displayName: req.file.originalname });
res.json({ id, name: escapeHtml(req.file.originalname) });
```

The key is server-chosen and scoped to the owner. `escapeHtml` is required only because this
example emits HTML; use the framework's auto-escaping template for real views.

## Download headers and separate origin

`A01:2025` · `A02:2025` · `A05:2025` · ASVS V3, V5 · `CWE-434`

A stored HTML file served on the main origin can run script against the user's session. Fixed
headers and a separate origin make it data, not an extension of the application.

```ts
// Vulnerable: echoes object metadata and lets the browser interpret active content
res.setHeader("Content-Type", object.contentType);
res.sendFile(object.path);
```

```ts
// Fixed: authorization first; type is a server-side validated value
if (object.ownerId !== req.user.id) return res.sendStatus(404);
res.set({
  "Content-Type": object.safeType,
  "Content-Disposition": `attachment; filename="${asciiFallback(object.displayName)}"`,
  "X-Content-Type-Options": "nosniff",
  "Content-Security-Policy": "default-src 'none'; sandbox",
});
return res.sendFile(object.path);
```

Serve this handler from `files.example.com`, not the application origin, with no session
cookies. A fixed type prevents type smuggling; attachment and `nosniff` reduce browser
interpretation. Do not use the display name unescaped in a header; reject CR/LF and use a
proper header serializer.

## Resolve before checking download paths

`A01:2025` · ASVS V5 · `CWE-22`

Rejecting strings containing `..` is not path security. Encodings, absolute paths, and symlinks
bypass string checks. Resolve first, then check containment. Prefer an object ID and database
lookup so the client never supplies a path.

```python
# Vulnerable: checks text and joins an attacker-controlled path
if ".." not in name:
    return send_file(os.path.join(UPLOAD_DIR, name))
```

```python
# Fixed: resolve both sides, then verify containment and ownership
from pathlib import Path

ROOT = Path("/srv/app-data/uploads").resolve()
def download(file_id, actor):
    row = db.file_for_owner(file_id, actor.id)
    if row is None:
        raise NotFound()
    target = (ROOT / row.storage_name).resolve()
    if not target.is_relative_to(ROOT) or not target.is_file():
        raise NotFound()
    return send_fixed_attachment(target, row.safe_type, row.display_name)
```

Resolution collapses `..`, absolute components, and symlinks before the boundary test. The
owner-scoped lookup prevents IDOR; a generated storage name makes traversal unnecessary.

## Archive extraction without zip slip or tar links

`A01:2025` · `A06:2025` · `A08:2025` · ASVS V5 · `CWE-22`, `CWE-409`

Zip entry names can write outside the destination. Tar archives also carry symlinks, hard
links, devices, and permissions. Inspect and count before extracting; use a fresh directory,
server names, and OS resource limits.

```python
# Vulnerable: archive metadata chooses the destination
with zipfile.ZipFile(upload) as archive:
    archive.extractall("/srv/app-data/work")
```

```python
# Fixed: normalize each entry, reject escape, links, and expansion
from pathlib import Path
import zipfile

DEST = Path("/srv/app-data/work/job-opaque").resolve()
MAX_ENTRIES, MAX_EXPANDED = 1000, 100 * 1024 * 1024

def safe_zip(path):
    with zipfile.ZipFile(path) as z:
        infos = z.infolist()
        if len(infos) > MAX_ENTRIES or sum(i.file_size for i in infos) > MAX_EXPANDED:
            raise ValueError("archive_expands_too_far")
        for info in infos:
            target = (DEST / info.filename).resolve()
            if not target.is_relative_to(DEST):
                raise ValueError("archive_path_traversal")
            mode = info.external_attr >> 16
            if mode and (mode & 0o170000) == 0o120000:
                raise ValueError("archive_symlink")
        for info in infos:
            target = (DEST / info.filename).resolve()
            target.parent.mkdir(parents=True, exist_ok=True)
            if not info.is_dir():
                with z.open(info) as src, target.open("xb") as dst:
                    copy_limited(src, dst, MAX_EXPANDED)
```

A production `copy_limited` must count per-entry and total bytes while streaming; the sum of
headers alone is not enough. On Python versions supporting tar filters, use `tar.extractall(
filter="data")`, while still enforcing counts and expanded bytes. The `data` filter does not
close all denial-of-service cases or repeated-name overwrites.

## Limits, scanners, and sandboxes

`A06:2025` · `A08:2025` · `A10:2025` · ASVS V2, V5, V16 · `CWE-409`

Rate-limit uploads by actor and IP. Cap request and file bytes, image pixels, archive entries
and expanded bytes, parser time, memory, and concurrent jobs. A decompression bomb is small on
the wire and huge after expansion. XML entity expansion can turn a tiny SVG or Office part
into a memory or CPU attack; disable DTD/external entities and use a hardened parser.

Run ClamAV or another scanner before release, ideally in a worker sandbox with no network,
read-only code, a private temp directory, low privileges, and OS CPU/memory limits. ClamAV is
useful baseline detection, not a guarantee. A scanner outage must quarantine or reject, never
approve. Image and document parsers are a large native-code attack surface; scanning does not
make their process safe.

## Direct-to-object-storage policy

`A01:2025` · `A06:2025` · `A08:2025` · ASVS V4, V5 · `CWE-434`

Presigned URLs reduce application bandwidth, not validation responsibility. Generate one
short-lived URL for one opaque key. A presigned POST policy must constrain `content-length-range`,
allowed `Content-Type`, key prefix/equality, and any ACL or metadata fields. After upload, a
worker reads the object, validates magic bytes, limits dimensions/expansion, strips metadata,
scans, and only then changes its state from `quarantine` to `available`.

```ts
// Vulnerable: broad PUT URL, no size, type, key, or post-upload validation
return getSignedUrl(s3, new PutObjectCommand({ Bucket: BUCKET, Key: req.body.key }), {
  expiresIn: 3600,
});
```

```ts
// Fixed design: server key and policy constraints; worker validates after upload
const key = `quarantine/${req.user.id}/${crypto.randomUUID()}`;
return createPresignedPost(s3, {
  Bucket: BUCKET, Key: key, Expires: 300,
  Conditions: [["content-length-range", 1, 10 * 1024 * 1024],
               ["eq", "$Content-Type", "image/png"], ["eq", "$key", key]],
  Fields: { key, "Content-Type": "image/png" },
});
// completion: validate object bytes, re-encode, scan; publish only on success
```

The policy limits what the browser can send, but it cannot prove the bytes are PNG. Post-upload
validation remains mandatory. A URL with no constraints lets a client overwrite or fill any key
it can reach and can create an unbounded storage bill.

## Nginx defense in depth

`A02:2025` · ASVS V3, V5 · `CWE-434`

Keep storage outside the document root. If a legacy deployment has an upload location, make
sure it is not sent to an interpreter and disable directory listings. This is not a substitute
for isolated storage.

```nginx
# files.example.com; files are private and application authorization is separate
server {
    server_name files.example.com;
    root /srv/app-data/uploads;
    autoindex off;
    client_max_body_size 10m;

    location ~* \.(php|phtml|phar|jsp|jspx|cgi|pl|py|sh)$ {
        return 404;
    }
    location / {
        default_type application/octet-stream;
        add_header Content-Disposition "attachment" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Content-Security-Policy "default-src 'none'; sandbox" always;
        try_files $uri =404;
    }
}
```

A deny extension rule is only defense in depth: handlers can be bypassed with configuration,
case, alternate suffixes, or a different executable type. The directory must still be
non-executable and outside the app's document root.
