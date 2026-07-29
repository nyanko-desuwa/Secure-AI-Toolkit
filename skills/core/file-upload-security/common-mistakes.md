# Common Mistakes

What goes wrong in upload code, why it goes wrong, and the fix. Every code block marked
`Vulnerable:` is unsafe by design.

## Trusting the extension or the declared Content-Type

```python
# Vulnerable
if file.content_type in ("image/png", "image/jpeg"):
    file.save(f"/var/www/html/uploads/{file.filename}")
```

Both values arrive in the multipart body. The client writes them. Renaming `shell.php` to
`shell.png` and sending `Content-Type: image/png` passes this check unchanged.

Fix: detect the type from the file's own leading bytes, and for images decode and re-encode to
a server-chosen format. See [best-practices.md](best-practices.md#type-detection-and-image-re-encoding).
Why it works: the decision comes from data the server read, not from a claim it was handed.

## Storing uploads under the document root

```php
// Vulnerable
move_uploaded_file($_FILES['f']['tmp_name'], __DIR__ . "/uploads/" . $safeName);
```

The moment a `.php`, `.phar`, `.jsp`, or `.cgi` file lands in a directory the web server maps
to an interpreter, the upload endpoint is remote code execution. A sanitized name does not
help if the extension survives, and handler mapping is often broader than expected.

Fix: store in a directory the web server does not serve, or in object storage. Serve bytes
through an application handler that sets the type itself.
Why it works: there is no URL that reaches the file as executable code.

## A UUID filename treated as access control

```ts
// Vulnerable
app.get("/files/:name", (req, res) => res.sendFile(join(DIR, req.params.name)));
```

Random names stop collisions and casual guessing. They are not authorization. Keys leak through
logs, `Referer`, shared links, backups, and support tickets, and the handler also has a path
traversal in it.

Fix: look the row up by ID scoped to the actor, then serve the resolved path.
Why it works: the check is ownership in the query, so a leaked identifier alone is not enough.

## Checking the path for `..` instead of resolving it

```python
# Vulnerable
if ".." in name or name.startswith("/"):
    abort(400)
path = os.path.join(UPLOAD_DIR, name)
```

String inspection runs before normalization. Percent-encoded and double-encoded separators,
platform-specific separators, and symlinks inside the upload directory all defeat it. On
Windows, `os.path.join` also discards the base when handed an absolute path.

Fix: resolve the candidate path, then require it to be inside the resolved root.
Why it works: `..`, symlinks, and absolute segments are already collapsed when the boundary
test runs. Best of all, do not accept a path from the client.

## `extractall` on an uploaded archive

```python
# Vulnerable
with zipfile.ZipFile(upload) as z:
    z.extractall(dest)
```

Zip entry names may contain `../` and write outside `dest` - zip slip. Python's `zipfile` has
sanitized entry names on extraction for some time, but code that builds its own paths from
`namelist()` does not inherit that, and other languages and libraries do not sanitize at all.
Tar is worse: entries can be symlinks, hard links, or device nodes, and setuid bits ride along.

Fix: validate each entry name against the resolved destination, reject links and special files,
cap entry count and expanded bytes, and extract into a fresh directory. On Python versions with
tar filters, pass `filter="data"`.
Why it works: the destination is decided by the server for every entry, and non-file members are
refused rather than recreated.

## Treating SVG as an image

```ts
// Vulnerable
res.type("image/svg+xml").send(await fs.promises.readFile(uploadPath));
```

SVG is XML that carries `<script>`, `on*` handlers, `<foreignObject>`, external references, and
a DTD. Served inline from the application origin it is stored XSS. It is also an XML entity
expansion vector, so it can be a CPU and memory attack before any script runs.

Fix: either rasterize to PNG/WebP on upload and discard the SVG, or sanitize with a maintained
sanitizer, disable DTD and external entities, and serve as an attachment from a separate origin.
Why it works: rasterizing removes the script-bearing document entirely; the header and origin
controls stop what remains from executing in the application's context.

## Size limits only at the framework layer

Framework body limits stop a large POST. They do not stop a 200 KB zip that expands to 4 GB, a
tiny PNG whose header claims 60,000 x 60,000 pixels, or a small SVG with nested entity
definitions. All three are CWE-409, and all three are cheap for an attacker.

Fix: cap request bytes, and separately cap decompressed size, pixel count, entry count, parse
time, and memory. Count expanded bytes while streaming rather than trusting declared sizes.
Why it works: the resource that is actually exhausted is the one being limited.

## Presigned URL with no policy conditions

```ts
// Vulnerable
const url = await getSignedUrl(s3, new PutObjectCommand({ Bucket, Key: req.body.key }));
```

The key comes from the client, and nothing constrains size or type. A caller can overwrite
another object it can name, upload arbitrary content, and run the storage bill up. Long expiry
turns one issued URL into a reusable upload channel.

Fix: server-generated key under a quarantine prefix, short expiry, and a POST policy with
`content-length-range`, an `eq` condition on `$Content-Type` and `$key`. Then validate the
stored object before publishing it.
Why it works: the policy bounds what the browser can send, and post-upload validation covers
what a policy cannot check - the actual bytes.

## Malware scanning as the only control

A clean ClamAV result means known signatures did not match. It says nothing about a targeted
payload, a polyglot, or a parser exploit. Codebases that scan and then skip type validation,
storage isolation, and download headers have swapped a strong control for a weak one.

Fix: keep scanning, but as one layer after type validation, re-encoding, isolation, and limits.
Quarantine on scanner error or timeout.
Why it works: the layers that do not depend on prior knowledge of the payload stay in place.

## Serving the file with its stored metadata

```ts
// Vulnerable
res.setHeader("Content-Type", row.clientContentType);
res.setHeader("Content-Disposition", `inline; filename="${row.originalName}"`);
```

The type was captured from the upload request, so the attacker chose it. The filename is
unescaped, so CR/LF or a quote can inject or break headers, and `inline` invites the browser to
render active content.

Fix: store a server-validated type, send `Content-Disposition: attachment` plus
`X-Content-Type-Options: nosniff`, and encode the filename (RFC 5987 `filename*` with an ASCII
fallback), rejecting control characters.
Why it works: nothing the client supplied influences how the browser interprets the response.

## Forgetting EXIF

Phone photos carry GPS coordinates, device serials, and timestamps. Publishing the original
bytes publishes a user's home address. This is a data protection failure, not a code execution
one, and it is easy to miss because nothing breaks.

Fix: re-encode without metadata, or strip explicitly, keeping only what the product needs
(often just orientation, applied then dropped).
Why it works: the bytes that contained the location no longer exist in the stored object.

## Parsing untrusted files in the request process

Image and document parsers are large native-code surfaces. Running them inline means a parser
bug is a compromise of the process holding your database credentials and session keys.

Fix: hand the file to a worker with no network egress, read-only code, a private temp directory,
an unprivileged user, and OS-level CPU/memory/time limits.
Why it works: a parser crash or exploit is contained by the process boundary rather than
inheriting the application's privileges.
