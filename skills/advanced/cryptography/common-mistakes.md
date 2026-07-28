# Common Mistakes

What goes wrong in crypto code, why it goes wrong, and why the fix actually closes the hole.

## The threat model was never written down

Data encrypted in the application, key read from an environment variable in the same container,
attacker gets application-level RCE. The encryption stopped nothing — the attacker has the key.

This is the most common crypto failure and it has no algorithm in it. Encryption at rest defends
against stolen disks, stolen backups, and cloned snapshots. It does not defend against an attacker
who is inside the process that decrypts.

Fix: name the attacker before choosing the primitive. If the answer is "a stolen backup", the
platform's disk or database encryption is usually sufficient and adds no key management risk. If it
is "a malicious operator", the key must be somewhere the operator cannot reach — a KMS with an IAM
policy they lack, or an HSM.

## Password hashed with a fast hash

```python
hashlib.sha256(password.encode()).hexdigest()
```

SHA-256 is designed to be fast, which is exactly the wrong property. A commodity GPU tries billions
per second. Adding a salt defeats precomputed tables and does nothing about throughput — the
attacker just works one account at a time.

Fix: Argon2id at the OWASP baseline. See
[references/password-storage.md](references/password-storage.md).

Wrong fix people reach for first: iterating SHA-256 ten thousand times in a hand-written loop. That
is PBKDF2 without the review, with no memory hardness, and it still runs fast on a GPU because SHA-256
needs almost no memory.

## Static or reused nonce in GCM

```python
NONCE = b"\x00" * 12         # module-level constant
AESGCM(key).encrypt(NONCE, pt, None)
```

The usual reasoning is that the nonce is not secret, so a constant seems harmless. GCM nonce reuse
is catastrophic, not degraded: two messages under one key/nonce pair leak their XOR, and the
authentication subkey becomes recoverable. The attacker then forges valid ciphertexts.

Fix: fresh random nonce per message, stored with the ciphertext. See
[best-practices.md](best-practices.md#aead-encryption-and-nonce-uniqueness).

The subtler version is a counter in a database column with two application instances writing it, or
a counter reset to zero on restart. If you cannot prove uniqueness across processes and restarts,
use random nonces, and use XChaCha20-Poly1305 if the volume is high.

## Unauthenticated cipher mode

```python
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
```

CBC with no MAC means an attacker can modify the ciphertext and you will decrypt the result. With a
distinguishable padding error you have a padding oracle and full plaintext recovery; without one you
still have malleability.

Fix: an AEAD mode — AES-GCM or ChaCha20-Poly1305. It authenticates as part of decryption, so
tampering surfaces as an exception.

Wrong fix: bolting on an HMAC yourself. Order matters, the MAC must cover the IV, the comparison
must be constant-time, and you now own a construction. Use AEAD.

## Key in source, or in the image

```javascript
const KEY = Buffer.from("2f8a1c...", "hex"); // TODO: move to env before launch
```

The TODO does not stop the commit. Once in git history the key is exposed even after the line is
deleted, and a key baked into a container layer is readable by anyone who can pull the image.

Fix: key from a KMS or secret manager, fetched at runtime. If a key has already been committed,
rotate it and re-encrypt — deleting the line is not remediation. See `secrets-management`.

## No key rotation path

Nothing is broken, so nothing looks wrong. Then a key leaks, and there is no way to re-encrypt
because ciphertexts carry no key ID and the code has one hardcoded call. Rotation becomes a
downtime migration during an incident, which is the worst possible time.

Fix: store `key_id` and `alg` with every ciphertext, keep a decrypt path for old keys, and rehearse
a rotation on a schedule so you know the procedure works before you need it.

## Certificate verification disabled to make it work

```python
requests.get(url, verify=False)          # "fixed" a self-signed cert error
```

```go
tls.Config{InsecureSkipVerify: true}
```

This removes the only thing that distinguishes the real server from an attacker on the path. TLS
still encrypts — to whoever answered.

Fix: point the client at the CA bundle that signed the certificate (`verify="/path/ca.pem"`,
`RootCAs: pool`). For a self-signed development certificate, add that certificate to the trust
store rather than turning verification off.

Half-fix worth knowing: validating the chain but not the hostname. Any certificate from any public
CA then passes. In Java, the missing piece is
`setEndpointIdentificationAlgorithm("HTTPS")`.

## JWT verified on the token's own terms

```javascript
jwt.verify(token, secret);               // no algorithms option
```

The header is attacker-controlled. Depending on library and version this admits `alg: none` or an
`HS256` token verified against a public key that the attacker also knows.

Fix: pin `algorithms`, `issuer`, and `audience` server-side. See
[best-practices.md](best-practices.md#signatures-jwt-and-webhooks).

Related: reading claims before verifying. `jwt.decode(token)` used for an authorization decision is
an unauthenticated read of attacker-supplied JSON.

## Signature verified over re-serialised JSON

```javascript
const body = JSON.parse(raw);
const expected = hmac(secret, JSON.stringify(body));   // key order may differ
```

Works in testing, fails in production when the sender orders keys differently or formats numbers
differently. Teams then "fix" it by skipping verification for the failing sender.

Fix: verify over the exact raw bytes received, before parsing. Configure the framework to retain the
raw body.

## Timing-unsafe comparison of a secret

```python
if token == expected_token:
```

`==` returns at the first differing byte, leaking a prefix oracle. Practicality varies enormously —
locally exploitable, hard over a noisy network — so rank it honestly rather than reflexively as
critical.

Fix: `hmac.compare_digest`. Better: look the credential up by an indexed prefix and compare a digest,
so timing reveals nothing useful.

## Encoding presented as encryption

```python
stored = base64.b64encode(ssn.encode())
```

base64 is reversible by anyone. It appears in code review because the output looks opaque. The same
error appears as "encrypted" JWT payloads and gzip'd blobs.

Fix: AEAD with a managed key. And check whether you need to store the value at all — the strongest
control on a sensitive field is not collecting it.

## Deterministic encryption used by default

Chosen because it makes `WHERE email_enc = ?` work. Equal plaintexts produce equal ciphertexts, so
the ciphertext column reveals the frequency distribution. For a `status` or `country` column that is
effectively plaintext.

Fix: randomized AEAD for storage, plus a keyed blind index for lookup. See
[best-practices.md](best-practices.md#deterministic-encryption). Note the residual leak — equal
values still share an index — rather than claiming the problem is solved.

## Decryption failure swallowed

```python
try:
    return aesgcm.decrypt(nonce, ct, aad)
except Exception:
    return None          # caller treats None as "empty field"
```

An authentication tag failure means tampering or the wrong key. Turning it into an empty value hides
an attack and, if the caller writes the record back, destroys the data.

Fix: let it raise, log the key ID and record ID, and alert. `A10:2025` and ASVS V16 both land here.

## Backups outside the crypto design

Encryption at rest is configured, then the nightly logical dump writes decrypted rows to object
storage, or the KMS key is deleted while backups that depend on it are still in retention.

Fix: decide explicitly whether backups hold ciphertext or plaintext, encrypt the backup with a key
that has its own lifecycle, and never schedule KEK deletion before every backup that needs it has
aged out. Test a restore — an unrestorable encrypted backup is a data loss event waiting for a
trigger.

## Rolling your own because the library "does not fit"

XOR with a repeating key, a cipher plus a hash assembled by hand, a custom padding scheme, or a
standard reimplemented from its specification. The result compiles, round-trips in tests, and fails
against an adversary.

Fix: use a maintained library's highest-level interface — libsodium, Go's AEAD interface, Python's
`cryptography`. If a requirement seems to demand a novel construction, challenge the requirement
first; it is usually a design problem wearing a crypto costume.
