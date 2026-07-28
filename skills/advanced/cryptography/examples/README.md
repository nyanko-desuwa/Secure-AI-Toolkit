# Cryptography Examples

Vulnerable code next to its fix. Each pair names the Top 10 category, the CWE, and why the fix
closes the hole rather than just looking stronger.

Every block labelled `Vulnerable:` is there to be recognised, not copied.

## Contents

- [Password stored with a salted fast hash](#password-stored-with-a-salted-fast-hash) — A04, CWE-916
- [Static IV in AES-GCM](#static-iv-in-aes-gcm) — A04, CWE-323
- [Reset token from a non-cryptographic RNG](#reset-token-from-a-non-cryptographic-rng) — A04, CWE-338
- [TLS verification disabled to make it work](#tls-verification-disabled-to-make-it-work) — A02, CWE-295
- [AES-CBC with no integrity check](#aes-cbc-with-no-integrity-check) — A04, CWE-353
- [JWT verified after the payload is trusted](#jwt-verified-after-the-payload-is-trusted) — A07, CWE-347
- [Webhook signature compared with ==](#webhook-signature-compared-with-) — A04, CWE-208
- [Hardcoded key with no rotation path](#hardcoded-key-with-no-rotation-path) — A04, CWE-321

---

## Password stored with a salted fast hash

`A04:2025` · `CWE-916`, `CWE-759` · ASVS V11, V6

```python
# Vulnerable: salted, iterated, and still fast
import hashlib, os

def store(password: str) -> tuple[bytes, str]:
    salt = os.urandom(16)
    h = password.encode()
    for _ in range(1000):
        h = hashlib.sha256(salt + h).digest()
    return salt, h.hex()
```

A stolen dump falls in hours. SHA-256 runs in the billions per second on a GPU; 1000 rounds of it
costs the attacker a factor of 1000 against a search space of millions. The salt stops rainbow
tables and nothing else.

```python
# Fixed: memory-hard, parameters carried in the stored string
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

ph = PasswordHasher(memory_cost=19456, time_cost=2, parallelism=1)

def store(password: str) -> str:
    return ph.hash(password)          # $argon2id$v=19$m=19456,t=2,p=1$...

def verify(stored: str, password: str) -> tuple[bool, str | None]:
    try:
        ph.verify(stored, password)
    except (VerifyMismatchError, InvalidHashError):
        return False, None
    return True, ph.hash(password) if ph.check_needs_rehash(stored) else None
```

Why this works: Argon2id's cost is memory, which a GPU cannot parallelise away cheaply. The
parameters live in the hash string, so `check_needs_rehash` gives a free upgrade path on the next
login — you cannot strengthen a hash you already have, only replace it while the plaintext is in
hand.

Parameters from [references/password-storage.md](../references/password-storage.md).

---

## Static IV in AES-GCM

`A04:2025` · `CWE-323`, `CWE-329` · ASVS V11

```go
// Vulnerable: one nonce, every message
var nonce = []byte("123456789012")

func Encrypt(key, plaintext []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil { return nil, err }
    gcm, err := cipher.NewGCM(block)
    if err != nil { return nil, err }
    return gcm.Seal(nil, nonce, plaintext, nil), nil
}
```

Two messages under this key leak their XOR, and — specific to GCM — repeating a nonce lets an
attacker recover the authentication subkey and forge ciphertexts that verify. The failure is total,
not partial.

```go
// Fixed: fresh random nonce per message, prepended to the ciphertext
func Encrypt(key, plaintext, aad []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil { return nil, err }
    gcm, err := cipher.NewGCM(block)
    if err != nil { return nil, err }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil { return nil, err }

    return gcm.Seal(nonce, nonce, plaintext, aad), nil // nonce || ct || tag
}
```

`crypto/rand`, never `math/rand`. Why prepending is safe: a nonce is not secret, only unique.

The tempting wrong fix is a counter, because "random might collide". A counter is worse in
practice — it has to survive restarts, replicas, and rollbacks, and two pods starting at zero reuse
every value. Random 96-bit nonces are fine up to roughly 2^32 messages per key; rotate the key on
message count, or use XChaCha20-Poly1305 with its 192-bit nonce and stop counting.

---

## Reset token from a non-cryptographic RNG

`A04:2025` · `CWE-338`, `CWE-330` · ASVS V11, V6

```javascript
// Vulnerable: Math.random is predictable, and the timestamp narrows it further
function resetToken(userId) {
  return Buffer.from(`${userId}-${Date.now()}-${Math.random()}`).toString("base64url");
}
```

`Math.random` is a fast PRNG with observable internal state; a few outputs are enough to predict the
rest in V8. The base64 makes it look random and adds nothing.

```javascript
// Fixed: CSPRNG, hashed at rest, single use, expiring
import { randomBytes, createHash } from "node:crypto";

export async function issueResetToken(userId) {
  const token = randomBytes(32).toString("base64url");           // 256 bits
  const lookup = createHash("sha256").update(token).digest("hex");

  await db.resetToken.deleteMany({ where: { userId } });
  await db.resetToken.create({
    data: { userId, tokenHash: lookup, expiresAt: new Date(Date.now() + 30 * 60_000) },
  });
  return token;                                                  // emailed, never stored raw
}
```

Why this works: `randomBytes` draws from the OS CSPRNG, so past outputs reveal nothing about future
ones. Storing only the hash means a leaked database does not hand over live reset links — the token
is a bearer credential, so treat it like a password. Argon2 is unnecessary here because the token
has 256 bits of entropy; there is nothing to brute force.

---

## TLS verification disabled to make it work

`A02:2025` · `CWE-295`, `CWE-297` · ASVS V12

```python
# Vulnerable: any machine on the path can read and rewrite this
resp = requests.post(
    "https://payments.internal/charge",
    json=payload,
    headers={"Authorization": f"Bearer {token}"},
    verify=False,
)
```

Usually written to silence a self-signed certificate error during testing, then shipped. TLS without
verification gives you encryption to whoever answered, which is exactly what an interceptor wants.
The bearer token goes with it.

```python
# Fixed: trust the internal CA explicitly, keep verification on
CA_BUNDLE = "/etc/ssl/certs/internal-ca.pem"

resp = requests.post(
    "https://payments.internal/charge",
    json=payload,
    headers={"Authorization": f"Bearer {token}"},
    verify=CA_BUNDLE,
    timeout=10,
)
```

```go
// Vulnerable
tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}

// Fixed: pin the CA that actually issued the cert
pool := x509.NewCertPool()
pem, err := os.ReadFile("/etc/ssl/certs/internal-ca.pem")
if err != nil { return err }
if !pool.AppendCertsFromPEM(pem) { return errors.New("bad CA bundle") }

tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
```

Why this works: the client still checks the chain and the hostname, just against a CA you chose. The
tempting wrong fix is a custom verifier that "only checks the fingerprint" — hand-written
verification callbacks routinely skip hostname validation, which is CWE-297 and passes every test
you would think to write.

---

## AES-CBC with no integrity check

`A04:2025` · `CWE-353`, `CWE-327` · ASVS V11

```java
// Vulnerable: confidentiality only. Nothing detects modification.
Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
byte[] ct = c.doFinal(plaintext);
```

An attacker who can modify the ciphertext gets bit-flipping in the following block, and if
decryption failures are distinguishable from padding failures, a padding oracle recovers the whole
plaintext without the key. `AES/ECB/PKCS5Padding` — the default when you write `"AES"` in Java — is
worse still: identical blocks give identical ciphertext.

```java
// Fixed: AEAD. Authentication is not optional and not separate.
private static final int GCM_TAG_BITS = 128;
private static final int GCM_IV_BYTES = 12;

byte[] iv = new byte[GCM_IV_BYTES];
SecureRandom.getInstanceStrong().nextBytes(iv);

Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
c.updateAAD(recordId.getBytes(StandardCharsets.UTF_8));   // binds ciphertext to its row
byte[] ct = c.doFinal(plaintext);
// store iv || ct, plus a key id and algorithm label
```

Decryption throws `AEADBadTagException` on any tampering. Let it propagate — catching it and
returning null converts an integrity failure into silent data corruption.

Why this works: GCM authenticates as part of decryption, so there is no ordering to get wrong and no
oracle to probe. The tempting wrong fix is CBC plus HMAC assembled by hand; that can be done
correctly (encrypt-then-MAC, separate keys, constant-time tag check) and is done incorrectly most of
the time. The AAD binding is what stops a valid ciphertext being moved from one row to another.

---

## JWT verified after the payload is trusted

`A07:2025` · `CWE-347`, `CWE-696` · ASVS V9

```javascript
// Vulnerable: the payload is read before anything is verified
const claims = jwt.decode(token);
if (claims.role === "admin") return next();
const verified = jwt.verify(token, publicKey);
```

`decode` does no verification at all. Anyone can craft `{"role":"admin"}` and the check passes before
the line that would have caught it. Even reordered, `verify` without an algorithm list may accept
`alg: none` or an HS256 token signed with the public key as its secret.

```javascript
// Fixed: verify first, pin the algorithm, pin issuer and audience
import { createRemoteJWKSet, jwtVerify } from "jose";

const jwks = createRemoteJWKSet(new URL("https://auth.example.com/.well-known/jwks.json"));

const { payload } = await jwtVerify(token, jwks, {
  algorithms: ["ES256"],
  issuer: "https://auth.example.com",
  audience: "https://api.example.com",
  clockTolerance: 5,
});
if (payload.role !== "admin") throw new ForbiddenError();
```

Why this works: nothing in the token influences how the token is checked. The algorithm comes from
server config, the key is selected from a trusted JWKS by `kid` — a `kid` pointing at a URL or a
file path is a separate vulnerability — and issuer and audience stop a valid token minted for another
service being replayed here.

Honest limitation: a verified JWT is still valid until it expires. If logout or a role change must
take effect immediately, keep server-side session state or a revocation list. Short expiry narrows
the window; it does not close it.

---

## Webhook signature compared with ==

`A04:2025` · `CWE-208` · ASVS V11

```python
# Vulnerable: comparison short-circuits on the first differing byte
expected = hmac.new(SECRET, body, hashlib.sha256).hexdigest()
if request.headers["X-Signature"] != expected:
    abort(401)
```

`!=` returns as soon as bytes differ, so response time correlates with how many leading bytes are
right. With enough samples an attacker walks the signature out one byte at a time and forges
webhooks.

```python
# Fixed: constant-time compare, plus a timestamp to stop replay
import hmac, hashlib, time
from flask import abort, request

MAX_SKEW = 300

def verify_webhook(body: bytes) -> None:
    ts = request.headers.get("X-Timestamp", "")
    sig = request.headers.get("X-Signature", "")
    if not ts.isdigit() or abs(time.time() - int(ts)) > MAX_SKEW:
        abort(401)

    signed = ts.encode() + b"." + body
    expected = hmac.new(SECRET, signed, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        abort(401)
```

Why this works: `compare_digest` examines every byte regardless of where the first difference is, so
timing carries no information about the correct value. Signing the timestamp alongside the body means
a captured request cannot be replayed later — signature verification alone does not give you
freshness.

Sign the raw bytes, not a re-serialised object. Re-encoding JSON changes key order and whitespace and
the signature stops matching for reasons that look like a crypto bug.

---

## Hardcoded key with no rotation path

`A04:2025` · `CWE-321`, `CWE-320`, `CWE-798` · ASVS V11, V14

```python
# Vulnerable: one key, in source, forever
KEY = b"7f3c9a1e5b2d8f4a6c0e9b7d3a5f1c8e"     # AES-256, "temporary"

def encrypt_ssn(ssn: str) -> bytes:
    return AESGCM(KEY).encrypt(os.urandom(12), ssn.encode(), None)
```

The key is in git history, in every image layer, and on every developer laptop. Rotating it means
re-encrypting every row with a deploy that can read both keys — which is why it never happens. There
is also no algorithm or key identifier stored, so a future migration cannot tell old ciphertext from
new.

```python
# Fixed: envelope encryption. KMS holds the key that encrypts the key.
import os, json, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KMS_KEY_ID = os.environ["KMS_KEY_ID"]

def encrypt_ssn(ssn: str, record_id: str) -> str:
    resp = kms.generate_data_key(KeyId=KMS_KEY_ID, KeySpec="AES_256")
    nonce = os.urandom(12)
    ct = AESGCM(resp["Plaintext"]).encrypt(nonce, ssn.encode(), record_id.encode())
    del resp["Plaintext"]

    return json.dumps({
        "v": 1,
        "alg": "AES-256-GCM",
        "edk": base64.b64encode(resp["CiphertextBlob"]).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ct": base64.b64encode(ct).decode(),
    })

def decrypt_ssn(envelope: str, record_id: str) -> str:
    e = json.loads(envelope)
    if e["v"] != 1 or e["alg"] != "AES-256-GCM":
        raise ValueError("unsupported_envelope")     # fail closed, do not guess
    dk = kms.decrypt(CiphertextBlob=base64.b64decode(e["edk"]))["Plaintext"]
    return AESGCM(dk).decrypt(
        base64.b64decode(e["nonce"]), base64.b64decode(e["ct"]), record_id.encode()
    ).decode()
```

Why this works: the only long-lived key never leaves KMS, so rotating it re-wraps data keys instead
of re-encrypting rows. The version and algorithm labels make a future migration mechanical. The AAD
binds each ciphertext to its record, so a row-swap attack fails.

What this does not fix: an attacker with the application's IAM role can still call `kms:Decrypt`.
Encryption at rest protects a stolen dump and a decommissioned disk, not an attacker inside the
application. KMS CloudTrail logs are what make the bulk-decrypt visible — alert on the volume.

---

## Sources

- <https://owasp.org/Top10/2025/>
- <https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html>
- <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>
- <https://cwe.mitre.org/>
