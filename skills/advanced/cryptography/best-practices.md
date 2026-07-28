# Cryptography Best Practices

Patterns that survive review. Each names its standard. Every vulnerable block is labelled and
paired with a fix.

## Password Hashing

`A07:2025` · ASVS V6, V11 · CWE-916, CWE-759

```python
# Vulnerable: fast hash, no salt. A stolen dump is cracked at GPU speed.
import hashlib
def store(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()
```

```python
# Fixed: Argon2id at OWASP baseline, library-generated salt, encoded params in the string
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

ph = PasswordHasher(memory_cost=19456, time_cost=2, parallelism=1)  # 19 MiB, t=2, p=1

def store(pw: str) -> str:
    return ph.hash(pw)          # "$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>"

def verify(stored: str, pw: str) -> bool:
    try:
        ph.verify(stored, pw)
    except (VerifyMismatchError, InvalidHashError):
        return False
    if ph.check_needs_rehash(stored):
        save_new_hash(ph.hash(pw))   # only place you ever hold the plaintext
    return True
```

Why this works: Argon2id is memory-hard, so a GPU cannot amortise it the way it does SHA-256. The
salt is per-hash, so identical passwords produce different rows. The parameters live in the string,
which is what makes `check_needs_rehash` — and therefore a cost upgrade without a mass reset —
possible at all.

The tempting wrong fix is `sha256(salt + password)` in a loop. You have invented PBKDF2 badly:
no memory hardness, no vetted iteration schedule, and a salt scheme you now own. See
[references/password-storage.md](references/password-storage.md) for parameters and the bcrypt
72-byte trap.

## Randomness

ASVS V11 · CWE-338, CWE-330

```javascript
// Vulnerable: Math.random is not a CSPRNG. Output is predictable from prior output.
const token = Math.random().toString(36).slice(2);
```

```javascript
// Fixed: 256 bits from the platform CSPRNG, URL-safe
import { randomBytes, randomUUID } from "node:crypto";

const resetToken = randomBytes(32).toString("base64url");  // ~256 bits
const requestId  = randomUUID();                           // 122 bits, fine for correlation
```

Why this works: `randomBytes` draws from the OS CSPRNG, so observing earlier outputs gives no
advantage on later ones. `Math.random` uses a fast PRNG whose internal state is recoverable from a
handful of outputs — an attacker who sees one token predicts the next reset link.

Store the hash of a reset token, not the token. A leaked table then yields nothing usable.

## AEAD Encryption and Nonce Uniqueness

`A04:2025` · ASVS V11 · CWE-323, CWE-353

```go
// Vulnerable: static nonce. Two messages under one key leak their XOR and the auth subkey.
var nonce = make([]byte, 12) // all zeros, every call
func seal(key, pt []byte) []byte {
    block, _ := aes.NewCipher(key)
    g, _ := cipher.NewGCM(block)
    return g.Seal(nil, nonce, pt, nil)
}
```

```go
// Fixed: random nonce per message, prepended; AAD binds the record it belongs to
package crypt

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "errors"
    "fmt"
)

func Seal(key, plaintext, aad []byte) ([]byte, error) {
    block, err := aes.NewCipher(key) // 32 bytes = AES-256
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    nonce := make([]byte, gcm.NonceSize())
    if _, err := rand.Read(nonce); err != nil {
        return nil, fmt.Errorf("nonce: %w", err)
    }
    return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

func Open(key, blob, aad []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }
    if len(blob) < gcm.NonceSize() {
        return nil, errors.New("ciphertext too short")
    }
    nonce, ct := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]
    return gcm.Open(nil, nonce, ct, aad) // returns an error on tamper — do not swallow it
}
```

Why this works: a fresh 96-bit random nonce per message keeps collisions at the birthday bound
rather than at one. GCM nonce reuse is not a partial failure — it exposes the authentication
subkey, so the attacker forges as well as reads. The AAD (`"invoice:4192:v1"`) means a ciphertext
moved to another row fails to open instead of decrypting into the wrong context.

Limitation worth naming: random 96-bit nonces bound you to well under 2^32 messages per key. If
this key encrypts high-volume events, either rotate on message count or use XChaCha20-Poly1305,
whose 192-bit nonce makes random selection safe indefinitely. See
[references/nist-crypto-standards.md](references/nist-crypto-standards.md).

## Envelope Encryption and Key Lifecycle

`A04:2025` · ASVS V11, V14 · CWE-320, CWE-321

A key hardcoded in source, or held in the same database as the ciphertext, is obfuscation. Envelope
encryption separates them: a KMS holds the key-encryption key (KEK), each record gets its own data
encryption key (DEK), and the wrapped DEK travels with the row.

```python
# Fixed: per-record DEK wrapped by a KMS KEK. Plaintext DEK never persisted.
import boto3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

kms = boto3.client("kms")
KEK_ALIAS = "alias/app-records"

def encrypt_record(record_id: str, tenant: str, plaintext: bytes) -> dict:
    resp = kms.generate_data_key(KeyId=KEK_ALIAS, KeySpec="AES_256")
    dek, wrapped = resp["Plaintext"], resp["CiphertextBlob"]
    try:
        nonce = os.urandom(12)
        aad = f"v1|{tenant}|{record_id}".encode()
        ct = AESGCM(dek).encrypt(nonce, plaintext, aad)
    finally:
        del dek
    return {"v": 1, "alg": "AES-256-GCM", "wrapped_dek": wrapped,
            "nonce": nonce, "ct": ct, "aad": aad.decode()}

def decrypt_record(row: dict) -> bytes:
    if row["v"] != 1 or row["alg"] != "AES-256-GCM":
        raise ValueError(f"unsupported envelope: v={row['v']} alg={row['alg']}")
    dek = kms.decrypt(CiphertextBlob=row["wrapped_dek"])["Plaintext"]
    try:
        return AESGCM(dek).decrypt(row["nonce"], row["ct"], row["aad"].encode())
    finally:
        del dek
```

Why this works: rotating the KEK is a KMS operation plus a re-wrap of the small `wrapped_dek`
values — the row ciphertext is untouched. Compromise of one DEK exposes one record. The KMS logs
every unwrap, so key use is auditable, and revoking IAM access to the KEK renders the whole dataset
unreadable immediately, which is a working kill switch.

The `v` and `alg` fields are the crypto-agility hook. Without them a future migration has no way to
tell which records are already re-encrypted.

Lifecycle answers to write down before shipping: how the key is generated (in the KMS, never
exported), where it lives (KMS/HSM, not the app database), rotation trigger (see the table in
`references/nist-crypto-standards.md`), revocation (IAM deny plus key disable), and destruction
(schedule deletion only after the retention period, since deleting a KEK destroys the data).

Do not use `del dek` as a security guarantee. Python offers no reliable zeroization; this narrows
the window and nothing more. If memory disclosure is in your threat model, the crypto belongs in an
HSM or an enclave, not in the application process.

## TLS and Certificate Validation

`A02:2025` · ASVS V12 · CWE-295, CWE-297

```java
// Vulnerable: trusts every certificate, checks no hostname. TLS with the security removed.
TrustManager[] trustAll = new TrustManager[]{ new X509TrustManager() {
    public void checkClientTrusted(X509Certificate[] c, String a) {}
    public void checkServerTrusted(X509Certificate[] c, String a) {}
    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
}};
SSLContext ctx = SSLContext.getInstance("TLS");
ctx.init(null, trustAll, new SecureRandom());
```

```java
// Fixed: platform trust store, TLS 1.2+ only, hostname verification on by default in HttpClient
import java.net.http.HttpClient;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.time.Duration;

SSLContext ctx = SSLContext.getDefault();          // platform trust store, no override

SSLParameters params = new SSLParameters();
params.setProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
params.setEndpointIdentificationAlgorithm("HTTPS"); // this is the hostname check

HttpClient client = HttpClient.newBuilder()
        .sslContext(ctx)
        .sslParameters(params)
        .connectTimeout(Duration.ofSeconds(10))
        .build();
```

Why this works: the default trust store validates the chain, and
`setEndpointIdentificationAlgorithm("HTTPS")` is what validates the name — a valid certificate for
`attacker.example` fails against `api.example.com`. Chain-only validation is a common half-fix and
still lets any CA-issued certificate impersonate your endpoint.

If the target uses a private CA, add that CA to a custom trust store. Do not disable verification
to make a self-signed certificate work.

## Signatures, JWT, and Webhooks

`A07:2025`, `A08:2025` · ASVS V9 · CWE-347, CWE-696

```javascript
// Vulnerable: the token's own header decides how it is verified
const claims = jwt.verify(token, process.env.JWT_SECRET);
```

```javascript
// Fixed: server states algorithm, issuer, audience
const claims = jwt.verify(token, process.env.JWT_SECRET, {
  algorithms: ["HS256"],
  issuer: "https://auth.example.com",
  audience: "https://api.example.com",
  clockTolerance: 5,
});
```

For asymmetric verification, resolve `kid` against a fetched JWKS and pin `algorithms: ["RS256"]`.
Never treat `kid` as a path or URL — that turns key selection into SSRF or file read.

Webhooks: verify over the raw body, before parsing.

```javascript
// Fixed: constant-time HMAC over the exact bytes received, plus a timestamp window
import { createHmac, timingSafeEqual } from "node:crypto";

export function verifyWebhook(rawBody, header, secret) {
  const [tsPart, sigPart] = header.split(",");             // "t=...,v1=..."
  const ts = Number(tsPart.slice(2));
  if (!Number.isFinite(ts) || Math.abs(Date.now() / 1000 - ts) > 300) return false;

  const expected = createHmac("sha256", secret)
    .update(`${ts}.`).update(rawBody)                       // Buffer, not a re-serialised object
    .digest();
  const got = Buffer.from(sigPart.slice(3), "hex");
  return got.length === expected.length && timingSafeEqual(got, expected);
}
```

Why this works: signing the raw bytes avoids the classic break where `JSON.parse` then
`JSON.stringify` reorders keys and the signature no longer matches what was signed. The timestamp
window bounds replay. `timingSafeEqual` removes the byte-by-byte timing leak, and the explicit
length check exists because it throws on unequal lengths.

A JWT cannot be revoked before expiry. If logout must take effect immediately, keep server-side
session state — a short expiry narrows the window without closing it.

## Constant-Time Comparison

ASVS V11 · CWE-208

```python
# Vulnerable: == returns on the first differing byte
if provided_key == stored_key:
```

```python
# Fixed
import hmac
if hmac.compare_digest(provided_key.encode(), stored_key.encode()):
```

Per language: `hmac.compare_digest` (Python), `crypto.timingSafeEqual` (Node),
`hmac.Equal`/`subtle.ConstantTimeCompare` (Go), `MessageDigest.isEqual` (Java).

Better still: make the comparison irrelevant. Look the API key up by an indexed prefix, then
compare a SHA-256 digest of the remainder in constant time. Now a timing leak reveals nothing about
a secret an attacker does not already hold.

## Encoding Is Not Encryption

`A04:2025` · CWE-311

base64, hex, URL encoding, `rot13`, gzip, and JWT payloads are all reversible without a key. If a
function name contains "encode" or "obfuscate", it provides no confidentiality. A JWT payload is
base64url and readable by anyone holding the token — never put anything sensitive in a claim.

## Deterministic Encryption

`A04:2025` · ASVS V11, V14

Same plaintext, same ciphertext. It enables equality lookup and leaks frequency: with a
deterministic `diagnosis` column, the most common ciphertext is the most common diagnosis, and low
cardinality fields (country, gender, status) are effectively public.

Use it only when equality search is a stated requirement, and prefer a keyed blind index over
deterministic encryption of the whole value:

```python
# Fixed: randomized ciphertext for storage, keyed HMAC index for lookup
import hmac, hashlib

def blind_index(value: str, index_key: bytes) -> bytes:
    return hmac.new(index_key, value.strip().lower().encode(), hashlib.sha256).digest()[:16]
```

Why this works: the stored value stays randomized under AEAD, and the index is keyed — so an
attacker with the database but not `index_key` cannot build a dictionary of candidate values.
A plain `sha256(value)` index would be trivially reversible for emails, names, or postcodes.

Remaining leak, stated honestly: equal values still share an index, so frequency analysis over the
index column survives. Truncating to 16 bytes deliberately adds collisions, which blurs frequency
at the cost of extra rows to filter after decryption. Range and prefix queries need a different
design; do not extend a blind index to cover them.

## Crypto Agility

Store `alg` and a key ID with every ciphertext, signature, and hash, and make the read path a
dispatch over versions rather than a single hardcoded call. The cost is one column. The alternative
is discovering during an incident that you cannot change algorithms without downtime.

Migration is decrypt-then-re-encrypt. There is no way to upgrade a ciphertext in place, and no way
to strengthen an existing password hash without the plaintext at login.

## Sources

- OWASP Top 10 2025 — <https://owasp.org/Top10/2025/>
- OWASP ASVS 5.0.0 — <https://owasp.org/www-project-application-security-verification-standard/>
- OWASP Password Storage Cheat Sheet —
  <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>
- OWASP Cryptographic Storage Cheat Sheet —
  <https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html>
