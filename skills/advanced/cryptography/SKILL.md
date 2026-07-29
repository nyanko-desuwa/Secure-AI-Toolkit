---
name: cryptography
description: 'Choose and apply cryptography correctly: password hashing, AEAD, nonces, key lifecycle, KMS and envelope encryption, TLS, signatures, JWT, and constant-time comparison. Maps to OWASP Top 10 2025 A04, ASVS 5.0 V11/V12/V14, and NIST FIPS/SP guidance. Triggers: "encrypt", "hash password", "AES", "AEAD", "key rotation", "KMS", "JWT signature", "TLS", "mã hoá", "băm mật khẩu".'
allowed-tools: Read, Glob, Grep, WebSearch, WebFetch
---

# Cryptography

Picking the right primitive, then using it in the one way that is safe.

## When to Use

- Storing passwords, API keys, or anything that gets verified rather than read back
- Encrypting data at rest: a column, a file, a backup
- Generating tokens, session IDs, reset links, or anything that must be unguessable
- Signing or verifying: JWT, webhooks, licences, artefacts
- Configuring TLS or writing a client that talks TLS
- Planning key rotation, revocation, or a migration off a weak algorithm
- Reviewing code that imports a crypto library

## The First Question Is Not Which Algorithm

Answer these three before naming a primitive. Most crypto bugs are a wrong answer here, not a wrong cipher.

1. What are you protecting against? A stolen database dump, a network attacker, a malicious
   insider with application access, or your own operators? Encryption in the application does
   nothing against an attacker who already has application access.
2. Who holds the key, and where does it live relative to the data? A key in the same database as
   the ciphertext is obfuscation. Name the separation.
3. What is the failure mode? If the key is lost, is the data gone? If the key leaks, what is the
   blast radius, and how do you find out?

If the answer to (1) is "compliance asked for encryption at rest", say so plainly and use the
platform's disk or database encryption. Do not build an application-layer scheme that adds key
management risk without adding a defence.

## Choosing a Primitive

| Need | Use | Never |
|---|---|---|
| Store a password | Argon2id (see [references/password-storage.md](references/password-storage.md)) | SHA-256, MD5, SHA-512, unsalted anything |
| Store an API key you must verify | SHA-256 of a high-entropy random key | Argon2 (unnecessary), plaintext |
| Random token, ID, nonce, salt | Platform CSPRNG | `Math.random`, `random`, `rand`, timestamps, UUIDv1 |
| Encrypt data | AES-256-GCM or ChaCha20-Poly1305 | AES-CBC, AES-ECB, any unauthenticated mode |
| Encrypt a large or high-volume stream | XChaCha20-Poly1305, or chunk with a key per chunk | one GCM key with a counter you manage by hand |
| Derive a key from a key | HKDF | SHA-256 of the key concatenated with a string |
| Derive a key from a password | Argon2id, then use the output as a key | HKDF, PBKDF2 with a low count |
| Authenticate a message | HMAC-SHA-256 | `hash(secret + message)` |
| Sign for third-party verification | Ed25519, or ECDSA P-256 | RSA PKCS#1 v1.5 for new systems |
| Compare two secrets | Constant-time comparison | `==`, `===`, `equals`, `strcmp` |
| Encode for transport | base64, hex - this is not encryption | base64 as a confidentiality control |

Use the highest-level API your language offers. `libsodium`, Go's `crypto/cipher` AEAD interface,
Java's `AES/GCM/NoPadding` via a vetted wrapper, Python's `cryptography` `AESGCM` or Fernet. If you
are choosing a mode and a MAC separately, stop - that is a construction, and constructions fail.

## Workflow

### 1. Scope and threat model

Write the three answers above into the pull request description. A reviewer cannot check
"encrypted with AES-256" against anything; they can check "protects against a stolen backup, key
lives in KMS, loss of key means data unrecoverable and that is accepted".

### 2. Pick the primitive

From the table. If the need is not in the table, it is probably a protocol, and you should adopt
one (TLS, JOSE, age, Signal) rather than assemble one.

### 3. Key lifecycle before implementation

Generation, storage, use, rotation, revocation, destruction. Answer all six now, not after
launch - retrofitting rotation onto data encrypted with a hardcoded key is a migration project.
See [best-practices.md](best-practices.md#key-lifecycle).

Envelope encryption is the default answer for data at rest: a KMS-held key encrypts a per-record
data key, and rotation touches keys instead of rows.

### 4. Implement

Real code in [best-practices.md](best-practices.md) and [examples/](examples/). Rules that hold
regardless of language:

- Never reuse a nonce under the same key. This is the one mistake that breaks GCM completely
- Store the algorithm and key ID next to the ciphertext, or you cannot ever migrate
- Fail closed: a decryption or verification error is an error, not an empty result
- Never log key material, plaintext, or a full token. Log the key ID

### 5. Verify

Run [checklist.md](checklist.md). Test the negative cases: tampered ciphertext must fail, an
expired signature must fail, a wrong key must fail loudly.

## Severity

- **Critical** - passwords stored with a fast hash or unsalted; a hardcoded key in source or an
  image layer; JWT verified with `algorithms` unpinned or `none` accepted; TLS certificate
  verification disabled on a path carrying credentials
- **High** - nonce reuse under a static key; unauthenticated cipher mode (CBC without a MAC);
  tokens from a non-cryptographic RNG; no key rotation path at all; ECB mode
- **Medium** - timing-unsafe secret comparison; PBKDF2 with a low iteration count; missing AAD
  where context binding matters; no algorithm identifier stored with ciphertext
- **Low** - a stronger parameter available but current one still acceptable; hex where base64url
  would be neater

Weight by what the attacker gets. A timing leak on an HMAC over a network is usually much harder
to exploit than the same leak locally; say so instead of ranking it critical by reflex.

## Never Do This

No homegrown crypto. That includes: writing your own cipher, combining a cipher and a hash into
your own authenticated mode, inventing a padding scheme, XOR with a repeating key, or "encrypting"
by base64 and reversing a string. It also includes reimplementing a standard from its
specification. Use a maintained library and its highest-level interface.

If a requirement seems to need a novel construction, the requirement is usually wrong. State that
before writing the construction.

## Related Skills

- `secrets-management` - where keys live, and how they reach the process
- `authentication` - password policy, MFA, session lifecycle around the hashing
- `api-security` - JWT and token handling at the API surface
- `cloud-security` - KMS/HSM configuration and IAM on key policies
- `ssh-server` - server-side TLS configuration in context

## Supporting Files

- [README.md](README.md) - purpose, standards table, limitations, security notes
- [checklist.md](checklist.md) - pre-return verification
- [best-practices.md](best-practices.md) - patterns with vulnerable/fixed pairs
- [common-mistakes.md](common-mistakes.md) - what goes wrong and why the fix works
- [troubleshooting.md](troubleshooting.md) - when the guidance cannot be applied
- [prompts.md](prompts.md) - prompts that produce findings
- [references/](references/) - version-pinned standard summaries
- [examples/](examples/) - vulnerable and fixed code side by side
