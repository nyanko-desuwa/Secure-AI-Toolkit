# Primitive Selection

The decision table. Find the job, take the primitive, do not assemble one.

Approval levels below follow ASVS 5.0.0 Appendix C, which grades each algorithm Approved (A),
Legacy (L, compatibility only), or Disallowed (D, considered broken). Verified 2026-07-28 against
<https://github.com/OWASP/ASVS/blob/master/5.0/en/0x92-Appendix-C_Cryptography.md>.

`A04:2025` · ASVS V11 (Cryptography), V12 (Secure Communication)

## By job

| Job | Use | Never | Why the "never" fails |
|---|---|---|---|
| Encrypt data at rest | AES-256-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305 | ECB (D), CBC/CTR/CFB/OFB without a verified MAC | No integrity: ciphertext is malleable, ECB leaks structure |
| Encrypt data in transit | TLS 1.3, TLS 1.2 with ECDHE + AEAD | application-layer crypto over plain TCP, "encrypted" payload inside HTTP | No key agreement, no identity, no replay protection |
| Authenticate a message (shared secret) | HMAC-SHA-256, AES-CMAC, Poly1305, KMAC | `hash(secret ‖ message)`, HMAC-MD5 (D) | Length-extension and a broken hash. Both are forgery, not weakness |
| Hash a password | Argon2id, then scrypt, bcrypt, PBKDF2-HMAC-SHA-256 | SHA-256/512, SHA-3, MD5 (D), HMAC, a hand-written loop | Fast by design. A GPU tries billions per second; a salt does not slow that down |
| Derive a key from a key | HKDF-SHA-256 (RFC 5869) | `sha256(key ‖ "purpose")`, truncating a key, reusing one key for two purposes | Not a KDF. No domain separation guarantee, no extract step for non-uniform input |
| Derive a key from a password | Argon2id, output used as the key | HKDF, PBKDF2 at a low iteration count | HKDF is fast: the password's low entropy is the whole attack surface |
| Generate a token, session ID, salt, nonce | CSPRNG: `secrets`, `crypto.randomBytes`, `crypto/rand`, `getentropy()` | `Math.random`, `random.random`, `rand()`, `mt_rand`, timestamps, counters, UUIDv1 | State recoverable from prior output, or no secret state at all |
| Sign a document for third parties | Ed25519, ECDSA P-256/P-384, RSA-PSS ≥ 3072-bit | RSA PKCS#1 v1.5 signatures (D), DSA (D), MD5/SHA-1 digests (D for signatures) | Padding forgery and collision attacks; DSA is removed from modern stacks |
| Encrypt to a public key | Hybrid: KEM/ECDH to a symmetric key, then AEAD. Or libsodium sealed boxes | RSA-OAEP for bulk data, RSA PKCS#1 v1.5 encryption (D) | RSA encrypts one small block; v1.5 padding is padding-oracle prone |
| Wrap a key | AES-256-KW or KWP (SP 800-38F), or a KMS `Encrypt`/`GenerateDataKey` | your own AEAD-over-key scheme with an ad hoc header | KW is specified for this; a home-made wrapper has no rotation or context binding |
| Compare two secrets | Constant-time comparison | `==`, `===`, `equals`, `strcmp`, `Arrays.equals` | Early return on the first differing byte is a prefix oracle |
| Make a value opaque in a URL | Random token stored server-side | base64, hex, JWT payload, gzip, reversed strings | Encoding is not encryption. Anyone decodes it |

Minimum strength: ASVS 5.0.0 V11 requires "all cryptographic primitives utilize a minimum of
128-bits of security", notes that "RSA requires a 3072-bit key to achieve 128 bits of security",
and sets collision-resistant hash output at "at least 256 bits". AES-128 is Legacy in Appendix C,
not disallowed — prefer AES-256 for new work.

## Signature or MAC

Both prove a message was not altered. They differ in who can produce one, and that difference is
the whole decision.

| | MAC (HMAC, CMAC, Poly1305) | Signature (Ed25519, ECDSA, RSA-PSS) |
|---|---|---|
| Key | One shared secret | Private key signs, public key verifies |
| Who can forge | Anyone holding the key, including every verifier | Only the private key holder |
| Non-repudiation | No | Yes |
| Speed | Microseconds | Slower, and the key is larger |
| Right for | Session cookies, internal service calls, webhook delivery you both control, tamper-proofing your own data | Software releases, licences, receipts, JWTs verified by parties you do not control, anything a third party audits |

The test: count the verifiers. If a verifier must not be able to mint a valid message, you need a
signature. A MAC shared with five services means five services can forge for each other, and a leak
at the least careful one forges for all of them.

Two failure directions, both common:

- MAC where a signature belongs. Webhooks signed with a secret you also give the receiver: the
  receiver can fabricate events and claim you sent them. Fine for delivery integrity, useless as
  evidence.
- Signature where a MAC belongs. Asymmetric signing on every internal request adds latency and key
  distribution work for a property nobody uses. Not insecure, just the wrong cost.

## Nonce and IV discipline

A nonce is not secret. It must be unique. Those are different requirements, and the second one is
where code fails.

| Mode | Nonce/IV requirement | Consequence of reuse |
|---|---|---|
| AES-GCM, AES-CCM | Unique per message per key. 96-bit nonce | Catastrophic. Leaks plaintext XOR and exposes the authentication subkey, so the attacker forges as well as reads |
| ChaCha20-Poly1305 | Unique per message per key. 96-bit nonce | Same as GCM. Keystream reuse plus Poly1305 key recovery |
| XChaCha20-Poly1305, XSalsa20 | Unique per message. 192-bit nonce, random is safe | Same in principle, but random collision is not a practical concern at this width |
| AES-CTR | Unique counter block per key | Keystream reuse: XOR of plaintexts. No integrity either way |
| AES-CBC | Unpredictable, not merely unique (CWE-329) | Predictable IV enables chosen-plaintext distinguishing (BEAST); reuse leaks equality of message prefixes |
| AES-SIV, deterministic AEAD | Nonce optional; reuse degrades to revealing equal plaintexts | Designed for this. The only mode where reuse is a documented tradeoff rather than a break |

Random 96-bit nonces are safe by the birthday bound only while the message count per key stays well
below 2^32. Either bound the count and rotate the key, or use a 192-bit nonce. Never mix a counter
and a random source under one key — that collides by construction.

ASVS 5.0.0 V11.3 states a single-use value must be "not used for more than one encryption key and
data-element pair" and that "the method of generation must be appropriate for the algorithm being
used".

## Randomness

ASVS 5.0.0 V11.5 requires values to be "generated using a cryptographically secure pseudo-random
number generator (CSPRNG) and have at least 128 bits of entropy", and adds: "Note that UUIDs do not
respect this condition." A UUIDv4 carries 122 random bits — fine for a correlation ID, short of the
bar for a password reset token. UUIDv1 and UUIDv7 embed a timestamp and are guessable.

Appendix C approves `/dev/random`, `/dev/urandom`, `getentropy()`, and the SP 800-90A DRBGs
(AES-CTR-DRBG, HMAC-DRBG, Hash-DRBG). Everything reached through a language's `Math.random`,
`random`, or `rand()` API is a fast statistical PRNG whose internal state is recoverable from a
handful of outputs. The failure is silent: the tokens look random in a test.

| Language | Use | Not |
|---|---|---|
| Python | `secrets.token_urlsafe(32)`, `os.urandom` | `random`, `numpy.random` |
| TypeScript / Node | `crypto.randomBytes(32)`, `crypto.getRandomValues` | `Math.random` |
| Go | `crypto/rand` | `math/rand`, including `math/rand/v2` |
| Java | `SecureRandom` | `java.util.Random`, `Math.random` |

## Where the key lives

Key storage is `secrets-management`; password policy and login flow are `authentication`. This file
decides the primitive, not the vault. What belongs here is the constraint the primitive imposes: a
key held in the same store as the ciphertext protects nothing, and an algorithm choice with no
rotation path is unfinished. See [nist-crypto-standards.md](nist-crypto-standards.md) for rotation
triggers.

## Sources

- OWASP ASVS 5.0.0, V11 Cryptography —
  <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x20-V11-Cryptography.md> (checked 2026-07-28)
- OWASP ASVS 5.0.0, Appendix C Cryptography —
  <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x92-Appendix-C_Cryptography.md> (checked
  2026-07-28)
- RFC 5869 (HKDF) — <https://www.rfc-editor.org/rfc/rfc5869.html>
- OWASP Cryptographic Storage Cheat Sheet —
  <https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html>
