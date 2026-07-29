# ASVS 5.0 V11 - Cryptography

Source: <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x20-V11-Cryptography.md>
Appendix C: <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x92-Appendix-C_Cryptography.md>
Version: ASVS 5.0.0, released 2025-05-30. Verified 2026-07-28.

Cite the chapter and section. Do not invent a requirement ID - 5.0 renumbered everything, so a
`V2.x` or `V6.2.x` citation carried over from 4.x means something else now.

## Sections

| Section | Title | What it covers |
|---|---|---|
| V11.1 | Cryptographic Inventory and Documentation | Key management policy, a live inventory of keys, algorithms and certificates, discovery tooling, migration plan |
| V11.2 | Secure Cryptography Implementation | Vetted implementations, crypto agility, minimum security strength, failing securely in constant time |
| V11.3 | Encryption Algorithms | Approved ciphers and modes, ciphertext integrity, single-use values |
| V11.4 | Hashing and Hash-based Functions | Approved hashes, password storage, key derivation, work factors |
| V11.5 | Random Values | CSPRNG, sufficient entropy, behaviour under load |
| V11.6 | Public Key Cryptography | Key generation, signatures, key exchange outside TLS |
| V11.7 | In-Use Data Cryptography | Memory encryption, data minimization while processing |

V11.1 is the section most projects skip and the one that decides whether a migration is possible.
An inventory is not paperwork: without a list of where each key and algorithm is used, "rotate the
signing key" has no scope.

## Statements worth quoting verbatim

Algorithms and modes:

- "Verify that only approved ciphers and modes such as AES with GCM are used."
- "Verify that insecure block modes (e.g., ECB) and weak padding schemes (e.g., PKCS#1 v1.5) are
  not used."
- "Disallowed hash functions, such as MD5, must not be used for any cryptographic purpose."

Strength:

- "all cryptographic primitives utilize a minimum of 128-bits of security"
- "RSA requires a 3072-bit key to achieve 128 bits of security"
- For collision resistance: "the output length must be at least 256 bits"

Integrity of ciphertext - AEAD "preferably", encrypt-then-MAC otherwise:

- "preferably by using an approved authenticated encryption method"
- "operating in encrypt-then-MAC mode"

Single-use values:

- "not used for more than one encryption key and data-element pair"
- "The method of generation must be appropriate for the algorithm being used."

Randomness:

- "generated using a cryptographically secure pseudo-random number generator (CSPRNG) and have at
  least 128 bits of entropy"
- "Note that UUIDs do not respect this condition."
- "the random number generation mechanism in use is designed to work securely, even under heavy
  demand"

Post-quantum, in the same chapter rather than as a separate topic: PQC is "cryptographic algorithms
designed to remain secure against attacks by quantum computers", and V11.1 asks for "the migration
path to new cryptographic standards, such as post-quantum cryptography".

## Appendix C approval levels

Three tiers. Approved (A) can be used. Legacy (L) "should not be used in applications but might
still be used for compatibility with existing legacy applications". Disallowed (D) "must not be
used because they are currently considered broken".

Symmetric ciphers, in the appendix's preference order:

| Level | Algorithms |
|---|---|
| A | AES-256, Salsa20, XChaCha20, XSalsa20, ChaCha20, AES-192 |
| L | AES-128 |
| D | 2TDEA, TDEA (3DES), IDEA, RC4, ARC4, Blowfish, DES |

AES modes:

| Level | Modes |
|---|---|
| A | GCM (SP 800-38D), CCM (SP 800-38C) |
| L | CBC (SP 800-38A), unauthenticated |
| D | CCM-8, ECB, CFB, OFB, CTR |

CTR being Disallowed surprises people. The reason is the same as for CBC being merely Legacy:
every encrypted message must be authenticated, and CTR alone is not. CBC survives as Legacy
because a paired MAC construction for it is specified; the appendix notes CBC needs
Encrypt-then-Hash, that "TLS 1.2 uses Hash-Then-Encrypt instead", and that padding verification
must run in constant time. CCM-8 is out because its 64-bit tag fails the 128-bit floor.

One documented exception to "always authenticate": disk encryption is out of ASVS scope and is the
sole case where unauthenticated encryption is accepted, with XTS, XEX and LRW typical there.

AEAD:

| Level | Constructions |
|---|---|
| A | AES-GCM, AES-CCM, ChaCha20-Poly1305, AEGIS-256, AEGIS-128, AEGIS-128L, Encrypt-then-MAC |
| L | MAC-then-encrypt (kept for legacy TLS 1.2 suites) |

Key wrapping: AES-256 per SP 800-38F, with KW and KWP both approved and KW preferred. AES-192 or
AES-128 are permitted where the use case requires, but the justification must be recorded in the
cryptography inventory.

Hash functions:

| Level | Functions |
|---|---|
| A | SHA3-512, SHA-512, SHA3-384, SHA-384, SHA3-256, SHA-512/256, SHA-256, SHAKE256, BLAKE2s, BLAKE2b, BLAKE3 |
| L | SHA-224, SHA-512/224, SHA3-224, SHA-1 - each marked "Not suitable for HMAC, KDF, RBG, digital signatures" |
| D | CRC (any length), MD4, MD5 |

The cutoff is phrased as output "less than 254 bit", which is barred from signatures and any
collision-resistant use and limited to legacy verification elsewhere.

MACs:

| Level | Algorithms |
|---|---|
| A | HMAC-SHA-256/384/512, KMAC128, KMAC256, BLAKE3 keyed_hash, AES-CMAC, AES-GMAC, Poly1305-AES |
| L | HMAC-SHA-1 |
| D | HMAC-MD5 |

Digital signatures:

| Level | Algorithms |
|---|---|
| A | EdDSA (Ed25519, Ed448), XEdDSA (Curve25519, Curve448), ECDSA (P-256, P-384, P-521), RSA-SSA-PSS |
| D | RSA-SSA-PKCS#1 v1.5, DSA at any key size |

Key exchange: minimum 112-bit security strength. FFDH with L ≥ 3072 and N ≥ 256 (A, forward
secret), ECDH with f ≥ 256-383 (A, forward secret), RSA-PKCS#1 v1.5 key transport (D, no forward
secrecy). New implementations must conform to SP 800-56A/B and SP 800-77, and "IKEv1 MUST NOT be
used in production". Approved groups include Curve25519, Curve448, the NIST P-curves, MODP-2048
through MODP-8192, and ffdhe2048 through ffdhe8192.

KDFs: HKDF (RFC 5869) approved; the TLS 1.2 PRF is legacy; MD5-based and SHA-1-based KDFs are
disallowed.

Random values, all approved: `/dev/random` (Linux 4.8+, ChaCha20-based per RFC 7539; also iOS
`SecRandomCopyBytes` and Android `SecureRandom`), `/dev/urandom`, AES-CTR-DRBG (e.g. Windows CNG
`BCryptGenRandom` with `BCRYPT_RNG_ALGORITHM`), HMAC-DRBG, Hash-DRBG, and `getentropy()`
(OpenBSD, glibc 2.25+, macOS 10.12+).

## Password storage parameters in Appendix C

These are ASVS's own minimums, and they differ slightly from the Password Storage Cheat Sheet.
See [password-storage-parameters.md](password-storage-parameters.md) for the comparison.

| Algorithm | Required parameters | Level |
|---|---|:-:|
| argon2id | t=1: m ≥ 47104 (46 MiB), p=1 · t=2: m ≥ 19456 (19 MiB), p=1 · t ≥ 3: m ≥ 12288 (12 MiB), p=1 | A |
| scrypt | p=1: N ≥ 2^17 (128 MiB), r=8 · p=2: N ≥ 2^16, r=8 · p ≥ 3: N ≥ 2^15, r=8 | A |
| bcrypt | cost ≥ 10 | A |
| PBKDF2-HMAC-SHA-512 | ≥ 210,000 iterations | A |
| PBKDF2-HMAC-SHA-256 | ≥ 600,000 iterations | A |
| PBKDF2-HMAC-SHA-1 | ≥ 1,300,000 iterations | L |

## Equivalent strengths

From SP 800-57 Part 1, reproduced in Appendix C. The last three columns assume no quantum computer
exists.

| Security strength | Symmetric | Finite field | Integer factorization | Elliptic curve |
|---|---|---|---|---|
| ≤ 80 | 2TDEA | L=1024, N=160 | k=1024 | f=160-223 |
| 112 | 3TDEA | L=2048, N=224 | k=2048 | f=224-255 |
| 128 | AES-128 | L=3072, N=256 | k=3072 | f=256-383 |
| 192 | AES-192 | L=7680, N=384 | k=7680 | f=384-511 |
| 256 | AES-256 | L=15360, N=512 | k=15360 | f=512+ |

## Levels

State which level you targeted. Level 1 is a black-box floor, Level 2 the right default for an
application handling sensitive data, Level 3 for health, finance, safety, and critical
infrastructure. Level 3 inventory work expects static and dynamic scanning; the appendix names
CryptoMon and Cryptobom Forge as freeware options. "ASVS compliant" without a level means nothing.

## Sources

- ASVS 5.0.0 V11 -
  <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x20-V11-Cryptography.md> (2026-07-28)
- ASVS 5.0.0 Appendix C -
  <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x92-Appendix-C_Cryptography.md> (2026-07-28)
- ASVS project page -
  <https://owasp.org/www-project-application-security-verification-standard/> (2026-07-28)
