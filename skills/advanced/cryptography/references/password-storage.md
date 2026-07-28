# Password Storage Parameters

Concrete parameters for password hashing. Copy the numbers, not the vibe.

Source: OWASP Password Storage Cheat Sheet —
<https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>
(checked 2026-07-28).

`A04:2025` · ASVS V11 (Cryptography), V6 (Authentication) · CWE-916 (Use of Password Hash With
Insufficient Computational Effort), CWE-759 (Use of a One-Way Hash without a Salt).

## Argon2id — first choice

Use the `id` variant. Not `i`, not `d`.

Baseline minimum: 19 MiB memory, 2 iterations, 1 degree of parallelism.

These configurations are treated as equivalent by OWASP; they trade CPU against RAM:

| memory (m) | iterations (t) | parallelism (p) |
|---|---|---|
| 47104 KiB (46 MiB) | 1 | 1 |
| 19456 KiB (19 MiB) | 2 | 1 |
| 12288 KiB (12 MiB) | 3 | 1 |
| 9216 KiB (9 MiB) | 4 | 1 |
| 7168 KiB (7 MiB) | 5 | 1 |

The 46 MiB and 19 MiB rows carry an explicit caveat: do not use them with Argon2i. Argon2id is
what balances side-channel and GPU resistance.

## scrypt — when Argon2id is unavailable

Baseline minimum: N = 2^17, r = 8, p = 1.

| cost (N) | block size (r) | parallelism (p) |
|---|---|---|
| 2^17 (128 MiB) | 8 | 1 |
| 2^16 (64 MiB) | 8 | 2 |
| 2^15 (32 MiB) | 8 | 3 |
| 2^14 (16 MiB) | 8 | 5 |
| 2^13 (8 MiB) | 8 | 10 |

## bcrypt — legacy systems only

Work factor 10 minimum, and as large as verification server performance allows.

The 72-byte input limit is the trap. Most implementations ignore everything past 72 bytes, so cap
password length at 72 bytes (or lower if the library's limit is smaller) rather than silently
truncating.

Pre-hashing to work around the limit is dangerous in two specific ways:

- Null bytes. Original bcrypt expects a null-terminated string, so input is truncated at the first
  null byte. `bcrypt(H($password))` collapses to `bcrypt("")` whenever the digest's first byte is
  zero. Encoding the digest to a printable form such as base64 avoids this, and the resulting
  truncation for a long digest like SHA-512 is negligible.
- Password shucking. If `H($password)` for the same password has leaked elsewhere, cracking your
  hash reduces to breaking `H`. Plain `bcrypt(base64(sha512($password)))` is described as dangerous
  and no stronger than SHA-512 alone.

If you must pre-hash with bcrypt, the recommended construction is:

```
bcrypt(base64(hmac-sha384(data: $password, key: $pepper)), $salt, $cost)
```

with the pepper stored outside the database.

## PBKDF2 — when FIPS-140 compliance is required

Internal PRF: HMAC-SHA-256.

| Variant | Iterations |
|---|---|
| PBKDF2-HMAC-SHA256 | 600,000 |
| PBKDF2-HMAC-SHA512 | 220,000 |
| PBKDF2-HMAC-SHA1 | 1,400,000 — legacy only, do not select for new systems |

Parallel PBKDF2 equivalents: PPBKDF2-SHA512 cost 2, PPBKDF2-SHA256 cost 5, PPBKDF2-SHA1 cost 10.

Long-input note: HMAC pre-hashes passwords exceeding the block size (64 bytes for SHA-256)
automatically. Some implementations redo that conversion every iteration, which turns a long
password into a denial-of-service vector — the 2013 Django advisory is the cited example. Manual
pre-hashing helps but needs its own salt.

## Cross-cutting rules

- Work factor tuning: as a general rule, calculating a hash should take less than one second.
  Measure on production-grade hardware, not on a laptop, and re-measure yearly
- Unicode: the library must accept the full range of codepoints including pictograms, must not
  reduce the entropy of what the user typed before hashing, and must tolerate a NULL byte in input
- Salts: the library generates and stores them. Do not supply your own, do not derive them from
  the username, do not store them in a separate column you designed
- Peppering is defence in depth only; it adds no new security property on its own. Store a pepper
  in a vault or HSM, never alongside the hashes. Rotating one forces a password reset for every
  affected user, so plan the rotation before you add the pepper

## Upgrading parameters without a mass reset

Store the full encoded hash string, which carries algorithm and parameters:

```
$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
```

On successful login, if the stored parameters are below current policy, re-hash the plaintext you
already have in hand and update the row. Within a year most active users are migrated, and the
remainder are dormant accounts you can force-reset. This is the only safe way to raise cost: you
cannot re-hash a hash into a stronger one.

## What not to use, ever

MD5, SHA-1, SHA-256, SHA-512, SHA-3 on their own, HMAC alone, a "salted SHA-256", a hash repeated
in a loop you wrote, or encryption instead of hashing. A fast hash is fast for the attacker too,
and a salt only defeats precomputation — it does nothing against a GPU working one hash at a time.

## Sources

- OWASP Password Storage Cheat Sheet —
  <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html> (2026-07-28)
- OWASP ASVS 5.0.0 — <https://owasp.org/www-project-application-security-verification-standard/>
- CWE-916 — <https://cwe.mitre.org/data/definitions/916.html>
