# Password Storage Parameters

Concrete parameters. Copy the numbers, not the vibe.

Two sources, checked 2026-07-28:

- OWASP Password Storage Cheat Sheet -
  <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>
- OWASP ASVS 5.0.0 Appendix C -
  <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x92-Appendix-C_Cryptography.md>

The cheat sheet carries no version number or publication date. The only temporal marker on the page
is on the parallel-PBKDF2 table, which says its figures are "as of december 2022, based on testing
of RTX 4000 GPUs". Treat the page as current-as-checked, not as a dated release.

`A04:2025`, `A07:2025` · ASVS V11.4 (Hashing), V6 (Authentication) · CWE-916, CWE-759

Login flow, MFA, lockout, and credential recovery are `core/authentication`. This file is only the
KDF and its parameters.

## Argon2id - first choice

Use the `id` variant. Not `i`, not `d`. The cheat sheet picks it because it "provides a balanced
approach to resisting both side-channel and GPU-based attacks".

Cheat sheet floor: 19 MiB memory, 2 iterations, 1 degree of parallelism. These five rows are
described as giving "an equal level of defense", trading CPU against RAM:

| memory (m) | iterations (t) | parallelism (p) | Note |
|---|---|---|---|
| 47104 KiB (46 MiB) | 1 | 1 | "Do not use with Argon2i" |
| 19456 KiB (19 MiB) | 2 | 1 | "Do not use with Argon2i" - the baseline |
| 12288 KiB (12 MiB) | 3 | 1 | |
| 9216 KiB (9 MiB) | 4 | 1 | |
| 7168 KiB (7 MiB) | 5 | 1 | |

ASVS Appendix C states the same requirement as inequalities, which is the more useful form for a
review: `t=1` needs `m ≥ 47104`, `t=2` needs `m ≥ 19456`, and `t ≥ 3` needs `m ≥ 12288`, all with
`p=1`. So `t=4, m=12288` passes ASVS and `t=4, m=9216` passes the cheat sheet. Where the two differ,
cite the one you followed. Memory is the parameter a GPU attacker feels most, so trade iterations
down before memory.

## scrypt - when Argon2id is unavailable

Cheat sheet floor: N = 2^17, r = 8, p = 1. Described as "a similar minimal level of defense".

| cost (N) | block size (r) | parallelism (p) |
|---|---|---|
| 2^17 (128 MiB) | 8 | 1 |
| 2^16 (64 MiB) | 8 | 2 |
| 2^15 (32 MiB) | 8 | 3 |
| 2^14 (16 MiB) | 8 | 5 |
| 2^13 (8 MiB) | 8 | 10 |

ASVS expresses it as `p=1: N ≥ 2^17`, `p=2: N ≥ 2^16`, `p ≥ 3: N ≥ 2^15`.

## bcrypt - legacy only

Work factor 10 minimum (both sources agree), and as high as the verification server tolerates.

The input limit is the trap. The cheat sheet gives 72 bytes: bcrypt "has a maximum length input
length of 72 bytes for most implementations". Cap password length at 72 bytes, or lower if your
library truncates earlier. Do not truncate silently - that turns a 100-character passphrase into a
72-byte one without telling anyone.

Pre-hashing to escape the limit is called out as dangerous for two specific reasons:

- Null bytes. Original bcrypt expects a null-terminated string, so input stops at the first null
  byte. `bcrypt(sha512($password))` collapses whenever the digest starts with a zero byte. Base64
  encoding the digest fixes this, and the cheat sheet calls the resulting truncation "negligible".
- Password shucking. If `H($password)` has leaked elsewhere for that password, cracking your hash
  reduces to breaking `H`. Plain `bcrypt(base64(sha512($password)))` is labelled "a dangerous
  practice" and is only as strong as SHA-512 alone.

If pre-hashing is unavoidable, the prescribed construction is:

```text
bcrypt(base64(hmac-sha384(data:$password, key:$pepper)), $salt, $cost)
```

with the pepper stored outside the database.

## PBKDF2 - when FIPS-140 validation is required

Internal PRF: HMAC-SHA-256. The two sources give different SHA-512 numbers; both are minimums, so
take the higher one if you want to satisfy both.

| Variant | Cheat sheet | ASVS Appendix C |
|---|---|---|
| PBKDF2-HMAC-SHA256 | 600,000 | ≥ 600,000 (A) |
| PBKDF2-HMAC-SHA512 | 220,000 | ≥ 210,000 (A) |
| PBKDF2-HMAC-SHA1 | 1,400,000 - legacy only | ≥ 1,300,000 (L) |

SHA-1 is disallowed for new use after 2030 per NIST SP 800-131A Rev. 2, cited on the cheat sheet.
Do not select it for a new system regardless of iteration count.

Parallel PBKDF2 equivalents from the cheat sheet: PPBKDF2-SHA512 cost 2, PPBKDF2-SHA256 cost 5,
PPBKDF2-SHA1 cost 10.

Denial-of-service note: HMAC automatically pre-hashes input longer than the block size (64 bytes for
SHA-256), and a poor implementation redoes that work every iteration. Django carried such a bug in
2013. Manual pre-hashing helps but needs its own salt.

Note the asymmetry in ASVS: bcrypt appears in its password-storage table but not in its
password-based-KDF table, and the KDF table lists only `t=1` and `t=2` for argon2id. If you are
deriving an encryption key from a password rather than verifying a login, use Argon2id or scrypt.

## Salts

Neither source gives a salt length, because you should not be choosing one. The library generates
the salt, stores it inside the encoded hash, and reads it back on verify. Argon2id, bcrypt, scrypt,
and PBKDF2 all require a salt at the spec level and all mainstream libraries handle it internally.

Do not supply your own, do not derive it from the username or user ID, and do not add a salt column
you designed. A salt forces per-hash cracking, defeats rainbow tables, and hides the fact that two
users chose the same password. It does nothing about throughput.

## Peppers

Defence in depth only. The cheat sheet is explicit that on its own a pepper "provides no additional
secure characteristics". Its value is narrow and real: an attacker holding only the database - SQL
injection, a stolen backup - cannot crack anything without also holding the pepper.

- A pepper is shared across all stored passwords. A salt is per user. They are not variants of the
  same idea.
- It must not be stored with the hashes. Secrets vault or HSM. See `core/secrets-management`.
- Rotation is the cost. A pepper "cannot be changed without knowledge of a user's password", so a
  pepper compromise forces a password reset for every affected account. Decide the rotation story
  before you add the pepper.

Two constructions: pre-hashing (a secret random value mixed into the password before hashing) and
post-hashing (HMAC the finished hash with the pepper as the HMAC key, sized per the HMAC algorithm).

## Work factor tuning

Target under one second per hash. Measure on the hardware that will run verification, not on a
laptop, and re-measure yearly. Too high a factor is its own vulnerability: repeated login attempts
become CPU exhaustion.

## Raising parameters without a mass reset

Store the full encoded string. It carries the algorithm and its parameters:

```text
$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
```

On a successful login, if the stored parameters are below current policy, re-hash the plaintext you
already hold and update the row. Active users migrate within weeks. Announce a deadline and
force-reset the dormant remainder rather than keeping weak hashes indefinitely.

There is no way around this. You cannot strengthen a hash without the plaintext, which you only ever
have at the moment of login. The PHC string format exists so this migration is possible at all;
store algorithm and work factor alongside the hash if your library does not.

## Upgrading from a legacy fast hash

The cheat sheet gives two paths beyond rehash-on-login:

- Delete hashes for long-inactive users and require a reset. Secure, unfriendly, and a mass expiry
  can read to users as a breach notification.
- Nest the old hash inside a strong one - `md5($password)` becomes `bcrypt(md5($password))`. This
  needs no plaintext, but the cheat sheet warns it "can make the hashes easier to crack" through
  shucking. Replace with a direct hash at next login.

## What not to use, ever

MD5, SHA-1, SHA-256, SHA-512, or SHA-3 alone. HMAC alone. A "salted SHA-256". A hash iterated in a
loop you wrote. Encryption instead of hashing, which converts a cracking problem into a key
management problem and loses.

A fast hash is fast for the attacker too. The salt only defeats precomputation; against a GPU
working one account at a time it changes nothing.

## Miscellaneous requirements

- Unicode must survive end to end, including pictograms and NULL bytes, with no entropy reduction
  before hashing.
- The algorithm need not be secret. A correctly configured modern KDF can be disclosed publicly.

## Sources

- OWASP Password Storage Cheat Sheet -
  <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html> (2026-07-28)
- OWASP ASVS 5.0.0 Appendix C -
  <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x92-Appendix-C_Cryptography.md> (2026-07-28)
- CWE-916 - <https://cwe.mitre.org/data/definitions/916.html>
- CWE-759 - <https://cwe.mitre.org/data/definitions/759.html>
