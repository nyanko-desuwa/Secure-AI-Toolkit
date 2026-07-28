# Password storage parameters

Source: OWASP Password Storage Cheat Sheet —
<https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>
Verified: 2026-07-28

NIST SP 800-63B-4 requires salting and hashing with a suitable one-way function but does not
publish cost parameters. These come from the cheat sheet. When you cite a specific `m`/`t`/`p`,
cite this source, not 800-63B.

## Argon2id

Preferred. Balances resistance to side-channel and GPU attacks.

Five configurations the cheat sheet describes as giving equal defence, differing only in the
CPU/RAM trade-off:

| memory | iterations | parallelism | note |
|---|---|---|---|
| m=47104 (46 MiB) | t=1 | p=1 | do not use with Argon2i |
| m=19456 (19 MiB) | t=2 | p=1 | do not use with Argon2i — the baseline recommendation |
| m=12288 (12 MiB) | t=3 | p=1 | |
| m=9216 (9 MiB) | t=4 | p=1 | |
| m=7168 (7 MiB) | t=5 | p=1 | |

Pick by what your verification host can afford. Memory is the parameter that costs an attacker
with GPUs the most, so trade iterations down before memory.

## bcrypt

Legacy use only, where Argon2 and scrypt are unavailable. Work factor should be as large as
verification server performance allows, minimum 10.

Input limit is 72 bytes. Enforce that as a maximum password length, or less if your
implementation truncates earlier. This collides with the 800-63B requirement to accept at
least 64 characters — 64 ASCII characters fit in 72 bytes, but 64 characters of non-Latin
script do not. That is a reason to choose Argon2id, not a reason to truncate silently.

If pre-hashing is unavoidable, the recommended construction is:

```text
bcrypt(base64(hmac-sha384(data:$password, key:$pepper)), $salt, $cost)
```

Naive pre-hashing is called out as risky: null-byte truncation and password shucking.

## PBKDF2

Use where FIPS-140 validation or NIST alignment is required. HMAC-SHA-256 recommended.

| Variant | Iterations |
|---|---|
| PBKDF2-HMAC-SHA256 | 600,000 |
| PBKDF2-HMAC-SHA512 | 220,000 |
| PBKDF2-HMAC-SHA1 | 1,400,000 — legacy only, do not select for new systems |

## Peppering

Defence in depth. The cheat sheet is explicit that alone it "provides no additional secure
characteristics". Its value is narrow and real: an attacker who reads the database — SQL
injection, a stolen backup — cannot crack any hash without also holding the pepper.

- A pepper is shared across all stored passwords. A salt is per user. They are not variants
  of the same thing.
- It must not be stored alongside the hashes. Secrets vault or HSM.
- Rotation is the cost. A pepper cannot be changed without knowing each user's password, so a
  pepper compromise forces a password reset for every affected account.

Two constructions: pre-hashing (random pepper prepended before hashing) and post-hashing
(HMAC the finished hash with the pepper as key). Post-hashing is easier to rotate through a
versioned scheme because the input to the KDF does not change.

## Session ID entropy

Source: OWASP Session Management Cheat Sheet —
<https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html>

Framework-generated session IDs need at least 64 bits of entropy from a CSPRNG. If you
generate your own, the guidance is 128 bits minimum with guaranteed uniqueness. Any fixed or
predictable portion of the value reduces effective entropy — a 16-character hex ID with half
of it hardcoded carries 32 bits, which is not enough.
