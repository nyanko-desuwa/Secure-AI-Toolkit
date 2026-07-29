# Troubleshooting

What to do when the guidance cannot be applied cleanly, or when applying it breaks something.

## The platform has no Argon2id

Order of fallback: Argon2id, then scrypt, then bcrypt, then PBKDF2-HMAC-SHA256 at 600,000
iterations. Parameters in [references/password-storage.md](references/password-storage.md).

Pick PBKDF2 only for a FIPS-140 requirement or where nothing else exists. Say which constraint drove
the choice in a comment next to the call, so the next reader does not "helpfully" leave it there
after the constraint disappears.

## FIPS mode forbids the algorithm you recommended

FIPS-validated modules exclude Argon2, scrypt, and ChaCha20-Poly1305. Inside a FIPS boundary you get
PBKDF2-HMAC-SHA256 and AES-GCM, and that is the correct answer there - a non-validated algorithm in
a FIPS environment is a compliance failure regardless of its strength.

Note the tradeoff honestly: PBKDF2 has no memory hardness, so it is weaker against GPU cracking than
Argon2id at equivalent wall-clock cost. Raise the iteration count to the performance ceiling and
document that the ceiling, not the ideal, set the parameter.

## Upgrading password parameters without resetting everyone

You cannot re-hash a hash into a stronger one. Rehash on next successful login, when the plaintext is
in hand:

```python
if ph.check_needs_rehash(stored):
    user.password_hash = ph.hash(password)
```

This requires the stored string to carry its own parameters, which the standard encoded formats do.
Active users migrate within weeks; force a reset on the dormant remainder after a deadline you
announce. Do not silently keep weak hashes forever because the migration has no end date.

## Migrating from a bare SHA-256 password column

There is no plaintext, so you cannot produce an Argon2id hash directly. Two options.

Wrap the old hash, then unwrap on login:

```python
# stored as argon2id(hex(sha256(password))) with scheme="legacy_wrapped"
if row.scheme == "legacy_wrapped":
    inner = hashlib.sha256(password.encode()).hexdigest()
    ph.verify(row.hash, inner)               # verifies the wrapped legacy hash
    row.hash, row.scheme = ph.hash(password), "argon2id"   # upgrade in place
```

Or keep the old verifier alongside the new one and upgrade on login. Both are acceptable; the wrap is
better because the weak hash stops being directly crackable from a dump immediately.

Wrapping inherits the shucking weakness described in the password storage reference: if
`sha256(password)` for that password has leaked elsewhere, cracking reduces to the inner hash. Say so.
The unwrap-on-login upgrade is what actually removes it.

## Decryption fails after a deploy and you do not know which key

If ciphertexts do not carry a key ID, you are guessing. Try each candidate key and see which
authenticates - with an AEAD this is safe, because a wrong key fails the tag rather than returning
garbage that looks plausible.

Then fix the cause: add `key_id` and `alg` to the stored envelope before the next rotation.

## GCM nonce uniqueness cannot be guaranteed

Symptoms: multiple writers, a counter that resets on restart, or a queue that replays.

Use random 96-bit nonces and rotate the key on message count rather than trying to coordinate a
counter. If your library offers XChaCha20-Poly1305, its 192-bit nonce makes random generation
comfortable at any realistic volume - that is the cleanest escape from the counting problem.

Do not mix random and counter nonces under one key. That combination reuses values by construction.

## TLS verification fails and you need it working now

Do not set `verify=False`, `InsecureSkipVerify`, or `rejectUnauthorized: false`, even temporarily.
Temporary flags survive to production; that is how most of them got there.

Work through the actual cause:

| Error | Cause | Fix |
|---|---|---|
| unable to get local issuer certificate | intermediate not served | fix the server chain, or set the CA bundle explicitly |
| self signed certificate | dev or internal CA | add that CA to the client trust store |
| certificate has expired | expired, or clock skew | renew; check the client clock |
| hostname mismatch | SAN does not match | reissue with the right SAN; do not disable hostname checks |
| certificate signed by unknown authority | private CA | pass the CA pool to the client |

For internal services, a private CA whose root is distributed to clients is the correct answer, not
verification-off.

## Legacy interop demands a broken algorithm

A partner accepts only AES-CBC, RSA PKCS#1 v1.5, or SHA-1 signatures.

Do not silently comply and do not silently refuse. Write down: which party requires it, what an
attacker gains, what compensating controls apply (mutual TLS, an allowlisted network path, short
message lifetime), and the date the exception is reviewed. Isolate the weak path to one module so it
cannot spread by copy-paste.

An undocumented exception becomes permanent. A documented one gets removed.

## The data has to be searchable and encrypted

Randomized AEAD kills equality lookups. Options in order of preference:

1. Do not encrypt the field at the application layer. Rely on disk or database encryption if the
   threat model is a stolen disk
2. Blind index: store randomized AEAD ciphertext for the value plus HMAC of the normalized value for
   lookup. Equality only
3. Deterministic AEAD (AES-SIV) where the field genuinely needs it. Accept and document the
   frequency-analysis leak
4. Range and prefix queries over encrypted data need a searchable-encryption scheme with real leakage
   analysis. If someone proposes ORE or OPE, that decision needs a cryptographer, not this skill

## Key rotation would require re-encrypting terabytes

Use envelope encryption so rotation does not touch the data. Rotate the KEK, re-wrap each DEK, leave
ciphertext untouched. See [best-practices.md](best-practices.md#envelope-encryption-and-key-lifecycle).

If the design encrypted rows directly with a single key, re-encryption is unavoidable. Do it in
batches keyed by `key_id`, keep both keys valid during the window, and treat the eventual switch to
new-key-only as a separate, verifiable step.

## KMS is unavailable and requests are failing

Fail closed. A decryption that cannot reach the KMS returns an error; it does not return plaintext,
a cached key of unknown age, or an empty value.

Reduce the blast radius properly: cache the unwrapped DEK in memory for a bounded TTL so a brief KMS
outage does not stop in-flight work, and use the KMS's multi-region or replica features. A local
plaintext key file as a fallback recreates exactly the risk the KMS removed.

## The library API you were told to use does not exist

Version drift. Check the installed version and read its documentation rather than adapting the code
until it compiles - a call that compiles is not evidence it is used correctly.

If you cannot confirm the correct usage for the pinned version, say so instead of guessing. A crypto
API misused compiles cleanly and fails silently, which is why "it runs" proves nothing here.

## You cannot tell whether a finding is exploitable

Report it with the uncertainty attached, naming the precondition you could not check.

"HMAC compared with `==` in `verify_webhook`; exploitability depends on whether the endpoint is
rate-limited and how much timing noise the network adds - I could not measure either" is useful.
"Critical timing attack" without that is noise, and noise gets checklists ignored.

## A checklist item genuinely does not apply

Write the reason. "No key rotation section: this change only reads existing ciphertext" is a complete
answer. An unexplained skip is indistinguishable from an oversight.

## The standard moved

The OWASP and NIST references here were verified on 2026-07-28. NIST SP 800-38D is marked for
revision, FIPS 203 and 204 have errata, and NIST IR 8547 was still a draft at that check. Re-fetch
before quoting a figure into a policy document. URLs are in [references/](references/).
