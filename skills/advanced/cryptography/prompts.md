# Prompt Examples

Prompts that produce crypto findings instead of a lecture on AES. Each names the scope, the standard,
and the shape of the answer.

## Review crypto usage in a diff

```
Review my staged changes for cryptographic failures (A04:2025). For each finding give the
algorithm or key involved, file:line, what an attacker gains, the ASVS chapter and CWE, and the
fix. Ignore anything that only imports a crypto library without using it.
```

Asking for "what an attacker gains" is what stops the answer being a list of algorithm names.

## Audit password storage

```
Find every place a password is hashed or verified in this repo. For each: the algorithm, the
parameters, whether the stored format carries its own parameters, and whether a rehash-on-login
upgrade path exists. Compare parameters against the OWASP Password Storage Cheat Sheet minimums.
```

The parameter-carrying question is the one people skip, and it decides whether the next upgrade
needs a mass password reset.

## Check nonce and IV handling

```
Find every AES-GCM, AES-CBC, and ChaCha20-Poly1305 call. For each, trace where the nonce or IV
comes from: is it random from a CSPRNG, a counter, a constant, or derived from data? Say which
calls can reuse a nonce under one key across processes or restarts.
```

"Across processes or restarts" is the phrase that surfaces real reuse. A counter looks fine until
two pods run it.

## Audit randomness

```
List every call that generates a token, session ID, password reset link, salt, nonce, or API key.
For each, name the RNG used and whether it is cryptographically secure. Flag Math.random,
random.random, rand(), UUIDv1, and anything seeded from a timestamp.
```

## Key lifecycle review before implementation

```
I am adding encrypted storage for customer bank details in Postgres. Before I write code, walk
the six lifecycle stages: generation, storage, use, rotation, revocation, destruction. Tell me
what breaks if the key leaks and what breaks if it is lost. Map each control to A04 and ASVS V11
or V14.
```

Design-time prompts are cheaper than review-time ones. Retrofitting rotation onto a hardcoded key
is a migration project.

## Review JWT verification

```
Read the JWT verification path. Check: is the algorithm list pinned server-side, are issuer and
audience validated, is expiry enforced, is the key selected by kid from a trusted set rather than
from the token, and does an unverified claim get read before verification? Cite CWE-347 where it
applies.
```

The last clause catches decode-then-verify, which is invisible in a test suite because the happy
path works.

## Verify TLS client configuration

```
Find every outbound HTTPS, database, and message-queue client. For each, state whether
certificate verification and hostname checking are enabled, and quote the line that proves it.
Flag verify=False, InsecureSkipVerify, rejectUnauthorized: false, and custom TrustManagers that
accept everything.
```

Asking for the proving line prevents an answer assembled from assumptions about defaults.

## Question a proposed construction

```
A colleague proposes encrypting with AES-CBC and appending HMAC-SHA256 of the ciphertext, with
the same key for both. Is that safe? If not, what specifically fails, and what should replace it?
```

Useful because the answer has to engage with a construction that looks correct. Key separation and
encrypt-then-MAC ordering both matter, and an AEAD removes the question.

## Plan a migration off a weak algorithm

```
We store card tokens with AES-128-CBC and a static IV, key hardcoded in config. Plan the
migration to AES-256-GCM with envelope encryption in KMS. Cover how ciphertexts are versioned,
how both paths coexist, how the old key is retired, and how I verify the migration finished.
```

Naming the verification step is what stops a migration stalling at 90% forever.

## Constant-time comparison audit

```
Find every comparison of a secret: HMAC digests, API keys, password reset tokens, signatures,
TOTP codes. For each, say whether the comparison is constant-time and give the correct helper for
that language. Rank exploitability honestly given whether the comparison is local or over a
network.
```

The honesty clause matters. A remote timing leak on an HMAC is real but hard; ranking it critical
by reflex is how the report loses credibility.

## Anti-patterns

| Prompt | Problem |
|---|---|
| "Is our encryption secure?" | No scope. Produces a description of AES |
| "Add encryption to this model" | Encryption without a threat model adds key risk, not security |
| "Make this FIPS compliant" | FIPS is a validated module plus a boundary, not a code change |
| "Use military-grade encryption" | Not a thing. Ask for AES-256-GCM and name where the key lives |
| "Write a function to encrypt and decrypt strings" | Invites a homegrown construction. Ask for a specific library's AEAD |
| "Hash the password securely" | Produces salted SHA-256 as often as Argon2id. Name the algorithm and parameters |
| "Rotate our keys" | Rotation without envelope encryption may mean re-encrypting everything. Ask for the plan first |
