# Post-Quantum Cryptography - Status

What is standardized, what is deployable, and what is still a draft. Verified 2026-07-28.

The honest summary: key exchange has a real migration path you can take today through hybrid TLS.
Signatures are standardized but thinly implemented. Anything beyond "turn on hybrid key agreement
where your stack offers it" needs a specialist and a reading of the actual documents.

`A04:2025` · ASVS V11.1 (Cryptographic Inventory), V11.6 (Public Key Cryptography)

## Published standards

All three were published 2024-08-13.

| Standard | Title | Algorithm | Purpose |
|---|---|---|---|
| FIPS 203 | Module-Lattice-Based Key-Encapsulation Mechanism Standard | ML-KEM | Key establishment |
| FIPS 204 | Module-Lattice-Based Digital Signature Standard | ML-DSA | Signatures |
| FIPS 205 | Stateless Hash-Based Digital Signature Standard | SLH-DSA | Signatures |

NIST describes these as the "first 3 finalized post-quantum encryption standards" and says they
"can and should be put into use now".

ML-KEM parameter sets, increasing security strength and decreasing performance: ML-KEM-512,
ML-KEM-768, ML-KEM-1024. Its security rests on the Module Learning with Errors problem. Go's
`crypto/mlkem` documentation recommends ML-KEM-768 for most applications, which matches what TLS
deployments have converged on.

SLH-DSA derives from SPHINCS+. It is a conservative hash-based fallback: large signatures, slow
signing, but its security assumptions do not depend on lattices, so it is the hedge if a lattice
attack appears.

Not verified from the NIST landing pages, and therefore not stated here: the ML-DSA and SLH-DSA
parameter set names. Pull those from the PDF before writing one into a config file.

Errata exist. FIPS 203 has a planning note dated 2025-11-17 describing an issue for a later update;
FIPS 204 has one dated 2026-02-23 pointing at an errata spreadsheet. Read the errata before
implementing from the published text.

## Still in progress

Selected but not published, with no FIPS number and no publication date:

- Falcon, a signature scheme, "selected for ongoing standardization; that process is underway".
- HQC, a key encapsulation mechanism, announced as a fourth-round selection in 2025.

The name FN-DSA is widely used for the Falcon standard. It does not appear on the NIST PQC project
page as of this check, so do not cite it as a published designation.

## The transition timeline

NIST IR 8547, "Transition to Post-Quantum Cryptography Standards", is an Initial Public Draft
published 2024-11-12. The comment window closed 2025-01-10; a compiled comment set was posted per a
planning note dated 2025-01-21. As of this check there is no final version.

Under the draft, quantum-vulnerable algorithms are to be deprecated and eventually removed from NIST
standards by 2035, with high-risk systems moving sooner.

Deliberately not reproduced here: the per-algorithm deprecation and disallowed years for RSA, ECDSA,
ECDH, and DH. Those tables are in the PDF, not on the landing page, and they drive procurement
decisions. Read the document rather than trusting a recalled year.

## Hybrid key exchange in TLS - the one thing to actually do

The urgency is asymmetric and it is worth being precise about why:

- Key exchange is urgent. Traffic captured today can be decrypted later once a cryptographically
  relevant quantum computer exists. This is "harvest now, decrypt later", and it means the deadline
  for confidentiality already passed for any data with a long secrecy lifetime.
- Signatures are not urgent in the same way. A signature verified today cannot be retroactively
  forged by a future machine. What does need a plan is long-lived roots of trust - code signing
  keys, firmware verification, CA roots - because those must still be trustworthy in 2040.

Hybrid means the session key derives from both a classical ECDH share and an ML-KEM share, so the
connection is secure unless both are broken. That is the property that makes it safe to deploy
before anyone is confident in lattice assumptions.

### Standardization status of the TLS groups

The specification is `draft-ietf-tls-ecdhe-mlkem`, "Post-quantum hybrid ECDHE-MLKEM Key Agreement
for TLSv1.3". Status as of 2026-07-28: revision 05, dated 2026-05-26, expiring 2026-11-27. It is an
active IETF TLS working group Internet-Draft with intended status Proposed Standard. IESG state is
"Approved-announcement sent" and RFC Editor state is "In Progress" - it is in the publication queue
and has no RFC number yet. Do not cite an RFC number for it. It replaces
`draft-kwiatkowski-tls-ecdhe-mlkem`.

Code points, all marked DTLS-OK:

| Group | Value | Recommended | Combination |
|---|---|---|---|
| X25519MLKEM768 | 4588 (0x11EC) | Y | X25519 ECDH + ML-KEM-768 |
| SecP256r1MLKEM768 | 4587 (0x11EB) | N | secp256r1 ECDH + ML-KEM-768 |
| SecP384r1MLKEM1024 | 4589 (0x11ED) | N | secp384r1 ECDH + ML-KEM-1024 |

X25519MLKEM768 is the one to configure. It is the only group marked Recommended, and it puts the
ML-KEM share first in the concatenation - a deviation from the hybrid design draft's naming
convention that the document attributes to "historical reasons". The other two put the ECDH share
first so the FIPS-approved scheme leads the HKDF input. If you are implementing the derivation
yourself, that ordering detail is load-bearing; if you are configuring a server, it is trivia.

The draft retires the pre-standard Kyber768 experiment: X25519Kyber768Draft00 (25497) and
SecP256r1Kyber768Draft00 (25498) get their IANA Recommended field set to 'D'. If your config still
names those, it is pinned to an obsolete experiment and will silently fall back to classical ECDH.

### Deployment maturity, honestly

ASVS 5.0.0 Appendix C names FIPS 203, 204, and 205 as the reference standards and adds the caveat
that few hardened implementations exist yet. On the hybrid group it says `mlkem768x25519` ships in
Firefox 132 and Chrome 131, and that it "may be used in cryptographic testing environments or when
available within industry- or government-approved libraries".

Read that carefully. ASVS is not telling you to require PQC. It is telling you to use it where a
vetted library offers it, and to have a documented migration path - V11.1 asks for "the migration
path to new cryptographic standards, such as post-quantum cryptography", which is an inventory and
planning requirement, not an algorithm requirement.

What that means in practice:

- Enabling X25519MLKEM768 on a TLS server or load balancer that supports it is low-risk and worth
  doing. A client that does not support it negotiates a classical group.
- Middleboxes are the failure mode. The ML-KEM share makes the ClientHello larger, which has broken
  poorly written TLS-inspecting appliances in the field. Test before enabling on a path that crosses
  one.
- Certificates are still classical. Hybrid key exchange protects confidentiality; the authentication
  in your TLS handshake is still ECDSA or RSA. A full PQC transition needs PQC certificates, and the
  CA ecosystem for those is immature. Do not claim a connection is post-quantum secure when only
  half of it is.
- Signature migration is a bigger project than key exchange. ML-DSA signatures and public keys are
  much larger than Ed25519's, which affects protocol size limits, embedded storage, and anything with
  a fixed-width field for a signature. Measure before committing.

## Do not build the hybrid yourself

Concatenating an ECDH secret and an ML-KEM secret and hashing them is not obviously wrong, and that
is exactly the problem - the safe combiners are specified, and the specification exists because the
obvious constructions have subtle issues around key-commitment and share ordering. Use what your TLS
or SSH implementation ships.

Where you genuinely need ML-KEM at the application layer - a stored-message protocol, not a
transport - the API is a KEM, not encryption. It gives you a shared secret; you still need an AEAD.
Go's standard library, since Go 1.24:

```go
package pqdemo

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/hkdf"
    "crypto/mlkem"
    "crypto/rand"
    "crypto/sha256"
    "fmt"
)

// Recipient generates a long-term key pair. dk.Bytes() is the 64-byte seed (d || z)
// and is secret key material: store it in a KMS or secret manager, never in the repo.
func NewRecipient() (*mlkem.DecapsulationKey768, []byte, error) {
    dk, err := mlkem.GenerateKey768()
    if err != nil {
        return nil, nil, err
    }
    return dk, dk.EncapsulationKey().Bytes(), nil // 1184-byte public encapsulation key
}

// Sender encapsulates to the recipient's public key, then encrypts with an AEAD.
func Seal(encapsulationKey, plaintext, aad []byte) (ct, kemCT []byte, err error) {
    ek, err := mlkem.NewEncapsulationKey768(encapsulationKey)
    if err != nil {
        return nil, nil, err
    }
    shared, kemCT := ek.Encapsulate() // shared is 32 bytes; kemCT is 1088 bytes

    key, err := hkdf.Key(sha256.New, shared, nil, "app/v1 message key", 32)
    if err != nil {
        return nil, nil, err
    }
    gcm, err := newGCM(key)
    if err != nil {
        return nil, nil, err
    }
    nonce := make([]byte, gcm.NonceSize())
    if _, err := rand.Read(nonce); err != nil {
        return nil, nil, fmt.Errorf("nonce: %w", err)
    }
    return gcm.Seal(nonce, nonce, plaintext, aad), kemCT, nil
}

func Open(dk *mlkem.DecapsulationKey768, kemCT, blob, aad []byte) ([]byte, error) {
    shared, err := dk.Decapsulate(kemCT) // errors on an invalid ciphertext
    if err != nil {
        return nil, err
    }
    key, err := hkdf.Key(sha256.New, shared, nil, "app/v1 message key", 32)
    if err != nil {
        return nil, err
    }
    gcm, err := newGCM(key)
    if err != nil {
        return nil, err
    }
    if len(blob) < gcm.NonceSize() {
        return nil, fmt.Errorf("ciphertext too short")
    }
    nonce, ct := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]
    return gcm.Open(nil, nonce, ct, aad) // tag failure is an error, not an empty result
}

func newGCM(key []byte) (cipher.AEAD, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    return cipher.NewGCM(block)
}
```

Two things to note about that code. The HKDF `info` string is domain separation: change the protocol
and change the string, or two protocols derive the same key from the same shared secret. And this is
ML-KEM alone, not hybrid - it is secure against a quantum adversary and it is not hedged against a
flaw in ML-KEM itself. For a stored-message protocol that is a defensible tradeoff you should state
explicitly; for transport, use TLS's hybrid group instead.

`crypto/mlkem` and `crypto/hkdf` were both added to the Go standard library in Go 1.24. The API above
is from the go1.26.5 documentation. Python's `cryptography` and Node's `crypto` had no stable ML-KEM
API at this check - verify against your installed version rather than assuming one exists.

## What to write in an inventory

V11.1 wants a migration plan, and a plan needs a list. For each place crypto is used, record the
algorithm, the key location, whether it protects confidentiality or authenticity, and the secrecy or
trust lifetime of what it protects. The last column is what tells you the ordering: a 30-year medical
record encrypted in transit today is a harvest-now-decrypt-later problem; a session cookie that
expires in an hour is not.

## Sources

- NIST PQC project - <https://csrc.nist.gov/projects/post-quantum-cryptography> (2026-07-28)
- FIPS 203 - <https://csrc.nist.gov/pubs/fips/203/final> (2026-07-28)
- FIPS 204 - <https://csrc.nist.gov/pubs/fips/204/final> (2026-07-28)
- FIPS 205 - <https://csrc.nist.gov/pubs/fips/205/final> (2026-07-28)
- NIST IR 8547 (ipd) - <https://csrc.nist.gov/pubs/ir/8547/ipd> (2026-07-28)
- draft-ietf-tls-ecdhe-mlkem-05 -
  <https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/> (2026-07-28)
- OWASP ASVS 5.0.0 Appendix C -
  <https://github.com/OWASP/ASVS/blob/master/5.0/en/0x92-Appendix-C_Cryptography.md> (2026-07-28)
- Go `crypto/mlkem` - <https://pkg.go.dev/crypto/mlkem> (2026-07-28)
- Go `crypto/hkdf` - <https://pkg.go.dev/crypto/hkdf> (2026-07-28)
