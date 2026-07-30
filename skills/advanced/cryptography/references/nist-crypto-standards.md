# NIST Cryptography Standards

What NIST has published, with exact titles and dates. Verified 2026-07-28 against
<https://csrc.nist.gov/>.

Where a figure is commonly quoted but could not be extracted from the source document, this file
says so instead of repeating it. That distinction matters: a wrong cryptoperiod cited as NIST
guidance is worse than no citation.

## Post-quantum standards

All three were published on 2024-08-13.

| Standard | Title | Algorithm |
|---|---|---|
| FIPS 203 | Module-Lattice-Based Key-Encapsulation Mechanism Standard | ML-KEM |
| FIPS 204 | Module-Lattice-Based Digital Signature Standard | ML-DSA |
| FIPS 205 | Stateless Hash-Based Digital Signature Standard | SLH-DSA |

ML-KEM parameter sets, in order of increasing security strength and decreasing performance:
ML-KEM-512, ML-KEM-768, ML-KEM-1024. ML-KEM security rests on the hardness of the Module Learning
with Errors problem.

SLH-DSA derives from SPHINCS+, selected through the NIST PQC standardization effort.

Not verified from the landing pages: the ML-DSA and SLH-DSA parameter set names. If you need to
write one into config, pull it from the PDF rather than from memory.

Errata: FIPS 203 has a planning note dated 2025-11-17 describing an issue to be fixed in a later
update; FIPS 204 has one dated 2026-02-23 pointing at an errata spreadsheet. Check the errata
before implementing from the published text.

### What to do about PQC today

- Key exchange is where the urgency is. Data captured now can be decrypted later once a
  cryptographically relevant quantum computer exists ("harvest now, decrypt later"). Hybrid KEX in
  TLS and SSH is available and cheap; adopt it where the stack supports it
- Signatures are less urgent. A signature verified today cannot be retroactively forged by a future
  machine - but long-lived roots of trust (code signing, firmware, CA roots) do need a plan
- Do not hand-roll a hybrid construction. Use what your TLS or SSH implementation ships

NIST IR 8547, "Transition to Post-Quantum Cryptography Standards", is an Initial Public Draft
published 2024-11-12. The comment window closed 2025-01-10 and a compiled comment set was posted
per a planning note dated 2025-01-21. As of this check there is no final version.

Deliberately not stated here: the per-algorithm deprecation and disallowed years for RSA, ECDSA,
ECDH, and DH. They are in the IR 8547 PDF, not on the landing page, and they drive procurement
decisions - read the document rather than trusting a recalled year.

## Symmetric encryption modes

NIST SP 800-38D, "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and
GMAC", November 2007, Morris Dworkin. NIST has stated it intends to revise this publication.

Not verified from the source: the exact invocation limit per key and the recommended IV length.
Those live in the PDF body, which is not extractable from the landing page.

What you can rely on without the document, because it is arithmetic rather than policy:

- A 96-bit nonce chosen at random collides by the birthday bound. At 2^32 messages under one key,
  collision probability is on the order of 2^-33; at 2^48 messages it is near certainty. Rotate the
  key long before you approach either
- A single nonce reused under one GCM key leaks the XOR of the two plaintexts and, worse, allows
  recovery of the authentication subkey - which lets an attacker forge messages, not just read them.
  There is no partial failure here
- A 64-bit random nonce is not enough for a high-volume key. If your library offers XChaCha20 with a
  192-bit nonce, random nonces stop being a counting problem

Practical rule: either a counter you can prove is never reused across processes and restarts, or a
random nonce with a key rotated on message count. Do not mix the two.

## Key management

NIST SP 800-57 Part 1 Revision 5, "Recommendation for Key Management: Part 1 - General", May 2020
(draft 2019-10-08, final posted 2020-05-04). Supersedes Revision 4 of 2016-01-28.

The publication defines originator-usage period and recipient-usage period, and specifies the
protection each type of key requires.

Not verified from the source: the cryptoperiod tables - the recommended maximum usage periods for
symmetric data encryption keys, private signature keys, and the rest. They appear in the PDF, not
on the landing page. Do not quote a number of years as "NIST says" without opening the document.

What to use in the meantime: rotate on a trigger you can define and observe.

| Trigger | Action |
|---|---|
| Suspected or confirmed exposure | Rotate immediately, then re-encrypt |
| Person with access leaves | Rotate |
| Message or byte count nears the nonce bound | Rotate |
| Fixed calendar interval | Rotate, so the mechanism is proven to work |
| Algorithm deprecated | Rotate to the new algorithm, keep old key for decrypt only |

The calendar rotation is not there because keys wear out. It is there so that when you need an
emergency rotation you already know the procedure works.

## Algorithm status, short form

| Algorithm | Status for new work |
|---|---|
| AES-128, AES-256 (GCM, CCM) | Use |
| ChaCha20-Poly1305 | Use |
| SHA-256, SHA-384, SHA-512, SHA-3 | Use |
| HMAC-SHA-256 | Use |
| Ed25519, ECDSA P-256/P-384 | Use |
| RSA-PSS, RSA-OAEP, 2048-bit minimum | Use; prefer 3072-bit for long-lived keys |
| RSA PKCS#1 v1.5 encryption | Avoid - padding-oracle prone |
| 3DES, RC4, Blowfish | Do not use |
| MD5, SHA-1 | Do not use for signatures or integrity |
| AES-ECB | Never. Identical plaintext blocks produce identical ciphertext |
| DSA | Removed from OpenSSH 10.0; treat as dead |

## Sources

- FIPS 203 - <https://csrc.nist.gov/pubs/fips/203/final> (checked 2026-07-28)
- FIPS 204 - <https://csrc.nist.gov/pubs/fips/204/final> (checked 2026-07-28)
- FIPS 205 - <https://csrc.nist.gov/pubs/fips/205/final> (checked 2026-07-28)
- NIST IR 8547 (ipd) - <https://csrc.nist.gov/pubs/ir/8547/ipd> (checked 2026-07-28)
- NIST SP 800-38D - <https://csrc.nist.gov/pubs/sp/800/38/d/final> (checked 2026-07-28)
- NIST SP 800-57 Part 1 Rev. 5 - <https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final> (checked
  2026-07-28)
