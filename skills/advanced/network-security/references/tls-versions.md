# TLS and Transport Standards

Standards cited for transport configuration. Every RFC number, title, and date below was
checked against `rfc-editor.org` on 2026-07-28.

## The two documents that decide a TLS config

| Document | Title | Status | Published |
|---|---|---|---|
| RFC 9325 | Recommendations for Secure Use of TLS and DTLS | BCP 195, Best Current Practice | November 2022 |
| RFC 8996 | Deprecating TLS 1.0 and TLS 1.1 | BCP 195, Best Current Practice | March 2021 |

Both are part of BCP 195. RFC 9325 obsoletes RFC 7525, so a config review that cites 7525 is
quoting a superseded document. RFC 9325 also updates RFC 5288 (AES-GCM nonce handling, after
the Böck et al. findings) and RFC 6066 (after the ALPACA attack).

RFC 8996 moves TLS 1.0, TLS 1.1, and DTLS 1.0 to Historic. DTLS 1.2 remains supported; there
is no DTLS 1.1. It also obsoletes RFC 5469 (DES and IDEA suites) and RFC 7507 (the fallback
SCSV, which exists only to protect downgrades to versions now deprecated).

Cite it like this: "TLS 1.1 is deprecated by RFC 8996 (BCP 195, March 2021)." That ends the
argument better than an opinion about cipher strength.

BCP 195 gained a third document in July 2026: RFC 9852, "New Protocols Using TLS Must Require
TLS 1.3", which updates RFC 9325. It applies to new protocol definitions, not to existing
deployments, and to TLS only - the RFC states DTLS 1.3 is not widely available or deployed. So
it does not make TLS 1.2 non-compliant for an existing service. It does mean a protocol you are
designing now has no defensible reason to allow 1.2.

## Protocol versions

| Document | Title | Published |
|---|---|---|
| RFC 8446 | The Transport Layer Security (TLS) Protocol Version 1.3 | August 2018 |

RFC 8446 obsoletes RFC 5077, RFC 5246 (TLS 1.2), and RFC 6961, and updates RFC 5705 and
RFC 6066. Note that "obsoletes RFC 5246" is a document relationship, not a deprecation of
TLS 1.2 as a protocol - RFC 9325 still permits TLS 1.2 with constraints. Do not tell a reader
that TLS 1.2 is deprecated. It is not.

Practical position for a new deployment:

- Prefer TLS 1.3. Its handshake removes renegotiation, static RSA key exchange, and CBC modes
  outright, so a misconfiguration has fewer places to hide.
- Allow TLS 1.2 only where a client requires it, and then restrict to AEAD suites with forward
  secrecy (ECDHE with AES-GCM or ChaCha20-Poly1305).
- Reject TLS 1.0 and 1.1 with no exception process that ends in "temporarily".

## Cipher profiles

Do not hand-assemble a cipher list. Take one of the two Mozilla Server Side TLS profiles and
paste it. Values below are from `ssl-config.mozilla.org/guidelines/5.7.json`, version 5.7,
fetched 2026-07-28. That document carries no date field of its own, only the version number.

| | Modern | Intermediate |
|---|---|---|
| TLS versions | 1.3 only | 1.2 and 1.3 |
| TLS 1.2 cipher list | none - no 1.2 | explicit ECDHE/DHE AEAD list, below |
| TLS 1.3 ciphersuites | `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256` | same three |
| HSTS minimum age | 63072000 | 63072000 |

Intermediate TLS 1.2 list, in Mozilla's order:

```text
ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305
```

Every entry is AEAD with an ephemeral key exchange. There is no CBC suite and no static RSA
key exchange, which is the difference between this list and `HIGH:!aNULL:!MD5`.

Choose Modern only when you know every client speaks TLS 1.3. Otherwise Intermediate. The
TLS 1.3 suite list is negotiated by a separate mechanism (`ssl_conf_command Ciphersuites` in
nginx, `SSLCipherSuite` under `TLSv1.3` in Apache), so a 1.2 cipher string never constrains it.

## Certificate lifetime is shrinking, on a published schedule

CA/Browser Forum ballot SC081v3 passed 2025-04-11 and amends Baseline Requirements section
6.3.2. It reduces the maximum lifetime of a public TLS certificate from 398 days to 47 days in
steps, starting March 2026 and concluding March 2029, and shortens domain validation reuse
alongside it.

| Effective | Max certificate lifetime | Max domain/IP validation reuse |
|---|---|---|
| through 2026-03-14 | 398 days | 398 days |
| 2026-03-15 | 200 days | 200 days |
| 2027-03-15 | 100 days | 100 days |
| 2029-03-15 | 47 days | 10 days |

The endpoints (398 to 47 days, March 2026 to March 2029) and the reuse reduction are stated on
the CA/Browser Forum ballot page. The per-step dates above come from the redline attached to
that ballot as summarised by secondary sources; verify against the current Baseline
Requirements before quoting them in a contract or an audit response.

Two consequences for an engineer, independent of the exact dates:

- Manual renewal stops being viable. At the final stage, validation data expires faster than
  the certificate, so revalidation has to happen more often than issuance. Automate with ACME
  now, not when the deadline moves.
- Expiry becomes the most likely cause of your next transport outage. Monitor the certificate
  the server is actually serving, from outside, with an alert at a multiple of the renewal
  interval - not a calendar reminder and not a check against the file on disk.

## Certificate and channel hardening

| Document | Title | Published |
|---|---|---|
| RFC 6797 | HTTP Strict Transport Security (HSTS) | November 2012 |
| RFC 8659 | DNS Certification Authority Authorization (CAA) Resource Record | November 2019 |

RFC 8659 obsoletes RFC 6844. The lookup algorithm changed: 8659 climbs only the FQDN being
processed and leaves alias handling to the CA's resolver, where 6844 also tree-climbed over
CNAME and DNAME targets. If you are debugging why a CA did or did not find a CAA record, the
version matters.

CAA constrains which CA may issue for your domain. It does not stop a CA that ignores it, and
it does not affect certificates already issued. Treat it as reducing the set of parties who
can mis-issue, not as preventing mis-issuance.

HSTS commits a browser to HTTPS for a domain. Two honest limitations: the first request before
any HSTS header is seen is unprotected unless the domain is preloaded, and `includeSubDomains`
with a long `max-age` is hard to undo - every subdomain, including internal-only ones served
over plain HTTP, must have a valid certificate.

## Encrypted DNS

| Document | Title | Published |
|---|---|---|
| RFC 7858 | Specification for DNS over Transport Layer Security (DNS over TLS) | May 2016 |
| RFC 8484 | DNS Queries over HTTPS (DoH) | October 2018 |

RFC 7858 defines DoT on port 853 and describes opportunistic and out-of-band key-pinned
privacy profiles. RFC 8484 defines DoH over HTTPS.

What they change for a defender: encrypting DNS protects resolution from a network observer
and from on-path tampering. It also removes plaintext DNS as a monitoring point, so if DNS
logs are part of your detection, collect them at the resolver you operate rather than from
the wire. In an environment with egress control, force clients to your resolver and block
outbound 853 and known DoH endpoints, or a client-side resolver setting bypasses your policy.

DoH is also how malware avoids a DNS sinkhole. Encrypted DNS is not a bad thing; unmonitored
egress to arbitrary resolvers is.

## Address space you must not treat as routable input

| Document | Title | Status | Published |
|---|---|---|---|
| RFC 6890 | Special-Purpose IP Address Registries | BCP 153 | April 2013 |
| RFC 8981 | Temporary Address Extensions for SLAAC in IPv6 | Standards Track | February 2021 |

RFC 6890 restructures the IANA IPv4 and IPv6 Special-Purpose Address Registries so each
records every special-purpose block with flags for Source, Destination, Forwardable, Global,
and Reserved-by-Protocol. It obsoletes RFC 4773, RFC 5156, RFC 5735, and RFC 5736. Use the
IANA registries as the source of truth for an SSRF denylist rather than a hand-written list -
hand-written lists miss `100.64.0.0/10`, `::ffff:0:0/96`, and `64:ff9b::/96`.

RFC 8981 obsoletes RFC 4941 and specifies temporary IPv6 addresses. Consequence for network
policy: a host's IPv6 source address changes over time, so IPv6 allowlists keyed on a single
host address break. Filter on prefix, or use identity rather than address.

## ASVS mapping

ASVS 5.0.0 was released 2025-05-30. Cite chapters, not requirement numbers, unless you have
read the requirement text at <https://github.com/OWASP/ASVS>.

| Chapter | Use for |
|---|---|
| V12 Secure Communication | TLS versions, cipher selection, certificate validation, mTLS |
| V13 Configuration | Listener binding, defaults, credential and certificate configuration |
| V2 Validation and Business Logic | Validating a destination host before an outbound request |
| V16 Security Logging and Error Handling | Flow and DNS logging, TLS failure visibility |

## Relevant CWEs

| CWE | Name |
|---|---|
| CWE-319 | Cleartext Transmission of Sensitive Information |
| CWE-295 | Improper Certificate Validation |
| CWE-297 | Improper Validation of Certificate with Host Mismatch |
| CWE-326 | Inadequate Encryption Strength |
| CWE-757 | Selection of Less-Secure Algorithm During Negotiation |
| CWE-918 | Server-Side Request Forgery |
| CWE-1327 | Binding to an Unrestricted IP Address |

## Sources

- RFC 9325 - <https://www.rfc-editor.org/rfc/rfc9325.html>
- RFC 8996 - <https://www.rfc-editor.org/rfc/rfc8996.html>
- RFC 9852 - <https://www.rfc-editor.org/rfc/rfc9852.html>
- BCP 195 membership - <https://www.rfc-editor.org/info/bcp195>
- RFC 8446 - <https://www.rfc-editor.org/rfc/rfc8446.html>
- RFC 6797 - <https://www.rfc-editor.org/rfc/rfc6797.html>
- RFC 8659 - <https://www.rfc-editor.org/rfc/rfc8659.html>
- RFC 7858 - <https://www.rfc-editor.org/rfc/rfc7858.html>
- RFC 8484 - <https://www.rfc-editor.org/rfc/rfc8484.html>
- RFC 6890 - <https://www.rfc-editor.org/rfc/rfc6890.html>
- RFC 8981 - <https://www.rfc-editor.org/rfc/rfc8981.html>
- IANA special-purpose registries - <https://www.iana.org/assignments/iana-ipv4-special-registry/>
- OWASP ASVS - <https://owasp.org/www-project-application-security-verification-standard/>
- CWE - <https://cwe.mitre.org/>

All URLs checked 2026-07-28.
