# HTTP, URI, and TLS References

> Sources checked 2026-07-29.

- RFC 9110 defines HTTP semantics, including redirect status behavior. Client policy must decide
  whether a redirect is permitted and whether credentials can cross the resulting origin.
- RFC 3986 defines URI generic syntax. String matching is not equivalent to parsed authority,
  scheme, port, userinfo, and host policy.
- RFC 9325 gives current TLS recommendations. Application clients should preserve certificate and
  hostname verification rather than bypass errors.

Sources:

- <https://www.rfc-editor.org/rfc/rfc9110>
- <https://www.rfc-editor.org/rfc/rfc3986>
- <https://www.rfc-editor.org/rfc/rfc9325>
