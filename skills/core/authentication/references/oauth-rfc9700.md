# RFC 9700 - OAuth 2.0 Security Best Current Practice

Also published as BCP 240. Authors T. Lodderstedt, J. Bradley, A. Labunets, D. Fett.
Published January 2025. This is the document to cite for grant selection, PKCE, redirect
URI handling, and refresh token handling - not RFC 6749, which predates every attack it
does not defend against.

Source: <https://www.rfc-editor.org/rfc/rfc9700.html>
Verified: 2026-07-28

## Grants

| Grant | Status in RFC 9700 |
|---|---|
| Authorization code + PKCE | the default for everything |
| Implicit (`response_type=token`) | SHOULD NOT be used |
| Resource owner password credentials | MUST NOT be used |
| Client credentials | fine, machine-to-machine only |

Implicit, Section 2.1.2. The objection is that returning an access token from the
authorization endpoint puts it in a URL, where it leaks through history, referrers, and
logs, and there is no standard way to sender-constrain a token issued that way. Use
`response_type=code` so tokens arrive in the token response, where the server can detect
replay.

Resource owner password credentials, Section 2.4. Prohibited outright. It hands user
credentials to the client, trains users to type their password into non-IdP surfaces, and
cannot accommodate MFA, step-up, or origin-bound credentials like WebAuthn.

## PKCE

Sections 2.1.1, 4.5.3.1, 4.8.2.

- Public clients MUST use PKCE.
- Confidential clients: RECOMMENDED. An OIDC confidential client may rely on `nonce`
  instead, with the extra precautions in 4.5.3.2.
- Authorization servers MUST support PKCE, and MUST require `code_verifier` at the token
  endpoint whenever the authorization request carried a valid `code_challenge`.
- Servers MUST prevent PKCE downgrade: accept `code_verifier` only if `code_challenge` was
  present on the authorization request.
- `code_challenge` values must be transaction-specific and bound to the client and the user
  agent that started the flow.
- `S256` is the only challenge method that currently qualifies, because `plain` leaks the
  verifier in the request.
- Publishing `code_challenge_methods_supported` in Authorization Server Metadata (RFC 8414)
  is recommended so clients can discover support.

## Redirect URIs

Sections 2.1 and 4.1.3. Authorization servers MUST use exact string matching against
pre-registered redirect URIs, judged by Simple String Comparison (RFC 3986 Section 6.2.1).

One carve-out: variable port numbers for `localhost` redirect URIs belonging to native apps.

The case against patterns is empirical, not theoretical - wildcard matching has produced
real attacks, including via subdomain takeover in deployments that parsed the wildcard
correctly. Related requirements: hosts serving redirect URIs must not run open redirectors,
and servers may append `#_` to the `Location` header to stop browsers reattaching fragments.

A narrow exception exists where the origin and integrity of the authorization request can be
verified, for example RFC 9101 (JAR) or RFC 9126 (PAR) plus client authentication.

## Refresh tokens

Section 4.14. For public clients, authorization servers MUST use one of two defences against
refresh token replay:

1. Sender-constraining - bind the token to a client instance cryptographically, via mutual
   TLS (RFC 8705) or DPoP (RFC 9449).
2. Rotation - issue a new refresh token with every refresh response, invalidate the old one,
   and keep a record linking them.

Rotation gives you detection: if a token is stolen and both the attacker and the legitimate
client use it, one of them presents an invalidated token. The server cannot tell which party
is which, so it revokes the whole active grant. The attack stops; the honest client has to
re-authorize. That trade-off is the intended behaviour, not a bug in the design.

Also in 4.14:

- Refresh tokens MUST be bound to the scope and resource servers the resource owner consented to.
- They SHOULD expire after a period of client inactivity.
- Servers may revoke automatically on events such as password change or logout.
- If the grant is encoded into the token value itself for lookup efficiency, the server MUST
  protect that value's integrity, for example with a signature.

## Related specifications

| RFC | What it is |
|---|---|
| RFC 6749 | OAuth 2.0 core. Read through the lens of 9700, not on its own |
| RFC 7636 | PKCE |
| RFC 8414 | Authorization Server Metadata |
| RFC 8705 | mutual TLS client authentication and certificate-bound tokens |
| RFC 9101 | JWT-Secured Authorization Request (JAR) |
| RFC 9126 | Pushed Authorization Requests (PAR) |
| RFC 9449 | DPoP |

## Scope limit

RFC 9700 is about the OAuth protocol. It does not tell you how to store a password, when to
rotate a session cookie, or which authorization model to use. Do not cite it for those.
