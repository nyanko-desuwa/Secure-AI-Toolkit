> Verified 2026-07-28 against the RFC text at `rfc-editor.org`. Quotations are from the
> published RFCs.
> Sources: <https://www.rfc-editor.org/rfc/rfc8252> · <https://www.rfc-editor.org/rfc/rfc7636>

# OAuth for native apps: RFC 8252 and RFC 7636

Two documents decide the shape of every mobile login. Read them once and most arguments about
WebViews end.

| RFC | Title | Status | Date |
|---|---|---|---|
| 8252 | OAuth 2.0 for Native Apps | BCP 212, updates RFC 6749 | October 2017 |
| 7636 | Proof Key for Code Exchange by OAuth Public Clients | Standards Track | September 2015 |

## RFC 8252: the browser, not a WebView

The abstract states the rule: "OAuth 2.0 authorization requests from native apps should only be
made through external user-agents, primarily the user's browser."

Section 8.12 is the requirement and the reasoning. Native apps "MUST NOT use embedded
user-agents to perform authorization requests", and authorization servers "MAY take steps to
detect and block authorization requests in embedded user-agents".

Why, quoted directly:

- "the app that hosts the embedded user-agent can access the user's full authentication
  credential, not just the OAuth authorization grant that was intended for the app"
- "the host application can record every keystroke entered in the login form to capture
  usernames and passwords, automatically submit forms to bypass user consent, and copy session
  cookies and use them to perform authenticated actions as the user"
- Even for a first-party app, embedded user-agents "violate the principle of least privilege by
  having access to more powerful credentials than they need"
- Without an address bar and certificate indicator, "it is impossible for the user to know if
  they are signing in to the legitimate site"

The last point is the one to raise with a product owner who wants the login inside the app for
branding. The address bar is the anti-phishing control. Removing it also trains the user that
entering credentials without checking the site is normal.

## Redirect URI options, ranked by the RFC

Section 7 gives three. Section 7.2 states the preference: app-claimed `https` scheme redirects
have "the identity of the destination app guaranteed to the authorization server by the
operating system. For this reason, native apps SHOULD use them over the other options where
possible."

| Option | Section | Property |
|---|---|---|
| Claimed `https` URI (Universal Links, Android App Links) | 7.2 | OS guarantees app identity to the server. Preferred |
| Private-use URI scheme | 7.1 | "multiple apps can typically register the same scheme, which makes it indeterminate as to which app will receive the authorization code" |
| Loopback interface | 7.3 | "may be susceptible to interception by other apps accessing the same loopback interface on some operating systems" |

For a private-use scheme, the RFC requires a scheme "based on a domain name under their control,
expressed in reverse order" - `com.example.app`, not `myapp`. A bare `myapp://` scheme does not
meet the requirement and collides with any other app that picked the same word.

## PKCE is not optional here

Section 8.1: PKCE "was created specifically to mitigate this attack" - another app on the device
registering the same scheme and receiving the code. Section 6 "requires that both clients and
servers use PKCE for public native app clients", and authorization servers "SHOULD reject
authorization requests from native apps that don't use PKCE".

Section 8.2 rules out the implicit flow: because it "cannot be protected by PKCE", "the use of
the Implicit Flow with native apps is NOT RECOMMENDED". It also cannot issue refresh tokens
without user interaction, so the authorization code grant is the practical choice as well as the
secure one.

## RFC 7636 parameters

From Section 4.1, the `code_verifier` is a "high-entropy cryptographic random STRING using the
unreserved characters `[A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"` ... with a minimum length
of 43 characters and a maximum length of 128 characters". The RFC recommends generating a
32-octet random sequence and base64url-encoding it, which yields exactly 43 characters.

Section 4.2 defines two transformations:

```text
plain   code_challenge = code_verifier
S256    code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
```

"If the client is capable of using `S256`, it MUST use `S256`, as `S256` is Mandatory To
Implement (MTI) on the server." `plain` is permitted only where S256 is technically impossible
and the server is known out of band to support `plain`. On iOS and Android, SHA-256 is available.
There is no case for `plain`.

Base64url encoding here means no padding and URL-safe alphabet. A `+`, `/`, or `=` in a
`code_challenge` is a bug that shows up as an opaque server-side mismatch.

## What this means in code

| Requirement | iOS | Android |
|---|---|---|
| External user-agent | `ASWebAuthenticationSession` | Chrome Custom Tabs, or a browser intent |
| Claimed https redirect | Universal Links via associated domains | App Links with `android:autoVerify="true"` |
| Verifier randomness | `SecRandomCopyRandomBytes` | `SecureRandom` |
| Challenge | SHA-256, base64url without padding | same |

Note what `ASWebAuthenticationSession` gives you beyond opening a browser: per Apple's
documentation, it "ensures that only the calling app's session receives the authentication
callback, even when more than one app registers the same callback URL scheme". That closes the
Section 7.1 collision on iOS. Android has no equivalent guarantee for custom schemes, which is
why App Links matter more there.

## Do not skip the state parameter

PKCE protects the code. It is not a CSRF defence for the redirect. Keep `state`, bind it to the
session that started the flow, and reject a callback whose `state` you did not issue. The two
parameters solve different problems and are frequently conflated.

## Tokens after the flow

The RFCs stop at the token response. What happens next is ASVS territory:

- ASVS V10 (OAuth and OIDC) for the flow and redirect handling
- ASVS V9 (Self-contained Tokens) if the access token is a JWT
- ASVS V6, V7 for the session the token represents
- MASVS-AUTH-1 for the app's obligation to use the protocol correctly, with enforcement on the
  remote endpoint

A refresh token on a mobile device should rotate on use and be revocable server-side. RFC 8252
does not require rotation; it is in the OAuth security BCP and in ASVS V10. Cite those, not 8252,
for that specific control.
