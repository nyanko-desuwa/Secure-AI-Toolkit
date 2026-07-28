# Troubleshooting

What to do when the guidance in this skill cannot be applied as written.

## The framework's session handling is opaque

Do not assume rotation happens. Check the version's documentation and then check the wire.
Log in with a captured pre-login cookie value and see whether the post-login response carries
a `Set-Cookie` with a different value. If it does not, the framework is not rotating and
session fixation is live regardless of what the docs claim.

Known shapes: Express `express-session` does not regenerate on its own — you call
`req.session.regenerate()`. Django's `login()` does cycle the key. PHP needs an explicit
`session_regenerate_id(true)`. Spring Security rotates by default but the behaviour is
configurable and sometimes disabled to keep a legacy integration working.

If you cannot confirm it from code or pinned documentation, report it as unverified rather
than as safe.

## Argon2id is not available in the runtime

Use bcrypt with a cost of at least 10, and enforce a maximum password length at or under
72 bytes so silent truncation cannot happen. State the substitution in the code comment and
in your report. Do not reach for PBKDF2 unless FIPS-140 validation is the actual constraint,
and if it is, use HMAC-SHA-256 with 600,000 iterations.

Do not compensate with a general-purpose hash and a bigger salt. Salt addresses precomputation,
not GPU throughput. See [references/password-storage.md](references/password-storage.md).

## The password policy conflicts with an internal standard

NIST SP 800-63B-4 Section 3.1.1.2 prohibits composition rules and periodic rotation. Many
internal policies still require both, usually because an old audit template says so.

Report the conflict rather than picking a side silently: name the requirement, name the
internal rule, and say what each buys. If the internal policy wins, implement it — but do not
also lower the length floor, because that is where the actual strength lives. A 15-character
minimum with no composition rule is stronger than 8 characters with four character classes.

## You cannot invalidate a JWT that is already issued

You cannot. Say so. There are three honest options, and the choice is a product decision:

1. Short access token lifetime plus a refresh token you can revoke. Logout takes effect
   within the access token's remaining life. Name the window in the report.
2. A server-side check on every request — a revocation list, or a `tokens_valid_after`
   timestamp on the user row. Correct and immediate, and it gives up statelessness, which was
   the reason for choosing JWT.
3. Server-side sessions instead. Often the right answer once someone writes down what
   immediate logout is worth.

Do not present option 1 as immediate revocation. It is a bounded delay.

## Uniform login errors break the product requirement

Product wants "this email is not registered" for conversion. That is a user enumeration
oracle (CWE-204).

The workable compromise: keep the login endpoint uniform, and move the enumeration risk to a
flow you can rate limit and monitor separately — registration tells the user the address is
taken only after an email round-trip, not in the form response. If the business accepts
enumeration knowingly, record the decision and the compensating controls (throttling,
alerting on enumeration patterns). An accepted risk documented is different from a bug.

## Rate limiting locks out real users

Per-account lockout is a denial-of-service lever: an attacker locks a known account on
purpose. NIST 3.2.2 flags this directly.

Prefer graduated friction over hard lockout — increasing delay, then a CAPTCHA, then a
verified email step. Reserve hard lockout for a very high failure count and make the recovery
path self-service. Never lock out based on IP alone; NAT and mobile carriers put thousands of
users behind one address.

## The OAuth provider does not support PKCE

Public clients must have it (RFC 9700 Section 2.1.1). If the provider genuinely lacks it:

- Never fall back to the implicit grant. That is trading one gap for a worse one.
- If the client can hold a secret — a server-side backend for frontend — use the code flow
  with client authentication and a strictly validated `state`, and keep tokens server-side.
- Log the provider limitation as an accepted risk with an owner, and check for support again
  at the next dependency review.

A browser-only public client against a provider with no PKCE has no safe configuration. Say
that plainly instead of building something that looks compliant.

## Existing password hashes use the wrong algorithm

Do not rehash the stored hashes — you cannot recover the passwords, and wrapping a weak hash
in a strong one leaves the weak hash's collision and shucking properties in place.

Migrate on next login: verify against the old scheme, and on success rehash the plaintext you
now have with Argon2id and replace the record. Track the fraction migrated. For accounts that
never come back, force a reset after a deadline rather than leaving SHA-1 hashes forever.

## The authorization model is already unauditable

Symptoms: nobody can answer "who can read this document" without running the code, and
policy lives in three places.

Do not rewrite it in one pass. Instead: write the read-only query first — a function that,
given a subject and a resource, returns the decision and the rule that produced it. That
makes the current behaviour observable. Migrate call sites to it, then consolidate the rules
behind it. An unobservable policy layer cannot be safely refactored.

## Two standards disagree

ASVS is a requirement set, the Top 10 is a risk ranking, NIST 800-63B is US federal guidance
for credential service providers, and RFC 9700 is protocol-level. They rarely conflict
because they operate at different levels. When they seem to:

- Implement the more specific requirement.
- Use the Top 10 category for reporting.
- Do not stretch a citation outside its scope. 800-63B says nothing about cookie attributes;
  RFC 9700 says nothing about password storage.

## A checklist item does not apply

Write the reason. "No OAuth section: this service issues its own sessions and integrates no
external provider" is a complete answer. An unexplained skip reads the same as an oversight.
