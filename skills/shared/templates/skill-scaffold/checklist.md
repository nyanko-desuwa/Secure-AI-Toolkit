# <Skill Name> Verification Checklist

Run before returning code. Mark each item pass, fail, or not applicable. "Not applicable"
needs a one-line reason - an unexplained skip is indistinguishable from an oversight.

Only the sections matching the change need running.

## Tiers

Every check carries a tier, written as a leading tag: `[critical]`, `[recommended]`, or
`[optional]`. Under a tight context budget the router loads critical checks first.

- `[critical]` - skipping it leaves an exploitable vulnerability or a broken security
  control (access control, injection, secrets, crypto correctness, authentication).
- `[recommended]` - defense-in-depth or hardening most applications should have; its
  absence is a weakness, not usually a direct exploit.
- `[optional]` - context-dependent or a refinement; apply when the situation calls for it.

## <Category> (<standard ID> · <ASVS chapter>)

- [ ] [critical] <A check that can be answered by reading the code. Not "is it secure"?>
- [ ] [recommended] <...>

## <Category> (<standard ID> · <ASVS chapter>)

- [ ] [optional] <...>

## Before Returning

- [ ] [critical] Build or compile step run
- [ ] [critical] Relevant tests run, with output reported honestly
- [ ] [recommended] Temporary files removed
- [ ] [critical] Documentation updated: skill `README.md`, root `README.md` status table, `CHANGELOG.md`
- [ ] [critical] Anything unverifiable stated plainly, not implied to be fine

## Writing checklist items

An item earns its place if a reviewer can answer it by looking. Compare:

- Bad: "Authorization is handled correctly"
- Good: "Every object read, write, and delete is scoped to the acting user server-side"

The first invites a checkmark. The second requires opening the file.

Every item needs a tier tag. If everything looks critical, the tiers are not being used -
reserve `[critical]` for checks whose failure is a real vulnerability.
