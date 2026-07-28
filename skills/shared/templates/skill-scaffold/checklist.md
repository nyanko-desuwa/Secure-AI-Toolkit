# <Skill Name> Verification Checklist

Run before returning code. Mark each item pass, fail, or not applicable. "Not applicable"
needs a one-line reason — an unexplained skip is indistinguishable from an oversight.

Only the sections matching the change need running.

## <Category> (<standard ID> · <ASVS chapter>)

- [ ] <A check that can be answered by reading the code. Not "is it secure"?>
- [ ] <...>

## <Category> (<standard ID> · <ASVS chapter>)

- [ ] <...>

## Before Returning

- [ ] Build or compile step run
- [ ] Relevant tests run, with output reported honestly
- [ ] Temporary files removed
- [ ] Documentation updated: skill `README.md`, root `README.md` status table, `CHANGELOG.md`
- [ ] Anything unverifiable stated plainly, not implied to be fine

## Writing checklist items

An item earns its place if a reviewer can answer it by looking. Compare:

- Bad: "Authorization is handled correctly"
- Good: "Every object read, write, and delete is scoped to the acting user server-side"

The first invites a checkmark. The second requires opening the file.
