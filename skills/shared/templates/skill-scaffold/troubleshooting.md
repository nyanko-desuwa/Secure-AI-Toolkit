# Troubleshooting

What to do when the guidance does not resolve cleanly. Every entry should end in an action,
not a caveat.

## Two standards disagree

Prefer the more security-focused option unless a project requirement says otherwise. State
that you made the call and why.

<Add the conflict specific to this skill. Most apparent conflicts are not real: one document
ranks risk, another sets requirements. Say which is which.>

## The secure fix breaks existing behaviour

Do not quietly weaken the control. Report the conflict:

1. What the current behaviour is
2. What the secure version changes
3. Who or what breaks
4. The migration path

Then ask. <Name the change in this domain that is never a solo decision.>

## The framework already handles it, allegedly

Verify before relying on it. Check the version, the configuration, and whether the protection
is on by default or opt-in.

<List the two or three protections in this domain that are commonly present and commonly
disabled.>

If you cannot confirm it from the code or the pinned version's documentation, say so instead
of assuming.

## You cannot tell whether a finding is exploitable

Report it with the uncertainty attached. State the precondition you could not verify.

<Give the shape of a good uncertain report for this domain.> Naming the unverified
precondition is useful; an unqualified severity label is noise, and noise gets checklists
ignored.

## The codebase is inconsistently secure

Match the more secure pattern, not the more common one. Note the inconsistency, but do not
expand the change into a cleanup sweep unless asked. Fix the file you are in.

## <A failure mode specific to this skill>

<The thing that actually stalls work in this domain. Concrete, with the way out.>

## A checklist item genuinely does not apply

Write the reason. An unexplained skip is indistinguishable from an oversight.

## The standard has moved on

The versions cited in [references/](references/) were verified on `<date>`. If a project
depends on precise category IDs or requirement numbers, re-check the source before quoting.

Never assume undocumented behaviour, including in a standard. Fetch it.
