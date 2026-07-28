# Troubleshooting

What to do when the guidance does not resolve cleanly.

## Two standards disagree

Prefer the more security-focused option unless a project requirement explicitly says
otherwise. State that you made the call and why.

When ASVS and the Top 10 seem to conflict, they usually are not. The Top 10 is a risk
ranking, ASVS is a requirement set. Implement the ASVS requirement and use the Top 10
category for reporting.

## The secure fix breaks existing behaviour

Do not quietly weaken the control. Report the conflict:

1. What the current behaviour is
2. What the secure version changes
3. Who or what breaks
4. The migration path

Then ask. A breaking change to auth is not a minor choice you make alone.

## The framework already handles it, allegedly

Verify before relying on it. Check the version, the configuration, and whether the
protection is on by default or opt-in. Template auto-escaping, CSRF middleware, and ORM
parameterization are all commonly present and commonly disabled.

If you cannot confirm it from the code or the pinned version's documentation, say so
instead of assuming.

## You cannot tell whether a finding is exploitable

Report it with the uncertainty attached. State the precondition you could not verify.

"SQL injection in `get_report`, exploitable if `sort` reaches the query unvalidated — I
could not find the caller, so the input source is unconfirmed" is useful. "Critical SQL
injection" without checking is noise, and noise gets checklists ignored.

## The codebase is inconsistently secure

Match the more secure pattern, not the more common one. Note the inconsistency, but do not
expand the change into a cleanup sweep unless asked. Fix the file you are in.

## No test framework exists and you need to prove the fix

Set up the standard choice for the language, write the regression test, and say what you
added. If the environment blocks it — missing dependencies, no network — state that plainly
rather than claiming the fix is verified.

## A checklist item genuinely does not apply

Write the reason. "No crypto section: this change touches only CSS" is a complete answer.
An unexplained skip is indistinguishable from an oversight.

## The standard has moved on

The Top 10 2025 and ASVS 5.0.0 references here were verified on 2026-07-28. If a project
depends on precise category IDs or requirement numbers, re-check the source before
quoting. See [references/](references/) for the URLs.

Never assume undocumented behaviour, including in a standard. Fetch it.
