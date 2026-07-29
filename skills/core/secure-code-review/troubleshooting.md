# Troubleshooting

What to do when a review will not resolve cleanly. Every entry ends with something you can
write in the report, because "unresolved" is a valid outcome and silence is not.

## You cannot find the caller

Grep found the sink. Nothing calls the function, or a hundred things do through a dispatcher,
a decorator, or dependency injection.

Try, in order: the route table or URL config, the DI container registration, the string name
of the function (frameworks call by name), and the test files. Tests are the fastest way to
learn how a function is meant to be reached.

If the source stays unconfirmed, report it with the gap named:

```text
SQL injection in reports.build_query:88 - `sort` is interpolated. I could not find a
caller; the only reference is a registry keyed by string. Exploitable if any route passes
a client-controlled value. Unconfirmed source.
```

That is useful to the author, who knows the answer in ten seconds. "Critical SQL injection"
without the caveat is not, and it is what gets review reports ignored.

## The framework might already stop it

You cannot tell whether the ORM parameterizes, whether auto-escaping is on, or whether the
CSRF middleware is registered.

Check three things and cite what you checked: the pinned version in the lockfile, the
configuration in the app factory or settings module, and whether the protection is on by
default in that version. If two of the three are unverifiable, say which.

Never resolve this by reputation. "Django escapes by default" is true and irrelevant if the
template uses `|safe`.

## Two categories both fit

Common with access control. Missing check entirely, wrong check, or a check keyed on a
user-supplied ID all look similar.

Pick by what the code does, not by impact:

| Code state | CWE |
|---|---|
| No authorization decision exists on the path | CWE-862 Missing Authorization |
| A decision exists but is wrong - wrong operator, wrong role, wrong order | CWE-863 Incorrect Authorization |
| The decision uses an identifier the client supplied | CWE-639 Authorization Bypass Through User-Controlled Key |
| Access control is structurally absent across the component | CWE-284 Improper Access Control |

If it still will not resolve, use the more specific CWE and name the parent in one clause.
See [references/cwe-top25.md](references/cwe-top25.md#picking-the-right-cwe).

## The severity depends on deployment

An SSRF is critical on a cloud instance with an IMDSv1 metadata endpoint and medium in a
container with no credentials to steal.

State the assumption in the finding, rate against it, and give the alternative rating:

```text
Severity  High, assuming internet-facing and running on a cloud instance with an
          instance-role credential. Medium if this service has no metadata endpoint
          reachable - I could not verify the runtime environment from the code.
```

Two ratings with the pivot named beats one confident wrong number.

## The fix breaks a documented contract

The secure change returns 404 where the API docs promise 403, or rejects input that a client
currently sends.

Do not weaken the control quietly. Report the four parts: current behaviour, secure
behaviour, what breaks, migration path. Then hand the decision to whoever owns the contract.
A breaking auth change is not a reviewer's call to make alone.

If the contract wins, record the accepted risk in the report rather than deleting the
finding. A finding closed as "accepted" is different from one that was never there.

## The vulnerability is in a dependency

You cannot patch it. Check whether your code reaches the vulnerable path at all - most
advisories affect a function nobody in the project calls.

Report reachability separately from presence: "advisory affects `parse_options`; this repo
calls only `load`, so the path is unreachable in the pinned version" is a different finding
from "we ship the vulnerable version and call it from the upload handler". Upgrade either
way, but the severity is not the advisory's severity.

## The code is generated and the author cannot explain it

Nobody knows why the check is there, so nobody can tell you whether removing it is safe.

Treat unexplainable code as untrusted. Verify the control does what it appears to: check
that the library method exists in the pinned version, that the config key is spelled the way
the library reads it, and that the branch is reachable. Silent no-ops are the characteristic
failure here. See [best-practices.md](best-practices.md#reviewing-ai-generated-code).

## You have twenty findings and no time

Rank by exploitability first, then blast radius, and report the top five properly. Five
findings with exploitation paths get fixed. Twenty one-line assertions get triaged into a
backlog and forgotten.

Say what you did not finish: "reviewed the API layer; did not review the admin console or
the background workers."

## You cannot run the code

No environment, no credentials, no test data. This is the normal case.

Static review is legitimate. The rule is to mark every claim you could not execute. "The
regex is quadratic on input matching `^(a+)+$`" is a static claim you can defend from the
pattern. "This times out at 10,000 characters" is a runtime claim, and you have not run it.

## No test framework exists and you need to prove the fix

Set up the standard choice for the language, write the regression test, and say what you
added. If the environment blocks it - missing dependencies, no network - state that plainly
rather than calling the fix verified. An unproven fix is a proposal.

## A checklist item does not apply

Write the reason. "No crypto section: this diff touches only template files" is complete. An
unexplained skip reads exactly like an oversight.

## The standard may have moved

The Top 10 2025, ASVS 5.0.0, CWE Top 25 2025, and CVSS 4.0 references here were verified on
2026-07-28. Category IDs move between editions - Injection was A03 in 2021 and is A05 in
2025. If a report depends on a precise ID, re-check the source in
[references/](references/) before quoting it.
