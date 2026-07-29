# Common Mistakes

How security reviews go wrong. Each entry: what it looks like, why it fails, and the fix.
These are mistakes in the review, not in the code under review.

## Reporting a smell as a vulnerability

The report says "SQL injection in `legacy_report`, critical". The function builds a query with
`%` formatting. It is called from one place, with a module-level constant, from a CLI script
that has no HTTP route.

Why it fails: the author checks it, finds no exploitation path, and now discounts the other
nine findings too. One unverified critical costs more credibility than nine real mediums earn.

Fix: move it to an observations list with the reason it is not exploitable. "Unsafe formatting;
only caller passes a constant; delete when convenient" is honest and still useful.

## Grepping for the sink and stopping there

```text
Found 14 uses of `execute(`. All potential SQL injection.
```

Why it fails: `execute(sql, params)` is the safe form. A hit count is not a finding count, and
publishing one teaches the author to skim the review.

Fix: for each hit, read the second argument and the caller. Report only the ones where an
attacker-controlled value is concatenated into the string.

## Reviewing the diff without opening what it calls

The diff adds `return get_document(doc_id)`. Nothing in those characters is wrong, so the
review passes it. `get_document` has no ownership filter.

Why it fails: a diff is a window, not a boundary. The vulnerability is in the interaction
between changed and unchanged code, which is where most real ones live.

Fix: trace one level out from every changed line. Open every function the diff calls, and check
the callers of every function the diff changed. If that is too much, say the review was
diff-only and name the limitation.

## Assuming the framework handles it

"Django escapes output." "The ORM parameterizes." "Spring has CSRF on by default."

Why it fails: all three are true by default and all three are one keyword from off -
`|safe`, `.extra()`, `.raw()`, `csrf().disable()`. Reputation is not verification.

Fix: confirm the version in the lockfile, the setting in the config, and the call site. Where
you cannot confirm, write "unverified" rather than picking a side.

## Trusting a client-side check because it is thorough

A React form validates length, character set, and format, and disables the submit button. The
review notes good validation.

Why it fails: the client is not a trust boundary. The request can be replayed with `curl`, and
the server-side handler behind it accepts anything.

Fix: read client validation as UX. The finding, if any, is on the server handler. When the
server has no equivalent check, the CWE is on the server file and line, not the component.

## Deriving severity from the category name

"SQL injection, therefore critical." The endpoint is admin-only, the parameter is cast to `int`
before it reaches the query, and the DB user is read-only on one table.

Why it fails: severity is exploitability multiplied by blast radius. Neither factor is in the
category name. Inflated severity gets the whole report reprioritised by someone else, badly.

Fix: use the matrix in [SKILL.md](SKILL.md#severity). State the preconditions you assumed and
which of them you verified.

## Rating a chain three times

Path traversal in the upload handler, then the upload directory being inside the web root, then
`.php` in the allowed extensions. Reported as three highs.

Why it fails: it is one remote code execution. Three highs suggest three fixes, and a team may
fix two and consider it progress while the RCE remains.

Fix: report the chain as one finding at the severity of the outcome, and list the links as the
fix steps. Note which single link, if removed, breaks the chain.

## Fixing more than the vulnerability

The fix for a missing ownership filter arrives as a 400-line PR that also renames the model,
extracts a repository layer, and reformats the module.

Why it fails: nobody can review it, so it sits. The vulnerability stays open longer than if the
fix had been three lines. It also cannot be cherry-picked to a release branch.

Fix: one PR for the security change, with the regression test. Open a separate issue for the
refactor. Say why they are separate.

## Writing a regression test that passes before the fix

```python
def test_download_is_safe(client):
    assert client.get("/download", params={"name": "report.pdf"}).status_code == 200
```

Why it fails: it tests the happy path. It passed on the vulnerable code and will pass on any
future regression too, while looking like coverage.

Fix: assert the security property with a malicious input, and run the test against the unfixed
code first. If it does not fail there, it is testing something else.

## Accepting a fix that moves the vulnerability

Traversal fix: `if ".." in name: reject()`. Injection fix: escaping quotes with `replace("'", "''")`.
Access control fix: switching integer IDs to UUIDs.

Why it fails, in order: `..%2f` and symlinks skip the string check; escaping misses backslash
handling, numeric contexts, and identifier positions; UUIDs are obscurity - IDs leak through
exports, logs, and referrer headers, and the object is still readable once you have one.

Fix: resolve then compare against the base directory; parameterize, and allowlist identifiers;
scope the query by actor. In review, name the wrong fix explicitly - the author will otherwise
reach for it again on the next finding.

## Treating a scanner result as a finding

Semgrep, CodeQL, or the dependency bot flags a line. It goes into the report with the tool's
message and severity attached.

Why it fails: scanners do not know reachability, the deployment context, or whether the
vulnerable code path is even compiled in. Forwarding a tool's output is not review.

Fix: triage each one. Confirm the source, confirm reachability, then write the finding in your
own words with your own severity. If you cannot confirm reachability, say the tool flagged it
and that reachability is unconfirmed.

## Reviewing generated code more gently because it reads well

The handler has clear names, a docstring, typed parameters, and a validation schema. The
authorization check is in a `useEffect`.

Why it fails: fluency and correctness are not correlated in generated code. It fails from
plausibility, not haste, and it defeats the reviewer's usual heuristics for "sloppy, look
harder".

Fix: run the four AI failure modes deliberately - auth in the wrong layer, validation without
encoding, fail-open catch, invented API surface. See
[best-practices.md](best-practices.md#reviewing-ai-generated-code).

## Silence as a pass

The review ends without saying what was not reviewed. Two months later the Terraform in the
same PR turns out to have opened a security group.

Why it fails: the author reads no comment as approval of everything in the PR. An unstated
scope is read as full scope.

Fix: state coverage. "Reviewed the Python handlers and the SQL. Did not review the Terraform,
the Dockerfile, or the frontend." Uncomfortable to write, and it is the honest artefact.

## Sources

- <https://owasp.org/www-project-code-review-guide/>
- <https://owasp.org/Top10/2025/>
- <https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html>
