# Common Mistakes

What goes wrong during an incident, why it goes wrong, and what to do instead. These are
pressure failures, not knowledge failures. Everyone here knew better on a calm day.

## Rebooting the host

The alert says something is running on `web-03`. Somebody reboots it. The process is gone, the
alert clears, and so does every answer.

Memory held the injected code, the decrypted credentials, the open sockets, and the parent
process that started it. None of that is on disk. After a reboot you can say the host looked
strange and nothing else, which means you cannot answer whether the same thing is on the other
eleven hosts.

Do instead: isolate at the network layer and leave the host running. Capture memory, socket
state, and the process list before anything resets, in that order (`RS.AN-07`, RFC 3227
volatility order). Reboot is a recovery action, not a containment action.

```bash
# Wrong
sudo reboot

# Right: access removed, state intact
aws ec2 modify-instance-attribute --instance-id i-EXAMPLE0123 --groups sg-QUARANTINE
# then run the collector from best-practices.md, then decide about the host
```

The same mistake wears other clothes: `kubectl delete pod`, `terminate-instances`, `docker rm`,
"just reimage it". Each one is a reboot with better branding.

When preservation and containment genuinely conflict — the workload is deleting or encrypting
data right now — containment wins. Say so in the decision log, with who decided. The failure is
not choosing containment; it is choosing it by reflex and not recording that a choice was made.

## Containing before you know the scope

One credential looks compromised, so it gets revoked in the first five minutes. It felt like
progress. Two things follow.

The attacker learns they were seen and moves to the access you have not found yet — the second
API key, the CI token, the added SSH key. And your only view of what they were doing was through
that credential's activity, which just stopped generating evidence.

Do instead: capture the audit trail for the identity first, enumerate what else it touched or
could mint, then revoke everything in one motion. Partial revocation is worse than none, because
it costs you surprise without costing them access.

```bash
# Wrong: revoke, then start looking
gh api -X DELETE /applications/CLIENT_ID_EXAMPLE/grant -f access_token=ghp_EXAMPLE

# Right: export the trail, list every derived credential, then revoke together
gh api /orgs/example-org/audit-log --paginate -f phrase='actor:contractor-example' > audit.json
gh api /users/contractor-example/keys
# ...enumerate sessions, PATs, deploy keys, OAuth grants, then revoke in one pass
```

`RS.MI-01` (contain) and `RS.MI-02` (eradicate) are separate outcomes for this reason. A
five-minute revocation that leaves three other doors open is not containment; it is a warning
shot.

Time-boxing helps: give scoping a written deadline, and revoke at the deadline whether or not
scoping is complete. Delaying containment indefinitely to keep watching is its own mistake, and
r3 is explicit that intentional delay needs legal input because the attacker can escalate while
you observe.

## Revoking the session and calling the credential dead

The password is rotated. The console shows the user as secure. The attacker is still in.

Everything derived from that credential survives a password change on at least one major
platform: refresh tokens, personal access tokens, API keys, app passwords, device trust
cookies, SSH keys, and third-party OAuth grants. Refresh tokens are the usual culprit, because
they are designed to outlive the session.

```sql
-- Wrong: the session dies, the refresh token mints a new one on the next request
DELETE FROM sessions WHERE user_id = $1;
```

```sql
-- Right: every derived artefact, in one transaction, with a reason
BEGIN;
UPDATE sessions       SET revoked_at = now(), revoked_reason = 'INC-2026-014'
 WHERE user_id = $1 AND revoked_at IS NULL;
UPDATE refresh_tokens SET revoked_at = now(), revoked_reason = 'INC-2026-014'
 WHERE user_id = $1 AND revoked_at IS NULL;
UPDATE api_keys       SET disabled_at = now(), disabled_reason = 'INC-2026-014'
 WHERE owner_id = $1 AND disabled_at IS NULL;
COMMIT;
```

Then verify by using the credential, not by reading the console. A UI that says "revoked" is a
claim about intent; a `401` is a fact.

```bash
curl -sS -o /dev/null -w '%{http_code}\n' -H 'Authorization: Bearer ghp_EXAMPLE' \
  https://api.example.com/user     # expect 401
```

Related: CWE-613 (insufficient session expiration), A07:2025, ASVS V7 and V10. Rotation
mechanics live in `skills/core/secrets-management/`.

## Not checking what the attacker changed while inside

Access is revoked, key rotated, incident feels closed. Three weeks later the same account is
compromised again, and nobody understands how.

While they held the account, they had the account's own settings. The usual changes, and each
one survives rotation:

| Change | Why rotation does not fix it |
|---|---|
| Email or phone changed | Password resets go to them |
| MFA factor enrolled | Their factor satisfies your MFA |
| Recovery codes regenerated | They hold a valid bypass |
| API key or PAT created | A new credential you never knew existed |
| OAuth grant authorized | A third-party app with standing access |
| Mail forwarding rule added | Reset mails keep arriving after rotation |
| Webhook target changed | Payloads keep flowing to them |
| SSH or deploy key added | Direct access with no password involved |
| Member invited, role granted | A second identity entirely |

Do instead: enumerate account-level changes across the whole exposure window, one by one, and
diff against a known-good baseline where you have one. Query shape is in
[best-practices.md](best-practices.md#credential-compromise-end-to-end).

Mail forwarding rules are the one most often missed, because nothing about the account looks
wrong afterwards.

## Treating a removal commit as fixing a leaked secret

A key gets committed. Someone pushes a commit deleting the line, or force-pushes over it, and
the ticket closes.

The blob is still in history, in every clone anybody made, in every fork, and in provider-side
cached views of the commit. If the repository was ever public, assume it was scraped: automated
collection of committed credentials is continuous, not opportunistic.

Rotation is the fix. History rewriting is optional cleanup afterwards, and it does not retract
anything already cloned.

```bash
# Wrong: this is not remediation
git commit -am "remove key"

# Right: find the true exposure start, rotate, then confirm reachability
git log --all --format='%H %cI %an' -S 'AKIAEXAMPLE'    # earliest commit = exposure start
git log --all --full-history -p -S 'AKIAEXAMPLE' | head -60
git grep -I 'AKIAEXAMPLE' $(git rev-list --all) | head  # still reachable anywhere?
```

The exposure window runs from the first commit containing the secret to the moment rotation
completed — not to the removal commit. Scope the blast radius over that whole window.

## Trusting logs the attacker could write

The timeline is built, it is clean, and the compromised identity had `logs:*` and delete rights
on the bucket the trail wrote to.

If the attacker could write or delete log records, the logs are evidence of nothing. Absence of
an entry means nothing, and presence of one means nothing either. Every conclusion built on that
trail inherits the doubt, and finding out after the report has gone to leadership is worse than
finding out first.

Do instead: check trail integrity before quoting the trail. Was logging stopped, was the trail
deleted or reconfigured, do the file digests validate, are there gaps or zero-length files with
suspicious mtimes.

```bash
aws cloudtrail get-trail-status --name org-trail
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging
journalctl --verify
```

Then state one of three things in the report: out of reach of the compromised identity,
reachable and therefore uncorroborated, or undetermined. Structural fix — separate account,
append-only, retention hold, separate shipper credential — is in `skills/core/logging-audit/`.

## Notifying before you know the scope

Pressure to say something early produces a statement with a number in it. "Approximately 400
accounts affected." Two days later it is 40,000, and the second statement is the story.

Under-stating gets corrected in public. Over-stating triggers obligations and customer action
you cannot walk back. Both come from the same cause: publishing a figure derived from the first
hour of an investigation.

Do instead: publish the shape, not the number. Say what is confirmed, say what is not yet
established, and give the next update time. Distinguish "no evidence of access" from "not
observable" — if data-event logging was never enabled, you have no evidence in either direction,
and saying "no evidence" is the sentence that gets quoted back at you.

Statutory notification deadlines vary by jurisdiction, sector, and contract. This skill does not
list them and does not give legal advice. Bring legal in at declaration when personal data is
plausibly in scope and let them own the clock. Note that contractual and insurance notification
windows are frequently tighter than statutory ones, and are missed for exactly that reason.

## No writeback into detection

The incident closes with a document. Nine months later the same intrusion path runs again and is
found the same way — by accident.

An after-action finding that does not become a test, a detection rule, or an owned tracked item
did not happen. "We should improve monitoring" is not a finding; it is a feeling with a verb.

Do instead: for every step of the attack that nobody saw, name the missing event and add it at
the source with actor, action, target, outcome, timestamp (CWE-778, A09:2025, ASVS V16). Then
add the rule that fires on it, and give the rule a documented action. For every exploited flaw,
merge a regression test that fails on the old code.

```yaml
# Right: gap closed as a rule with an owner and a first action
- alert: DeployKeyAddedOutsideChangeWindow
  expr: increase(vcs_deploy_key_added_total[5m]) > 0
  labels: { severity: sev3, owner: platform-team, runbook: ops/runbooks/vcs-persistence.md }
  annotations:
    action: "Confirm with the named actor out of band. Capture repo audit log before removing."
```

Any secret found in a log during the investigation is a second incident: rotate, then remediate
the log line (CWE-532).

## Swallowing the exception in the alerting path

The detection was written, tested, and merged. It never fired, because the code that sends it
cannot fail loudly.

```python
# Wrong: the detection is now decorative
def send_alert(event):
    try:
        siem.emit(event)
    except Exception:
        pass
```

A network blip, an expired SIEM token, a schema change — any of them turns detection off
permanently and silently. This is A10:2025 and A09:2025 in the same four lines, CWE-390
(detection of error condition without action).

```python
# Right: buffer locally, surface the failure, and monitor the failure counter
def send_alert(event):
    try:
        siem.emit(event)
    except SiemUnavailable:
        ALERT_DELIVERY_FAILURES.inc()          # this counter has its own alert
        spool.append(event)                    # bounded on-disk spool, replayed on recovery
        log.error("siem_emit_failed event_type=%s incident_relevant=true", event["type"])
        raise                                  # let the caller decide, do not pretend success
```

Then alert on the failure counter and on the absence of expected events. A pipeline nobody
monitors is indistinguishable from a pipeline that works.

## Runbooks that assume access the on-call does not have

3am. The runbook says "revoke the production credential". The on-call engineer has read-only
production access, the person who can revoke is asleep with a silenced phone, and the runbook
does not say who else can.

Every step needs three things: who can do it, what to do when that person is unreachable, and
how long to wait before escalating. A step without a named role and a timeout is a step that
stalls.

```markdown
# Wrong
- [ ] Revoke the compromised credential
- [ ] Notify customers if needed

# Right
- [ ] Revoke the compromised credential
      Owner:    on-call SRE (has `SecurityBreakGlass` role — verified in last quarterly drill)
      Deputy:   security lead, then platform manager
      Timeout:  15 min unreachable -> use break-glass, log the use in the working record
- [ ] Customer notification decision
      Owner:    VP Engineering, with legal
      Deputy:   CTO
      Timeout:  60 min unreachable -> escalate to CEO. Nobody else may publish.
```

Verify the access in a drill, not in the document. A runbook step that has never been executed
by the role named in it is an assumption. Rehearsing the break-glass path is also how you find
out it expired.

## Sources

- <https://doi.org/10.6028/NIST.SP.800-61r3>
- <https://www.rfc-editor.org/rfc/rfc3227.html>
- <https://owasp.org/Top10/2025/>
- <https://cwe.mitre.org/data/definitions/613.html> · <https://cwe.mitre.org/data/definitions/778.html> · <https://cwe.mitre.org/data/definitions/390.html> · <https://cwe.mitre.org/data/definitions/532.html>
