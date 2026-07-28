# Incident Response Best Practices

Patterns for the hours when nobody has time to think. Each one names the outcome it serves
from NIST SP 800-61r3 (subcategory IDs as recorded in
[references/nist-800-61.md](references/nist-800-61.md)), plus the OWASP category and CWE where
the underlying weakness has one.

Commands are illustrative. Placeholders are obvious: `example.com`, `203.0.113.10`,
`123456789012`, `ghp_EXAMPLE`. Substitute your own and read the command before you run it.

## Detection to triage handoff

`DE.AE-02` · `RS.MA-02` · A09:2025 · ASVS V16

The handoff fails when the alert has everything except what a responder needs first: who,
where, when, and can I still see it. Make the alert carry that.

Wrong: an alert that requires a human to go looking before they can even classify it.

```yaml
# Wrong: nothing here is actionable
- alert: SuspiciousLogin
  expr: rate(auth_failures[5m]) > 20
  annotations:
    summary: "Suspicious login activity"
```

```yaml
# Right: the alert carries the pivot points and the first action
- alert: CredentialStuffingSuspected
  expr: |
    sum by (source_ip, tenant) (rate(auth_failures_total[5m])) > 20
    and on (tenant) sum by (tenant) (rate(auth_success_total[5m])) > 0
  for: 2m
  labels:
    severity: sev3
    runbook: ops/runbooks/credential-stuffing.md
  annotations:
    summary: "Failed-auth burst with at least one success, tenant={{ $labels.tenant }}"
    source_ip: "{{ $labels.source_ip }}"
    first_action: "Do not block yet. Extend auth-log retention, then run the scoping query."
    log_query: 'index=auth tenant={{ $labels.tenant }} src={{ $labels.source_ip }} | table _time,actor,outcome,request_id'
```

Why it works: severity, runbook, pivot fields, and the first action are all in the page. The
responder classifies from the alert rather than from a guess. Detection rules for the guessing
side of this belong in `skills/core/brute-force-defense/`; the log fields that make the query
possible belong in `skills/core/logging-audit/`.

Triage decides three things and writes them down: is this an incident (`DE.AE-08`), what
severity, and who leads. Two minutes of writing beats re-deriving it in a thread.

## Capture before you change anything

`RS.AN-06` · `RS.AN-07` · RFC 3227 order of volatility

Volatile state dies in a predictable order: CPU and memory, network state, running processes,
then disk. Containment changes all four. Capture first, then contain — unless the attacker is
actively destroying data, which is the one case where containment wins and you say so in the
decision log.

Wrong, and the single most common irreversible mistake:

```bash
# Wrong: memory, network state, and process list are gone forever
sudo reboot
```

```bash
#!/usr/bin/env bash
# Right: collect off-host, in volatility order, hashing as you go.
# Run as root on the suspect host. Requires an already-mounted evidence path.
set -uo pipefail   # deliberately not -e: a failing collector must not abort the rest

INC="${1:?usage: collect.sh INC-YYYY-NNN}"
OUT="/mnt/evidence/${INC}/$(hostname)"
mkdir -p "$OUT"

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" | tee -a "$OUT/collection.log"; }

log "collector start, operator=${SUDO_USER:-unknown}"

# 1. Memory first. LiME or avml; both write a raw image.
if command -v avml >/dev/null; then
  avml "$OUT/memory.raw" && log "memory captured"
else
  log "MEMORY NOT CAPTURED - no acquisition tool present"   # say it, do not skip silently
fi

# 2. Network state before anything resets a socket.
ss -tupan            > "$OUT/sockets.txt"   2>&1
ip -o addr           > "$OUT/addrs.txt"     2>&1
ip route             > "$OUT/routes.txt"    2>&1
iptables-save        > "$OUT/iptables.txt"  2>&1

# 3. Processes, with the executable path and start time.
ps -eo pid,ppid,user,lstart,etimes,args --sort=lstart > "$OUT/processes.txt" 2>&1
ls -l /proc/*/exe 2>/dev/null                         > "$OUT/proc-exe.txt"

# 4. Login and persistence surface.
last -Fwx           > "$OUT/last.txt"       2>&1
journalctl --since "-14 days" --no-pager > "$OUT/journal.txt" 2>&1
crontab -l -u root  > "$OUT/root-cron.txt" 2>&1
cp -a /etc/passwd /etc/group /etc/sudoers.d "$OUT/" 2>/dev/null
for h in /home/* /root; do
  [ -f "$h/.ssh/authorized_keys" ] && cp -a "$h/.ssh/authorized_keys" "$OUT/authkeys$(echo "$h" | tr / _)"
done

# 5. Hash everything, then hash the manifest.
( cd "$OUT" && find . -type f ! -name manifest.sha256 -exec sha256sum {} + > manifest.sha256 )
sha256sum "$OUT/manifest.sha256" | tee -a "$OUT/collection.log"

log "collector done"
```

Why it works: output lands off-host so the collection does not overwrite unallocated space on
the volume you are investigating, order follows volatility, and the failure to capture memory
is recorded instead of hidden. `set -e` is omitted on purpose — one missing tool must not stop
the rest of the collection.

Cloud and container equivalents, before any restart or delete:

```bash
# EBS volume snapshot before you touch the instance
aws ec2 create-snapshot --volume-id vol-EXAMPLE0123 \
  --description "INC-2026-014 preserve web-03" \
  --tag-specifications 'ResourceType=snapshot,Tags=[{Key=incident,Value=INC-2026-014}]'

# Kubernetes: the pod filesystem and logs die with the pod
kubectl logs pod/api-7d9f-EXAMPLE --all-containers --timestamps > "$OUT/pod-logs.txt"
kubectl logs pod/api-7d9f-EXAMPLE --previous --timestamps       > "$OUT/pod-logs-prev.txt" 2>/dev/null
kubectl get pod api-7d9f-EXAMPLE -o yaml                        > "$OUT/pod-spec.yaml"
kubectl cp api-7d9f-EXAMPLE:/tmp "$OUT/pod-tmp" 2>/dev/null
# only then: kubectl delete pod / cordon the node
```

Extend log retention as a first action, not after you find the gap. Default retention is often
7 to 30 days and intrusions routinely predate it.

```bash
aws logs put-retention-policy --log-group-name /aws/lambda/checkout --retention-in-days 365
```

## Log integrity, before you trust a timeline

`RS.AN-07` · A09:2025 · ASVS V16 · CWE-778 · CWE-117

If the compromised identity had write or delete access to the log store, the logs are evidence
of nothing. Establish that first, because every later conclusion rests on it.

```bash
# Did anyone touch the trail itself? Check before quoting the trail.
aws cloudtrail get-trail-status --name org-trail
aws cloudtrail lookup-events --max-results 50 \
  --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging
aws cloudtrail lookup-events --max-results 50 \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteTrail
# Log-file validation digests, if they were enabled before the incident
aws cloudtrail validate-logs --trail-arn arn:aws:cloudtrail:us-east-1:123456789012:trail/org-trail \
  --start-time 2026-07-01T00:00:00Z
```

```bash
# Local host: gaps and truncation are as informative as entries
journalctl --verify
sudo ls -la --time-style=full-iso /var/log/ | head -40   # a log with mtime after the intrusion, size 0
```

State the answer in the report as one of three things: the trail was append-only and out of
reach of the compromised identity, the trail was reachable and is therefore uncorroborated, or
you could not determine which. Write the third honestly rather than picking the first.

Structural fix afterwards, so the next incident has usable evidence: ship to a store the
production identity cannot write, with object lock or an equivalent retention hold, and a
separate credential for the shipper. Field-level requirements are in
`skills/core/logging-audit/`.

## Contain without erasing

`RS.MI-01` · A10:2025

Prefer containment that removes access and leaves the system observable.

| Prefer | Avoid | Why |
|---|---|---|
| Security-group rule to a deny-all, host left running | Terminate instance | Memory and disk survive |
| `kubectl cordon` plus a deny-all NetworkPolicy | `kubectl delete pod` | Pod filesystem survives |
| Revoke sessions and rotate the key | Delete the user | Audit linkage to past events survives |
| Disable the CI workflow trigger | Delete the repository | History and workflow logs survive |
| Quarantine the image tag | `docker rmi` | Layers stay inspectable |

```yaml
# Kubernetes: isolate a suspect pod, keep it running for inspection
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: quarantine-api-7d9f
  namespace: production
spec:
  podSelector:
    matchLabels: { incident-quarantine: "INC-2026-014" }
  policyTypes: [Ingress, Egress]   # both empty below = deny all, pod stays alive
```

Label the pod, do not delete it. The one exception: if the workload is actively deleting or
encrypting data, stopping it beats preserving it. Record that trade in the decision log with
who made it.

Containment and eradication are separate steps (`RS.MI-01` then `RS.MI-02`). Doing them in one
motion is how root cause disappears.

## Credential compromise, end to end

`RS.MI-01` · `RS.MI-02` · A07:2025 · ASVS V6, V7, V10 · CWE-613 · CWE-522

This is the incident you will actually get. A leaked token, a phished password, a key in a
public repository. The order is: preserve the audit trail, revoke everything derived from the
credential, rotate, then find what the attacker changed while they were inside.

Revoking the password is not revoking access. Every one of these survives a password change on
at least one major platform:

- Active sessions and session cookies
- OAuth refresh tokens
- Personal access tokens and API keys
- App passwords and legacy protocol credentials
- Enrolled MFA factors the attacker added
- Registered devices and trusted-device cookies
- Third-party OAuth grants the attacker authorized
- SSH keys and deploy keys added to the account

```bash
# GitHub-style: audit first, then revoke, then verify
gh api /orgs/example-org/audit-log --paginate \
  -f phrase='actor:contractor-example created:2026-07-20..2026-07-28' > audit.json

# Revoke the exposed token's grant, not just the token row
gh api -X DELETE /applications/CLIENT_ID_EXAMPLE/grant -f access_token=ghp_EXAMPLE

# Verify by using it. A console that says "revoked" is a claim, not a check.
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H 'Authorization: Bearer ghp_EXAMPLE' https://api.example.com/user   # expect 401
```

```sql
-- Right: invalidate every session and refresh token for the identity,
-- and record why, so the timeline can tell our action from theirs.
UPDATE sessions
   SET revoked_at = now(), revoked_reason = 'INC-2026-014'
 WHERE user_id = $1 AND revoked_at IS NULL;

UPDATE refresh_tokens
   SET revoked_at = now(), revoked_reason = 'INC-2026-014'
 WHERE user_id = $1 AND revoked_at IS NULL;

UPDATE api_keys
   SET disabled_at = now(), disabled_reason = 'INC-2026-014'
 WHERE owner_id = $1 AND disabled_at IS NULL;
```

Then check what changed while they were in. This list is the one teams skip, and each item is
persistence that survives the rotation:

```sql
-- Account-level changes in the exposure window
SELECT event_time, event_type, actor_ip, detail
  FROM account_audit
 WHERE user_id = $1
   AND event_time BETWEEN $2 AND $3
   AND event_type IN ('email_changed','phone_changed','password_changed',
                      'mfa_enrolled','mfa_removed','recovery_code_regenerated',
                      'api_key_created','oauth_grant_created','oauth_grant_scope_added',
                      'mail_forwarding_rule_created','webhook_target_changed',
                      'ssh_key_added','deploy_key_added','member_invited','role_granted')
 ORDER BY event_time;
```

Mail forwarding rules and webhook targets deserve naming twice. A forwarding rule keeps
delivering password resets long after the password is rotated, and a changed webhook target
keeps receiving payloads after every credential in the account is new.

Rotation itself, including who owns which secret and how a rotation is verified, is
`skills/core/secrets-management/`. Repeated-guessing entry paths — the password spray or OTP
brute force that started this — are `skills/core/brute-force-defense/`.

### A secret in git history

A later commit that removes the line does not fix anything. The blob stays in history, in every
clone, in every fork, and in the provider's cached views. Rotation is the fix; history rewriting
is optional cleanup afterwards.

```bash
# Find it, and find when it first appeared
git log --all --full-history -p -S 'AKIAEXAMPLE' -- . | head -100
git log --all --format='%H %cI %an' -S 'AKIAEXAMPLE'      # earliest commit = start of exposure window
git rev-list --objects --all | git cat-file --batch-check='%(objecttype) %(objectname) %(rest)' \
  | awk '$1=="blob"' | head   # blobs survive even when no tree references them

# Is it still reachable after the "fix" commit?
git grep -I 'AKIAEXAMPLE' $(git rev-list --all) -- . | head
```

Treat the exposure window as starting at the first commit that contained it and ending at
rotation — not at the removal commit. If the repository was ever public, or has forks, assume
disclosure and scope accordingly.

## Blast radius assessment

`DE.AE-03` · `DE.AE-04` · `RS.AN-08`

The policy is the ceiling. The logs are the floor. Report both, and never present the ceiling
as if it were the floor or the floor as if it were the ceiling.

```bash
# 1. What could it do? (ceiling)
aws iam get-user --user-name svc-example
aws iam list-attached-user-policies --user-name svc-example
aws iam list-access-keys --user-name svc-example

# 2. What did it do? (floor) - control plane
aws cloudtrail lookup-events --start-time 2026-07-20T00:00:00Z --end-time 2026-07-28T00:00:00Z \
  --lookup-attributes AttributeKey=Username,AttributeValue=svc-example \
  --max-results 200 > events.json
jq -r '.Events[].CloudTrailEvent | fromjson
       | [.eventTime, .eventName, .sourceIPAddress, (.errorCode // "ok")] | @tsv' events.json | sort

# 3. Did it mint anything? Privilege reach outlives the key you just rotated.
jq -r '.Events[].CloudTrailEvent | fromjson | select(.eventName
       | test("^(CreateUser|CreateAccessKey|CreateRole|AttachRolePolicy|PutUserPolicy|AssumeRole|UpdateAssumeRolePolicy|CreateLoginProfile)$"))
       | [.eventTime, .eventName, .requestParameters.userName // .requestParameters.roleName] | @tsv' events.json
```

Data-plane access is logged separately and usually off by default. If S3 data events were not
enabled, object reads are unobservable: that is "possible", not "ruled out".

```bash
aws cloudtrail get-event-selectors --trail-name org-trail   # were data events ever on?
```

Two habits that change the answer:

- Search backwards past the earliest hit. The first thing you find is the first thing that was
  logged, which is rarely the first thing that happened.
- Correlate two independent sources before writing "confirmed" — application log plus provider
  audit trail, or auth log plus network flow.

Superficial magnitude estimation is called out in r3 as letting the incident continue on other
targets without the organization noticing. That is the failure mode this section exists for.

## Communication

`RS.CO-02` · `RS.CO-03` · `RC.CO-03` · `RC.CO-04`

Four things per update, nothing else: what we know, what we do not know, what we are doing, when
the next update lands.

```markdown
INC-2026-014 update 3 — 2026-07-28T16:00Z

Known:    One contractor PAT was valid and used from 203.0.113.10 between 13:47Z and 14:15Z.
          40 private repositories were cloned. Token revoked 14:15Z, verified 14:18Z.
Unknown:  Whether CI secrets were read. S3 data events were not enabled on the artifact
          bucket, so object reads in that window are not observable either way.
Doing:    Rotating all CI secrets. Reviewing workflow file changes in the window.
Next:     20:00Z, or sooner if scope changes.
```

Rules that hold under pressure:

- "No evidence of X" only when you have shown the log covers the window. Otherwise write "not
  observable".
- No attribution. Naming an actor from log evidence is not something a development team can do
  defensibly, and a wrong attribution reshapes the whole response.
- Do not coordinate the response on infrastructure the intruder may hold. If the identity
  provider or chat platform is in scope, start in the fallback channel from the runbook.
- Internal audiences get instructions, not just narrative. "Re-authenticate and re-enrol MFA"
  is an update; "we are investigating" is not.

On notification obligations, plainly: statutory breach-notification deadlines and thresholds
vary by jurisdiction, sector, and contract, and they change. This skill does not give legal
advice and does not list deadlines. Bring legal in at declaration when personal data is
plausibly in scope, and let them own the clock. Contractual and insurance notification windows
are often tighter than statutory ones and are commonly missed for that reason — the runbook
should carry them because someone verified them, not because a model recalled them.

## Recovery validation

`RS.MA-05` · `RC.RP-02` · `RC.RP-03` · `RC.RP-05` · `RC.RP-06`

Recovery starts when eradication is done, not in progress. Restoring into an unfixed entry point
gets you the same incident with a worse timeline.

```bash
# Backup must predate the earliest evidence of access, and be verified before trust
aws rds describe-db-snapshots --db-instance-identifier prod-db \
  --query 'DBSnapshots[].{id:DBSnapshotIdentifier,created:SnapshotCreateTime,status:Status}'
# Restore to an isolated subnet first, check indicators there, then cut over.
```

Verification checks that would fail if the compromise persisted, not checks that pass either way:

```bash
# The revoked credential must not work
curl -sS -o /dev/null -w '%{http_code}\n' -H 'Authorization: Bearer ghp_EXAMPLE' \
  https://api.example.com/user     # expect 401

# The added persistence must be gone
gh api /repos/example-org/app/keys --jq '.[] | [.id,.title,.created_at] | @tsv'
gh api /orgs/example-org/members --paginate --jq '.[].login' | sort > members.now
diff members.baseline members.now

# The exploited flaw must fail the old test
pytest tests/regression/test_inc_2026_014.py -q
```

Leave the incident's detections in place after closure for longer than feels necessary.
Re-entry attempts cluster after eradication, because the attacker also noticed.

Declare the end of recovery explicitly, with a timestamp and a name (`RC.RP-06`). Incidents
that fade out instead of closing never get their after-action report written.

## Post-incident review

`ID.IM-01` · `ID.IM-03` · `ID.IM-04` · A09:2025 · A10:2025 · CWE-778

A finding that does not become a test, a detection rule, or an owned tracked item did not
happen. Write the review around three questions:

1. What did the attacker do that nobody saw, and what would have seen it?
2. Which decision cost the most time, and what information was missing when it was made?
3. What did the runbook not contain that we needed at 3am?

For every unseen step, name the detection gap and close it at the source. Missing actor, action,
target, outcome, and timestamp on a security event is CWE-778, and it is why the timeline had
holes.

```yaml
# Right: the gap becomes a rule with a documented action
- alert: PersonalAccessTokenUsedFromNewASN
  expr: |
    sum by (actor, asn) (increase(api_requests_by_token_total[10m])) > 0
    unless on (actor, asn) actor_asn_seen_90d
  labels: { severity: sev3, runbook: ops/runbooks/token-misuse.md }
  annotations:
    action: "Confirm with the actor out of band. Do not revoke before capturing recent activity."
```

Anything found in a log that should not have been there — a token, a password, a session ID —
is its own incident: rotate, then remediate the log line (CWE-532). Do not treat "the secret was
only in our logs" as containment.

Run the review without attributing the incident to an individual. The person who clicked the
link is not the control that failed.

## Sources

- <https://doi.org/10.6028/NIST.SP.800-61r3>
- <https://www.rfc-editor.org/rfc/rfc3227.html>
- <https://csrc.nist.gov/pubs/sp/800/86/final>
- <https://csrc.nist.gov/pubs/sp/800/184/final>
- <https://owasp.org/Top10/2025/>
- <https://owasp.org/www-project-application-security-verification-standard/>
- <https://cwe.mitre.org/>
