# Incident Response Examples

Wrong response next to right response. These are defensive patterns for systems you own or are
authorized to defend. Nothing here reproduces an intrusion, delivers a payload, or evades a
control.

All identifiers are obvious placeholders. `web-03.example.com`, `203.0.113.10`,
`123456789012`, `ghp_EXAMPLE`, and `INC-2026-014` are not real.

## Contents

- [Reboot versus preserve then isolate](#reboot-versus-preserve-then-isolate) — A09, ASVS V16, CWE-778
- [Partial versus complete credential revocation](#partial-versus-complete-credential-revocation) — A07, ASVS V7/V10, CWE-613
- [Unusable versus correlatable audit records](#unusable-versus-correlatable-audit-records) — A09, ASVS V16, CWE-778
- [Ownerless versus executable runbook step](#ownerless-versus-executable-runbook-step) — A10, ASVS V16, CWE-636
- [Silently dropped versus durable alert delivery](#silently-dropped-versus-durable-alert-delivery) — A09/A10, ASVS V16, CWE-390
- [Removing versus rotating a committed secret](#removing-versus-rotating-a-committed-secret) — A04/A09, ASVS V11/V16, CWE-798
- [Trusting versus validating the log source](#trusting-versus-validating-the-log-source) — A09, ASVS V16, CWE-778
- [Hope-based versus evidence-based recovery](#hope-based-versus-evidence-based-recovery) — A10, ASVS V16, CWE-636

---

## Reboot versus preserve then isolate

`A09:2025` · `ASVS V16` · `CWE-778` · NIST SP 800-61r3 `RS.AN-06`, `RS.AN-07`, `RS.MI-01`

The alert says an unknown process on `web-03.example.com` opened an outbound connection.
Rebooting clears the alert and destroys the evidence that tells you what happened.

### Wrong

```bash
#!/usr/bin/env bash
set -e

HOST="web-03.example.com"
ssh "$HOST" 'sudo systemctl stop app && sudo reboot'
# Ticket note: "Suspicious process removed; monitoring."
```

Memory is gone. Open sockets are gone. Process ancestry is gone. The ticket says the process was
removed, but nobody identified it, so nobody knows whether it persists elsewhere. This is not
containment; it is evidence destruction followed by hope.

`systemctl stop app` also changes the very process tree the responder needed to capture. Even if
the reboot failed, collection would already be contaminated.

### Right

```bash
#!/usr/bin/env bash
# Defensive collector for an authorized Linux host.
# An evidence volume must already be mounted at /mnt/evidence.
set -uo pipefail       # not -e: one missing collector must not abort the rest

INC="INC-2026-014"
HOST="web-03.example.com"
OUT="/mnt/evidence/$INC/${HOST%%.*}"
mkdir -p "$OUT"

stamp() { date -u +%FT%TZ; }
note()  { printf '%s %s\n' "$(stamp)" "$*" | tee -a "$OUT/collection.log"; }

note "start operator=${SUDO_USER:-unknown}"

# Volatile first: memory, sockets, processes.
if command -v avml >/dev/null; then
  avml "$OUT/memory.raw" && note "memory captured"
else
  note "GAP memory not captured: avml absent"
fi

ss -tupan > "$OUT/sockets.txt" 2>&1
ip -o addr > "$OUT/addresses.txt" 2>&1
ip route > "$OUT/routes.txt" 2>&1
ps -eo pid,ppid,user,lstart,etimes,args --sort=lstart > "$OUT/processes.txt" 2>&1
ls -l /proc/*/exe 2>/dev/null > "$OUT/executables.txt"

# Less volatile next.
last -Fwx > "$OUT/logins.txt" 2>&1
journalctl --since "-14 days" --no-pager > "$OUT/journal.txt" 2>&1
cp -a /etc/passwd /etc/group /etc/sudoers.d "$OUT/" 2>/dev/null

# Hash before containment changes anything else.
( cd "$OUT" && find . -type f ! -name manifest.sha256 -exec sha256sum {} + > manifest.sha256 )
sha256sum "$OUT/manifest.sha256" | tee -a "$OUT/collection.log"
note "capture complete; ready for network isolation"
```

Then isolate at the network layer without powering off:

```bash
aws ec2 modify-instance-attribute \
  --instance-id i-EXAMPLE0123 \
  --groups sg-QUARANTINE
```

Why this closes the failure: memory, network state, and processes are captured in volatility
order and stored off-host before containment changes them. The hash manifest records what was
collected. A missing memory tool becomes an explicit gap instead of silently stopping the
script. Network quarantine removes access while preserving the running state.

Limitation: a live collector changes memory and filesystem metadata merely by running. For a
prosecution or insurance claim, use a trained examiner and approved acquisition tools. If the
host is actively encrypting or deleting data, contain immediately and record why preservation
lost the trade.

---

## Partial versus complete credential revocation

`A07:2025` · `ASVS V7, V10` · `CWE-613` · NIST SP 800-61r3 `RS.MI-01`, `RS.MI-02`

A user account was taken over. Deleting the current session leaves the attacker with the refresh
token, a newly created API key, and an OAuth grant.

### Wrong

```python
# Wrong: only the browser session dies
def revoke_compromised_user(user_id: str) -> None:
    db.execute("DELETE FROM sessions WHERE user_id = %s", (user_id,))
    db.commit()
```

The refresh token mints a new session on the next request. Any PAT or API key continues to work.
The account may also have a malicious MFA factor or forwarding rule that survives every
credential rotation.

### Right

```python
from dataclasses import dataclass
from datetime import datetime, timezone

@dataclass(frozen=True)
class RevocationResult:
    sessions: int
    refresh_tokens: int
    api_keys: int


def revoke_compromised_user(user_id: str, incident_id: str) -> RevocationResult:
    now = datetime.now(timezone.utc)
    with db.transaction() as tx:
        sessions = tx.execute(
            """UPDATE sessions
                  SET revoked_at = %s, revoked_reason = %s
                WHERE user_id = %s AND revoked_at IS NULL""",
            (now, incident_id, user_id),
        ).rowcount
        refresh = tx.execute(
            """UPDATE refresh_tokens
                  SET revoked_at = %s, revoked_reason = %s
                WHERE user_id = %s AND revoked_at IS NULL""",
            (now, incident_id, user_id),
        ).rowcount
        keys = tx.execute(
            """UPDATE api_keys
                  SET disabled_at = %s, disabled_reason = %s
                WHERE owner_id = %s AND disabled_at IS NULL""",
            (now, incident_id, user_id),
        ).rowcount
    return RevocationResult(sessions, refresh, keys)
```

The provider-side runbook continues after the transaction:

```markdown
- [ ] Revoke app passwords and legacy-protocol credentials
- [ ] Remove newly enrolled MFA factors; issue new recovery codes
- [ ] Revoke third-party OAuth grants and device trust
- [ ] Remove SSH keys, deploy keys, and PATs created in the exposure window
- [ ] Inspect email/phone changes, mail forwarding rules, and webhook targets
- [ ] Inspect users, invitations, roles, and API keys created by this identity
- [ ] Rotate the root credential in the provider, then update every legitimate consumer
- [ ] Verify the old credential and refresh token return 401
```

Why this closes the failure: every first-party artefact is revoked atomically, each mutation is
attributed to the incident, and the checklist catches persistence outside the application
database. Verification tests revocation rather than trusting a console message.

Limitation: there is no universal API for third-party grants, MFA factors, mail rules, or webhook
targets. Inventory those integrations before the incident. Provider-specific rotation belongs in
`skills/core/secrets-management/`; repeated-guessing defenses belong in
`skills/core/brute-force-defense/`.

---

## Unusable versus correlatable audit records

`A09:2025` · `ASVS V16` · `CWE-778` · NIST SP 800-61r3 `DE.AE-03`, `RS.AN-06`

An admin changes a webhook target. The old log says only that something changed.

### Wrong

```javascript
app.patch("/admin/webhooks/:id", requireAdmin, async (req, res) => {
  await webhooks.update(req.params.id, { url: req.body.url });
  logger.info("webhook updated");
  res.sendStatus(204);
});
```

The record lacks actor, target, request ID, outcome, and source. Ten identical entries cannot be
joined to an authentication event, a load-balancer request, or a specific webhook. It cannot
support a timeline.

### Right

```javascript
import crypto from "node:crypto";

app.patch("/admin/webhooks/:id", requireAdmin, async (req, res, next) => {
  const requestId = req.get("x-request-id") || crypto.randomUUID();
  const audit = {
    timestamp: new Date().toISOString(),
    event: "webhook_target_change",
    request_id: requestId,
    actor_id: req.user.id,
    actor_session_id: req.user.sessionId,
    target_type: "webhook",
    target_id: req.params.id,
    source_ip: req.ip,
    user_agent: req.get("user-agent") || null,
  };

  try {
    const before = await webhooks.get(req.params.id);
    await webhooks.update(req.params.id, { url: req.body.url });
    logger.info({
      ...audit,
      outcome: "success",
      old_target_host: new URL(before.url).hostname,
      new_target_host: new URL(req.body.url).hostname,
    });
    res.set("x-request-id", requestId).sendStatus(204);
  } catch (error) {
    logger.error({ ...audit, outcome: "failure", error_type: error.name });
    next(error);
  }
});
```

Why this closes the failure: actor, target, request ID, outcome, timestamp, and source are all
present. The request ID joins the application event to upstream records. The code logs both
success and failure. It records only target hostnames, not full URLs that may contain credentials
or personal data (CWE-532).

Limitation: fields do not create integrity. Ship the event to an append-only store outside the
application identity's write access. If the attacker could edit that store, this event is
uncorroborated regardless of field quality. Full logging design is in
`skills/core/logging-audit/`.

---

## Ownerless versus executable runbook step

`A10:2025` · `ASVS V16` · `CWE-636` · NIST SP 800-61r3 `RS.MA-01`, `RS.MA-04`

The runbook is opened at 03:00. It says what should happen but not who has authority or what to
do when they are unreachable.

### Wrong

```markdown
## Credential compromise

1. Revoke all production credentials.
2. Take the affected service offline if necessary.
3. Notify customers if data may be involved.
```

The on-call role is read-only in production. Nobody knows who can approve downtime. The person
who normally publishes customer updates is asleep. Every step waits for an undocumented social
network.

### Right

```markdown
## Credential compromise

### Revoke production credentials
Owner:   on-call SRE, using `SecurityBreakGlass` (access verified in quarterly drill)
Deputy:  security lead, then platform manager
Timeout: 15 minutes unreachable -> on-call uses break-glass
Record:  incident timeline, including who authorized and provider audit event ID
Verify:  old credential returns 401; legitimate consumers use the new version

### Take the affected service offline
Owner:   incident lead recommends; VP Engineering decides
Deputy:  CTO
Timeout: 20 minutes unreachable during active data destruction -> incident lead may isolate;
         they may not erase or rebuild until evidence is captured
Record:  decision, evidence sacrificed, customer impact, rollback criterion

### External notification decision
Owner:   VP Engineering with legal and communications
Deputy:  CTO with external counsel
Timeout: 60 minutes unreachable -> escalate to CEO; nobody else publishes
Input:   confirmed scope, possible scope, evidence gaps, statutory/contractual clocks from legal
```

Why this closes the failure: every action has a role with verified access, a deputy, an
escalation timeout, authority boundaries, a verification test, and a record destination. The
on-call does not have to invent governance during the incident.

Limitation: writing "access verified" is not verification. Exercise the break-glass path. A
runbook tested only by its author is still an assumption.

Statutory notification deadlines vary by jurisdiction and sector. This skill gives no legal
advice and does not provide a deadline; legal owns that input.

---

## Silently dropped versus durable alert delivery

`A09:2025` · `A10:2025` · `ASVS V16` · `CWE-390`

The authentication service detects a suspicious account change, but the SIEM is temporarily
unavailable.

### Wrong

```python
def alert_account_change(event: dict) -> None:
    try:
        siem.emit(event)
    except Exception:
        pass
```

`except: pass` turns any failure — expired credential, schema mismatch, outage, programming
error — into silent permanent loss. The caller believes the event was delivered because the
function returned normally. The detection exists only in code review.

### Right

```python
import json
import logging
from pathlib import Path

log = logging.getLogger(__name__)
SPOOL = Path("/var/spool/security-events/queue.ndjson")
MAX_SPOOL_BYTES = 50 * 1024 * 1024

class SiemUnavailable(Exception):
    pass


def append_bounded(event: dict) -> None:
    SPOOL.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if SPOOL.exists() and SPOOL.stat().st_size >= MAX_SPOOL_BYTES:
        raise RuntimeError("security event spool is full")
    with SPOOL.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, separators=(",", ":")) + "\n")


def alert_account_change(event: dict) -> None:
    try:
        siem.emit(event)
    except SiemUnavailable:
        ALERT_DELIVERY_FAILURES.inc()       # this metric has an independent page
        append_bounded(event)               # replay worker drains after recovery
        log.error(
            "siem_emit_failed event_type=%s request_id=%s",
            event.get("type"),
            event.get("request_id"),
        )
        raise
```

```yaml
- alert: SecurityEventDeliveryFailed
  expr: increase(alert_delivery_failures_total[5m]) > 0
  labels:
    severity: sev2
    runbook: ops/runbooks/security-event-delivery.md
  annotations:
    action: "Check SIEM health and bounded spool. Do not restart until spool is copied."

- alert: SecurityAuthEventsAbsent
  expr: time() - security_auth_event_last_seen_seconds > 300
  labels:
    severity: sev2
  annotations:
    action: "Confirm auth traffic exists; if yes, treat as pipeline failure."
```

Why this closes the failure: a known delivery outage is handled narrowly, events survive in a
bounded local spool, the caller receives failure, and both positive failures and suspicious
silence alert independently. The spool cap prevents a SIEM outage from exhausting disk.

Limitations: local spool data dies with an ephemeral pod and may contain security-sensitive
fields. Put it on encrypted persistent storage with restrictive permissions, or use a durable
queue outside the workload. Never place secrets or session tokens in the event (CWE-532).

---

## Removing versus rotating a committed secret

`A04:2025` · `A09:2025` · `ASVS V11, V16` · `CWE-798`

A cloud key is committed and then removed in the next commit. The removal is not the fix.

### Wrong

```bash
git rm config/production.env
git commit -m "remove accidentally committed key"
git push
# Ticket closed: "key no longer in main"
```

The blob remains in history, clones, forks, and provider caches. An attacker holding the old key
does not care which commit is currently checked out.

### Right

```bash
# 1. Identify the exposure window without printing the secret value.
KEY_ID='AKIAEXAMPLE'
git log --all --format='%H %cI %an' -S "$KEY_ID"
git log --all --full-history -p -S "$KEY_ID" -- . | head -100
git grep -I "$KEY_ID" $(git rev-list --all) -- . | head

# 2. Preserve the provider audit trail for that key before rotation changes activity.
aws cloudtrail lookup-events \
  --start-time 2026-07-20T00:00:00Z \
  --end-time 2026-07-28T23:59:59Z \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIAEXAMPLE \
  --max-results 200 > INC-2026-014-key-events.json
sha256sum INC-2026-014-key-events.json > INC-2026-014-key-events.json.sha256

# 3. Disable and delete through the provider's approved runbook, then verify.
aws iam update-access-key --user-name svc-example --access-key-id AKIAEXAMPLE --status Inactive
aws iam delete-access-key --user-name svc-example --access-key-id AKIAEXAMPLE
aws sts get-caller-identity --profile compromised-example   # must fail
```

Then issue a new credential through the secret manager, update every legitimate consumer, and
review the entire exposure window for use. History rewriting may reduce future accidental
discovery, but it happens after rotation and requires coordination with every clone and fork.

Why this closes the failure: the provider rejects the leaked credential, which is the only state
that invalidates copies already taken. Git searches establish the real start of exposure, and
the audit export scopes observed use.

Limitations: cloud control-plane audit records may not include every data-plane read. If data
events were not enabled, report object access as possible and unobservable, not absent. Rotation
patterns belong in `skills/core/secrets-management/`.

---

## Trusting versus validating the log source

`A09:2025` · `ASVS V16` · `CWE-778` · NIST SP 800-61r3 `RS.AN-07`

The cloud audit trail shows no data access. Before that sentence reaches the report, establish
whether the attacker could change the trail.

### Wrong

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=svc-example > events.json

if [ "$(jq '.Events | length' events.json)" -eq 0 ]; then
  echo "No unauthorized access occurred"
fi
```

An empty result can mean no event, wrong region, expired retention, disabled data events,
stopped logging, deleted trail, or a filter mismatch. If `svc-example` could alter the log
bucket, a non-empty result is not trustworthy either.

### Right

```bash
set -uo pipefail
TRAIL="org-trail"
OUT="evidence/INC-2026-014/log-integrity"
mkdir -p "$OUT"

aws cloudtrail get-trail-status --name "$TRAIL" > "$OUT/status.json"
aws cloudtrail get-event-selectors --trail-name "$TRAIL" > "$OUT/selectors.json"
aws cloudtrail lookup-events --max-results 50 \
  --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging \
  > "$OUT/stop-logging.json"
aws cloudtrail lookup-events --max-results 50 \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteTrail \
  > "$OUT/delete-trail.json"
aws cloudtrail lookup-events --max-results 50 \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutEventSelectors \
  > "$OUT/selector-changes.json"

# Only useful if log-file validation was enabled before the incident.
aws cloudtrail validate-logs \
  --trail-arn arn:aws:cloudtrail:us-east-1:123456789012:trail/org-trail \
  --start-time 2026-07-20T00:00:00Z \
  > "$OUT/validation.txt" 2>&1

( cd "$OUT" && sha256sum ./* > manifest.sha256 )
```

The report then says exactly one:

```text
Usable: trail integrity validation succeeded, the compromised identity could not write the
trail or destination, and selectors plus retention cover the full interval.

Uncorroborated: the compromised identity could reconfigure or delete the trail. Entries may be
used as leads but not as sole evidence.

Indeterminate: pre-incident integrity validation or authorization history was unavailable.
```

Why this closes the failure: integrity and coverage are checked before content, and the result
limits which claims the source can support. Data-event selectors establish whether object reads
were observable at all.

Limitation: successful digest validation proves files have not changed since delivery; it does
not prove every expected event was generated by the source. Correlate with another independent
source. See `skills/core/logging-audit/`.

---

## Hope-based versus evidence-based recovery

`A10:2025` · `ASVS V16` · `CWE-636` · NIST SP 800-61r3 `RC.RP-03`, `RC.RP-05`, `RC.RP-06`

Alerts stopped after the host was rebuilt. That is not a recovery test.

### Wrong

```bash
kubectl rollout restart deployment/api
sleep 60
kubectl get pods
# All Ready -> close incident
```

The restored image may contain the same injected CI step, the backup may postdate initial
access, and the compromised refresh token may still work. `Ready` proves only that the health
endpoint returned success.

### Right

```bash
# Backup inventory: select one predating earliest evidence, then restore in isolation.
aws rds describe-db-snapshots --db-instance-identifier prod-db \
  --query 'DBSnapshots[].{id:DBSnapshotIdentifier,created:SnapshotCreateTime,status:Status}' \
  > evidence/INC-2026-014/db-snapshots.json

# Verify the old credential is dead.
status=$(curl -sS -o /dev/null -w '%{http_code}' \
  -H 'Authorization: Bearer ghp_EXAMPLE' https://api.example.com/user)
test "$status" = "401" || { printf 'old credential still works: %s\n' "$status"; exit 1; }

# Verify account and repository persistence against known-good baselines.
gh api /orgs/example-org/members --paginate --jq '.[].login' | sort > members.now
diff -u baselines/members.txt members.now

gh api /repos/example-org/app/hooks --paginate \
  --jq '.[] | [.id,.active,.config.url] | @tsv' | sort > webhooks.now
diff -u baselines/webhooks.tsv webhooks.now

# Verify the exploited application behavior is unavailable.
pytest tests/regression/test_inc_2026_014.py -q

# Verify restored assets before production cutover.
kubectl -n isolated-recovery get pods -o wide
kubectl -n isolated-recovery logs deployment/api --all-containers --since=1h > recovery-logs.txt
sha256sum recovery-logs.txt > recovery-logs.txt.sha256
```

Closure criteria are written before the checks:

```markdown
- [x] Entry point closed; regression test passes on fixed build
- [x] Backup predates earliest observed access and was outside compromised role's reach
- [x] Restored assets checked in isolated recovery namespace
- [x] Old session, refresh token, and API key all rejected
- [x] MFA, OAuth grants, forwarding rules, deploy keys, and webhook targets reviewed
- [x] Membership and role grants match baseline
- [x] Monitoring for the same indicators remains active
Recovery ended: 2026-07-28T22:40Z by <INCIDENT_LEAD>
```

Why this closes the failure: every check would fail if a specific part of the compromise
persisted. Backup age and reachability are verified, restored assets are inspected before
receiving production traffic, and closure is an explicit decision instead of the absence of new
alerts.

Limitation: a clean regression test proves only the known entry point is closed. It does not
prove no second entry point exists. Keep post-recovery monitoring and carry unresolved scope as a
stated limitation.

---

## Common reporting shape

Every incident finding should preserve uncertainty rather than polishing it away:

```markdown
- Category: A09:2025 · ASVS V16 · CWE-778
- Location: cloud audit configuration, account 123456789012
- Evidence: data-event selectors were absent from 2026-07-20T00:00Z through rotation
- Impact: object reads by AKIAEXAMPLE cannot be observed; policy allowed reads from bucket
  example-artifacts
- State: possible, unproven — not "no evidence of access"
- Fix: enable organization-level data events to an append-only destination outside the
  workload account; alert on selector changes and logging stops
- Severity: SEV2 pending independent CDN/object-store access records; escalate if reads confirm
```

The report does not invent a timeline entry, overstate a clean log, or turn a capability into a
confirmed action. It says what would settle the question.

## Sources

- <https://doi.org/10.6028/NIST.SP.800-61r3>
- <https://www.rfc-editor.org/rfc/rfc3227.html>
- <https://csrc.nist.gov/pubs/sp/800/86/final>
- <https://csrc.nist.gov/pubs/sp/800/184/final>
- <https://owasp.org/Top10/2025/>
- <https://owasp.org/www-project-application-security-verification-standard/>
- <https://cwe.mitre.org/>
