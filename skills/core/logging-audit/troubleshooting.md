# Troubleshooting

What to do when logging guidance conflicts or cannot be applied cleanly.

## Security wants the full body for forensics

Do not log it by default. Full request bodies on auth endpoints contain passwords, tokens,
recovery codes, and identity documents; the log store then becomes the highest-value database
in the organisation (A09, ASVS 16.2.5, CWE-532).

Offer three narrower options:

1. Named fields with a documented allowlist
2. Counts, hashes, or classifications instead of values
3. A time-limited debug capture approved through incident change control, written to a
   dedicated encrypted store with named readers and automatic deletion

If legal interception or a regulatory obligation genuinely requires content, document the
legal basis, isolate the store, and state that the log now inherits the data's classification.
Do not call a sink regex enough.

## Operations needs synchronous logging; developers need availability

Separate the streams. Application logs use a bounded queue and expose dropped-event count.
Must-not-lose audit rows commit with the business transaction. That is the trade: either the
change and its audit row both commit, or neither does.

Never use an unbounded queue as a compromise. It delays the failure until memory exhaustion.
Never wait 30 seconds on a remote SIEM from the request path. A sink outage is not permission
to deny the whole application unless the operation's audit record is a formal precondition.

State which events can be dropped and which cannot. "All logs are critical" is not a design.

## The SIEM requires a different schema

Map at one controlled boundary. Prefer the application's shared logging module if all services
can use it; otherwise normalise once at ingest. Do not let each call site speak vendor syntax.

Keep the domain event name (`authz_fail`) even when mapping fields to ECS, OCSF, or CEF. That
lets the application test what it owns. Add a contract test that feeds one event through the
normaliser and asserts the fields the detection rule reads.

If a rename is unavoidable, deploy in this order:

1. Make the SIEM accept old and new field names
2. Deploy applications emitting the new name
3. Confirm nonzero event volume under the new name
4. Remove the old mapping

The reverse creates a silent detection gap.

## The framework says JSON logging prevents injection

Verify the renderer and the viewer. A real JSON encoder escapes CR, LF, NUL, and ESC inside a
string. String-building something that looks like JSON does not.

```java
// Not structured logging. Still injectable, and not valid JSON when username has a quote
log.info("{\"event\":\"login_fail\",\"actor\":\"" + username + "\"}");
```

Also check the output after the transport. Some syslog formatters flatten a JSON object into
free text; some viewers render ANSI escapes instead of displaying them. Test with CR, LF,
NUL, ESC, backspace, quotes, and a maximum-length value (ASVS 16.4.1, CWE-117).

## The vendor guarantees immutability

Read the actual permission and retention policy. "Immutable" may mean ordinary users cannot
edit an object while the account owner can shorten retention, delete the bucket, or disable
object lock.

Check:

- Can the application principal delete or rewrite an object?
- Can an administrator shorten retention retroactively?
- Is governance mode bypassable by a role the app can assume?
- Are bucket deletion and retention-policy changes logged somewhere outside the bucket?
- Is the external anchor under a separate account or trust domain?

Hash chaining without an external anchor is not tamper evidence against a full writer. Say
what threat it covers: accidental loss and partial compromise.

## Privacy asks to erase an immutable audit row

Do not quietly rewrite the trail and do not tell privacy "immutable wins". The conflict is
real: GDPR data subject rights collide with evidence and legal-retention duties.

Work through it with privacy counsel:

1. Identify the legal basis and mandatory retention period for this stream
2. Determine whether the row needs direct identity at all
3. Delete the identity mapping and preserve a pseudonymous actor ID where that meets both
   purposes
4. Remove optional fields such as user agent after a shorter period even if the core audit row
   remains
5. Record the residual data - source IP and timestamps can still identify a person

Pseudonymisation narrows the conflict. It does not make the log anonymous and does not erase
the right-to-access problem.

## Support needs broad log access

Build a view, not a broad grant. The view enforces tenant and field restrictions, masks IP and
email where they are not needed, and records every search and export. The raw sink remains
available only to named incident responders (ASVS 16.4.2).

If the support tool accepts an arbitrary query over the raw log store, it is a data export API.
Authorize, rate-limit, and audit it like one. "Internal" is not an access control.

## No one knows the right retention period

Do not choose "forever" and do not apply one number to every stream. Build the ASVS 16.1.1
inventory first, then ask per stream:

- Longest realistic incident-detection delay
- Legal or contractual minimum
- Legal or privacy maximum
- Cost and operational value
- Whether fields can age out at different times

Set an explicit temporary period, owner, and review date if counsel has not answered. An
expiring interim policy is safer than permanent undefined retention.

## The alert is noisy

Do not mute it without replacement. First decide whether the event is wrong or the threshold
is wrong.

- Repeated denial: group by distinct target, not just count
- Impossible travel: account for known VPN egress and require a privileged action after login
- Bulk export: compare with actor baseline and include row count
- Login failure: alert on success after failures, not every failure

Capture false-positive examples in the rule's test dataset. Tune, replay, and only then change
the threshold. An alert with no current playbook is also a failure under A09; write the first
three response steps before re-enabling it.

## The alert never fires

Walk backwards, in this order:

1. Does the rule query a real event name?
2. Does any code path emit that exact name?
3. Does the deployed path execute?
4. Does the processor preserve the event name and required fields?
5. Does the shipper deliver it to the index the rule reads?
6. Is the rule enabled, scheduled, and notifying a live route?

Add a synthetic canary event and a test. If the canary arrives but the application event does
not, the bug is the emitter. If neither arrives, it is the pipeline. If both arrive and nobody
is notified, it is the alert route.

Do not "test" by lowering the threshold in production and waiting for a user to trigger it.
Emit a clearly labelled synthetic event in staging, or through an approved production canary.

## Logging fails while authorization is deciding

Authorization still fails closed. A log exception cannot become a grant (A10:2025, ASVS
16.5.3). Catch the known logging failure, increment a local metric, deny the protected action
if the audit row is mandatory, or continue with a dropped-event metric if it is an application
log.

Do not catch `Exception` around both the security check and the logger: that makes it
impossible to tell which one failed and tempts the caller to continue.

## The service has too many 403 paths to instrument by hand

Log at the central policy decision point or denial middleware, where actor, action, target,
and reason are still available. Then test one handler per policy shape. Do not log only in the
HTTP exception handler; by then it may know the status but not the target or policy reason.

The central point does not eliminate business-specific events. A bulk export needs row count,
and a secret read needs the secret name; emit those at the domain layer.

## Logs disappear on crash

Establish which boundary lost them: application buffer, sidecar, node, network, or sink. Then
fix the nearest durable hop.

- Application logs: local durable spool plus asynchronous ship; bounded and monitored
- Audit entries: same transaction as the state change
- Planned shutdown: stop accepting traffic, drain queue with a timeout, then exit
- Unhandled failure: last-resort handler emits `sys_crash`; Go uses `recover()` middleware
- `SIGKILL` / power loss: no handler can help. Durability comes from the local spool or
  transactional store, not an `atexit` promise

State the remaining loss window. "Flushes on shutdown" does not cover a kill or kernel panic.

## The standard has moved on

The references here were verified 2026-07-28: Top 10 2025 and ASVS 5.0.0. ASVS requirement
numbers are version-specific. Fetch the source before citing a number not in
[references/asvs-v16-logging.md](references/asvs-v16-logging.md).

Never invent a requirement number to make a finding look formal. A chapter citation you read
is stronger than a precise ID you guessed.
