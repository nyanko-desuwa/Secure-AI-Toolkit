# Detection Rules

> Event vocabulary verified 2026-07-28 against the OWASP Application Logging Vocabulary Cheat
> Sheet - <https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html>
>
> Rules below are this skill's own, not OWASP text. Pseudo-query syntax; SIEM dialects differ.

An event with no rule is storage. A rule with no emitter is theatre. Check both directions.

## Event vocabulary

Use a stable machine name so one rule works across services.

| Prefix | High-value events |
|---|---|
| `authn_` | `login_success`, `login_fail`, `login_successafterfail`, `impossible_travel`, `token_reuse` |
| `authz_` | `fail`, `change`, `admin` |
| `privilege_` | `permissions_changed` |
| `sensitive_` | `create`, `read`, `update`, `delete` |
| `session_` | `created`, `expired`, `logout`, `use_after_expire` |
| `user_` | `created`, `updated`, `archived`, `deleted` |
| `excess_` | `rate_limit_exceeded`, `sessions_exceeded` |
| `malicious_` | `excess_404`, `attack_tool`, `sqli`, `csrf`, `direct_reference` |
| `sys_` | `crash`, `monitor_disabled`, `monitor_enabled` |

The OWASP vocabulary also defines `input_`, `upload_`, `crypt_`, `sequence_`, and `mcp_`
events. Its envelope includes event time with UTC offset, application ID, event, level, user
agent, source and host IP, host, request URI and method, region, and geography.

Make two deliberate additions:

- Put actor in its own field. Do not pack an ID into the event name. That breaks grouping and
  creates millions of distinct event names.
- Add `request_id` / `trace_id`. Cross-service correlation needs it.

## Rules worth having

### Impossible travel

```text
event = authn_login_success | group by actor | window 1h
alert when distinct(geo_country) >= 2
  and haversine(first.geo, last.geo) / hours_between > 900 km/h
```

Tune for VPN and corporate egress. Lower-noise variant: a country this actor has never used,
plus a privileged action in the same session. A nightly false positive gets the rule muted.

### Privilege escalation

```text
event in (authz_change, privilege_permissions_changed, user_updated)
where to_role in ("admin", "owner", "billing_admin") -> alert always
where actor == target                                -> severity high
```

Role grants are rare enough to review individually. Self-elevation usually has no legitimate
workflow.

### Bulk export

```text
event in (sensitive_read, sensitive_export) | group by actor | window 15m
alert when count > 5 * p99(actor_baseline_15m) or record_count > 10000
```

Needs successful reads logged: ASVS 16.3.2 Level 3, not Level 2. Emit row count, or one row
and 500,000 rows look identical.

### Repeated authorization denial

```text
event = authz_fail | group by actor | window 10m
alert when count >= 10 or distinct(target_id) >= 20
```

Distinct targets separate a stale bookmark from ID enumeration. Also detect denial followed
by success on a neighbouring ID: that sequence means the actor found one that works.

### Deadman: volume drops to zero

```text
for each (service, event_stream):
  alert when count(last 15m) == 0 and count(same window, 7d ago) > threshold
```

Catches a dead shipper, full sink, changed log level, or disabled logging. Alert on
`sys_monitor_disabled` too. Every other rule silently stops when this one is missing.

### Brute force, and success after it

```text
authn_login_fail | group by source_ip | 5m | alert when distinct(actor) >= 20
authn_login_fail | group by actor     | 5m | alert when count >= 10
authn_login_successafterfail where preceding_fail_count > 20 | alert always
```

The third is the one most often missing. Failures are noise; a success after many failures is
an incident.

### Token reuse and audit integrity

```text
authn_token_reuse                 -> alert always, high
audit_hash_chain_mismatch         -> alert always, critical
audit_table_delete_update_attempt -> alert always, critical
```

Token reuse means replay or theft; revoke the family. Integrity events must come from the
database or object-store audit log. An application cannot reliably report tampering with its
own store.

## Rules that look useful and are not

| Rule | Why it fails |
|---|---|
| Every login failure | Baseline noise buries the success after failures |
| Every HTTP 500 | Operational noise, not a security event on its own |
| Every authorization denial | Broken UI links page constantly. Group by distinct target |
| Regex for `password` in log bodies | Catches a field name, not every leak. Fix at emission |
| Sensitive read with no baseline | At ASVS L3 it fires continuously and gets muted |

## Wire each rule to its emitter

Keep a contract table next to the rules:

| Rule | Event | Emitter | Test |
|---|---|---|---|
| Bulk export | `sensitive_export` | `api/exports.py:create_export` | `test_export_emits_event` |
| Repeated denial | `authz_fail` | `middleware/authorize.py:deny` | `test_denial_emits_event` |
| Privilege grant | `privilege_permissions_changed` | `admin/roles.py:set_role` | `test_role_change_emits_event` |

A refactor that deletes or renames an emitter must fail CI, not silently reduce a rule to zero
results. Assert the event in the same test that asserts the 403.

## Sources

- OWASP A09:2025 - <https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/>
- OWASP Application Logging Vocabulary Cheat Sheet - <https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html>
- OWASP Logging Cheat Sheet - <https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html>
