# Broker Controls: What the Broker Enforces For You

E8 and most of E6 are broker configuration, not application code. This file records what the
vendor documentation says, so a review can cite a control instead of asserting one. Every number
here was read from the source URL at the bottom on 2026-07-28.

Read this before recommending a setting. These values are version-sensitive, and a stale default
quoted confidently is how a review loses credibility.

## Kafka authorization (source: Confluent ACL documentation)

Resource types: Cluster, Topic, Group, TransactionalId, DelegationToken. Each is identified by a
name — topic name, group name — and patterns can be LITERAL (the default), PREFIXED, or the
wildcard `*`.

Note that Group is broader than "consumer group". The documentation states it covers Consumer
Group, Stream Group (`application.id`), Connect Worker Group, and anything else using the consumer
group protocol. A prefixed grant on Group is therefore wider than it reads.

| Principal needs | Operation | Resource | Maps to |
|---|---|---|---|
| Produce to a topic | WRITE | Topic | Produce, AddPartitionsToTxn |
| Consume from a topic | READ | Topic | Fetch, OffsetCommit, TxnOffsetCommit |
| Join a consumer group | READ | Group | JoinGroup, SyncGroup, Heartbeat, LeaveGroup, OffsetCommit, OffsetFetch, AddOffsetsToTxn, TxnOffsetCommit |
| Transactional producer | WRITE | TransactionalId | Produce, AddPartitionsToTxn, AddOffsetsToTxn, EndTxn, InitProducerId, TxnOffsetCommit |

DESCRIBE does not need a separate grant. The documentation states that when granted READ, WRITE,
or DELETE, "users implicitly derive the DESCRIBE operation". A review that flags a missing
DESCRIBE ACL on a producer that already has WRITE is flagging nothing.

Two defaults that decide whether you have a boundary at all:

- With no ACLs on a resource, only super users can access it. `allow.everyone.if.no.acl.found` in
  `server.properties` inverts that for resources with no ACLs. Confluent calls production use of
  it "strongly discouraged", and gives the reason: deleting your last ACL exposes the cluster to
  everyone, and adding the first one silently revokes access from principals who had it a moment
  earlier. If this is `true` in a cluster you are reviewing, that is the E8 finding — everything
  else is secondary.
- Deny takes precedence over allow. A broad allow plus a narrow deny is a valid shape, but the
  deny has to exist; there is no implicit deny for a principal already covered by a wildcard
  allow.

Super users bypass ACLs entirely, and wildcards do not work there — `User:*` in `super.users` does
not make everyone a super user. The broker principal must be a super user or replication breaks.

What this means for a review: "our services authenticate to Kafka" is not authorization. Ask for
the ACL list per principal. One principal shared by every service with WRITE on `*` is a single
credential that can forge any event on any topic (`CWE-522`, `CWE-1220`).

IdempotentWrite is not covered on the page consulted, so nothing is claimed about it here. Check
the Kafka version's own security section before recommending it.

## RabbitMQ quorum queues: redelivery, delivery limit, dead lettering

Redelivery tracking:

- `x-delivery-count` header carries failed redelivery attempts.
- RabbitMQ 4.3 adds `x-acquired-count`, counting how many times a message was assigned to a
  consumer. The documentation calls it "the recommended header for tracking the number of times a
  message has been assigned to a consumer."

Delivery limit:

- Default is 20, since RabbitMQ 4.0. On exceeding it, the message "will be dropped (removed) or
  dead-lettered (if a DLX is configured)". Dropped, if you have no DLX. That is the E6 data-loss
  path, on by default.
- Queue argument `x-delivery-limit`, policy key `delivery-limit`.
- `-1` disables the limit and restores 3.13.x behaviour. The documentation says plainly: "This is
  _not_ recommended."
- As of 4.3 the limit is evaluated against delivery-count rather than acquired-count, so `nack`
  and AMQP 1.0 `modify` with `delivery_failed=false` do not advance it. `reject`, `modify` with
  `delivery_failed=true`, and channel or session crashes do. A requeue loop built on `nack`
  therefore does not terminate via the delivery limit.

Dead lettering:

- Policy keys: `dead-letter-exchange`, `dead-letter-routing-key`, `dead-letter-strategy`
  (`at-most-once` is the default, `at-least-once` is the other option), and `overflow`, which must
  be `reject-publish` for `at-least-once` to take effect.
- The internal dead-letter consumer's prefetch is `dead_letter_worker_consumer_prefetch` in
  advanced config, default 32.
- The guidance is that every quorum queue should have some dead-letter configuration so dropped
  messages are not lost. A low-priority stream is suggested as a cheap retention target.

Example from the documentation, combining both:

```json
{"delivery-limit": 50, "dead-letter-exchange": "redeliveries.limit.dlx"}
```

applied with `--apply-to "quorum_queues"`.

For requeue loops, 4.3 offers delayed retry (`x-delayed-retry-type` / `delayed-retry-type`,
`x-delayed-retry-min`, `x-delayed-retry-max`) and the documentation recommends it over leaning on
the delivery limit.

## Amazon SQS quotas that change a design

| Quota | Value |
|---|---|
| Message size | 1 byte minimum, 1,048,576 bytes (1 MiB) maximum |
| Message retention | 4 days default; 60 seconds minimum, 1,209,600 seconds (14 days) maximum |
| Visibility timeout | 30 seconds default; 0 minimum, 12 hours maximum |
| Message timer (delay) | 0 seconds default, 15 minutes maximum |
| Batch size | 10 messages per batch request |
| Message attributes | 10 metadata attributes per message |
| Message content | XML, JSON, unformatted text; a restricted Unicode range, other characters rejected |
| Queue policy | 8,192 bytes, 20 statements, 50 principals, or 10 conditions |

Three consequences for the hazards in this skill:

- Visibility timeout is the redelivery clock. A handler that takes longer than the visibility
  timeout will have its message delivered to a second consumer while the first is still working.
  That is the most common source of E4 duplicates, and it is a configuration mismatch rather than
  a code bug. The dedupe store's TTL must exceed the retention period, not just the visibility
  timeout, because a message can be redelivered any time within retention.
- Retention up to 14 days is the E2 retention argument in concrete terms: whatever personal data
  you put in the payload is held, and replayable, for up to two weeks after the request that
  produced it completed.
- The 1 MiB ceiling is what pushes teams to the Extended Client Libraries, which store the payload
  in S3 and put a reference in the message. That moves the authorization question to the S3
  object: whoever can read the message can read the object. Check the bucket policy, not just the
  queue policy.

`MessageGroupId` is required on FIFO queues; sending without it fails. On standard queues it
enables fair queues. Valid characters are alphanumeric plus punctuation, 128 characters. Do not
use a raw email address or any personal identifier as the group ID — it is metadata, it appears in
logs and metrics, and it is not covered by whatever you did to the payload.

## What none of these give you

- None of them re-authorize a business action. Broker ACLs answer "may this principal publish to
  this topic". They never answer "was the user in this message allowed to trigger this refund".
  That is E1 and it stays in your code.
- None of them make delivery exactly-once end to end. SQS standard is at-least-once by design;
  Kafka's transactional guarantees cover the read-process-write cycle inside Kafka, not your
  external side effect. Idempotency in the handler is not optional (E4).
- None of them validate your schema. A registry can reject an incompatible schema at publish
  time; it does not stop a valid-schema message from carrying a hostile value.

## Verification status

Kafka ACL details come from the Confluent platform documentation rather than the Apache Kafka
site — the `kafka.apache.org/documentation#security` anchor returned a redirect stub when fetched
on 2026-07-28, with no content. Confluent's page covers Apache Kafka's authorizer semantics, but
if you need the Apache wording, fetch a versioned path such as
`kafka.apache.org/40/documentation/#security_authz`.

Everything else was read directly from the vendor page listed below.

## Sources

- Confluent, Authorization using ACLs — <https://docs.confluent.io/platform/current/security/authorization/acls/overview.html> (verified 2026-07-28)
- RabbitMQ, Quorum Queues — <https://www.rabbitmq.com/docs/quorum-queues> (verified 2026-07-28)
- Amazon SQS message quotas — <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/quotas-messages.html> (verified 2026-07-28)
