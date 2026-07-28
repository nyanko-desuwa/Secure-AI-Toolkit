# Event-Driven Architecture Skill

Events, queues, and brokers reviewed as what they are: a network boundary that most consumers
treat as a trusted one.

## Purpose

Ask an AI for an event-driven design and you get a publisher, a topic, a handler, and a
`@EventPattern` decorator. What you do not get is the answer to "who may publish this, and what
does the consumer believe because the message arrived".

The consumer usually believes everything. It reads `event.userId`, `event.tenantId`, and
`event.role` and acts on them, because the message came off the internal bus. That moves the
authorization decision off the request path — where a session, a token, and a policy existed —
onto an unauthenticated struct that anyone with publish rights on the topic can write. This is
the central failure of the pattern, and it is `A01:2025` with `CWE-602` and `CWE-1220` behind it.

The second reason this skill exists: an event bus is the most commonly adopted piece of
architecture that the adopting team did not need. `SKILL.md` has a "when NOT to use this"
section that is longer than most skills' recommendation sections, on purpose.

## How It Works

Plain Markdown. Nothing executes. An assistant reads `SKILL.md`, works the eight-step workflow,
and pulls the supporting file for the step it is on. Findings are labelled E1 to E9 from the
hazard table in `SKILL.md`, and the same labels are used in every other file so a finding can be
traced from checklist item to code fix.

The `allowed-tools` frontmatter limits the assistant to reading, searching, web lookup, `ls`,
and `cat`. It cannot run arbitrary commands, publish to your broker, or inspect a live queue.

## File Layout

```text
SKILL.md              hazards E1-E9, workflow, severity, when NOT to use
README.md             this file
checklist.md          pre-return verification, grouped by hazard
best-practices.md     the nine hazards with real code, each with a security and a cost note
common-mistakes.md    what goes wrong, including the wrong fixes
troubleshooting.md    when the pattern does not fit, and what you cannot verify from source
prompts.md            prompts that produce structure, plus an anti-pattern table
references/
  owasp-mapping.md    Top 10 2025 and ASVS 5.0 chapters per hazard
  cwe-event-driven.md the CWE entries cited here, titles checked at cwe.mitre.org
  broker-controls.md  Kafka ACLs, RabbitMQ delivery limits and DLX, SQS quotas
  outbox-pattern.md   transactional outbox, at-least-once, dual-write
examples/
  README.md           eight before/after pairs
```

## Standards Covered

| Standard | What it covers here | Version | Verified |
|---|---|---|---|
| OWASP Top 10 | A01, A02, A04, A06, A07, A08, A09, A10 | 2025 | 2026-07-28, pinned by the repo brief |
| OWASP ASVS | V2, V8, V11, V12, V13, V14, V15, V16 | 5.0.0 (released 2025-05-30) | 2026-07-28, pinned by the repo brief |
| CWE | 290, 359, 367, 390, 400, 401, 502, 522, 532, 602, 770, 772, 799, 841, 863, 1220 | current | 2026-07-28, `cwe.mitre.org` |

ASVS is cited at chapter level only. 5.0.0 renumbered requirements, so a requirement ID copied
from an older report now points somewhere else. Details in
[references/owasp-mapping.md](references/owasp-mapping.md).

## Configuration

None. No build step, no dependency, no environment variable.

To use it in Claude Code, keep this repository in the working directory so
`skills/architecture/event-driven/SKILL.md` is readable, or copy the `event-driven` directory
into `~/.claude/skills/`.

## Example Usage

Decide whether the event should exist at all:

```text
Read skills/architecture/event-driven/SKILL.md. We want to publish user.deleted and have three
services react. One of them must finish before we return 200 to the caller. Work the "when NOT
to use this" section against this case and tell me which of the three should stay synchronous.
```

Review a handler for the trust boundary:

```text
Using skills/architecture/event-driven, review src/consumers/*.ts. For each handler, list every
field it reads from the message and say whether that field influences an access decision. Label
findings E1-E9 and give me the re-authorization rewrite for any E1.
```

Review resource lifetime in a long-lived consumer:

```text
Review src/bus/InMemoryBus.ts and every call site of bus.on(). Which subscriptions are never
removed, is the internal queue bounded, and what happens when the producer is faster than the
handler? Map each finding to the E9 section of best-practices.md.
```

Audit the failure path:

```text
For each consumer in services/billing, tell me the retry cap, the backoff, where a permanently
failing message ends up, whether anything alerts on it, and what the dedupe store's TTL is. If
any of those is missing, say which and what the consequence is.
```

More in [prompts.md](prompts.md).

## Limitations

- Markdown guidance, not analysis. It cannot see your queue depth, consumer lag, DLQ size, or
  whether broker ACLs are actually applied. Every claim about runtime state must be verified
  against the running system, and the skill is instructed to say so rather than guess.
- Broker configuration is where most of the E8 controls live, and broker config usually is not
  in the application repository. A review that only reads application code cannot confirm topic
  authorization, TLS, or retention. Report it as unverified, not as absent.
- Languages are TypeScript and Python, with one Java/Kafka example for consumer-side commit and
  authorization. Nothing here is Go, Rust, C#, or PHP specific, though the shapes transfer.
- Broker specifics that are quoted (RabbitMQ quorum-queue delivery limits, SQS quotas, Kafka
  ACL operations) are version-sensitive. Dates and sources are in
  [references/broker-controls.md](references/broker-controls.md); re-check before relying on a
  number in production.
- Memory-leak and resource-lifecycle depth belongs to `skills/architecture/performance/`. This
  skill names the leak shapes that are specific to event-driven structure (E9) and links out for
  heap diagnosis, allocation profiling, and the general leak taxonomy.
- Exactly-once is not covered as an achievable property, because across a broker and an external
  side effect it is not one. The skill covers at-least-once plus idempotency, which is what
  actually ships.
- Whether a retention period on a topic carrying personal data satisfies a legal obligation is a
  legal question. The skill describes the technical shape and says to get it reviewed.

## Security Notes

This skill contains deliberately broken code in `best-practices.md`, `common-mistakes.md`, and
`examples/`. Every such block is labelled `Vulnerable:` and paired with a fixed version. Do not
copy a labelled-vulnerable block into a project.

Three things in here should be treated as incidents rather than design smells if found in
production:

- A consumer that grants, charges, or discloses based on a role or tenant read from the message
  body. Anyone with publish rights on the topic has that privilege (`A01:2025`, `CWE-602`).
- A message body reaching a polymorphic deserializer — `pickle.loads`, Java
  `enableDefaultTyping`, or any format where the payload names the class to construct
  (`A08:2025`, `CWE-502`).
- A poison-message handler that logs the whole payload. Events carry tokens, card fragments, and
  personal data, and the log usually has broader read access than the topic (`A09:2025`,
  `CWE-532`).

One retention point that is easy to miss: an event outlives the request that produced it. A
topic with 14-day retention holds every field you put in the payload for 14 days, replayable,
and a replay re-emits that personal data to every consumer subscribed at replay time. Payload
minimisation is a data-protection control here, not a bandwidth optimisation (ASVS V14).

All examples use clearly synthetic values — `broker.internal.example`, `user-0001`,
`REPLACE_WITH_SECRET_REF`. No real credentials, hostnames, or personal data appear in this skill.

## References

- OWASP Top 10 2025 — <https://owasp.org/Top10/2025/>
- OWASP ASVS — <https://owasp.org/www-project-application-security-verification-standard/>
- CWE — <https://cwe.mitre.org/>
- Confluent, Authorization using ACLs — <https://docs.confluent.io/platform/current/security/authorization/acls/overview.html>
- RabbitMQ, Quorum Queues — <https://www.rabbitmq.com/docs/quorum-queues>
- Amazon SQS message quotas — <https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/quotas-messages.html>
- microservices.io, Transactional Outbox — <https://microservices.io/patterns/data/transactional-outbox.html>
