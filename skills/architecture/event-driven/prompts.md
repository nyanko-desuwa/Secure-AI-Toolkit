# Prompt Examples

Prompts that produce structure instead of a lecture on pub/sub. Each names the scope, the hazard in
play, and the shape of the answer wanted. Hazard labels E1-E9 are in [SKILL.md](SKILL.md).

## Decide whether it should be an event at all

```
We have a checkout that currently calls the inventory service synchronously. Someone proposed
publishing OrderPlaced and letting inventory subscribe. Using skills/architecture/event-driven,
tell me what the user is told if the reservation later fails, and whether this should stay a
synchronous call. If it should, say so.
```

Why it works: it forces the question the pattern hides. Async does not make a dependency optional,
it makes the failure invisible.

## Find every handler that trusts the payload's identity

```
Grep src/consumers/ for handlers that read userId, tenantId, role, permissions, or isAdmin from
the message. For each, tell me which branch the field controls and what a principal with publish
rights on that topic could do. Cite E1 / A01:2025 / CWE-863 where it applies. Do not report
fields that are only used as lookup keys.
```

The exclusion in the last sentence is what keeps the output short enough to act on.

## Review one event contract for over-broad payload

```
Read the schema for customer.updated and list every field. For each, name which consumer needs
it. Then tell me what a new subscriber would gain access to on day one, and what the topic's
retention means for the personal data in there. E2, ASVS V14.
```

Asking about a hypothetical new subscriber is stronger than asking whether the payload is too big.
The first surfaces the trust model; the second gets answered with "it seems fine".

## Audit the deserialization path

```
Show me how message bodies are turned into objects in src/consumers/. For each path, tell me
whether the payload can influence which class is constructed, and whether unknown fields are
ignored, rejected, or assigned. Flag any pickle, ObjectInputStream, YAML full loader, or
enableDefaultTyping. E3, CWE-502.
```

## Check idempotency the way a redelivery would

```
This handler runs behind an at-least-once consumer. Walk me through delivery of the same message
twice, including a crash after the side effect and before the ack. If a dedupe key exists,
confirm it commits in the same transaction as the effect. Do not accept a SELECT-then-INSERT as a
fix; explain the race if that is what you find.
```

The last sentence pre-empts the most common wrong answer. `CWE-367` is the race.

## Audit the dedupe store for growth

```
Find the dedupe or idempotency key store. Tell me what the key is derived from, whether a caller
can influence it, whether entries expire, and what the retention is relative to the broker's
maximum redelivery window. If the key is caller-controlled and entries never expire, say what
volume of requests it takes to become a problem. E9, CWE-770.
```

The caller-controlled question turns a leak into an exhaustion vector, which changes the severity.

## Review the failure path per class of failure

```
For each consumer in src/consumers/, tell me what happens on: a schema-invalid message, an
authorization failure, a transient dependency timeout, and a permanent business rejection. I want
four answers per consumer, plus whether the retry has a ceiling and whether the DLQ has an alert.
E6, E9.
```

Asking for four distinct answers is what exposes handlers that treat every failure as retryable.

## Audit subscription lifecycle

```
Read src/**/*.ts for calls to on(), subscribe(), addListener(), and consume(). For each, find the
matching teardown and the scope it is bound to. Report registrations inside a request handler, a
loop, or a React effect without cleanup. Classify against skills/architecture/performance leak
shapes and give me the bounded rewrite. E9, CWE-401.
```

## Review broker configuration for topic authorization

```
Read the broker config and the IAM or ACL definitions in infra/. Tell me per topic who can
produce and who can consume. Flag any credential shared by more than one service, any topic
readable by everything, and whether TLS is required on the listener. E8, A02:2025.
```

## Cost a schema change before shipping it

```
We want to add a required field customerSegment to order.placed and remove shippingAddress.
List every consumer, say what each does on receipt of an old-format and a new-format message,
and give me the ordered rollout. If either change is breaking, say which consumers break and how
loudly. E7.
```

Asking "how loudly" separates a break that pages someone from one that silently drops messages.

## Anti-patterns

| Prompt | Problem |
|---|---|
| "Make this event-driven" | No consumer, no contract, no failure path. Produces an emitter and a topic name |
| "Add an event bus" | Skips the question of whether anything needs to fan out. You get infrastructure and one subscriber |
| "Set up Kafka for this project" | Product choice before the ordering, retention, and authorization requirements exist |
| "Make this handler idempotent" | Gets a `Set` of seen IDs in module scope: unbounded, in-process, lost on restart |
| "Add retries to the consumer" | Produces an uncapped loop against a failing dependency unless a ceiling and a DLQ are asked for |
| "Add a dead-letter queue" | Gets a topic with nothing draining it and no alert. Ask for the owner and the alert in the same prompt |
| "Validate the event payload" | Answered with a shape check. Say "parse with a closed schema and re-authorize the action" |
| "Publish the full order object so consumers have what they need" | E2 stated as a requirement. Ask which consumer needs which field |
| "Is my event-driven architecture correct?" | No scope. Ask about one topic, one handler, or one failure path |
| "Why did this run twice?" | Fine as a symptom, but pair it with the ack mode and the visibility timeout or you get guesses |
| "Make the events secure" | Gets signing, which proves origin and authorizes nothing. Name the boundary you want enforced |
