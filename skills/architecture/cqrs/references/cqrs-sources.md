# CQRS Sources

Primary sources for the pattern claims in this skill. Each entry states what it is used for and
the date the page was checked.

## Martin Fowler, CQRS

<https://martinfowler.com/bliki/CQRS.html> - verified 2026-07-28.

Fowler credits the pattern to Greg Young and states the core idea as using a different model to
update information than the model used to read it. The two models are usually distinct object
models, potentially in separate processes or on separate hardware, and they may share a database
or use separate ones.

Used in this skill for the "when NOT to use" position, which is Fowler's own and is unusually
blunt for a pattern writeup:

- For most systems CQRS adds risky complexity.
- Apply it to a particular portion of a system - a bounded context in DDD terms - never the whole
  system.
- Domains complex enough to warrant it are very much the minority case; usually command and query
  overlap enough that one shared model is simpler.
- Misapplied, it reduces productivity and increases risk, even in the hands of a capable team.
- For demanding queries in a domain that is not a CQRS fit, use a reporting database instead:
  keep the main system for most queries and offload only the expensive ones.

Fowler mentions eventual consistency once, and frames it as a consequence rather than a benefit -
maintaining two models raises the question of how hard to keep them consistent, which raises the
likelihood of using eventual consistency.

On event sourcing he positions it as an adjacent fit, not a requirement. CQRS fits well with
event-based programming models, and CQRS systems are often decomposed into services communicating
via event collaboration, which makes event sourcing easy to take advantage of. That is the basis
for keeping event sourcing optional and separate in `best-practices.md`.

## Azure Architecture Center, CQRS pattern

<https://learn.microsoft.com/en-us/azure/architecture/patterns/cqrs> - verified 2026-07-28. Page
`ms.date` 2025-02-20.

Used for the level table in `SKILL.md`. Microsoft describes two approaches to read/write model
separation:

- Separate models in a single data store - the foundational level. Both models share one database
  but maintain distinct logic. The write model holds validation and domain logic; the read model
  serves DTOs or projections optimised for presentation and avoids domain logic.
- Separate models in different data stores - the advanced level. Each model scales to match its
  load and can use a different storage technology.

Points this skill leans on directly:

- Security is listed as one of the problems with a single shared model: it is difficult to manage
  security when entities are subject to both read and write operations, and that overlap can
  expose data in unintended contexts. This is the same claim the skill makes about the read model
  being a second path.
- When separate stores are used, the write model typically publishes events that the read model
  consumes. Because message brokers and databases usually cannot be enlisted in a single
  distributed transaction, consistency problems occur between updating the database and publishing
  the event. That is the dual-write problem the outbox pattern addresses.
- Commands should represent specific business tasks rather than low-level data updates - "Book
  hotel room", not "Set ReservationStatus to Reserved".
- Queries never alter data and return DTOs with no domain logic.
- Stated as not suitable when the domain or business rules are simple, or when a CRUD-style UI and
  data access operations are sufficient.
- On combining with event sourcing: generating materialized views can consume significant time and
  resources, and snapshots at intervals reduce the need to reprocess full event history.

## microservices.io, Transactional Outbox

<https://microservices.io/patterns/data/transactional-outbox.html> - verified 2026-07-28.

Used for the outbox section in `best-practices.md`.

The problem: a command often has to change database state and emit messages at the same time, and
two-phase commit is not an option. Sending mid-transaction risks a rollback that the broker never
sees; sending after commit risks a crash before the message goes out. Ordering matters too -
events must reach the broker in the sequence the service produced them, including across multiple
instances updating the same aggregate.

The mechanism: the message is written to the database inside the same transaction that updates the
business entities. A separate process - the message relay - then sends the messages to the broker.
In a relational database the outbox is a table of pending messages. Two relay implementations are
referenced: transaction log tailing and polling publisher.

Drawbacks the page names, and which this skill repeats rather than glossing over:

- Error prone in practice; a developer can forget to publish the event after the database update.
- The relay may deliver duplicates - for example by crashing after publishing but before recording
  that it did, then republishing on restart.

On idempotency the page is explicit: a message consumer must be idempotent, perhaps by tracking
the IDs of messages it has already processed. It notes this is usually not a burden, since
consumers already need idempotency because brokers can deliver more than once. That is the basis
for the `last_event_seq` guard in the projector examples.

## GDPR Article 17, right to erasure

<https://gdpr-info.eu/art-17-gdpr/> - verified 2026-07-28.

Used for the PII-in-an-immutable-log section. Article 17 is titled "Right to erasure ('right to be
forgotten')". Paragraph 1 gives a data subject the right to have personal data erased without
undue delay, and places a matching obligation on the controller, where at least one listed ground
applies. Grounds include: the data is no longer necessary for the purpose it was collected for,
consent is withdrawn and no other legal basis exists, the data subject objects and nothing
overrides the objection, the processing was unlawful, erasure is required by law, and the data was
collected in connection with information society services offered to a child.

Paragraphs 2 and 3 add a notification duty for data made public and five exemptions covering free
expression, legal obligations and public-interest tasks, public health, archiving/research/
statistics, and legal claims.

This skill's use of it is narrow: an append-only event store and an erasure obligation are in
direct conflict, and "the store is immutable" is not one of the listed exemptions. Whether
crypto-shredding discharges the obligation in a given jurisdiction is a legal question. The
summary above is a reading of the text, not legal advice.

## What is deliberately not cited

- No CVE is referenced. Cross-tenant read-model exposure is a design failure in application code,
  not a vulnerability in a named product.
- No ASVS requirement IDs. 5.0.0 renumbered them relative to 4.0.3, so this skill cites chapters
  only. See `owasp-cqrs-mapping.md`.
- No benchmark numbers for projection lag, replay duration, or index overhead. Those depend on row
  count, row width, and hardware. The skill tells you to measure and state the basis; it does not
  invent a figure.
