# Ports and Adapters, the original description

Verified 2026-07-28 against Alistair Cockburn's pattern write-up:
<https://alistair.cockburn.us/hexagonal-architecture/>.

## Source

Alistair Cockburn, "Hexagonal architecture". The page presents the pattern under the name
"Ports and Adapters (Object Structural)", with "Hexagonal Architecture" given as an alternative
name, and identifies it as a use of the generic Adapter pattern from Design Patterns.

It is a pattern description, not a versioned standard. No requirement IDs, no conformance levels,
no security mappings originate here.

## Stated intent

The intent on the page is to allow an application to be driven equally by users, programs,
automated tests, or batch scripts, and to be developed and tested in isolation from the eventual
runtime devices and databases.

Two things follow from that sentence, and they are the whole basis for this skill's security
argument:

- If a test script and a production HTTP request enter through the same port, then whatever the
  port enforces is enforced for both. Whatever only the HTTP adapter enforces is enforced for
  neither the test nor any adapter added later.
- If the application is developed without the database, then the database's behaviour - including
  a tenant predicate - is the adapter's responsibility, and the core cannot assume it.

## Mechanism

External events arrive at a port. A technology-specific adapter converts the event into a
procedure call or message the application understands. Outbound, the application sends through a
port to an adapter that produces whatever signals the receiving technology needs.

The page stresses that the meaningful distinction is inside versus outside, not left versus right,
and that code on the inside must not leak outward. The application is described as remaining
ignorant of what lies beyond its adapters.

In this skill's terms: a transport type, ORM entity, or broker message in a core signature ends
the pattern, because the core is then no longer ignorant of what lies beyond the adapter, and no
new adapter can call the core without fabricating that type.

## Primary and secondary

The page distinguishes two kinds of port and adapter, also called driving adapters and driven
adapters.

| | Primary / driving | Secondary / driven |
|---|---|---|
| Actor relationship | Primary actors drive the application out of quiescence | Actors the application drives, to query or to notify |
| Drawn | Left, or top | Right, or bottom |
| Natural test substitute | A test framework that reads a script and drives the app | Mocks that answer queries and record events |

Cockburn notes that this primary/secondary mapping should be a consequence of applying the
architecture rather than a shortcut around it, and that the real payoff is being able to run the
application in full isolation.

The security consequence this skill draws from the split: primary ports are where every actor
converges, so they are the natural authorization choke point. Secondary ports are where outside
data enters, so they are the natural validation and egress-control choke point. Neither of those
claims is made by the source.

## Number of ports

The page treats the count as largely a matter of taste. Neither one port per use case nor
collapsing everything into two extremes is presented as optimal. The stated preference is a small
number - two, three, or four - with four reported as the most encountered in practice.

The hexagon shape is not about the number six. Six sides simply leave drawing room for ports and
adapters without forcing a one-dimensional layered picture.

This is the source for the skill's position that one port per adapter means you have renamed your
controllers. If the number of ports tracks the number of adapters, the ports are not abstractions.

## Related patterns named on the page

MVC and its variants are described as applying the idea to primary ports only. The page also cites
Rubel's Pedestal, Cunningham's Checks, the Loopback pattern, and Martin's Dependency Inversion
with Fowler's Dependency Injection, optionally via a container, for swappable secondary adapters.

## What the source does not establish

- It does not claim a security benefit, and it makes no OWASP, ASVS, or CWE mapping.
- It does not prescribe a directory layout, a naming convention, or a package structure.
- It does not require a DI container, a repository per aggregate, or a DTO per boundary.
- It does not say where authorization belongs.
- It says nothing about connection lifetime, pooling, subscription teardown, or memory.
- It does not state when the pattern is not worth its cost.

Everything in this skill about actors in port signatures, adapter-side validation, egress control,
error translation, resource lifetime, and when not to use the pattern is this skill's application
of the pattern, not a claim by the source.

## Verification notes

- Pattern name, alternative name, classification as a use of Adapter, the intent sentence, the
  inside-versus-outside framing, the primary/secondary split with its test substitutes, and the
  "two, three or four ports" preference were checked on 2026-07-28.
- Cockburn's page references his own earlier HaT technical report for the pattern write-up. This
  skill cites the page, not a report number or year, because the page is what was read.
- No wording is quoted here as normative. If the page changes, re-check the intent sentence and
  the primary/secondary section before relying on the exact phrasing above.
