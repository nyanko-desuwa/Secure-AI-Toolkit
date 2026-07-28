# Deserialization Troubleshooting

## Legacy protocol requires Java/.NET serialization

Do not expose it to Internet clients. Put it behind a mutually authenticated, isolated adapter,
allowlist types if the runtime supports it, cap resources, and create a migration to data-only DTOs.

## YAML needs custom tags

Design a small explicit tag schema that maps to plain data, not arbitrary constructors. If the
library cannot guarantee that, use JSON or a restricted parser.

## XML schema validation is required

Schema validation does not automatically disable external resolution. Configure the parser first,
then provide local controlled schemas/catalogs and bounded resources.

## A parser is only used for internal queue messages

Verify producers, consumers, ACLs, and replay paths. Internal systems become external after a
compromise or misrouting event; model the queue as a trust boundary.