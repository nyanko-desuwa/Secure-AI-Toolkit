# Deserialization Security Prompts

## Beginner

```text
Explain whether this parser treats input as plain data or as instructions that can create objects,
read other resources, or consume unlimited memory. Show the file and safe replacement.
```

## Developer

```text
Find pickle/ObjectInputStream/BinaryFormatter/unserialize/yaml.load/XML parser calls. For each trace
input origin, parser options, type selection, entity/resource resolution, and limits. Give file:line,
CWE, reachable precondition, safe API, and migration test.
```

## Review

```text
Review imports, workers, queues, cache codecs, and upload parsers for unsafe deserialization. Do not
report a generic risk: identify the concrete call, untrusted data path, dangerous capability, and
smallest data-only replacement.
```

## Audit

```text
Assess parser boundaries against OWASP A08 and ASVS V2/V5/V13. For each parser provide format,
producer/consumer trust evidence, safe configuration, resource limits, CWE, and any library behavior
that must be verified from current vendor documentation.
```

## Anti-patterns

| Weak prompt | Finding prompt |
|---|---|
| "Check serialization." | "Find each deserializer call and prove whether untrusted bytes can select a type, entity, or remote resource." |
| "Is XML safe?" | "Show entity/network/parser settings and size/depth limits for every XML entry point." |
