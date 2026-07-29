# Deserialization Security Checklist

## Inventory and trust boundary

- [ ] Every parser/deserializer call has a documented input source and trust level.
- [ ] Bytes from request, queue, cache, file, database, or peer are not called trusted merely because another service sent them.
- [ ] Legacy serialized state has a migration or isolation plan.

## Object/type deserialization - CWE-502

- [ ] `pickle`, Java `ObjectInputStream`, .NET `BinaryFormatter`/`LosFormatter`, and PHP `unserialize` do not process untrusted input.
- [ ] Data-only formats and strict schemas replace behavior-carrying formats where possible.
- [ ] If a legacy format remains, type allowlist, integrity protection, size/depth limits, and process isolation are documented.
- [ ] Polymorphic type names cannot select arbitrary application classes.

## YAML and XML - CWE-611/CWE-776

- [ ] YAML uses a safe loader that constructs plain data only.
- [ ] XML disables external general/parameter entities and remote resource resolution.
- [ ] Parser has document size, depth, expansion, and timeout limits.
- [ ] XML/XSLT/schema locations cannot fetch arbitrary network/file resources.

## Return

- [ ] Tests use malformed, oversized, foreign-type, and external-reference inputs without real exploit payloads.
- [ ] Findings distinguish confirmed reachable unsafe decode from dead/development-only code.
