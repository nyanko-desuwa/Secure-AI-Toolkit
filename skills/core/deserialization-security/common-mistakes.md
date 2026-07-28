# Deserialization Common Mistakes

## "The data is signed"

Integrity can prove a known trusted producer, but it does not make an unsafe general-purpose object
format suitable for every consumer or future key compromise. Prefer data-only representations.

## "Base64 makes it safe"

Base64 is encoding, not validation. The decoded bytes retain all parser behavior.

## "safe_load means business validation"

A safe YAML loader prevents type construction; it does not enforce fields, ranges, ownership, or
business authorization. Parse into a strict schema afterward.

## "XXE is only about local files"

External entities can trigger network requests and entity expansion can exhaust resources. Disable
resolution and set limits together.

## "Only administrators import this file"

Admin browsers, queues, and files are still input boundaries. An attacker can often influence an
admin's source data or compromise an upstream system.