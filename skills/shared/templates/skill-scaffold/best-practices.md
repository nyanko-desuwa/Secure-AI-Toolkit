# <Skill Name> Best Practices

Patterns that hold up under review. Each one names the standard and chapter it serves, so a
finding can be traced back.

## <Pattern name>

`<Top 10 category>` · ASVS V<n> (<chapter name>)

<One or two sentences on the decision this pattern encodes. Lead with the failure it
prevents, not the theory behind it.>

```<language>
# Vulnerable: <what an attacker does with this>
<minimal code, no framework scaffolding>
```

```<language>
# Fixed: <what changed structurally>
<minimal code>
```

<Why the fix works. Prefer structural reasons - "there is no branch to forget" - over
"this is more secure". If the obvious alternative fix is weaker, say why: readers reach for
regex denylists and UUIDs on their own.>

Rules that follow:

- <Consequence a reviewer can check>
- <...>

## <Pattern name>

`<category>` · ASVS V<n>

<...>

## Sources

- <https://owasp.org/...>
- <https://cheatsheetseries.owasp.org/...>
