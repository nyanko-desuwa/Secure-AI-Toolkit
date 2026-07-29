# Common Mistakes

What goes wrong in practice, and why the fix works. These are mistakes made by people who
already know the rule - the interesting cases are where the wrong version looks right.

## <Mistake, phrased as the thing someone actually does>

`<category>` · `<CWE-nnn>`

<What it looks like in a diff. One or two sentences.>

```<language>
# Vulnerable: <the exploitation, concretely>
<minimal code>
```

<Why it survives review: what makes it look correct. This is the part worth writing.>

```<language>
# Fixed
<minimal code>
```

<Why the fix closes it. Name the weaker fix people reach for first and say what it misses.>

## <Mistake>

`<category>` · `<CWE-nnn>`

<...>

## Quick table

For mistakes that need no more than a line each.

| Mistake | Why it fails | Fix |
|---|---|---|
| <...> | <...> | <...> |

## Sources

- <https://owasp.org/...>
- <https://cwe.mitre.org/data/definitions/nnn.html>
