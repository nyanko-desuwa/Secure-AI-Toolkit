# References

One file per standard this skill maps to. Summaries, not copies — link to the source for the
full text.

```text
references/
├── README.md            this file
└── <standard>-<ver>.md  one per standard
```

## What each reference file needs

- The version, and the date you verified it against the source
- The source URL
- The category or chapter list, verbatim IDs and names
- For each entry, the question it implies. `A01 Broken Access Control` is a label; "is every
  object access scoped to the acting user server-side?" is usable

## Version pinning

Category IDs move between editions. Guidance written against a stale ID mis-maps every
finding, which is worse than no mapping at all — a reviewer trusts the number.

So every reference file opens with:

```markdown
> Version <X>, verified <YYYY-MM-DD> against <URL>.
```

Fetch the source when you write it. Do not reconstruct a category list from memory: the
2021→2025 Top 10 renumbering is exactly the kind of change that looks plausible either way.

## Worked example

`skills/core/owasp/references/` holds three: the Top 10 2025, the API Security Top 10 2023,
and an ASVS 5.0 chapter map. The ASVS one also records what each verification level is for,
since that is the part people get wrong.
