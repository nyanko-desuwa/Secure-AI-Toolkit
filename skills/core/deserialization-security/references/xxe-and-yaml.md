# XML and YAML Parser Controls

Sources: CWE-611 <https://cwe.mitre.org/data/definitions/611.html>, CWE-776
<https://cwe.mitre.org/data/definitions/776.html>, OWASP XXE Prevention Cheat Sheet. Checked:
2026-07-28.

Disable XML external general and parameter entities, external DTD/schema/resource resolution, and
network access before parsing untrusted XML. Set document size, nesting, expansion, and time limits.
Use a YAML safe loader that constructs plain scalars, collections, and mappings rather than language
objects, then validate the resulting data with an application schema.
