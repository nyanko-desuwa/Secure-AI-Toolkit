# SBOM formats — CycloneDX and SPDX

> Verified 2026-07-28 against <https://cyclonedx.org/specification/overview/>,
> <https://spdx.dev/use/specifications/> and <https://spdx.github.io/spdx-spec/>.

Two formats, both a list of components with identity and relationships. CycloneDX grew out of
security use cases, SPDX out of licence compliance. Both now cover both. Pick one per
organisation and hold to it — a consumer that parses one format and is handed the other has no
inventory, only a file.

## Versions

| Format | Current | Notes |
|---|---|---|
| CycloneDX | 1.7, released 2025-10-21 | Developed by the OWASP Foundation and Ecma International. Published as ECMA-424 on 2025-12-10. Technical work sits with Ecma TC54 |
| SPDX | 3.0.1, specification site; spdx.dev lists 3.0 as current | Previous versions listed: 2.3, 2.2, 2.1, 2.0, 1.2, 1.1, 1.0 |

spdx.dev states the SPDX specification is an international open standard, ISO/IEC 5962:2021.
The page does not say which SPDX version that ISO edition corresponds to, so do not assert a
mapping.

CycloneDX carries its version in the media type:
`application/vnd.cyclonedx+xml; version=1.7;`. Tooling that ignores the parameter will parse an
older document against newer assumptions and quietly drop fields.

CycloneDX 1.7 supports JSON, XML, and Protocol Buffers. Its official object model goes beyond a
software package list: components can be software, hardware devices, machine-learning models,
source, and configurations; services describe external APIs and trust-boundary crossings; its
Vulnerabilities object supports vulnerability disclosure and VEX. The specification names SBOM,
SaaSBOM, and HBOM varieties directly.

SPDX 3.0.1 is profile-based. The specification lists Core, Software, Security, Licensing,
SimpleLicensing, ExpandedLicensing, Dataset, AI, Build, Lite, and Extension profiles. Use this
when the inventory has to carry licence expressions, build information, datasets, or AI model
relationships in one graph. The site pages read here did not enumerate the normative
serialisation formats, so this reference does not invent them.

## What each is for

| Need | Prefer | Reason |
|---|---|---|
| Security inventory, services, VEX, operational vulnerability response | CycloneDX | Security-first object model and broad BOM varieties |
| Licence and legal inventory, cross-domain graph with dataset/AI/build profiles | SPDX | Licence lineage and explicit profiles |
| A customer names a format/version | The named one | Interoperability beats preference |
| No consumer exists | Neither yet | Build the consumption path first; a file nobody reads is not a control |

Neither choice proves completeness. Tool coverage and the build/scan vantage point decide more
than the schema.

## Build-time versus scan-time

This is the distinction that decides whether an SBOM is worth generating.

A scan-time SBOM is produced by pointing a scanner at a finished artefact — a container image,
a directory, a released tarball. It reports what it can recognise from what survived the build:
package manager databases, vendored manifests, filenames it has fingerprints for.

What it misses, structurally:

- Statically linked or vendored native libraries with no manifest left behind
- Dependencies fetched, compiled, and deleted inside the build
- Anything installed by `curl | tar` into `/usr/local`, because no package database records it
- Build-time-only components — the compiler, the code generator, the test runner — which are
  exactly the components a build-tampering attack targets
- Which of two candidate versions was actually linked, when both are present on disk

A build-time SBOM is emitted by the build from its own resolved dependency graph. It has the
exact versions and hashes the build used, it includes development and test scopes, and it can
be signed as part of the same attestation that covers the artefact — so the SBOM is bound to a
digest rather than floating beside it.

Run both. Build-time for accuracy and attestation, scan-time against the deployed artefact to
catch what the build never declared, chiefly base-image OS packages. When the two disagree,
that disagreement is the finding: something entered the artefact outside the declared graph.

## Consuming an SBOM

Generating one and filing it satisfies nobody. The inventory earns its keep at correlation
time:

1. Store every SBOM keyed by artefact digest, not by version string. Two builds of `v1.4.2`
   are two artefacts.
2. Feed SBOMs into a component inventory that re-evaluates them as advisories land — OWASP
   Dependency-Track is the tool the A03 prevention text names for this.
3. Correlate against OSV, NVD, and ecosystem advisories continuously, not on release day. The
   value is answering "which running builds contain the bad version" in minutes.
4. Keep the version-to-deployment map. An SBOM that cannot be tied to what is currently
   running answers a historical question.

ASVS 15.1.2 (L2) is the requirement: maintain an inventory catalog, such as an SBOM, of all
third-party libraries in use, and verify components come from pre-defined, trusted, and
continually maintained repositories. Note the second clause — the inventory alone does not
satisfy it.

## Generating and gating

`A03:2025` · ASVS 15.1.2

```bash
# Exact shipped image, not a mutable source directory
syft "registry.example/app@sha256:${DIGEST}" \
  -o cyclonedx-json=sbom.cdx.json \
  -o spdx-json=sbom.spdx.json

# Gate the inventory. Generation without this is archival.
grype "sbom:sbom.cdx.json" --fail-on high

# Bind the chosen SBOM to the image digest as an in-toto attestation
cosign attest --yes --type cyclonedx \
  --predicate sbom.cdx.json \
  "registry.example/app@sha256:${DIGEST}"
```

npm 10.9.3 also exposes both schemas:

```bash
npm sbom --sbom-format cyclonedx --sbom-type application > sbom.cdx.json
npm sbom --sbom-format spdx --sbom-type application > sbom.spdx.json
```

`npm sbom` reads the installed tree by default. `--package-lock-only` reads intent from the
lockfile. Generate from the graph and scan the artefact; neither view alone is complete.

## Limitations worth saying out loud

- An SBOM is a claim. Unsigned and unattested, it inherits the trustworthiness of whoever
  handed it to you.
- Component identity is the weak joint. Ecosystem-specific identifiers (`purl`) work well;
  matching an OS package or a vendored C library to a CVE identifier is still lossy, and both
  false positives and misses come from there.
- Presence is not reachability. An SBOM tells you a vulnerable version is included, not that
  the vulnerable function is called. Do not promise your triage process more precision than
  the inventory has.
- Neither format records why a component was chosen or who reviewed it. Provenance and review
  history live elsewhere.

## Sources

- <https://cyclonedx.org/specification/overview/>
- <https://spdx.dev/use/specifications/>
- <https://spdx.github.io/spdx-spec/>
- <https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/>
- OWASP Dependency-Track — <https://dependencytrack.org/>
