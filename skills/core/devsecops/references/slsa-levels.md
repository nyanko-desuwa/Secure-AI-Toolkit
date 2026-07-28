# SLSA Build Levels

SLSA specification version 1.2, status Approved. Verified 2026-07-28 against
<https://slsa.dev/spec/> and <https://slsa.dev/spec/v1.2/build-track-basics>.

SLSA is a set of incrementally adoptable supply-chain security tracks. This skill uses the Build
track. Version 1.2 also has a Source track; do not quote Build levels as an assessment of source
control.

## Build Track

| Level | Name | Producer/platform requirement | What it buys |
|---|---|---|---|
| Build L0 | No guarantees | Nothing required | No SLSA assurance. Suitable for local development/test artifacts that are not released |
| Build L1 | Provenance exists | The producer uses a consistent build process and an L1 platform. The platform automatically generates provenance covering who built, the process, and top-level inputs. Provenance may be incomplete or unsigned | Consumers can inspect how an artifact claims to have been built, but forgery or bypass is trivial |
| Build L2 | Hosted build platform | Everything in L1, plus a hosted platform generates and authenticates/signs the provenance. Consumers verify authenticity | Protects provenance against post-build tampering and moves trust to an auditable build platform |
| Build L3 | Hardened builds | Everything in L2, plus builds cannot influence one another and user-defined build steps cannot access provenance signing secrets | Resists build-time tampering by insiders, stolen build credentials, and other tenants; requires real platform isolation |

Other authentication mechanisms can satisfy the provenance authenticity objective; signatures are
the common implementation.

## Provenance Is Not a Security Verdict

Provenance is machine-generated metadata about how an artifact came to be: builder identity, build
process, parameters, and top-level inputs. Higher levels make that statement harder to forge.
Provenance does not say the source code is safe, the dependencies are vulnerability-free, or the
build process is desirable.

A consumer must verify provenance against policy. Producing an attestation and never checking it is
not an integrity control.

## Practical Adoption

`A03:2025` · `A08:2025` · ASVS V15 · NIST SSDF PS.2, PS.3 · CWE-506

1. L1: generate provenance automatically at release and bind it to the artifact digest.
2. L2: move releases to a hosted build service that signs provenance. Verify builder identity,
   repository, workflow/ref, and artifact digest before deployment.
3. L3: use isolated, ephemeral build workers; prevent build steps from accessing the signing key;
   assess platform administration and cross-tenant controls.
4. Keep admission verification at the consumption boundary. Trust policy names allowed issuers,
   identities, repositories, refs/environments, and required predicates.

For many teams L2 is the practical first target. Do not label a project "SLSA L2" solely because
cosign signed an image. The build platform and provenance requirements must all be met.

## Signing with cosign

Cosign can create keyless signatures using an OIDC identity and record them in Sigstore's
transparency infrastructure. Verification must constrain the expected certificate issuer and
identity, not merely check that some valid signature exists.

```bash
cosign verify \
  --certificate-identity-regexp '^https://github.com/acme/app/.github/workflows/release.yml@refs/tags/v[0-9].*$' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  'registry.example/app@sha256:REPLACE_WITH_DIGEST'
```

This is a policy example. Replace the identity, registry, and digest. Pin the cosign binary or
installer action and verify its release before use.

## Admission-Time Verification

The admission controller, deployment service, or release consumer should reject unless all apply:

- the requested artifact uses an immutable digest;
- the signature is valid;
- certificate issuer and workload identity match policy;
- provenance refers to the same digest;
- builder ID, repository, and protected ref/environment are allowed;
- required SBOM/provenance predicates exist and pass policy.

Verifying a mutable tag and then deploying the tag has a time-of-check/time-of-use gap. Verify and
deploy the same digest.

## Reproducible Builds

Reproducible builds allow an independent party to rebuild the same inputs and compare output
bytes. This can corroborate provenance and expose undisclosed inputs. It is feasible only when the
toolchain controls timestamps, locale, ordering, network resolution, compiler versions, and other
sources of nondeterminism.

Pursue reproducibility where feasible, but do not make it a prerequisite for provenance. Record
remaining nondeterminism and pin all controllable inputs.

## Version Note

SLSA v0.1 used one sequence of levels 1 through 4. SLSA v1.0 introduced the Build track with L0
through L3. SLSA v1.2 is the version used here. Do not copy an older "SLSA 4" checklist into a
v1.2 assessment; the model and requirements changed.

## Sources

- SLSA v1.2 specification — <https://slsa.dev/spec/>
- Build track basics — <https://slsa.dev/spec/v1.2/build-track-basics>
- Build requirements — <https://slsa.dev/spec/v1.2/build-requirements>
- Verifying artifacts — <https://slsa.dev/spec/v1.2/verifying-artifacts>
- Sigstore cosign — <https://docs.sigstore.dev/cosign/>
