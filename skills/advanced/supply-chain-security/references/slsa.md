# SLSA v1.2 and Sigstore

> SLSA v1.2, status Approved. Verified 2026-07-28 against <https://slsa.dev/spec/v1.2/> and
> <https://slsa.dev/spec/v1.2/levels>. v1.1 is marked Retired.
>
> Sigstore cosign flags verified 2026-07-28 against
> <https://docs.sigstore.dev/cosign/verifying/verify/> and
> <https://docs.sigstore.dev/quickstart/verification-cheat-sheet/>.

SLSA is organised into tracks so progress in one dimension is not gated on unrelated work.
v1.2 has a Build track and a Source track. Build is the one with stable, widely implemented
levels; that is what this file covers.

## Build track levels

| Level | Name | Requires | Threat it addresses |
|---|---|---|---|
| Build L0 | No guarantees | Nothing. "The lack of SLSA." Local dev and test builds | None |
| Build L1 | Provenance exists | Consistent build process on an L1 platform; platform auto-generates provenance covering builder, process, and top-level inputs; provenance distributed to consumers | Nothing reliably — provenance may be unsigned and incomplete, described as "trivial to bypass or forge" |
| Build L2 | Hosted build platform | L1, plus a hosted platform that generates and signs the provenance itself, and consumers validate its authenticity | Tampering after the build |
| Build L3 | Hardened builds | L2, plus platform controls so runs cannot influence one another, and provenance signing keys are unreachable from user-defined build steps | Tampering during the build, by insiders, stolen credentials, or co-tenants |

Signing at L2 may be substituted with equivalent authenticity verification.

### What the levels mean in practice

L1 is a documentation exercise. It tells a consumer where an artefact claims to come from. It
does not stop anyone lying, so do not report L1 as an integrity control.

L2 is the first level that resists anything. The jump is moving the build off a laptop or a
self-hosted runner into a hosted platform that signs provenance the build cannot forge.

L3 is where the interesting requirement lives: user-defined build steps cannot reach the
signing key, and runs are isolated from each other. A self-hosted runner shared between
repositories fails L3 by construction, because a build in repo A can leave state that a build
in repo B picks up.

There is no L4 in v1.2. If someone reports "SLSA Level 4", ask which version they read.

### Claiming a level

State the track: "Build L2", not "SLSA Level 2". A claim covers a specific artefact produced
by a specific pipeline, not an organisation. And the consumer half matters — L2 requires that
consumers validate provenance authenticity. A pipeline that produces signed provenance nobody
checks is not L2 in effect, whatever the builder supports.

## Provenance and attestation formats

Provenance is a recommended attestation format, not mandatory. It binds a subject (an
artefact name plus its digest) to a predicate using the in-toto attestation format.

- in-toto attestation spec — <https://github.com/in-toto/attestation/tree/main/spec/v1>
- SLSA provenance predicate — <https://slsa.dev/spec/v1.0/provenance>

Verification Summary Attestations (VSA) let one party assert that it verified an artefact, so
downstream consumers can trust the verifier instead of re-running the whole check.

## Sigstore cosign

Keyless signing uses an ephemeral key and an OIDC identity instead of a stored private key.
Sigstore's supported providers on the docs page: Google, GitHub, Microsoft. The signing
command is simply:

```bash
cosign sign "$IMAGE"
```

Key-based and KMS-backed signing also exist. `cosign generate-key-pair` for a local pair;
go-cloud style URIs for managed keys: `awskms://`, `gcpkms://`, `azurekms://`,
`hashivault://`, `openbao://`, `k8s://`, `env://`.

Signatures use the OCI 1.1 referrer specification. Inspect with `cosign tree "$IMAGE"`.

### Verification — the part that is usually wrong

```bash
cosign verify "$IMAGE" \
  --certificate-identity="name@example.com" \
  --certificate-oidc-issuer="https://accounts.example.com"
```

Both flags are required for keyless verification. Without them the command checks that
*someone* signed the artefact, which is not a control. For a blob, the bundle or the explicit
signature and certificate must be supplied:

```bash
cosign verify-blob "$FILE" --bundle artifact.sigstore.json \
  --certificate-identity="name@example.com" \
  --certificate-oidc-issuer="https://accounts.example.com"
```

Issuer values from the docs: Google `https://accounts.google.com`, Microsoft
`https://login.microsoftonline.com`, GitHub `https://github.com/login/oauth`, GitLab
`https://gitlab.com`.

### Workflow identities

A signature produced by CI has a machine identity, not a human one. From the Sigstore OIDC
verification cheat sheet:

| Platform | `--certificate-oidc-issuer` | `--certificate-identity` shape |
|---|---|---|
| GitHub Actions | `https://token.actions.githubusercontent.com` | `https://github.com/USERNAME/REPOSITORY_NAME/.github/workflows/WORKFLOW_NAME@refs/heads/BRANCH_NAME` |
| GitLab CI | `https://gitlab.com` | `https://gitlab.com/PROJECT_PATH//CI_CONFIG_PATH@REF_PATH` |
| Buildkite | `https://agent.buildkite.com` | `https://buildkite.com/ORGANIZATION/APP_ID` |

Note the GitHub identity includes the workflow file and the ref. Pinning it to the release
workflow on the release branch is what stops a signature minted by an unrelated workflow —
or by a branch an attacker pushed — from passing verification. A verify step that omits the
workflow path accepts any workflow in that repository.

## GitHub-native provenance

`actions/attest` (v4) generates signed attestations; `actions/attest-build-provenance` is now
a wrapper over it, and new implementations should use `actions/attest` directly. Modes are
selected by input: provenance by default, SBOM when `sbom-path` is given, custom when a
predicate is supplied.

Required permissions:

```yaml
permissions:
  id-token: write        # mint the OIDC token for the Sigstore signing certificate
  attestations: write    # persist the attestation
  artifact-metadata: write
```

Verify with `gh attestation verify`. Availability caveat from the action's own README:
attestations are available in public repositories on current GitHub plans; private or
internal repositories require GitHub Enterprise Cloud, and they are not supported on GitHub
Enterprise Server.

## Honest limitations

- Provenance says how an artefact was built, not whether the source was good. A backdoor
  committed by a compromised maintainer produces perfect L3 provenance.
- Keyless signing moves trust to the OIDC issuer and the certificate transparency log. If an
  attacker controls the identity — a compromised GitHub account with write access to the
  release workflow — signatures verify correctly.
- The `--certificate-identity` value is the whole control. Getting it wrong, or using a broad
  regexp variant, silently widens what you accept.

## Sources

- <https://slsa.dev/spec/v1.2/>
- <https://slsa.dev/spec/v1.2/levels>
- <https://docs.sigstore.dev/cosign/signing/signing_with_containers/>
- <https://docs.sigstore.dev/cosign/verifying/verify/>
- <https://docs.sigstore.dev/quickstart/verification-cheat-sheet/>
- <https://github.com/actions/attest>
- <https://github.com/actions/attest-build-provenance>
