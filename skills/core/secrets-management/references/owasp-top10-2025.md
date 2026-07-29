# OWASP Top 10 2025 - the two categories that carry secrets

Source: <https://owasp.org/Top10/2025/> · verified 2026-07-28

The 2025 edition is not a renumbering of 2021. A03 and A10 are new, and Injection moved from
A03 to A05. If a project's tooling still emits 2021 IDs, map them rather than renumbering
silently.

Secrets work lands mainly in two categories, with three more appearing depending on where the
credential leaked.

## A02:2025 - Security Misconfiguration

The delivery path. A secret that is handled correctly in code and wrong in the pipeline, the
image, or the cluster is an A02 finding.

Applies when:

- A credential lives in a build arg, an image `ENV`, a compose file, or a Helm values file
- A Kubernetes Secret is treated as encrypted when `data` is only base64
- etcd encryption at rest is off for `secrets`
- A CI variable is unmasked, or reachable from a fork-triggered workflow
- A long-lived cloud access key is used where a role is available
- An IRSA or workload identity trust policy is too broad
- Terraform state holding credentials sits in an unencrypted or publicly readable backend
- Local development requires production credentials because nothing else works

Ask: what is different between this configuration and production? Who can read the place the
value ends up - and is that group larger than the group allowed to use the credential?

## A04:2025 - Cryptographic Failures

The credential itself. Storage, comparison, lifetime, and the keys that protect other data.

Applies when:

- A credential is hardcoded in source, tests, or fixtures
- A secret is compared with `==` rather than a constant-time function
- A credential has no expiry and no rotation path
- A signing or encryption key is shared across environments, or reused across purposes
- A secret is transmitted in a URL, a query string, or over a channel without TLS
- Rotation exists on paper but has never been executed

Ask: what is sensitive here, and what makes the stored form safe if the store is read? For a
credential the answer is usually "nothing" - which is why revocability and short lifetime carry
the weight, not the storage format.

## Where a leaked secret is reported

The category depends on the leak path, not on the credential.

| Leak path | Category |
|---|---|
| Hardcoded in source | A04, CWE-798 |
| In an image layer, build arg, CI variable, k8s manifest, Terraform state | A02 |
| Pulled in from a compromised dependency or a build tool | A03 Software Supply Chain Failures |
| Written to a log, an error tracker, or an APM trace | A09 Security Logging and Alerting Failures, CWE-532 |
| Printed in a stack trace or an error response to the client | A10 Mishandling of Exceptional Conditions |
| Accepted after a failed manager fetch fell back to a default | A10 |

A09's 2025 wording is "Logging and Alerting", not "Monitoring". For secrets that matters in both
directions: logs must not contain the credential, and use of a credential outside its expected
pattern should raise an alert someone actually receives.

## What this reference does not settle

The Top 10 is a risk ranking. It tells you a misconfiguration is common; it does not give you a
testable statement. For that, use ASVS V13 and V14 - see [asvs-5.0.md](asvs-5.0.md).
