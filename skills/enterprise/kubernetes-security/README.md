# Kubernetes Security Skill

Manifest-level and cluster-level hardening guidance for Kubernetes, mapped to published
standards.

## Purpose

Kubernetes fails secure almost nowhere. Leave `securityContext` out and the container runs as
root with a writable root filesystem and the default capability set. Leave NetworkPolicy out
and every pod in the cluster can reach every other pod. Leave `automountServiceAccountToken`
alone and a credential is mounted into a workload that never calls the API.

This skill gives an assistant the specific field to set, the standard that requires it, and
the reason the obvious alternative fix does not work.

## How It Works

Plain Markdown. Nothing executes. An assistant reads `SKILL.md`, follows the five-step
workflow (scope, map, apply, verify, report), and pulls the supporting file it needs.

```text
SKILL.md                            workflow, severity, the escape chain summary
README.md                           this file
checklist.md                        pre-return verification, grouped by control area
best-practices.md                   patterns, with vulnerable/fixed manifests
common-mistakes.md                  what goes wrong and why the fix works
troubleshooting.md                  when a control cannot be applied
prompts.md                          prompts that produce findings
references/
  pod-security-and-rbac.md          PSA levels, verified apiVersions, RBAC risk,
                                    token behaviour, standards and CWE map
  network-policy.md                 isolation model, default-deny pair, CNI caveats
examples/
  README.md                         eight vulnerable/fixed manifest pairs
```

## Standards Covered

| Standard | Version | Verified |
|---|---|---|
| OWASP Top 10 | 2025 (A01, A02, A03, A09) | 2026-07-28, pinned by the toolkit |
| OWASP ASVS | 5.0.0 (V13, V14, V15), chapter level | 2026-07-28, pinned by the toolkit |
| CIS Kubernetes Benchmark | v2.0.1 as listed by CIS | 2026-07-28, against `cisecurity.org` |
| NSA/CISA Kubernetes Hardening Guidance | version not verified | 2026-07-28, fetch blocked |
| CWE | CWE-250, 269, 284, 306, 522, 668, 778, 1104 | 2026-07-28, against `cwe.mitre.org` |
| Kubernetes API | v1.36 documentation | 2026-07-28, against `kubernetes.io/docs` |

Two honest gaps in that table. CIS publishes the benchmark PDF behind a registration form, so
this skill names the version but cites no recommendation IDs — a control described without an
ID is still checkable, an invented ID is not. The NSA/CISA guidance is hosted on
`media.defense.gov`, which returned HTTP 403 to the fetch; the document is cited by name and
its content is described from the Kubernetes documentation that covers the same controls, not
quoted. See `references/pod-security-and-rbac.md`.

## Configuration

None. No build step, no dependency, no environment variable.

To use it in Claude Code, keep this repository in the working directory so
`skills/enterprise/kubernetes-security/SKILL.md` is readable, or copy the
`kubernetes-security` directory into `~/.claude/skills/`. The frontmatter `allowed-tools`
limits it to read, search, and web lookup plus `ls`/`cat`. It cannot apply a manifest or
touch a cluster.

## Example Usage

Review manifests for the escape chain first:

```text
Review k8s/ for anything that gives a pod a path to the node: privileged, hostPath,
hostPID, hostNetwork, or a ServiceAccount bound to cluster-admin. For each, tell me
whether Pod Security Admission at restricted would have blocked it.
```

Audit an identity rather than a file:

```text
Read k8s/rbac/ and tell me the effective permissions of the api-sa ServiceAccount. Flag
wildcards, cluster-scoped bindings, and the escalate, bind, and impersonate verbs. Give me
the kubectl auth can-i command that confirms each finding on a live cluster.
```

More in [prompts.md](prompts.md).

## Limitations

- Reads YAML. It cannot see the cluster. Namespace PSA labels, etcd encryption, audit policy,
  admission webhooks, and whether the CNI plugin enforces NetworkPolicy at all are runtime
  facts that a manifest review cannot confirm.
- A NetworkPolicy is inert without a CNI plugin that implements it. Flannel in its default
  configuration does not. The object applies cleanly and enforces nothing, which is the worst
  possible failure mode because it looks fine.
- No control IDs from the CIS Kubernetes Benchmark, for the reason above. For a formal CIS
  audit, run kube-bench against the published benchmark.
- ASVS mapping is at chapter level (V13, V14, V15), not requirement IDs.
- Managed control planes differ. On EKS, GKE, and AKS you cannot pass `--audit-policy-file`
  or `--encryption-provider-config` to the API server; the provider does it. Sections here
  that configure the API server apply to self-managed clusters. See
  [troubleshooting.md](troubleshooting.md).
- Container image content is out of scope. Base image selection, build-time users, layer
  secrets, and vulnerability scanning belong to `docker-security`. This skill covers how the
  image runs.
- Service meshes, OPA Gatekeeper and Kyverno policy language, and cloud IAM federation
  (IRSA, Workload Identity) are named where relevant but not taught here.
- Nothing about node OS hardening, kernel parameters, or etcd cluster operations.

## Security Notes

This skill contains deliberately insecure manifests in `best-practices.md`,
`common-mistakes.md`, and `examples/`. Every one is labelled `Vulnerable:` and paired with a
fixed version. Do not apply a labelled-vulnerable manifest to a cluster.

The escape chain in `best-practices.md` is described as a mechanism and paired with the
control that blocks it. There is no exploit payload here and none should be added. A reader
learning that `hostPath: /` plus `privileged: true` reaches node root learns why the field is
blocked at admission; that is the point.

All values are placeholders. No real registry hostnames, image digests, tokens, or
credentials. The digests in examples are illustrative and will not resolve.

## References

- Pod Security Standards — <https://kubernetes.io/docs/concepts/security/pod-security-standards/>
- Pod Security Admission — <https://kubernetes.io/docs/concepts/security/pod-security-admission/>
- RBAC good practices — <https://kubernetes.io/docs/concepts/security/rbac-good-practices/>
- Good practices for Secrets — <https://kubernetes.io/docs/concepts/security/secrets-good-practices/>
- NetworkPolicy — <https://kubernetes.io/docs/concepts/services-networking/network-policies/>
- Auditing — <https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/>
- OWASP Top 10 2025 — <https://owasp.org/Top10/2025/>
- OWASP ASVS — <https://owasp.org/www-project-application-security-verification-standard/>
- CIS Benchmarks — <https://www.cisecurity.org/benchmark/kubernetes>
- NSA/CISA Kubernetes Hardening Guidance — <https://www.cisa.gov/news-events/alerts/2022/03/15/updated-kubernetes-hardening-guide>
