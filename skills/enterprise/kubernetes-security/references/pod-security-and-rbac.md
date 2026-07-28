# Pod Security, RBAC, Tokens, and Standards

Version-specific claims checked 2026-07-28.

## Pod Security Admission

Source: <https://kubernetes.io/docs/concepts/security/pod-security-standards/>

Source: <https://kubernetes.io/docs/concepts/security/pod-security-admission/>

Pod Security Admission (PSA) is stable from Kubernetes v1.25. Its three cumulative levels are:

| Level | Definition |
|---|---|
| `privileged` | Unrestricted; allows known privilege escalations |
| `baseline` | Minimally restrictive; prevents known privilege escalations |
| `restricted` | Heavily restricted; follows current pod-hardening practices |

Baseline blocks privileged containers, HostProcess, host namespaces, hostPath, unsafe host
ports, `Unconfined` seccomp, unsafe proc mounts, unsafe sysctls, and capability additions
outside its allowlist. Restricted includes baseline and additionally:

- Limits volumes to ConfigMap, CSI, downwardAPI, emptyDir, ephemeral, PVC, projected, and Secret
- Requires `allowPrivilegeEscalation: false` for Linux containers
- Requires `runAsNonRoot: true` and forbids `runAsUser: 0`
- Requires seccomp `RuntimeDefault` or `Localhost`
- Requires dropping `ALL` capabilities; only `NET_BIND_SERVICE` may be added

All app, init, and ephemeral containers are checked. A failed container fails the Pod. Enforce
applies to Pods, not directly to a workload controller; warnings and audit annotations can be
produced for controllers, but a Deployment may be accepted while its Pod is rejected.

Namespace labels:

```text
pod-security.kubernetes.io/<MODE>: <LEVEL>
pod-security.kubernetes.io/<MODE>-version: <MINOR_OR_latest>
```

`MODE` is `enforce`, `audit`, or `warn`. `LEVEL` is `privileged`, `baseline`, or `restricted`.
Enforce rejects. Audit records an audit annotation. Warn returns a warning. Pinning the version
stabilizes policy behavior over upgrades.

PodSecurityPolicy `policy/v1beta1` and its admission controller were removed in Kubernetes
v1.25. There is no newer PSP API. Migration requires PSA or a third-party admission policy.

## Stable API Versions Used Here

Source: <https://kubernetes.io/docs/reference/kubernetes-api/>

Checked against the current Kubernetes v1.36 API reference on 2026-07-28.

| Objects | Stable apiVersion |
|---|---|
| Pod, Namespace, Service, ServiceAccount, Secret | `v1` |
| ResourceQuota, LimitRange | `v1` |
| Deployment | `apps/v1` |
| NetworkPolicy | `networking.k8s.io/v1` |
| Role, ClusterRole, RoleBinding, ClusterRoleBinding | `rbac.authorization.k8s.io/v1` |
| ValidatingWebhookConfiguration, MutatingWebhookConfiguration | `admissionregistration.k8s.io/v1` |
| ValidatingAdmissionPolicy and Binding | `admissionregistration.k8s.io/v1` |
| Audit Policy | `audit.k8s.io/v1` |
| EncryptionConfiguration | `apiserver.config.k8s.io/v1` |

Do not infer a cluster supports an API merely because the current stable reference does. Check
`kubectl api-resources` and the cluster minor version when portability matters.

## RBAC Risk

Source: <https://kubernetes.io/docs/concepts/security/rbac-good-practices/>

RBAC is additive; it has no deny rules. Prefer Roles and RoleBindings. Avoid wildcard resources
and verbs because `*` includes API types added in the future. A namespaced RoleBinding may refer
to a ClusterRole; binding `cluster-admin` to a workload ServiceAccount is unrestricted access,
not namespace-only administration.

High-impact permissions:

- `escalate`: bypasses the normal rule-creation check and can create a role more powerful than
  the creator
- `bind`: bypasses role-binding escalation prevention and can bind a role whose permissions the
  creator does not hold
- `impersonate`: acts as another user, group, ServiceAccount, UID, or extra attribute
- `get` on `nodes/proxy`: reaches Kubelet APIs, including process execution and attachment
- `list` or `watch` on Secrets: returns Secret content, not only names
- Workload creation: can mount namespace Secrets and use available ServiceAccounts

Check effective permissions:

```bash
kubectl auth can-i --list --as=system:serviceaccount:reports:reader -n reports
kubectl auth can-i get secrets --as=system:serviceaccount:reports:reader -n reports
kubectl auth can-i '*' '*' --as=system:serviceaccount:reports:reader -A
```

The caller needs impersonation permission to use `--as` against a live cluster.

## ServiceAccount Tokens

Source: <https://kubernetes.io/docs/concepts/security/service-accounts/>

Pods receive a ServiceAccount token by default. Pod-level `automountServiceAccountToken` takes
precedence over the ServiceAccount setting. Disable it when the workload does not call the API.

Since v1.22, pod tokens use TokenRequest and a projected volume: they are short-lived,
audience-bound, and rotated by kubelet. Exact projection fields are `path`, `audience`, and
`expirationSeconds`; the documented default expiry is 3600 seconds and minimum is 600. The
client must reread the token file after rotation.

Automatic creation of legacy long-lived token Secrets stopped by default in v1.24 and became
permanent in v1.27. A manually created `kubernetes.io/service-account-token` Secret remains a
non-expiring bearer credential and is discouraged.

## Standards Map

Pinned by the repository brief and verified 2026-07-28 where noted:

| Control | OWASP Top 10 2025 | ASVS 5.0 chapter | CWE |
|---|---|---|---|
| RBAC and workload identity | A01 Broken Access Control | V13 Configuration | CWE-269, CWE-284 |
| PSA and securityContext | A02 Security Misconfiguration | V13 Configuration | CWE-250, CWE-732 |
| ServiceAccount bearer tokens | A01, A02 | V13, V14 Data Protection | CWE-306, CWE-522 |
| Images, charts, operators | A03 Software Supply Chain Failures | V15 Secure Coding and Architecture | CWE-1104 |
| Audit policy | A09 Security Logging and Alerting Failures | V13 | CWE-778 |

CWE sources: <https://cwe.mitre.org/data/definitions/250.html>,
<https://cwe.mitre.org/data/definitions/269.html>,
<https://cwe.mitre.org/data/definitions/284.html>,
<https://cwe.mitre.org/data/definitions/306.html>,
<https://cwe.mitre.org/data/definitions/522.html>,
<https://cwe.mitre.org/data/definitions/668.html>, and
<https://cwe.mitre.org/data/definitions/1104.html>.

## CIS and NSA/CISA

The CIS Kubernetes Benchmark page listed version 2.0.1 on 2026-07-28:
<https://www.cisecurity.org/benchmark/kubernetes>. The benchmark text was not available without
registration, so this skill cites no recommendation IDs.

NSA/CISA Kubernetes Hardening Guidance:
<https://www.cisa.gov/news-events/alerts/2022/03/15/updated-kubernetes-hardening-guide>.
The linked `media.defense.gov` PDF returned HTTP 403 during verification. This skill therefore
cites the guidance by title but does not assert a version number or quote it. Controls are
independently supported by the Kubernetes sources above.
