# Common Kubernetes Security Mistakes

Each mistake states what goes wrong, why the tempting fix fails, and what closes the path.

## `cluster-admin` through a namespaced RoleBinding

`A01:2025` · ASVS V13 · CWE-269

```yaml
# Vulnerable: namespace scope does not narrow cluster-admin
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: api-admin
  namespace: payments
subjects:
  - kind: ServiceAccount
    name: api
    namespace: payments
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
```

A RoleBinding may reference a ClusterRole. When it references `cluster-admin`, the workload
gets that role's power; the namespace on the binding is not a security filter for its rules.

Fix: create a namespaced Role with exact resources and verbs, then confirm it with
`kubectl auth can-i --list --as=system:serviceaccount:payments:api -n payments`.

## `restricted` in warn mode only

`A02:2025` · ASVS V13 · CWE-732

```yaml
# Vulnerable: warnings do not reject pods
metadata:
  labels:
    pod-security.kubernetes.io/warn: restricted
```

The warning appears at apply time and the pod still runs. This is a migration aid, not a
boundary.

Fix: stage with `warn` and `audit`, remediate violations, then add
`pod-security.kubernetes.io/enforce: restricted` and pin `enforce-version`.

## Treating old PSP manifests as protection

`A02:2025` · ASVS V13 · CWE-732

PodSecurityPolicy was deprecated and `policy/v1beta1` PSP plus its admission controller were
removed in Kubernetes v1.25. Keeping the YAML in a chart creates an invalid object, not a
policy.

Fix: map old PSP controls to PSA levels and a validating policy engine for requirements PSA
does not express. Test the generated pods. A Deployment can be admitted while its Pod is later
rejected.

## One pod-level security field and calling it hardened

`A02:2025` · ASVS V13 · CWE-250

```yaml
# Vulnerable: non-root alone leaves privilege escalation, capabilities, and writes
spec:
  securityContext:
    runAsNonRoot: true
```

`runAsNonRoot` says nothing about capabilities, seccomp, or a writable root filesystem.
Container-level values can also override pod-level defaults.

Fix: set non-root and seccomp at pod level, then on every app, init, and ephemeral container
set `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, and drop `ALL`.

## Adding many capabilities back after dropping ALL

`A02:2025` · ASVS V13 · CWE-250, CWE-732

```yaml
# Vulnerable: the drop is cosmetic after broad additions
securityContext:
  capabilities:
    drop: [ALL]
    add: [SYS_ADMIN, NET_ADMIN, SYS_PTRACE]
```

`SYS_ADMIN` is especially broad. PSA `restricted` allows adding only `NET_BIND_SERVICE`.

Fix: change the application to bind above port 1024 and need no added capability. If one is
unavoidable, justify it individually and enforce it in admission. A capability allowlist is
stronger than a reviewer comment.

## Turning off token automount but granting pod creation

`A01:2025` · ASVS V13 · CWE-269, CWE-284

A principal that can create a Pod in a namespace can choose another ServiceAccount and mount
Secrets it can reference. Setting `automountServiceAccountToken: false` on one Deployment does
not constrain that principal.

Fix: remove unnecessary workload-creation permission, constrain allowed ServiceAccounts with
admission, keep ServiceAccounts narrow, and separate trust levels by namespace.

## Manually creating a legacy ServiceAccount token Secret

`A01:2025` · ASVS V13 · CWE-522

A `kubernetes.io/service-account-token` Secret is long-lived and does not rotate. It survives
outside the pod and often ends up in CI variables or operator configuration.

Fix: use projected bound tokens or `kubectl create token`/TokenRequest with an audience and
expiry. The wrong fix is rotating a static Secret manually; it remains static between rotations.

## Base64 treated as Secret encryption

`A02:2025` · ASVS V14 · CWE-522

```yaml
# Vulnerable assumption: anyone can decode this
apiVersion: v1
kind: Secret
metadata:
  name: database
type: Opaque
data:
  password: cGFzc3dvcmQ=
```

Base64 only serializes bytes. Kubernetes stores Secrets unencrypted in etcd by default.

Fix: configure etcd encryption at rest, preferably KMS-backed, restrict Secret RBAC, and keep
Secret manifests out of source control. `stringData` is not less secure or more secure; it is
only another input form.

## Secret injected into an environment variable

`A02:2025` · ASVS V14 · CWE-522, CWE-668

```yaml
# Vulnerable: inherited by child processes and exposed by debug tooling
- name: DATABASE_PASSWORD
  valueFrom:
    secretKeyRef:
      name: database
      key: password
```

Environment values can appear in crash reports, process inspection, diagnostic endpoints,
and child environments. They cannot rotate in place for a running process.

Fix: mount only the required keys as read-only files and have the application reread them.
This narrows accidental exposure; it does not protect against code execution in that container.

## Applying a NetworkPolicy without checking the CNI

`A02:2025` · ASVS V13 · CWE-668

The API accepts NetworkPolicy even when the network plugin does not enforce it. The manifest
looks correct while traffic remains open.

Fix: identify the installed CNI and its policy capabilities, then test one allowed and one
denied flow. Source review cannot prove runtime enforcement.

## Default-deny egress without DNS

`A02:2025` · ASVS V13 · CWE-668

An empty egress policy blocks name resolution too. Teams then delete the policy to recover
availability.

Fix: pair default deny with a narrow UDP and TCP port 53 rule selecting the actual DNS pods.
Do not allow all egress to the kube-system namespace; that is much broader than DNS.

## `imagePullPolicy: Always` used as immutability

`A03:2025` · ASVS V15 · CWE-1104

`Always` asks the registry to resolve the reference each start. A mutable tag can still point
to different bytes tomorrow.

Fix: pin the image digest. Signature verification at admission proves approved provenance;
digest pinning alone proves only immutability. Image contents belong to `docker-security`.

## Trusting a registry allowlist as signature verification

`A03:2025` · ASVS V15 · CWE-1104

An allowed registry can contain an overwritten tag, a compromised account's image, or an
unreviewed repository.

Fix: verify a trusted signature or attestation at admission and bind it to the digest. Decide
whether verification failure denies deployment (`Fail`) or creates an availability bypass
(`Ignore`). Security-critical production policy should fail closed.

## `kubectl apply -f <url>` from documentation

`A03:2025` · ASVS V15 · CWE-1104

The URL is mutable. The response may contain CRDs, admission webhooks, cluster-wide RBAC, and
hooks that are hard to see in terminal output.

Fix: download a pinned release, verify checksum or signature, review rendered YAML, commit the
reviewed artifact, then apply it. HTTPS authenticates the server connection; it does not prove
the content was reviewed.

## Treating an operator as an ordinary application

`A03:2025`, `A01:2025` · ASVS V15, V13 · CWE-1104, CWE-269

Operators commonly watch all namespaces, manage CRDs, create workloads, and hold broad
ClusterRoles. Compromise becomes a control-plane-like event.

Fix: review its RBAC, image provenance, update channel, CRDs, admission hooks, and namespace
scope. Prefer namespace-scoped installation where supported.

## Namespace called a tenant boundary

`A01:2025`, `A02:2025` · ASVS V13 · CWE-284, CWE-668

Namespaces share nodes, kernel, networking implementation, and control plane. A privileged pod
or node mount crosses them immediately.

Fix: use PSA, RBAC, NetworkPolicy, quota, and isolated nodes as layers. Use separate clusters
where tenants require a hard boundary. Quota protects availability, not confidentiality.

## Audit policy logs Secret bodies

`A09:2025`, `A02:2025` · ASVS V13, V14 · CWE-522, CWE-778

`RequestResponse` on all resources records Secret values and TokenRequest results into the
audit backend.

Fix: use Metadata for Secrets and authentication material, higher levels for selected mutation
and pod subresources, and protect the backend. More logging can create a second secret store.

## Audit policy misses `pods/exec`

`A09:2025` · ASVS V13 · CWE-778

Matching `resources: ["pods"]` does not match the `pods/exec` subresource. Interactive access
then disappears from the expected rule.

Fix: name `pods/exec`, `pods/attach`, and `pods/portforward` explicitly and alert on unexpected
actors, namespaces, and ServiceAccounts.
