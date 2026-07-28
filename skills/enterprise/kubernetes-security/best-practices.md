# Kubernetes Best Practices

Each pattern has a failure first, a complete or deployable manifest, and the control that
closes it. References use OWASP Top 10 2025 categories, ASVS 5.0 chapters, and a CWE where
one genuinely fits.

## Pod Security Admission

`A02:2025` · ASVS V13 · CWE-250, CWE-732

A namespace with no labels accepts privileged pods. PSA is built in and stable in Kubernetes
v1.25. The three levels are cumulative:

| Level | Meaning |
|---|---|
| `privileged` | Unrestricted. Intended for trusted system and infrastructure workloads. |
| `baseline` | Blocks known privilege escalations while allowing ordinary default pods. |
| `restricted` | Current hardening best practices. Requires non-root, no privilege escalation, safe volumes, seccomp, and dropped capabilities. |

`restricted` blocks `hostPath`, privileged containers, host namespaces, HostProcess,
`allowPrivilegeEscalation: true`, root UID, `Unconfined` seccomp, and capabilities beyond
`NET_BIND_SERVICE`; it requires `drop: [ALL]`. It applies to the resulting Pod. A Deployment
object can be accepted while its generated Pod is rejected.

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: payments
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: v1.36
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: v1.36
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: v1.36
```

`enforce` rejects, `audit` records a violation annotation, and `warn` returns a user-facing
warning. Pinning a minor version avoids a surprise policy change during a cluster upgrade.
The tempting wrong fix is only `warn`; it creates evidence, not a boundary. The other wrong
fix is preserving old PSP YAML. `policy/v1beta1` PSP and its admission controller were removed
in v1.25. Migrate to PSA or a reviewed third-party admission policy.

## Hardened Deployment

`A02:2025` · ASVS V13, V15 · CWE-250, CWE-732

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payments-api
  namespace: payments
spec:
  replicas: 2
  selector:
    matchLabels:
      app: payments-api
  template:
    metadata:
      labels:
        app: payments-api
    spec:
      serviceAccountName: payments-api
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: api
          image: registry.example.invalid/payments-api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
          imagePullPolicy: IfNotPresent
          ports:
            - name: http
              containerPort: 8080
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: [ALL]
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
          volumeMounts:
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: tmp
          emptyDir: {}
```

`runAsNonRoot` prevents an image defaulting to UID 0; `runAsUser` makes the identity
predictable. `allowPrivilegeEscalation: false` sets Linux `no_new_privs`; it is not the same
as dropping capabilities. `readOnlyRootFilesystem` removes a convenient persistence and
rewrite location, but the app needs an explicit writable `emptyDir` for `/tmp`. Dropping
`ALL` removes ambient capability power; add only a documented capability, and expect PSA
`restricted` to allow only `NET_BIND_SERVICE`.

This does not prove the image contains no setuid binary, the node kernel is hardened, or the
CNI enforces policies. Those require runtime checks. Image construction belongs to
`docker-security`.

## RBAC Least Privilege

`A01:2025` · ASVS V13 · CWE-269, CWE-284

A RoleBinding can bind a ClusterRole. The most common real finding is a workload ServiceAccount
bound to the `cluster-admin` ClusterRole through a namespaced RoleBinding. The binding's
namespace does not shrink the ClusterRole's permissions.

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: report-reader
  namespace: reports
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: report-reader
  namespace: reports
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["report-settings"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: report-reader
  namespace: reports
subjects:
  - kind: ServiceAccount
    name: report-reader
    namespace: reports
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: report-reader
```

Kubernetes RBAC permissions are additive. `*` in verbs or resources includes future API
objects, not just today's inventory. `escalate` bypasses the normal check that a creator may
only create roles no more powerful than itself. `bind` lets a subject create bindings to roles
with rights it does not have. `impersonate` lets it act as another user, group, or ServiceAccount;
impersonating a user or group is cluster-scoped. Scope all three or avoid them.

Check effective access rather than reading Role files:

```bash
kubectl auth can-i --list --as=system:serviceaccount:reports:report-reader -n reports
kubectl auth can-i get secrets --as=system:serviceaccount:reports:report-reader -n reports
kubectl auth can-i '*' '*' --as=system:serviceaccount:reports:report-reader -A
```

The last command is a test, not a permission grant. `list` or `watch` on Secrets exposes their
values. `nodes/proxy` is not read-only: `get` reaches Kubelet APIs and can execute or attach to
processes while bypassing Kubernetes admission and audit paths.

## ServiceAccount Tokens

`A01:2025` · ASVS V13 · CWE-306, CWE-522

Set `automountServiceAccountToken: false` for workloads that do not call the API. A pod-level
setting overrides the ServiceAccount setting. When API access is necessary, request a projected,
bound token with a narrow audience and expiry.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: token-client
  namespace: reports
spec:
  serviceAccountName: report-reader
  automountServiceAccountToken: false
  containers:
    - name: client
      image: registry.example.invalid/client@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
      volumeMounts:
        - name: api-token
          mountPath: /var/run/secrets/tokens
          readOnly: true
  volumes:
    - name: api-token
      projected:
        sources:
          - serviceAccountToken:
              path: token
              audience: reports-api
              expirationSeconds: 3600
```

Projected tokens use the TokenRequest API, are audience-bound, expire, and rotate. The client
must reread the file. Kubernetes stopped auto-creating legacy non-expiring token Secrets in
v1.24 and the behavior became permanent in v1.27. Manually creating one is a long-lived bearer
credential and should be avoided.

## Secret Handling

`A02:2025` · ASVS V14 · CWE-522, CWE-668

A Secret's `data` is base64 encoding, not encryption. By default Secret objects are stored
unencrypted in etcd. Configure an API-server EncryptionConfiguration, preferably backed by a
KMS provider, and verify that the live control plane uses it.

A mounted file is generally easier to scope to one container and is absent from process
argument and environment listings. It is not magic: the application can still log the value,
readers of the volume can still read it, and a pod creator can often mount a Secret. External
Secret Operators or the Secrets Store CSI Driver reduce durable Kubernetes copies but introduce
another privileged component that needs review.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: database-credentials
  namespace: reports
type: Opaque
stringData:
  username: report-reader
  password: replace-at-deploy-time
---
apiVersion: v1
kind: Pod
metadata:
  name: report-api
  namespace: reports
spec:
  serviceAccountName: report-reader
  automountServiceAccountToken: false
  containers:
    - name: api
      image: registry.example.invalid/report-api@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
      volumeMounts:
        - name: database-credentials
          mountPath: /var/run/secrets/database
          readOnly: true
  volumes:
    - name: database-credentials
      secret:
        secretName: database-credentials
        defaultMode: 0400
```

Do not commit the example password. `stringData` is used only to make the input readable; it
is still stored as Secret data by the API server. Never log the mounted file.

## NetworkPolicy

`A02:2025` · ASVS V13 · CWE-668

No policy means a pod is non-isolated in that direction. Policies are additive and both sides
of a pod-to-pod connection must allow it. Start with two policies per namespace, then add the
application rules. Egress default deny also blocks DNS, so allow DNS explicitly.

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: reports
spec:
  podSelector: {}
  policyTypes: [Ingress]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: reports
spec:
  podSelector: {}
  policyTypes: [Egress]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: report-api-traffic
  namespace: reports
spec:
  podSelector:
    matchLabels:
      app: report-api
  policyTypes: [Ingress, Egress]
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              tenant: reports
          podSelector:
            matchLabels:
              app: gateway
      ports:
        - protocol: TCP
          port: 8080
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
    - to:
        - podSelector:
            matchLabels:
              app: postgres
      ports:
        - protocol: TCP
          port: 5432
```

The namespace and DNS labels must match the actual cluster. The API object being accepted does
not prove the CNI implements NetworkPolicy; verify the CNI and test reachability. NetworkPolicy
cannot express TLS identity, explicit deny rules, or node identity, and it does not block
traffic to the node in every implementation.

## Admission: Validate, Mutate, Fail Closed

`A02:2025`, `A03:2025` · ASVS V13, V15 · CWE-284, CWE-1104

Validating admission rejects or accepts an object. Mutating admission changes it before later
validation. A mutator that adds a securityContext is useful, but a validating control is still
needed: a webhook outage or an excluded namespace must not silently permit unsafe input.

`admissionregistration.k8s.io/v1` is stable for webhook configurations. The following
ValidatingAdmissionPolicy API is also stable in the current API reference. CEL is deliberately
kept small and only checks the presence of a non-root requirement; a real policy engine should
also check every container, image provenance, and allowed volumes.

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: require-non-root
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: ["apps"]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["deployments"]
        scope: Namespaced
  validations:
    - expression: "has(object.spec.template.spec.securityContext) && object.spec.template.spec.securityContext.runAsNonRoot == true"
      message: "Deployment pod templates must require non-root"
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: require-non-root
spec:
  policyName: require-non-root
  validationActions: [Deny]
```

Fail closed (`Fail`) protects the boundary during a policy-service outage but can block
deployments when the control is unavailable. Fail open (`Ignore`) preserves availability but
turns an outage into a bypass. Use `Fail` for security-critical controls and make the outage
cost explicit. Admission cannot validate an image's bytes unless signature verification is
actually configured; a registry allowlist is not signature verification.

## Images and Runtime

`A03:2025` · ASVS V15 · CWE-1104

Pin a production image by digest. Tags are mutable. `IfNotPresent` is efficient but can use a
stale cached tag; `Always` still does not make a tag immutable. Digest pinning is the control;
`imagePullPolicy` governs when the reference is resolved.

```yaml
containers:
  - name: api
    image: registry.example.invalid/team/api@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
    imagePullPolicy: IfNotPresent
imagePullSecrets:
  - name: private-registry
```

The private registry Secret is itself sensitive and should be namespace-scoped. Do not duplicate
base-image or Dockerfile guidance here; use `docker-security` for the image itself.

## Multi-tenancy and Availability

`A01:2025`, `A02:2025` · ASVS V13 · CWE-284, CWE-668

A namespace is a soft boundary. It scopes names, RBAC Roles, quotas, and many selectors; it does
not isolate a kernel, node, privileged workload, hostPath, control plane, or a user with broad
cluster permissions. Use node labels, taints, and tolerations for workload placement, but use
separate nodes or clusters for hard tenant isolation.

`ResourceQuota` and `LimitRange` are availability controls, not confidentiality controls:

```yaml
apiVersion: v1
kind: ResourceQuota
metadata:
  name: reports-quota
  namespace: reports
spec:
  hard:
    requests.cpu: "4"
    requests.memory: 8Gi
    limits.cpu: "8"
    limits.memory: 16Gi
    pods: "40"
---
apiVersion: v1
kind: LimitRange
metadata:
  name: reports-defaults
  namespace: reports
spec:
  limits:
    - type: Container
      defaultRequest:
        cpu: 100m
        memory: 128Mi
      default:
        cpu: 500m
        memory: 512Mi
      max:
        cpu: "2"
        memory: 2Gi
```

Defaults prevent one omitted field from consuming a node. They do not prevent an application
from abusing its permitted budget, and quotas do not stop a tenant from reading another
namespace.

## Supply Chain in the Cluster

`A03:2025` · ASVS V15 · CWE-1104

A Helm chart is executable configuration. Review its templates, hooks, CRDs, default values,
image references, and ServiceAccounts. `kubectl apply -f <url>` moves trust to a network
response and makes review and provenance easy to skip; download, pin, verify, review, then
apply. An operator that needs a ClusterRole may be legitimate, but its controller is a
cluster-wide privileged workload and its update path is supply-chain risk.

## Audit Logging and `exec`

`A09:2025` · ASVS V13 · CWE-778

Audit levels are `None`, `Metadata`, `Request`, and `RequestResponse`. Capture metadata for
ordinary reads and mutations. Use Request or RequestResponse for security-sensitive operations
only when bodies do not contain secrets. Explicitly capture `pods/exec`, `pods/attach`, and
`pods/portforward`; an exec event is evidence of interactive access, not proof of compromise.

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  - level: Request
    resources:
      - group: ""
        resources: ["pods/exec", "pods/attach", "pods/portforward"]
  - level: Metadata
```

The API server must be configured with `--audit-policy-file`; a policy file in a repository does
not activate logging. Route events to a protected backend and alert on unexpected workload
identity, namespace, or source address.

## The Escape Chain and What Blocks It

`A01:2025`, `A02:2025` · ASVS V13 · CWE-250, CWE-269, CWE-668

```yaml
# Vulnerable: this is a complete manifest that enables the chain. Do not apply it.
apiVersion: v1
kind: Pod
metadata:
  name: node-filesystem-access
  namespace: reports
spec:
  containers:
    - name: diagnostic
      image: registry.example.invalid/diagnostic@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
      securityContext:
        privileged: true
      volumeMounts:
        - name: node-root
          mountPath: /host
  volumes:
    - name: node-root
      hostPath:
        path: /
        type: Directory
```

This gives a container root access to the node filesystem. From there, node and pod
credentials may be exposed. The defensive fix is not an exploit: deny `privileged` and
`hostPath` at `restricted` PSA, set a hardened `securityContext`, and use RBAC that gives the
workload no unnecessary API access. A runtime review must additionally check node isolation,
Kubelet configuration, and the CNI; YAML cannot prove those.

## References

- <https://kubernetes.io/docs/concepts/security/pod-security-standards/>
- <https://kubernetes.io/docs/concepts/security/pod-security-admission/>
- <https://kubernetes.io/docs/reference/access-authn-authz/rbac-good-practices/>
- <https://kubernetes.io/docs/concepts/services-networking/network-policies/>
- <https://kubernetes.io/docs/concepts/security/secrets-good-practices/>
- <https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/>
- <https://owasp.org/Top10/2025/>
