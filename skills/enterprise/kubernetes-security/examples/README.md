# Kubernetes Security Examples

Eight complete vulnerable/fixed YAML pairs. Vulnerable manifests are runnable but deliberately
unsafe. Do not apply them. Placeholder image digests do not resolve; replace them with reviewed
images pinned to real digests before deployment.

## Contents

1. [Privileged pod mounting node root](#1-privileged-pod-mounting-node-root)
2. [Workload ServiceAccount bound to cluster-admin](#2-workload-serviceaccount-bound-to-cluster-admin)
3. [Namespace with no NetworkPolicy](#3-namespace-with-no-networkpolicy)
4. [Secret in environment variables](#4-secret-in-environment-variables)
5. [Deployment with no securityContext](#5-deployment-with-no-securitycontext)
6. [ServiceAccount token automounted](#6-serviceaccount-token-automounted)
7. [Admission policy fails open](#7-admission-policy-fails-open)
8. [Unbounded resources](#8-unbounded-resources)

---

## 1. Privileged pod mounting node root

`A01:2025`, `A02:2025` · ASVS V13 · CWE-250, CWE-269, CWE-668

Vulnerable:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: diagnostics
---
apiVersion: v1
kind: Pod
metadata:
  name: node-diagnostic
  namespace: diagnostics
spec:
  containers:
    - name: diagnostic
      image: registry.example.invalid/diagnostic@sha256:1111111111111111111111111111111111111111111111111111111111111111
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

Privileged execution plus `hostPath: /` removes the useful boundary between container and node.
The process can read node files, where kubelet and pod credentials may exist. That creates the
defensive chain worth recognizing: pod privilege, node root, cluster credential exposure. No
escape command or payload is needed to establish the risk.

Fixed:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: diagnostics
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: v1.36
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/audit-version: v1.36
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/warn-version: v1.36
---
apiVersion: v1
kind: Pod
metadata:
  name: workload-diagnostic
  namespace: diagnostics
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: diagnostic
      image: registry.example.invalid/diagnostic@sha256:2222222222222222222222222222222222222222222222222222222222222222
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: [ALL]
      volumeMounts:
        - name: tmp
          mountPath: /tmp
  volumes:
    - name: tmp
      emptyDir: {}
```

Why this works: restricted PSA rejects privileged and hostPath pods before they run. The fixed
pod has no node mount and no ambient capability. Runtime review must still verify the namespace
labels are deployed and no admission exemption applies.

---

## 2. Workload ServiceAccount bound to cluster-admin

`A01:2025` · ASVS V13 · CWE-269, CWE-284

Vulnerable:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: reports
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: report-api
  namespace: reports
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: report-api-admin
  namespace: reports
subjects:
  - kind: ServiceAccount
    name: report-api
    namespace: reports
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
```

A namespaced RoleBinding does not make `cluster-admin` safe. The workload receives the bound
role's broad permissions, creating a direct cluster takeover path if its token is stolen.

Fixed:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: reports
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: report-api
  namespace: reports
automountServiceAccountToken: false
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: report-settings-reader
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
  name: report-settings-reader
  namespace: reports
subjects:
  - kind: ServiceAccount
    name: report-api
    namespace: reports
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: report-settings-reader
```

Why this works: one ServiceAccount can get one named ConfigMap in one namespace. No wildcards,
Secrets, pod creation, `escalate`, `bind`, or `impersonate`. Confirm effective access with:

```bash
kubectl auth can-i --list --as=system:serviceaccount:reports:report-api -n reports
```

---

## 3. Namespace with no NetworkPolicy

`A02:2025` · ASVS V13 · CWE-668

Vulnerable:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: storefront
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: storefront-api
  namespace: storefront
spec:
  replicas: 1
  selector:
    matchLabels:
      app: storefront-api
  template:
    metadata:
      labels:
        app: storefront-api
    spec:
      automountServiceAccountToken: false
      containers:
        - name: api
          image: registry.example.invalid/storefront@sha256:3333333333333333333333333333333333333333333333333333333333333333
          ports:
            - name: http
              containerPort: 8080
```

No NetworkPolicy means the pod is non-isolated for ingress and egress: full mesh reachability
under the Kubernetes model.

Fixed:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: storefront
  labels:
    tenant: storefront
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: storefront
spec:
  podSelector: {}
  policyTypes: [Ingress]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: storefront
spec:
  podSelector: {}
  policyTypes: [Egress]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: storefront-api
  namespace: storefront
spec:
  podSelector:
    matchLabels:
      app: storefront-api
  policyTypes: [Ingress, Egress]
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: storefront-gateway
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
        - {protocol: UDP, port: 53}
        - {protocol: TCP, port: 53}
    - to:
        - podSelector:
            matchLabels:
              app: storefront-db
      ports:
        - {protocol: TCP, port: 5432}
```

Why this works: default denies isolate every pod; explicit rules add only gateway ingress,
database egress, and DNS. Verify DNS labels and CNI enforcement live. Source review cannot prove
packet filtering.

---

## 4. Secret in environment variables

`A02:2025` · ASVS V14 · CWE-522, CWE-668

Vulnerable:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: database
  namespace: default
type: Opaque
data:
  password: cGFzc3dvcmQ=
---
apiVersion: v1
kind: Pod
metadata:
  name: env-secret
spec:
  containers:
    - name: api
      image: registry.example.invalid/api@sha256:4444444444444444444444444444444444444444444444444444444444444444
      env:
        - name: DATABASE_PASSWORD
          valueFrom:
            secretKeyRef:
              name: database
              key: password
```

Base64 is not encryption. The environment can leak through debug tooling, crash reports, child
processes, and logs, and cannot rotate in place for an existing process.

Fixed:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: database
  namespace: default
type: Opaque
stringData:
  password: replace-at-deploy-time
---
apiVersion: v1
kind: Pod
metadata:
  name: file-secret
spec:
  automountServiceAccountToken: false
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: api
      image: registry.example.invalid/api@sha256:5555555555555555555555555555555555555555555555555555555555555555
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: [ALL]
      volumeMounts:
        - name: database
          mountPath: /var/run/secrets/database
          readOnly: true
  volumes:
    - name: database
      projected:
        sources:
          - secret:
              name: database
              items:
                - key: password
                  path: password
                  mode: 0400
```

Why this works: only the selected key appears as a read-only file and can update in place. The
application must reread it and avoid logging it. This manifest does not prove etcd encryption;
configure and verify `apiserver.config.k8s.io/v1` EncryptionConfiguration, preferably KMS-backed,
on the live control plane. Do not commit the placeholder value.

---

## 5. Deployment with no securityContext

`A02:2025`, `A03:2025` · ASVS V13, V15 · CWE-250, CWE-732, CWE-1104

Vulnerable:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: catalog
  namespace: default
spec:
  replicas: 2
  selector:
    matchLabels:
      app: catalog
  template:
    metadata:
      labels:
        app: catalog
    spec:
      containers:
        - name: catalog
          image: registry.example.invalid/catalog:latest
          ports:
            - containerPort: 8080
```

The container may run as root, elevate, retain default capabilities, write its root filesystem,
use unconfined seccomp depending on runtime configuration, and receive a token. `latest` is
mutable.

Fixed:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: catalog
  namespace: default
spec:
  replicas: 2
  selector:
    matchLabels:
      app: catalog
  template:
    metadata:
      labels:
        app: catalog
    spec:
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: catalog
          image: registry.example.invalid/catalog@sha256:6666666666666666666666666666666666666666666666666666666666666666
          imagePullPolicy: IfNotPresent
          ports:
            - containerPort: 8080
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: [ALL]
          resources:
            requests: {cpu: 100m, memory: 128Mi}
            limits: {cpu: 500m, memory: 512Mi}
          volumeMounts:
            - {name: tmp, mountPath: /tmp}
      volumes:
        - name: tmp
          emptyDir: {}
```

Why this works: the runtime identity and privilege surface are explicit, writes are confined,
and the image bytes are immutable. Digest pinning does not prove the image is safe; use
`docker-security` and admission signature verification for image trust.

---

## 6. ServiceAccount token automounted

`A01:2025`, `A02:2025` · ASVS V13, V14 · CWE-306, CWE-522

Vulnerable:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: metrics-exporter
  namespace: default
---
apiVersion: v1
kind: Pod
metadata:
  name: metrics-exporter
spec:
  serviceAccountName: metrics-exporter
  containers:
    - name: exporter
      image: registry.example.invalid/exporter@sha256:7777777777777777777777777777777777777777777777777777777777777777
```

The default mounts an API credential even if the exporter never calls Kubernetes.

Fixed for a workload with no API need:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: metrics-exporter
  namespace: default
automountServiceAccountToken: false
---
apiVersion: v1
kind: Pod
metadata:
  name: metrics-exporter
spec:
  serviceAccountName: metrics-exporter
  automountServiceAccountToken: false
  containers:
    - name: exporter
      image: registry.example.invalid/exporter@sha256:8888888888888888888888888888888888888888888888888888888888888888
```

Fixed alternative for a client that needs a bounded token:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: metrics-api-client
spec:
  serviceAccountName: metrics-exporter
  automountServiceAccountToken: false
  containers:
    - name: client
      image: registry.example.invalid/client@sha256:9999999999999999999999999999999999999999999999999999999999999999
      volumeMounts:
        - {name: api-token, mountPath: /var/run/secrets/tokens, readOnly: true}
  volumes:
    - name: api-token
      projected:
        sources:
          - serviceAccountToken:
              path: token
              audience: metrics-api
              expirationSeconds: 3600
```

Why this works: no token exists when none is needed. When one is needed, it is audience-bound,
expiring, and kubelet-rotated. The client must reread the file. Do not replace it with a manually
created legacy token Secret.

---

## 7. Admission policy fails open

`A02:2025`, `A03:2025` · ASVS V13, V15 · CWE-284, CWE-1104

Vulnerable:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: require-digest
spec:
  failurePolicy: Ignore
  matchConstraints:
    resourceRules:
      - apiGroups: ["apps"]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["deployments"]
        scope: Namespaced
  validations:
    - expression: "object.spec.template.spec.containers.all(c, c.image.contains('@sha256:'))"
      message: "Images must use a digest"
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: require-digest
spec:
  policyName: require-digest
  validationActions: [Warn]
```

`Ignore` plus `Warn` does not maintain a production boundary. Policy evaluation failure or a
warning still permits deployment. Digest syntax also proves immutability, not signer identity.

Fixed:

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: require-digest
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
    - expression: "object.spec.template.spec.containers.all(c, c.image.matches('^.+@sha256:[a-f0-9]{64}$'))"
      message: "Every image must be pinned to a sha256 digest"
---
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: require-digest
spec:
  policyName: require-digest
  validationActions: [Deny]
```

Why this works: a failed decision or invalid reference denies creation. The cost is deployment
availability if admission fails, so monitor and test it. For provenance, use a policy engine or
webhook that verifies trusted image signatures and attestations; this CEL policy does not.

---

## 8. Unbounded resources

`A02:2025` · ASVS V13 · CWE-400

Vulnerable:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: batch
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: batch-worker
  namespace: batch
spec:
  replicas: 20
  selector:
    matchLabels:
      app: batch-worker
  template:
    metadata:
      labels:
        app: batch-worker
    spec:
      automountServiceAccountToken: false
      containers:
        - name: worker
          image: registry.example.invalid/worker@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

Twenty containers have no scheduler request and no runtime limit. One workload can starve the
node or crowd out other tenants.

Fixed:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: batch
---
apiVersion: v1
kind: ResourceQuota
metadata:
  name: batch-quota
  namespace: batch
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
  name: batch-limits
  namespace: batch
spec:
  limits:
    - type: Container
      defaultRequest: {cpu: 100m, memory: 128Mi}
      default: {cpu: 500m, memory: 512Mi}
      max: {cpu: "2", memory: 2Gi}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: batch-worker
  namespace: batch
spec:
  replicas: 4
  selector:
    matchLabels:
      app: batch-worker
  template:
    metadata:
      labels:
        app: batch-worker
    spec:
      automountServiceAccountToken: false
      containers:
        - name: worker
          image: registry.example.invalid/worker@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
          resources:
            requests: {cpu: 250m, memory: 256Mi}
            limits: {cpu: "1", memory: 1Gi}
```

Why this works: scheduler accounting, runtime bounds, per-container defaults, and namespace
aggregate caps limit availability blast radius. Quota and LimitRange do not provide tenant data
isolation; combine them with PSA, RBAC, NetworkPolicy, and node or cluster separation.

---

## Sources

- <https://kubernetes.io/docs/concepts/security/pod-security-standards/>
- <https://kubernetes.io/docs/concepts/security/pod-security-admission/>
- <https://kubernetes.io/docs/concepts/security/rbac-good-practices/>
- <https://kubernetes.io/docs/concepts/security/service-accounts/>
- <https://kubernetes.io/docs/concepts/security/secrets-good-practices/>
- <https://kubernetes.io/docs/concepts/services-networking/network-policies/>
- <https://kubernetes.io/docs/reference/kubernetes-api/>
