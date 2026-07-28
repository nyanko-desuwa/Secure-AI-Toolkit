# Kubernetes Security Verification Checklist

Run the sections that match the change. Mark each item pass, fail, or not applicable. A pass
means the manifest or live cluster output proves it. A manifest alone cannot prove admission,
CNI enforcement, etcd encryption, or audit delivery.

## Pod Admission (A02 · ASVS V13 · CWE-250, CWE-732)

- [ ] Every workload namespace has `pod-security.kubernetes.io/enforce` set
- [ ] Production namespaces enforce `restricted`, unless a documented workload need prevents it
- [ ] The `enforce-version` label is pinned to a tested Kubernetes minor version
- [ ] `audit` and `warn` labels test `restricted` before rollout
- [ ] PSA exemptions are narrow and reviewed; controller ServiceAccounts are not exempted
- [ ] Old PodSecurityPolicy manifests and assumptions have been removed
- [ ] Migration testing covers generated pods, not only Deployment admission
- [ ] Privileged containers, host namespaces, host ports, and `hostPath` are rejected
- [ ] Init and ephemeral containers meet the same policy as app containers

## Workload Security Context (A02 · ASVS V13 · CWE-250, CWE-732)

- [ ] Pod or every container sets `runAsNonRoot: true`
- [ ] `runAsUser` is a known non-zero UID where the image supports one
- [ ] Every container sets `allowPrivilegeEscalation: false`
- [ ] Every container sets `readOnlyRootFilesystem: true`
- [ ] Writable paths use named `emptyDir` or persistent volumes, not a writable root filesystem
- [ ] Every container drops `ALL` capabilities
- [ ] Added capabilities are individually justified; only `NET_BIND_SERVICE` passes restricted PSA
- [ ] Pod or every container sets `seccompProfile.type: RuntimeDefault`
- [ ] No container sets `privileged: true`
- [ ] No workload uses `hostPID`, `hostIPC`, or `hostNetwork` without a system-level exception
- [ ] No volume mounts the node filesystem with `hostPath`
- [ ] Windows HostProcess containers are absent or explicitly approved

## Workload Identity and RBAC (A01 · ASVS V13 · CWE-269, CWE-284)

- [ ] Every workload names a dedicated ServiceAccount
- [ ] The namespace `default` ServiceAccount has no added permissions
- [ ] Workload permissions use Role and RoleBinding where namespace scope is sufficient
- [ ] No workload ServiceAccount is bound to `cluster-admin`
- [ ] No user or ServiceAccount is placed in `system:masters`
- [ ] Rules name required API groups, resources, and verbs; no `*` wildcards
- [ ] Secret `list` and `watch` are treated as secret-read permissions
- [ ] Pod or workload creation is treated as access to mountable Secrets and ServiceAccounts
- [ ] `escalate`, `bind`, and `impersonate` are absent unless explicitly required and scoped
- [ ] `nodes/proxy` is absent from application roles
- [ ] `roleRef` and every subject refer to the intended namespace and identity
- [ ] Effective permissions were checked with `kubectl auth can-i --list --as=...`
- [ ] High-impact permissions were checked individually in every relevant namespace

## ServiceAccount Tokens (A01 · ASVS V13 · CWE-306, CWE-522)

- [ ] Workloads that do not call the API set `automountServiceAccountToken: false`
- [ ] The ServiceAccount also defaults automount to false where practical
- [ ] API clients use projected bound tokens, not manually created legacy token Secrets
- [ ] A projected token has the narrow consumer audience
- [ ] `expirationSeconds` is short enough for the use case and at least 600 seconds
- [ ] The client rereads the projected token file after kubelet rotation
- [ ] No long-lived `kubernetes.io/service-account-token` Secret is created without justification

## Secrets and Storage (A02 · ASVS V14 · CWE-522, CWE-668)

- [ ] Reviewers do not mistake base64 in `data` for encryption
- [ ] The live API server is configured to encrypt Secrets in etcd
- [ ] A KMS provider is preferred over keys stored beside the API server configuration
- [ ] Encryption was verified by inspecting etcd storage, not only the config file
- [ ] Encryption was rotated or rewritten after enabling a new provider
- [ ] Secret RBAC grants `get` only to components that require it
- [ ] Applications receive Secrets as read-only files where possible, not environment variables
- [ ] Secret values cannot appear in process dumps, debug endpoints, logs, or child environments
- [ ] External secret operators have only the namespaces and secret paths they need
- [ ] Secret manifests are absent from source control, including Helm values

## Network Isolation (A02 · ASVS V13 · CWE-668)

- [ ] Every workload namespace has default-deny ingress and egress policies
- [ ] Explicit ingress rules select both source and destination narrowly
- [ ] Explicit egress rules name required destinations and ports
- [ ] DNS egress permits UDP and TCP 53 to the actual cluster DNS pods
- [ ] No policy uses an empty allow rule (`- {}`) by accident
- [ ] Source and destination selectors use labels controlled by trusted administrators
- [ ] The deployed CNI plugin is confirmed to implement NetworkPolicy
- [ ] Connectivity tests prove allowed traffic works and denied traffic fails
- [ ] Policies do not claim to block traffic from a pod to itself or its node

## Admission Control (A02, A03 · ASVS V13, V15 · CWE-284, CWE-1104)

- [ ] Validating controls reject unsafe objects; mutation is not the only enforcement
- [ ] Mutating webhooks are idempotent and declare dry-run side effects correctly
- [ ] Security-critical admission fails closed unless availability risk is documented
- [ ] Webhook timeout and outage behavior were tested
- [ ] Webhook TLS trust and Service endpoints are managed and monitored
- [ ] Policy engines cannot be bypassed through excluded namespaces or ServiceAccounts
- [ ] Image signature verification occurs at admission for production workloads
- [ ] The admission policy checks a digest or trusted signature, not only an allowed registry name
- [ ] Admission denials and failures are visible in audit logs and alerts

## Images and In-cluster Supply Chain (A03 · ASVS V15 · CWE-1104)

- [ ] Production images are pinned by immutable digest
- [ ] `imagePullPolicy` matches the digest/tag strategy and is explicit
- [ ] Private registry credentials are scoped to the namespace and registry
- [ ] Helm chart source, version, provenance, templates, hooks, and CRDs were reviewed
- [ ] No manifest is applied directly from an unreviewed URL
- [ ] Operators are treated as privileged software and have reviewed cluster-wide RBAC
- [ ] Image content checks are delegated to `docker-security`, not duplicated here

## Multi-tenancy and Availability (A01, A02 · ASVS V13 · CWE-284, CWE-668)

- [ ] A namespace is not described as a hard tenant boundary
- [ ] Tenants cannot create privileged pods, change namespace labels, or bind arbitrary roles
- [ ] ResourceQuota caps aggregate CPU, memory, storage, object counts, and workload counts
- [ ] LimitRange supplies defensible defaults and bounds per-container resources
- [ ] Every container sets CPU and memory requests and limits
- [ ] Higher-risk tenants use isolated nodes, taints/tolerations, and separate credentials
- [ ] Hard isolation requirements use separate clusters or equivalent infrastructure boundaries

## Audit Logging (A09 · ASVS V13 · CWE-778)

- [ ] The API server has a non-empty `audit.k8s.io/v1` Policy
- [ ] Policy captures authentication, RBAC, admission, Secret access, and workload mutation
- [ ] `pods/exec`, `pods/attach`, and `pods/portforward` are logged at Request or RequestResponse
- [ ] Secret request and response bodies are not logged
- [ ] Audit backends are durable, access-controlled, monitored, and sized for policy volume
- [ ] Alerts detect pod exec, privileged workload creation, RBAC grants, and admission failures
- [ ] Audit retention matches incident-response needs

## Before Returning

- [ ] Every finding names object, namespace, exploit path, fix, OWASP category, ASVS chapter, and CWE
- [ ] Every vulnerable manifest has a fixed counterpart
- [ ] Stable apiVersions were checked against the current Kubernetes API reference
- [ ] No CIS recommendation ID was quoted without checking the benchmark text
- [ ] Runtime facts that could not be verified are stated plainly
- [ ] Vulnerable examples were not applied to a cluster
