# Kubernetes Security Verification Checklist

Run the sections that match the change. Mark each item pass, fail, or not applicable. A pass
means the manifest or live cluster output proves it. A manifest alone cannot prove admission,
CNI enforcement, etcd encryption, or audit delivery.

## Pod Admission (A02 · ASVS V13 · CWE-250, CWE-732)

- [ ] [critical] Every workload namespace has `pod-security.kubernetes.io/enforce` set
- [ ] [critical] Production namespaces enforce `restricted`, unless a documented workload need prevents it
- [ ] [recommended] The `enforce-version` label is pinned to a tested Kubernetes minor version
- [ ] [recommended] `audit` and `warn` labels test `restricted` before rollout
- [ ] [critical] PSA exemptions are narrow and reviewed; controller ServiceAccounts are not exempted
- [ ] [recommended] Old PodSecurityPolicy manifests and assumptions have been removed
- [ ] [recommended] Migration testing covers generated pods, not only Deployment admission
- [ ] [critical] Privileged containers, host namespaces, host ports, and `hostPath` are rejected
- [ ] [critical] Init and ephemeral containers meet the same policy as app containers

## Workload Security Context (A02 · ASVS V13 · CWE-250, CWE-732)

- [ ] [critical] Pod or every container sets `runAsNonRoot: true`
- [ ] [recommended] `runAsUser` is a known non-zero UID where the image supports one
- [ ] [critical] Every container sets `allowPrivilegeEscalation: false`
- [ ] [recommended] Every container sets `readOnlyRootFilesystem: true`
- [ ] [recommended] Writable paths use named `emptyDir` or persistent volumes, not a writable root filesystem
- [ ] [critical] Every container drops `ALL` capabilities
- [ ] [critical] Added capabilities are individually justified; only `NET_BIND_SERVICE` passes restricted PSA
- [ ] [recommended] Pod or every container sets `seccompProfile.type: RuntimeDefault`
- [ ] [critical] No container sets `privileged: true`
- [ ] [critical] No workload uses `hostPID`, `hostIPC`, or `hostNetwork` without a system-level exception
- [ ] [critical] No volume mounts the node filesystem with `hostPath`
- [ ] [critical] Windows HostProcess containers are absent or explicitly approved

## Workload Identity and RBAC (A01 · ASVS V13 · CWE-269, CWE-284)

- [ ] [recommended] Every workload names a dedicated ServiceAccount
- [ ] [critical] The namespace `default` ServiceAccount has no added permissions
- [ ] [recommended] Workload permissions use Role and RoleBinding where namespace scope is sufficient
- [ ] [critical] No workload ServiceAccount is bound to `cluster-admin`
- [ ] [critical] No user or ServiceAccount is placed in `system:masters`
- [ ] [critical] Rules name required API groups, resources, and verbs; no `*` wildcards
- [ ] [critical] Secret `list` and `watch` are treated as secret-read permissions
- [ ] [critical] Pod or workload creation is treated as access to mountable Secrets and ServiceAccounts
- [ ] [critical] `escalate`, `bind`, and `impersonate` are absent unless explicitly required and scoped
- [ ] [critical] `nodes/proxy` is absent from application roles
- [ ] [recommended] `roleRef` and every subject refer to the intended namespace and identity
- [ ] [recommended] Effective permissions were checked with `kubectl auth can-i --list --as=...`
- [ ] [recommended] High-impact permissions were checked individually in every relevant namespace

## ServiceAccount Tokens (A01 · ASVS V13 · CWE-306, CWE-522)

- [ ] [recommended] Workloads that do not call the API set `automountServiceAccountToken: false`
- [ ] [recommended] The ServiceAccount also defaults automount to false where practical
- [ ] [recommended] API clients use projected bound tokens, not manually created legacy token Secrets
- [ ] [recommended] A projected token has the narrow consumer audience
- [ ] [recommended] `expirationSeconds` is short enough for the use case and at least 600 seconds
- [ ] [recommended] The client rereads the projected token file after kubelet rotation
- [ ] [critical] No long-lived `kubernetes.io/service-account-token` Secret is created without justification

## Secrets and Storage (A02 · ASVS V14 · CWE-522, CWE-668)

- [ ] [critical] Reviewers do not mistake base64 in `data` for encryption
- [ ] [critical] The live API server is configured to encrypt Secrets in etcd
- [ ] [recommended] A KMS provider is preferred over keys stored beside the API server configuration
- [ ] [critical] Encryption was verified by inspecting etcd storage, not only the config file
- [ ] [recommended] Encryption was rotated or rewritten after enabling a new provider
- [ ] [critical] Secret RBAC grants `get` only to components that require it
- [ ] [recommended] Applications receive Secrets as read-only files where possible, not environment variables
- [ ] [critical] Secret values cannot appear in process dumps, debug endpoints, logs, or child environments
- [ ] [recommended] External secret operators have only the namespaces and secret paths they need
- [ ] [critical] Secret manifests are absent from source control, including Helm values

## Network Isolation (A02 · ASVS V13 · CWE-668)

- [ ] [critical] Every workload namespace has default-deny ingress and egress policies
- [ ] [recommended] Explicit ingress rules select both source and destination narrowly
- [ ] [recommended] Explicit egress rules name required destinations and ports
- [ ] [recommended] DNS egress permits UDP and TCP 53 to the actual cluster DNS pods
- [ ] [recommended] No policy uses an empty allow rule (`- {}`) by accident
- [ ] [recommended] Source and destination selectors use labels controlled by trusted administrators
- [ ] [critical] The deployed CNI plugin is confirmed to implement NetworkPolicy
- [ ] [recommended] Connectivity tests prove allowed traffic works and denied traffic fails
- [ ] [recommended] Policies do not claim to block traffic from a pod to itself or its node

## Admission Control (A02, A03 · ASVS V13, V15 · CWE-284, CWE-1104)

- [ ] [critical] Validating controls reject unsafe objects; mutation is not the only enforcement
- [ ] [recommended] Mutating webhooks are idempotent and declare dry-run side effects correctly
- [ ] [critical] Security-critical admission fails closed unless availability risk is documented
- [ ] [recommended] Webhook timeout and outage behavior were tested
- [ ] [recommended] Webhook TLS trust and Service endpoints are managed and monitored
- [ ] [critical] Policy engines cannot be bypassed through excluded namespaces or ServiceAccounts
- [ ] [critical] Image signature verification occurs at admission for production workloads
- [ ] [critical] The admission policy checks a digest or trusted signature, not only an allowed registry name
- [ ] [recommended] Admission denials and failures are visible in audit logs and alerts

## Images and In-cluster Supply Chain (A03 · ASVS V15 · CWE-1104)

- [ ] [critical] Production images are pinned by immutable digest
- [ ] [recommended] `imagePullPolicy` matches the digest/tag strategy and is explicit
- [ ] [recommended] Private registry credentials are scoped to the namespace and registry
- [ ] [recommended] Helm chart source, version, provenance, templates, hooks, and CRDs were reviewed
- [ ] [critical] No manifest is applied directly from an unreviewed URL
- [ ] [recommended] Operators are treated as privileged software and have reviewed cluster-wide RBAC
- [ ] [recommended] Image content checks are delegated to `docker-security`, not duplicated here

## Multi-tenancy and Availability (A01, A02 · ASVS V13 · CWE-284, CWE-668)

- [ ] [recommended] A namespace is not described as a hard tenant boundary
- [ ] [critical] Tenants cannot create privileged pods, change namespace labels, or bind arbitrary roles
- [ ] [recommended] ResourceQuota caps aggregate CPU, memory, storage, object counts, and workload counts
- [ ] [recommended] LimitRange supplies defensible defaults and bounds per-container resources
- [ ] [recommended] Every container sets CPU and memory requests and limits
- [ ] [recommended] Higher-risk tenants use isolated nodes, taints/tolerations, and separate credentials
- [ ] [recommended] Hard isolation requirements use separate clusters or equivalent infrastructure boundaries

## Audit Logging (A09 · ASVS V13 · CWE-778)

- [ ] [recommended] The API server has a non-empty `audit.k8s.io/v1` Policy
- [ ] [recommended] Policy captures authentication, RBAC, admission, Secret access, and workload mutation
- [ ] [recommended] `pods/exec`, `pods/attach`, and `pods/portforward` are logged at Request or RequestResponse
- [ ] [critical] Secret request and response bodies are not logged
- [ ] [recommended] Audit backends are durable, access-controlled, monitored, and sized for policy volume
- [ ] [recommended] Alerts detect pod exec, privileged workload creation, RBAC grants, and admission failures
- [ ] [recommended] Audit retention matches incident-response needs

## Before Returning

- [ ] [recommended] Every finding names object, namespace, exploit path, fix, OWASP category, ASVS chapter, and CWE
- [ ] [recommended] Every vulnerable manifest has a fixed counterpart
- [ ] [recommended] Stable apiVersions were checked against the current Kubernetes API reference
- [ ] [recommended] No CIS recommendation ID was quoted without checking the benchmark text
- [ ] [critical] Runtime facts that could not be verified are stated plainly
- [ ] [recommended] Vulnerable examples were not applied to a cluster
