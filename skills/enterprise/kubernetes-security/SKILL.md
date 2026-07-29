---
name: kubernetes-security
description: 'Harden Kubernetes workloads and clusters when writing or reviewing manifests, RBAC, and cluster config. Covers Pod Security Admission, securityContext, RBAC least privilege, NetworkPolicy, Secrets, and admission control. Triggers: "Kubernetes", "k8s", "pod security", "RBAC", "NetworkPolicy", "securityContext", "Helm", "cluster hardening", "bảo mật Kubernetes", "phân quyền".'
allowed-tools: Read, Glob, Grep, WebSearch, WebFetch
---

# Kubernetes Security

Kubernetes defaults are permissive. A Deployment with no `securityContext` runs as root, with
a writable root filesystem, full default capability set, and a mounted ServiceAccount token.
A namespace with no NetworkPolicy is reachable from every pod in the cluster. Neither is a
misconfiguration you introduced; both are what you get by leaving fields out.

This skill turns that into concrete manifest-level decisions, each traced to a standard.

## When to Use

- Writing or reviewing a Pod, Deployment, StatefulSet, DaemonSet, Job, or CronJob
- Writing or reviewing Role, ClusterRole, RoleBinding, ClusterRoleBinding, or ServiceAccount
- Writing NetworkPolicy, or noticing a namespace has none
- Reviewing a Helm chart, an operator, or anything applied from a URL
- Setting up Pod Security Admission, admission webhooks, or audit policy
- Handling Secrets, etcd encryption, or external secret stores
- Investigating whether a workload could reach the node or the control plane

## The Failure That Matters Most

One chain accounts for most real cluster compromise, and it is short:

1. A pod runs privileged, or mounts a `hostPath` of `/` or `/var/lib/kubelet`.
2. Privileged or host-mounted means the container namespace is no longer a boundary. The
   process reads and writes the node filesystem as root.
3. The node filesystem holds kubelet credentials and the projected ServiceAccount tokens of
   every pod scheduled there.
4. Those credentials are cluster credentials. If any pod on that node has a broad token, the
   attacker now has it.

Nothing in that chain is exotic. Step 1 is a single field. Everything else follows. The
controls that break it are Pod Security Admission at `restricted` (blocks step 1 at admission)
and RBAC that keeps step 4 from being worth anything. See
[best-practices.md](best-practices.md#the-escape-chain-and-what-blocks-it).

## Workflow

### 1. Scope

For each manifest, answer:

- What can this pod reach? Node, control plane, other namespaces, the internet.
- What identity does it carry? Which ServiceAccount, and what can that ServiceAccount do.
- What happens at admission? Is anything actually checking this before it runs.

If you cannot answer all three, read the RBAC and namespace labels before writing YAML.

### 2. Map

| What you are looking at | Categories |
|---|---|
| RBAC, ServiceAccounts, tokens | A01 · ASVS V13 · CWE-269, CWE-284 |
| securityContext, PSA, host mounts | A02 · ASVS V13 · CWE-250, CWE-732 |
| Secrets, etcd encryption | A02 · ASVS V14 · CWE-522, CWE-668 |
| NetworkPolicy, namespace isolation | A02 · ASVS V13 · CWE-668 |
| Images, Helm charts, operators | A03 · ASVS V15 · CWE-1104 |
| Audit policy, admission logging | A09 · ASVS V13 · CWE-778 |

Do not reach for A05 (Injection). Kubernetes findings are almost always misconfiguration or
access control.

### 3. Apply Controls

Order matters, because each layer assumes the one below it:

1. **Admission first.** A namespace labelled
   `pod-security.kubernetes.io/enforce: restricted` makes most of the rest unnecessary to
   argue about. Without it, every hardened manifest is a convention someone can skip.
2. **securityContext on every container.** Non-root, no privilege escalation, read-only root
   filesystem, drop `ALL` capabilities, seccomp `RuntimeDefault`.
3. **Least-privilege RBAC.** Namespaced Role over ClusterRole. Named resources over
   wildcards. No `cluster-admin` on a workload ServiceAccount, ever.
4. **Default-deny NetworkPolicy per namespace,** ingress and egress, then allow what is
   needed. Remember DNS.
5. **Turn off token automount** where the workload does not call the API.
6. **Pin images by digest.** Encrypt Secrets at rest. Log the API server.

### 4. Verify

Run [checklist.md](checklist.md). Every unchecked box is a fix or a stated limitation.

Two checks you can run without a cluster and one you cannot:

```bash
# What can this ServiceAccount actually do
kubectl auth can-i --list --as=system:serviceaccount:prod:api-sa -n prod

# Does anything grant cluster-admin to a ServiceAccount
kubectl get clusterrolebindings,rolebindings -A -o json \
  | jq -r '.items[] | select(.roleRef.name=="cluster-admin")
           | "\(.kind) \(.metadata.namespace // "-")/\(.metadata.name)"'
```

Reading YAML cannot tell you whether the namespace carries PSA labels, whether etcd
encryption is on, or whether the CNI plugin enforces NetworkPolicy at all. Say so instead of
implying the manifest is sufficient.

### 5. Report

For each finding: object and name, what an attacker with a foothold in the cluster gains,
the field to change, and whether admission would have stopped it. A `securityContext` gap in
a namespace enforcing `restricted` is not exploitable - the pod never starts. Say which case
you are in.

## Severity

Rank by what the finding gives an attacker who already has code execution in one pod, which
is the realistic starting point.

- **Critical** - path to node root or control plane credentials: privileged pod, `hostPath`
  on a sensitive path, `hostPID`, `cluster-admin` on a workload ServiceAccount, `escalate`
  or `bind` or `impersonate` granted broadly, `get` on `nodes/proxy`
- **High** - cross-namespace or cross-tenant reach: no NetworkPolicy in a multi-tenant
  cluster, `list` on Secrets cluster-wide, wildcard verbs on a wildcard resource
- **Medium** - missing defence in depth with no direct path: no `readOnlyRootFilesystem`,
  token automounted but the token is narrow, Secret in env vars
- **Low** - hygiene: mutable image tag in a non-production namespace, missing resource limits

State the reasoning. "Runs as root, therefore critical" is wrong if the namespace enforces
`restricted` and the pod is rejected at admission.

## Related Skills

- `docker-security` - the image itself: base image choice, build-time users, layer secrets,
  multi-stage builds. This skill covers how the image runs, not what is in it. Do not
  duplicate image scanning guidance here.
- `owasp-security` - the application inside the container
- `compliance` - CIS Benchmark and control-framework mapping

## Supporting Files

- [README.md](README.md) - purpose, standards table, limitations
- [checklist.md](checklist.md) - pre-return verification
- [best-practices.md](best-practices.md) - patterns, with vulnerable/fixed manifests
- [common-mistakes.md](common-mistakes.md) - what goes wrong and why the fix works
- [troubleshooting.md](troubleshooting.md) - when a control cannot be applied
- [prompts.md](prompts.md) - prompts that produce findings
- [references/](references/) - version-pinned standard and API summaries
- [examples/](examples/) - eight vulnerable/fixed manifest pairs
