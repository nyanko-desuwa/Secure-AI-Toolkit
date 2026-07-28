# Kubernetes Security Prompt Examples

Good prompts name the object boundary, attacker starting point, standard, and answer shape.

## Review a workload

```text
Review k8s/deployment.yaml against OWASP A02:2025, ASVS V13, and CWE-250/CWE-732.
Check every pod, init, and ephemeral container for non-root, privilege escalation,
read-only root, capabilities, seccomp, host namespaces, hostPath, and token automount.
For each finding give object:field, exploitation path, severity, and fixed YAML.
```

## Review a namespace

```text
Review the namespace and all its workloads. Tell me whether PSA enforce is active,
which level and version it uses, whether ingress and egress are default-deny, and whether
quota and limits exist. Separate facts visible in YAML from runtime facts that need kubectl.
Map findings to A02, ASVS V13, and the relevant CWE.
```

## Review RBAC effective access

```text
Audit every RoleBinding and ClusterRoleBinding for ServiceAccounts. Flag cluster-admin,
ClusterRole references, wildcard verbs/resources, Secrets list/watch, nodes/proxy,
escalate, bind, and impersonate. For each finding give the effective permission and the
kubectl auth can-i command that verifies it.
```

## Design a least-privilege identity

```text
The workload only reads ConfigMap report-settings in namespace reports. Write a complete
ServiceAccount, Role, and RoleBinding using stable apiVersions. It must not read Secrets,
create Pods, or call the API outside reports. Explain why a ClusterRole or wildcard is wrong.
Map to A01, ASVS V13, and CWE-269.
```

## Review ServiceAccount tokens

```text
Find workloads that do not call the Kubernetes API but receive an automounted token. Fix
those with automountServiceAccountToken: false. For the one API client, use a projected
serviceAccountToken with audience reports-api and a bounded expiration. Explain the legacy
Secret-token migration and token rotation behavior.
```

## Review Secrets

```text
Find Secret values in source, Helm values, env-var injection, logs, and ConfigMaps. Explain
that base64 is not encryption. Recommend mounted files or an external secret store, and list
what live control-plane evidence proves etcd encryption at rest. Map to A02, ASVS V14,
CWE-522, and CWE-668.
```

## Review NetworkPolicy

```text
For namespace reports, write complete networking.k8s.io/v1 policies for default-deny
Ingress and Egress, then allow gateway to report-api on TCP 8080, report-api to postgres
on TCP 5432, and DNS UDP/TCP 53. Verify selectors against the labels. State that YAML cannot
prove the CNI enforces policies.
```

## Review admission controls

```text
Review all admission webhooks and ValidatingAdmissionPolicy objects. Separate mutating from
validating controls. Flag failurePolicy: Ignore on security-critical controls, broad
namespace exclusions, weak TLS, missing image signature verification, and policies that
only warn. Explain the availability cost of failurePolicy Fail versus Ignore.
```

## Review supply chain in cluster

```text
Review this Helm chart and operator as untrusted executable configuration. Check chart
provenance, hooks, CRDs, image digests, registry credentials, ServiceAccounts, ClusterRoles,
and namespace scope. Also flag kubectl apply -f URL instructions. Map to A03, ASVS V15,
and CWE-1104 without inventing CIS control IDs.
```

## Review audit coverage

```text
Review the audit.k8s.io/v1 Policy. Confirm authentication, RBAC changes, Secret access,
workload mutations, pods/exec, pods/attach, and pods/portforward are covered without logging
Secret bodies. Explain levels None, Metadata, Request, RequestResponse and how to detect exec.
Map to A09, ASVS V13, and CWE-778.
```

## Threat-model the escape chain

```text
Threat-model a pod with privileged: true or a hostPath mount of /. Describe the defensive
chain from workload to node root to exposed cluster credentials, but do not provide exploit
commands or payloads. Show the manifest fields that enable the condition and the PSA,
securityContext, RBAC, node isolation, and audit controls that block or detect it.
```

## Validate generated examples

```text
Check every vulnerable/fixed pair in examples/README.md. Ensure each is a complete runnable
YAML document, uses a verified stable apiVersion, labels the vulnerability, cites A01/A02/A03/A09,
ASVS V13/V14/V15 where applicable, and names a genuine CWE. Do not apply the vulnerable side.
```

## Anti-patterns

| Prompt | Problem |
|---|---|
| "Make Kubernetes secure" | No namespace, workload, threat, or runtime scope |
| "Use best practices" | Produces generic advice instead of fields and checks |
| "Add a NetworkPolicy" | An allow rule can leave the namespace broadly reachable |
| "Encrypt this Secret with base64" | Base64 is not encryption |
| "Give the pod admin so it works" | Hides the real API call and creates escalation |
| "Use `Always` so the image is safe" | Pull behavior does not provide immutability or provenance |
| "Apply this URL directly" | Skips review, pinning, provenance, and supply-chain controls |
| "Set `privileged: false`" | Does not address hostPath, root UID, capabilities, or tokens |
| "Is the cluster compliant?" | A skill cannot prove runtime state, provider settings, or benchmark IDs |
