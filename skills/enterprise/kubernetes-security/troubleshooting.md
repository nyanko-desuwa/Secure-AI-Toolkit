# Kubernetes Troubleshooting

Use the more security-focused option unless a documented availability or compatibility need
requires otherwise. State the trade-off and the migration path; do not silently weaken a
boundary.

## PSA rejects an existing workload

A Deployment can be accepted while its resulting Pod is rejected. Inspect the namespace labels,
then create the Pod template locally and remove privileged fields, hostPath, host namespaces,
root UID, unsafe capabilities, and `Unconfined` seccomp. Check init and ephemeral containers too.
Do not change `enforce` to `warn` as a permanent fix.

If a system workload genuinely needs a restricted field, isolate it in a tightly controlled
namespace and document the exemption. A broad namespace exemption is a new privileged boundary,
not a fix.

## An old PSP chart fails after upgrade

PSP `policy/v1beta1` was removed in Kubernetes v1.25. Delete the obsolete object and map its
controls to PSA. Use a validating policy engine for conditions PSA cannot express, such as a
specific image signature or approved host path. Test generated Pods rather than only chart
installation.

## A webhook blocks every deployment

Check Service endpoints, TLS certificate validity, CA bundle, DNS, timeout, and webhook logs.
Then check `failurePolicy` and whether the webhook matches its own namespace or the control
plane's objects. For a security-critical validating webhook, `Fail` is normally correct; repair
the dependency rather than setting `Ignore` indefinitely. Use a narrow `namespaceSelector` and
explicitly document excluded system namespaces.

## Fail closed or open?

`Fail` denies when the webhook or policy service cannot decide. It costs deployment availability
and may interrupt incident response. `Ignore` permits the request when the security check is
unavailable. It costs the admission boundary and turns an outage into a bypass.

Use `Fail` for privileged workload prevention, image signature verification, and production
Secret policy. Use `Ignore` only where the policy is advisory or the availability requirement
is explicit, monitored, and bounded. Record the decision under A02/A10 and ASVS V13/V16.

## NetworkPolicy has no effect

First confirm the CNI plugin and whether its NetworkPolicy feature is enabled. The Kubernetes
API server stores the object but does not enforce packet filtering itself. Check for another
policy selecting the same pods; policies are additive, so an allow-all rule can defeat the
expected default deny.

Test from a disposable pod in the same namespace and from another namespace. Test both directions:
a connection needs source egress and destination ingress. Source code cannot prove this runtime
property.

## DNS stopped after egress deny

Default-deny egress isolates DNS too. Find the actual CoreDNS or kube-dns Service and pod labels,
then permit UDP and TCP 53 to those pods. Do not assume `k8s-app: kube-dns` on every distribution.
Use `kubectl get pods -n kube-system --show-labels` to verify labels.

## The fixed container cannot start as non-root

Read the image documentation and inspect its declared user with the image tooling covered by
`docker-security`. Set a known non-zero UID only when the image owns its files and can bind to
its port. Move writable paths to `emptyDir` or a PVC, and choose a port above 1024 instead of
adding `NET_BIND_SERVICE`.

Do not fix a root-only image by setting `allowPrivilegeEscalation: true`; that restores a
privilege path. If the image cannot run non-root, rebuild it or isolate it as an exception.

## Read-only root filesystem breaks the app

Look at the error path. Add a named `emptyDir` only for data that is intentionally ephemeral,
or a PVC for durable application data. Do not mount the host filesystem or make `/` writable.
Document caches, temporary files, and runtime sockets separately.

## A ServiceAccount needs the API unexpectedly

Start with `automountServiceAccountToken: false`, then identify the exact API calls. Add a
minimal Role and use a projected token with the API server's expected audience and short expiry.
Do not restore a long-lived token Secret because a legacy client cannot reread a file; add a
sidecar or update the client.

Use `kubectl auth can-i` as the ServiceAccount identity. A Role file does not show permissions
from other RoleBindings or ClusterRoleBindings.

## `kubectl auth can-i` says yes unexpectedly

List all bindings in the namespace and cluster. Search for `cluster-admin`, wildcard rules,
`system:masters`, and group membership. Check impersonation permission before trusting a test
using `--as`.

```bash
kubectl auth can-i --list --as=system:serviceaccount:reports:report-reader -n reports
kubectl auth can-i get secrets --as=system:serviceaccount:reports:report-reader -A
```

Remember that `list` and `watch` on Secrets expose their contents. `nodes/proxy` is a Kubelet
API boundary, not a harmless read permission.

## A Secret looks encrypted in Git

Base64 is reversible encoding. Remove it from source control, rotate the value, and configure
API-server encryption at rest. Prefer an external secret store or operator, but review that
operator's ClusterRole and provider credentials. A Secret manifest alone cannot prove etcd
uses encryption; verify the live control plane.

## Quota rejects an otherwise valid Pod

ResourceQuota may require requests or limits, or the namespace may have a LimitRange that sets a
maximum below the requested value. Inspect both objects and calculate the aggregate remaining
budget. Quotas constrain availability; do not remove them to solve an authorization problem.

## Digest pull fails from a private registry

Check registry DNS, credentials, `imagePullSecrets`, and whether the digest exists in that
repository. The ServiceAccount may need the image pull Secret, but do not give it unrelated API
permissions. `IfNotPresent` does not manufacture a missing digest and `Always` does not fix
credentials.

## An audit policy appears configured but no events arrive

A policy file in a repository does nothing until the API server is started with
`--audit-policy-file` and a backend is configured. Managed control planes expose provider-specific
settings instead. Check API-server flags or provider settings, audit backend health, disk/queue
pressure, and retention. A non-empty `audit.k8s.io/v1` Policy is required.

Use explicit resources `pods/exec`, `pods/attach`, and `pods/portforward`; `pods` does not match
their subresources. Avoid RequestResponse for Secrets because audit output becomes sensitive
storage.

## A policy cites a CIS control ID that cannot be found

Remove the ID. The current CIS Kubernetes Benchmark page lists Kubernetes 2.0.1, but this skill
did not verify control numbering against the benchmark PDF. Describe the control plainly and
link the benchmark page. Never make up a control ID to look precise.

## Managed cluster cannot accept encryption or audit flags

EKS, GKE, AKS, and other managed control planes may not expose API-server flags. Use the
provider's documented encryption and audit controls, then verify their status in the provider
console or API. Do not claim a self-managed `EncryptionConfiguration` is active when the
provider owns the API server.

## The standards appear to disagree

Top 10 prioritizes risk; ASVS supplies verification chapters; Kubernetes documents the field
behavior. Implement the concrete Kubernetes control and map it to A01/A02/A03/A09 plus the
relevant ASVS chapter. If a workload need conflicts with `restricted`, state what breaks, who
owns the exception, how it is isolated, and when it will be removed.

## Runtime enforcement cannot be proven from YAML

Say this plainly. YAML cannot prove PSA labels are present, a webhook is reachable, an image
signature was checked, a CNI filters packets, etcd encrypts data, a token audience is accepted,
or audit events reach a protected backend. Request live commands or provider evidence instead
of marking the item pass.
