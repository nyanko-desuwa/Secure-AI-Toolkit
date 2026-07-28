# NetworkPolicy, Secrets, Admission, and Audit

Version-specific claims checked 2026-07-28.

## NetworkPolicy

Source: <https://kubernetes.io/docs/concepts/services-networking/network-policies/>

Stable API: `networking.k8s.io/v1`.

Pods are non-isolated for ingress and egress by default. A pod becomes isolated in a direction
when a NetworkPolicy selects it and includes that direction in `policyTypes`. Once isolated,
only the union of applicable allow rules passes. Policies are additive; there is no ordering or
explicit deny rule. A pod-to-pod connection requires source egress and destination ingress to
allow it.

An empty `podSelector: {}` selects all pods in the policy namespace. A default-deny policy
selects all pods and has no allow rules:

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
```

Default-deny egress blocks DNS. Add a narrow allow rule for UDP and TCP 53 to the actual
cluster DNS pods. Verify labels; distributions vary.

Limitations:

- The CNI plugin, not the API server, enforces the policy
- Applying successfully does not prove packets are filtered
- NetworkPolicy cannot express TLS identity, service names, or general layer 7 policy
- There are no explicit deny rules; only default deny plus additive allows
- Traffic to a pod from its node and traffic from a pod to itself have special allowances
- IPBlock behavior around ingress/egress rewriting varies with implementation

Map: OWASP A02:2025, ASVS V13, CWE-668.

## Secrets and etcd

Source: <https://kubernetes.io/docs/concepts/security/secrets-good-practices/>

Source: <https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/>

Secret `data` values are base64-encoded and stored unencrypted by default. Base64 provides no
confidentiality. Stable encryption config:

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
```

The first provider writes new data. `identity` means plaintext. Prefer KMS where supported;
key material in a local config must itself be protected. Existing Secret records are not
rewritten merely by changing the provider order, so rotate/rewrite and verify data in etcd.

A mounted file usually leaks less accidentally than an environment variable: it can be scoped
to one container, does not appear in child-process environments, and can rotate in place. It
still does not resist code execution in that container. External secret operators and the
Secrets Store CSI Driver reduce Kubernetes copies but add privileged software and provider
credentials that need review.

Map: OWASP A02:2025, ASVS V14, CWE-522 and CWE-668.

## Admission Control

Source: <https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/>

Stable APIs in the current reference:

- `admissionregistration.k8s.io/v1` `ValidatingWebhookConfiguration`
- `admissionregistration.k8s.io/v1` `MutatingWebhookConfiguration`
- `admissionregistration.k8s.io/v1` `ValidatingAdmissionPolicy`
- `admissionregistration.k8s.io/v1` `ValidatingAdmissionPolicyBinding`

Mutation changes an object. Validation accepts or rejects it. Security should not depend only
on mutation because mutation can be skipped, fail, or be overridden later. Image signature
verification needs a policy engine or webhook that verifies an approved identity/attestation
against the image digest; an allowed registry or mutable tag is not a signature.

For webhook `failurePolicy`, `Fail` rejects on timeout or internal error; `Ignore` allows the
request to continue. `Fail` costs deployment availability. `Ignore` turns a policy outage into
a bypass. Use `Fail` for critical production boundaries and design the webhook for high
availability. Test timeout behavior and excluded namespaces.

Map: OWASP A02 and A03:2025, ASVS V13 and V15, CWE-284 and CWE-1104.

## Image and Chart Trust

Pin production images by digest. `imagePullPolicy: Always` controls resolution timing; it does
not make a tag immutable. Private registry pull Secrets are namespace credentials and require
the same handling as other Secrets.

A Helm chart can install hooks, CRDs, webhooks, operators, and ClusterRoles. Review rendered
manifests, source version, provenance, images, and lifecycle hooks. Do not run
`kubectl apply -f <url>` against an unreviewed mutable URL. Download, verify, pin, review, and
commit the artifact. Treat an operator with cluster-wide RBAC as privileged supply-chain code.

Image construction and scanning belong to `docker-security`; this skill covers runtime and
admission.

Map: OWASP A03:2025, ASVS V15, CWE-1104.

## Audit Logging

Source: <https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/>

Stable policy header:

```yaml
apiVersion: audit.k8s.io/v1
kind: Policy
```

The policy requires at least one rule. Rules are first-match. Levels:

| Level | Captures |
|---|---|
| `None` | Nothing |
| `Metadata` | Actor, time, resource, verb, and other metadata; no bodies |
| `Request` | Metadata and request body; not response body |
| `RequestResponse` | Metadata plus request and response bodies |

Stages are `RequestReceived`, `ResponseStarted`, `ResponseComplete`, and `Panic`.
`omitStages` suppresses named stages. Log `pods/exec`, `pods/attach`, and `pods/portforward`
explicitly because `pods` does not match subresources. An exec request records interactive
access; alert by actor, ServiceAccount, namespace, source, and time.

Avoid request bodies for Secrets and token APIs. An overly broad `RequestResponse` policy
creates a second secret store. Audit logging consumes API-server memory and backend capacity.
A policy file is inert unless the self-managed API server uses `--audit-policy-file`, or the
managed provider enables its equivalent.

Map: OWASP A09:2025, ASVS V13, CWE-778.

## Multi-tenancy and Availability

Namespaces scope names, many RBAC objects, quota, and policy selectors. They do not isolate a
kernel, node, control plane, privileged pod, hostPath, or a cluster-wide identity. Use PSA,
least-privilege RBAC, NetworkPolicy, ResourceQuota, LimitRange, and node isolation as layers.
Separate clusters are the clearer boundary for mutually untrusted tenants.

ResourceQuota and LimitRange limit denial-of-service blast radius. They do not protect data.
Node labels and taints guide scheduling but are not enough if tenants can change node selectors,
tolerations, or run privileged containers.

Map: OWASP A01 and A02:2025, ASVS V13, CWE-284 and CWE-668.
