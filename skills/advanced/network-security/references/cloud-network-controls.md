# Cloud Network Controls

The same control under three names, plus the defaults each provider ships. Read this before
applying guidance written for one provider to another - the roles match, the semantics do not.

Verified 2026-07-28 against the provider documentation linked at the bottom.

`A02:2025` · ASVS V13 · `CWE-1327`

## Equivalents

| Concern | AWS | Azure | GCP |
|---|---|---|---|
| Virtual network | VPC | VNet | VPC network |
| Workload-level filter | Security group (stateful) | NSG (stateful) | VPC firewall rule (stateful) |
| Subnet-level filter | Network ACL (stateless) | NSG attached to subnet | Firewall rule with target tags or SA |
| Grouping for rules | Security group as source | Application security group | Network tag, service account |
| Default egress | Allow all | `AllowInternetOutBound` rule | Implied allow-egress rule |
| Default ingress | Deny all | `DenyAllInbound` rule | Implied deny-ingress rule |
| Hostname-based egress | Network Firewall, or a proxy | Azure Firewall FQDN rules | Firewall policy FQDN objects |
| Private access to managed services | VPC endpoint, PrivateLink | Private Endpoint, Service Endpoint | Private Service Connect, Private Google Access |
| Managed WAF | AWS WAF | WAF on App Gateway or Front Door | Cloud Armor |
| Flow logging | VPC Flow Logs | VNet flow logs | VPC Flow Logs |
| Identity-aware admin access | Systems Manager Session Manager, Verified Access | Entra Private Access, Bastion | Identity-Aware Proxy, IAP TCP forwarding |

## Defaults that decide your blast radius

Read the row for your provider before writing a rule.

| Behaviour | AWS security group | Azure NSG | GCP firewall rule |
|---|---|---|---|
| Stateful | Yes | Yes, via flow records | Yes |
| Explicit deny rules | No. Allow-only | Yes, `Deny` action | Yes, `denied` action |
| Rule evaluation | Union of all allows | First match by priority, 100 to 4096, lower first | First match by priority, 0 to 65535, lower first |
| Egress default | All allowed | Allowed to internet by default rule 65001 | Allowed by implied rule |
| Removing an allow rule | Existing connections continue | Existing connections continue | Existing connections continue |

Two consequences people trip over.

AWS security groups have no deny. You cannot write "allow the subnet except this host" - you
express it by narrowing the allow, or you move up to a Network ACL, which is stateless and
therefore needs the ephemeral-port return range opened explicitly.

Azure's default rules cannot be deleted, only overridden by a rule with a lower priority number.
Egress is open until you add a rule below priority 65001 that denies it. Writing a
`DenyInternetOutbound` rule at priority 4096 and an allow at 100 is the pattern; leaving the
defaults alone and adding only allows changes nothing.

## Traffic the provider exempts from your rules

Every provider carves out platform traffic. If you assume a default-deny egress rule covers
everything, this is where that assumption is wrong.

| Provider | Not filtered by your rules |
|---|---|
| AWS | Amazon DNS, DHCP, EC2 instance metadata, ECS task metadata endpoints, Windows license activation, Amazon Time Sync, the default VPC router addresses |
| Azure | Platform DNS and IMDS via `168.63.129.16` and `169.254.169.254`, unless you deny them with the `AzurePlatformDNS`, `AzurePlatformIMDS`, or `AzurePlatformLKM` service tags |
| GCP | Metadata server traffic to `169.254.169.254` / `metadata.google.internal` |

So a security group cannot block the metadata service. On AWS the control is
`http_tokens = "required"` (IMDSv2) plus `http_put_response_hop_limit = 1`, or
`http_endpoint = "disabled"` where the workload needs no metadata. On a Linux host you can drop
it in the host firewall, which is outside the provider's exemption. On Azure and GCP the metadata
service requires a non-forwardable header, so a plain URL-controlling SSRF cannot read it - but a
request-header-controlling SSRF can.

## Hostname-based egress: read the limits before you rely on it

FQDN-based rules look like the answer to "allowlist `api.stripe.com` and nothing else". They are
a real improvement over an IP list and they are not equivalent to a proxy. GCP documents the
constraints most explicitly, and the shape of them applies to the other providers' FQDN features
too.

| Limit | Effect |
|---|---|
| 32 IPv4 and 32 IPv6 addresses per FQDN object | Larger answer sets are truncated. The rest of the addresses are not allowed |
| Unresolvable name is silently ignored | `NXDOMAIN`, an answer with no address, or an unreachable DNS server produces partial enforcement, not an error |
| TTL below 90 seconds unsupported | Short-TTL records go stale between resolutions |
| Answers vary by client location and DNS load balancing | The programmed addresses do not contain every address for the name. Google's own documentation says to use address groups for `googleapis.com`-style domains |
| Enforcement is by resolved IP | Two names on one address collapse into whichever rule has better priority |
| No wildcards, no single-label names | `*.example.com` is not expressible |

A rule that fails open on a DNS error is not a rule you can cite as the control. Where the
requirement is "this workload may reach exactly these three APIs", the answer is an egress proxy
enforcing a host allowlist, with the firewall permitting outbound only to the proxy. FQDN rules
are a good coarse filter in front of that, not a replacement for it.

## Kubernetes NetworkPolicy

`networking.k8s.io/v1`. What it is, stated precisely, because most misuse comes from expecting
more.

- Layer 3/4 only: pod, namespace, and CIDR selectors with ports, for TCP, UDP, and SCTP.
- Allow-only and purely additive. There are no deny rules; the permitted set is the union of
  every policy that selects the pod, so evaluation order does not exist.
- Isolation is per-direction. A pod is unrestricted until some policy selects it and names that
  direction in `policyTypes`. `podSelector: {}` with a direction and no rules is the default-deny
  idiom, and it is namespace-scoped - you need one per namespace.
- Enforcement comes from the CNI. A policy on a plugin that does not implement NetworkPolicy is
  a YAML file with no effect. Verify the plugin, not the object.
- Traffic from the node a pod runs on is always allowed, and a pod cannot block access to itself.
- No logging, no TLS or L7 awareness, no Service-name targeting, and no cluster-wide default
  policy. Those need a CNI extension (Cilium, Calico) or a mesh.

Existing connections are not necessarily cut when you apply a deny policy; behaviour depends on
the plugin. Do not assume applying a policy stops traffic already in flight.

## Reading a provider config for findings

| Look for | Finding |
|---|---|
| `0.0.0.0/0` or `::/0` ingress on anything but 80/443 | Public exposure. Critical for a datastore, admin interface, or orchestrator API |
| An IPv4 CIDR list with the IPv6 field empty | Unfiltered over IPv6 on a dual-stack subnet. `CWE-1327` |
| No egress rule at all | Default allow-all. `A01:2025`, `CWE-918` |
| A security group referenced as its own source, all ports | Flat segment. Any pod or instance reaches every peer |
| Flow logs absent | `A09:2025`, `CWE-778`. No answer to "what did it talk to" |
| `http_tokens = "optional"` on AWS | IMDSv1 reachable. SSRF becomes credential disclosure |
| NetworkPolicy present, CNI unknown | Cannot claim it is enforced. State the uncertainty |

## Sources

- AWS security groups - <https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html>
- AWS instance metadata options - <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html>
- Azure network security groups overview - <https://learn.microsoft.com/azure/virtual-network/network-security-groups-overview>
- Azure service tags - <https://learn.microsoft.com/azure/virtual-network/service-tags-overview>
- GCP firewall FQDN objects - <https://cloud.google.com/firewall/docs/fqdn-objects-overview>
- Kubernetes NetworkPolicy - <https://kubernetes.io/docs/concepts/services-networking/network-policies/>
- OWASP Top 10 2025 - <https://owasp.org/Top10/2025/>
- OWASP ASVS - <https://owasp.org/www-project-application-security-verification-standard/>

All URLs checked 2026-07-28. Azure NSG flow logs are being retired on 2027-09-30 and new ones
could not be created after 2025-06-30; the current control is VNet flow logs.
