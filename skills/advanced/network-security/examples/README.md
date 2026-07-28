# Network Security Examples

Insecure configuration next to its fix. Each example names the Top 10 2025 category, the CWE,
and why the fix closes the hole rather than just looking safer.

Read these as patterns. The syntax is nftables, nginx, OpenSSH, Kubernetes, and cloud-neutral
policy; the mistake is none of those things.

Every address here is from a documentation range (`10.0.0.0/8`, `192.0.2.0/24`,
`2001:db8::/32`) or `example.com`. Nothing here scans, floods, or exploits anything.

## Contents

- [Datastore reachable from the internet](#datastore-reachable-from-the-internet) — A02, CWE-1327
- [Flat network with no policy between tiers](#flat-network-with-no-policy-between-tiers) — A06, CWE-923
- [SSRF blocked in the application only](#ssrf-blocked-in-the-application-only) — A01, CWE-918
- [TLS verification disabled between services](#tls-verification-disabled-between-services) — A04, CWE-295
- [Admin endpoint protected by network location alone](#admin-endpoint-protected-by-network-location-alone) — A01, CWE-306
- [IPv6 left out of the policy](#ipv6-left-out-of-the-policy) — A02, CWE-923
- [Dangling DNS record](#dangling-dns-record) — A02, CWE-829
- [VPN that grants the whole estate](#vpn-that-grants-the-whole-estate) — A01, CWE-668

---

## Datastore reachable from the internet

`A02:2025` · `CWE-1327` · ASVS V13

Two independent mistakes have to line up, and they usually do: the process binds to every
interface, and the perimeter rule was written during setup.

```yaml
# Vulnerable: cloud-neutral firewall policy, written to unblock a laptop
- name: postgres-access
  direction: ingress
  protocol: tcp
  ports: [5432]
  source: 0.0.0.0/0
  action: allow
```

```conf
# Vulnerable: postgresql.conf
listen_addresses = '*'
```

Managed database ports on public addresses are found by continuous internet-wide scanning, not
by an attacker who was looking for you. From there it is a password-guessing problem, and the
password is usually in an environment variable that has never rotated.

```yaml
# Fixed: only the app tier, and only the app tier's port
- name: postgres-from-app
  direction: ingress
  protocol: tcp
  ports: [5432]
  source: 10.0.3.0/24        # app subnet
  action: allow
- name: postgres-from-migrations
  direction: ingress
  protocol: tcp
  ports: [5432]
  source: 10.0.9.20/32       # migration runner
  action: allow
- name: default-deny-ingress
  direction: ingress
  source: 0.0.0.0/0
  action: deny
```

```conf
# Fixed: postgresql.conf — private interface, TLS required
listen_addresses = '10.0.4.10'
ssl = on
```

Why this works: two layers now have to be wrong at once. The bind address means a perimeter
mistake does not expose the listener, and the source allowlist means a bind mistake does not
either.

The tempting wrong fix is moving the port. Changing 5432 to 55432 removes it from the top of
the scan list and nothing else — the service still answers, and a banner grab identifies it.

---

## Flat network with no policy between tiers

`A06:2025` · `CWE-923` · ASVS V13

One namespace, no policy, and a compromised image-resizing pod can open a connection to the
payments service and the cluster's internal APIs.

```yaml
# Vulnerable: no NetworkPolicy exists, so the CNI default is allow-all.
# Some teams make it explicit, which is worse because it looks deliberate:
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all
  namespace: production
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
  ingress: [{}]
  egress: [{}]
```

```yaml
# Fixed: deny by default in the namespace, then one policy per allowed pair
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: production
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: payments-from-orders
  namespace: production
spec:
  podSelector:
    matchLabels: { app: payments }
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector:
            matchLabels: { app: orders }
      ports:
        - port: 8443
          protocol: TCP
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: orders-egress
  namespace: production
spec:
  podSelector:
    matchLabels: { app: orders }
  policyTypes: [Egress]
  egress:
    - to:
        - podSelector:
            matchLabels: { app: payments }
      ports: [{ port: 8443, protocol: TCP }]
    - to:
        - namespaceSelector:
            matchLabels: { kubernetes.io/metadata.name: kube-system }
          podSelector:
            matchLabels: { k8s-app: kube-dns }
      ports: [{ port: 53, protocol: UDP }, { port: 53, protocol: TCP }]
```

Why this works: a policy that selects a pod for a direction denies everything not listed for
that direction, so the allowlist is the whole story. Naming the pair also documents the intended
call graph, which makes an unexpected connection reviewable.

Two things to state honestly. The DNS egress rule is mandatory — a default-deny egress policy
without it breaks name resolution, and that gets fixed by deleting the policy. And
NetworkPolicy enforcement is the CNI's job: with a CNI that does not implement it, these objects
are accepted by the API server and enforce nothing. Confirm which CNI is running.

---

## SSRF blocked in the application only

`A01:2025` · `CWE-918` · ASVS V2, V12

```python
# Vulnerable: resolve, check, then hand the name back to the HTTP client
import ipaddress, socket, requests
from urllib.parse import urlparse

def fetch_preview(url: str) -> str:
    host = urlparse(url).hostname
    ip = ipaddress.ip_address(socket.gethostbyname(host))
    if ip.is_private or ip.is_loopback:
        raise ValueError("blocked")
    return requests.get(url, timeout=5).text[:2000]
```

The check and the connection each perform their own DNS lookup. An attacker-controlled name with
a one-second TTL answers with a public address for the check and `169.254.169.254` for the
request. `gethostbyname` also returns only the first IPv4 answer, so an AAAA record is never
looked at.

```python
# Fixed: the workload has no route out except a proxy that enforces the allowlist
import requests

SESSION = requests.Session()
SESSION.proxies = {"http": "http://10.0.4.10:3128", "https": "http://10.0.4.10:3128"}
SESSION.trust_env = False

def fetch_preview(url: str) -> str:
    resp = SESSION.get(url, timeout=5, allow_redirects=False, stream=True)
    return resp.raw.read(2000, decode_content=True).decode("utf-8", "replace")
```

```bash
# Fixed: the rule that makes the above true, not just tidier
table inet filter {
  chain output {
    type filter hook output priority 0; policy drop;
    oif lo accept
    ct state established,related accept
    ip  daddr 169.254.169.254 drop comment "imds v4"
    ip6 daddr fd00:ec2::254   drop comment "imds v6"
    ip  daddr 10.0.4.10 tcp dport 3128 accept comment "egress proxy"
    udp dport 53 ip daddr 10.0.0.2 accept comment "internal resolver"
  }
}
```

Why this works: the destination is decided after DNS by a component the application cannot
influence, so a rebound name resolves inside the proxy where the allowlist applies. The
application check is worth keeping for fast failure and clearer errors, but it is no longer the
only thing standing between an SSRF and the metadata service.

`trust_env = False` is deliberate: it stops a `NO_PROXY` value in the environment from quietly
restoring direct connections.

---

## TLS verification disabled between services

`A04:2025` · `CWE-295`, `CWE-297` · ASVS V12

```javascript
// Vulnerable: added during a certificate rollout, never removed
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const res = await fetch("https://payments.svc.internal/charge", {
  method: "POST",
  body: JSON.stringify(payload),
});
```

The connection is encrypted and unauthenticated, which means anyone who can answer for that name
— through DNS, ARP or NDP spoofing, or a takeover of the internal name — reads and rewrites
payment requests. The process-wide flag disables verification for every TLS client in the
runtime, including the ones you did not write.

```javascript
// Fixed: verify against the internal CA explicitly, keep verification on
import { Agent } from "undici";
import { readFileSync } from "node:fs";

const agent = new Agent({
  connect: {
    ca: readFileSync("/etc/ssl/internal-ca.pem"),
    rejectUnauthorized: true,
    minVersion: "TLSv1.2",
    servername: "payments.svc.internal",
  },
});

const res = await fetch("https://payments.svc.internal/charge", {
  method: "POST",
  body: JSON.stringify(payload),
  dispatcher: agent,
});
```

Why this works: the trust decision is narrowed to one CA for one client rather than removed for
the whole process, and hostname verification still runs — that is the part `CWE-297` covers and
the part a bare `ca:` addition without `servername` on a mismatched SNI can still get wrong.

The tempting wrong fix is pinning the certificate's fingerprint. It works until renewal, and the
renewal happens at 3am, and the fix under pressure is the flag you just removed. Trust the
issuing CA and keep certificate lifetimes short instead.

---

## Admin endpoint protected by network location alone

`A01:2025` · `CWE-306` · ASVS V6, V12

```nginx
# Vulnerable: reachability is the only control
location /admin/ {
  allow 10.0.0.0/8;
  deny all;
  proxy_pass http://admin-backend;
}
```

Every workload in `10.0.0.0/8` is now an administrator. A compromised batch job, a
misconfigured test pod, or an SSRF in any service on the private network reaches this. The
backend also receives no identity, so it cannot log who acted.

```nginx
# Fixed: network restriction as one layer, authenticated identity as the control
location /admin/ {
  allow 10.0.9.0/24;          # jump segment only
  deny all;

  # Client certificate required in addition to the network restriction.
  if ($ssl_client_verify != SUCCESS) { return 403; }

  auth_request /_authz;       # identity-aware proxy decides per request

  proxy_set_header X-Admin-Subject $ssl_client_s_dn_cn;
  proxy_set_header X-Admin-Subject-Original "";
  proxy_pass https://admin-backend;
}

location = /_authz {
  internal;
  proxy_pass https://authz.svc.internal/verify;
  proxy_pass_request_body off;
  proxy_set_header Content-Length "";
  proxy_set_header X-Original-URI $request_uri;
}
```

Why this works: the request now needs a private key the CA issued and a positive authorisation
decision, so being on the network is a precondition rather than the credential. Clearing the
inbound `X-Admin-Subject` copy matters — otherwise the caller supplies the value the backend
logs.

Note the `if` here is a verification check on a value nginx set, not a rewrite of a client
input; `if` inside `location` is safe for `return` but has documented surprises with other
directives. Prefer `ssl_verify_client on` at server level where every location needs it.

---

## IPv6 left out of the policy

`A02:2025` · `CWE-923` · ASVS V13

```bash
# Vulnerable: careful IPv4 rules, and the host also has a global IPv6 address
table ip filter {
  chain input {
    type filter hook input priority 0; policy drop;
    ip saddr 10.0.1.0/24 tcp dport 8443 accept
  }
}
```

The `ip` family only sees IPv4. On a dual-stacked host the IPv6 path has no table at all, so
`policy drop` is not in effect there and `8443` — plus everything else listening — is reachable
over IPv6 from wherever the route reaches. The rule set looks locked down in review.

```bash
# Fixed: one inet table covers both families
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept

    ip  saddr 10.0.1.0/24      tcp dport 8443 accept
    ip6 saddr 2001:db8:1::/64  tcp dport 8443 accept

    # ICMPv6 neighbour discovery is required. Dropping it breaks IPv6 in ways
    # that get diagnosed by turning the firewall off.
    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert,
                  nd-router-solicit, nd-router-advert,
                  packet-too-big, time-exceeded, parameter-problem } accept
    icmp   type { echo-request, destination-unreachable, time-exceeded } accept
  }
}
```

Why this works: `inet` is a single rule set applied to both families, so there is no second file
whose absence is invisible. The explicit ICMPv6 allowances keep neighbour discovery and path MTU
discovery working, which is what stops someone from "fixing" a stall by flushing the table.

Allowlist an IPv6 prefix, not a single host address. RFC 8981 (February 2021, obsoletes
RFC 4941) specifies temporary SLAAC addresses that rotate, so a `/128` entry silently stops
matching the host it was written for.

The other half of this mistake is disabling IPv6 to avoid the problem. It is a supported
protocol on every modern network, cloud providers assign it, and "disabled" often means
"disabled on the interface you checked".

---

## Dangling DNS record

`A02:2025` · `CWE-829` · ASVS V13

```dns
; Vulnerable: the bucket and the app were decommissioned, the records were not
docs      CNAME  legacy-docs-bucket.storage.example-cloud.net.
promo     CNAME  campaign-2019.example-paas.net.
```

The provider released both names. Anyone can register `campaign-2019` on that platform and serve
content from `promo.example.com`. That is a phishing page on your domain with a valid
certificate, and worse, any cookie scoped to `.example.com` is now readable by attacker-served
JavaScript — including a session cookie set without a host-only scope.

```dns
; Fixed: records removed with the resource, and CAA limits who can issue
docs      CNAME  docs-prod.storage.example-cloud.net.   ; verified live 2026-07-28
example.com.  CAA  0 issue "letsencrypt.org"
example.com.  CAA  0 iodef "mailto:security@example.com"
```

```yaml
# Fixed: the process change that stops it recurring
decommission_checklist:
  - remove DNS records that target the resource   # before releasing the resource
  - release the resource
  - verify no remaining record resolves to a name you no longer control
monitoring:
  - schedule: daily
    check: every CNAME target still resolves to a resource in our inventory
    on_failure: alert security, do not auto-delete
```

Why this works: deleting the record before releasing the resource removes the window entirely —
ordering is the whole fix. The daily inventory check catches the ones that slip, because in
practice some will.

CAA (RFC 8659, November 2019, obsoletes RFC 6844) limits which CAs may issue for the domain. Be
precise about what that buys: it reduces the set of parties who can mis-issue. It does not stop a
CA that ignores it, has no effect on already-issued certificates, and does not help at all when
the attacker legitimately controls the takeover target and requests their own certificate for it.

The tempting wrong fix is a wildcard `*.example.com` pointing at a "not found" page. That makes
takeover harder to notice, not harder to do — the specific record still wins.

---

## VPN that grants the whole estate

`A01:2025` · `CWE-668` · ASVS V6, V12

```conf
# Vulnerable: one credential, one route, everything
# VPN server config
push "route 10.0.0.0 255.0.0.0"
duplicate-cn
auth-user-pass-verify /etc/openvpn/check-password.sh via-file
```

```bash
# Vulnerable: bastion as a general-purpose tunnel
# /etc/ssh/sshd_config
PasswordAuthentication yes
AllowTcpForwarding yes
PermitTunnel yes
```

A stolen laptop or a phished password now reaches every subnet. `AllowTcpForwarding yes` makes
the bastion a SOCKS proxy for anyone who can log in, so the segmentation it was deployed to
enforce is bypassed by `ssh -D`. `duplicate-cn` means sessions cannot be attributed to a device.

```conf
# Fixed: VPN reaches a jump segment only, certificate-based, one session per identity
push "route 10.0.9.0 255.255.255.0"
verify-x509-name "CN=" name-prefix
remote-cert-tls client
tls-version-min "1.2"
# no duplicate-cn: one concurrent session per certificate
```

```bash
# Fixed: bastion authenticates, does not forward, and is auditable
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
PermitRootLogin no
AllowTcpForwarding no
PermitTunnel no
AllowAgentForwarding no
X11Forwarding no
LogLevel VERBOSE
ClientAliveInterval 300
ClientAliveCountMax 2
AllowGroups bastion-users
```

Why this works: the VPN grants reachability to one small segment instead of the estate, and
reaching a workload from there needs a second authorisation step. `AllowTcpForwarding no` is the
line that preserves that boundary — with forwarding on, the jump segment restriction is
decorative. `LogLevel VERBOSE` records the key fingerprint used, so a session maps to a specific
credential rather than to an account name shared by four people.

Stated limitation: this still trusts a long-lived private key on an endpoint. An identity-aware
proxy that authorises per connection against current device and user posture is the stronger
model (NIST SP 800-207, August 2020) — a bastion is the pragmatic step, not the destination.

Do not test any of this by port-scanning the jump segment. Read the rule set and the sshd
config; they are authoritative and they do not generate an incident.

---

## Sources

- OWASP Top 10 2025 — <https://owasp.org/Top10/2025/>
- OWASP ASVS — <https://owasp.org/www-project-application-security-verification-standard/>
- RFC 9325 (BCP 195) — <https://www.rfc-editor.org/rfc/rfc9325.html>
- RFC 8996 (BCP 195) — <https://www.rfc-editor.org/rfc/rfc8996.html>
- RFC 8659 (CAA) — <https://www.rfc-editor.org/rfc/rfc8659.html>
- RFC 8981 (IPv6 temporary addresses) — <https://www.rfc-editor.org/rfc/rfc8981.html>
- NIST SP 800-207 — <https://csrc.nist.gov/pubs/sp/800/207/final>
- CWE — <https://cwe.mitre.org/>

All URLs checked 2026-07-28.
