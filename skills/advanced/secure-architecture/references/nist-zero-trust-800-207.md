# NIST SP 800-207 - Zero Trust Architecture

Version: NIST Special Publication 800-207, August 2020, 59 pages. Authors Scott Rose and
Oliver Borchert (NIST), Stu Mitchell (Stu2Labs), Sean Connelly (CISA).

Source: <https://csrc.nist.gov/pubs/sp/800/207/final> · DOI 10.6028/NIST.SP.800-207
Verified: 2026-07-28, against the published PDF (tenets read from Section 2.1).

There is no later revision as of the check date. If a project cites "zero trust" without a
document, this is the one to anchor to.

## The model in one paragraph

A subject requests a resource. A policy decision point (PDP) decides, a policy enforcement
point (PEP) enforces. Everything past a PEP is an "implicit trust zone" - an area where
entities are trusted to the level of the last PDP/PEP gateway. The document's airport analogy:
once through the checkpoint, everyone in the boarding area is treated as trusted. The design
goal follows directly - move PEPs close to the resource so the implicit trust zone is as small
as possible.

That sentence is the whole architectural instruction. A single gateway in front of forty
services creates one enormous implicit trust zone.

## The seven tenets (Section 2.1)

Paraphrased, in order. The document notes these are the ideal goal and that not all will be
fully implemented in their purest form.

1. All data sources and computing services are considered resources.
2. All communication is secured regardless of network location. Requests from inside the
   enterprise network must meet the same requirements as requests from anywhere else.
3. Access to individual resources is granted on a per-session basis, with least privilege.
   Authorization to one resource does not automatically grant access to another.
4. Access is determined by dynamic policy - client identity, application/service, requesting
   asset state, plus behavioural and environmental attributes. Least privilege restricts both
   visibility and accessibility.
5. The enterprise monitors and measures the integrity and security posture of all owned and
   associated assets. No asset is inherently trusted.
6. All resource authentication and authorization are dynamic and strictly enforced before
   access is allowed. Continual re-evaluation, not a one-time check at login.
7. The enterprise collects as much information as possible about asset state, network
   infrastructure, and communications, and uses it to improve policy.

Scope limit stated in the document: these tenets apply to work inside an organization or with
partner organizations, not to anonymous public or consumer-facing processes. An organization
cannot impose internal policy on external actors. Do not cite 800-207 to justify device
posture checks on your public signup page.

## The six network assumptions (Section 2.2)

Useful when someone argues the private network is safe:

1. The enterprise private network is not an implicit trust zone. Assets should act as if an
   attacker is present.
2. Devices on the network may not be owned or configurable by the enterprise.
3. No resource is inherently trusted. Subject credentials alone are insufficient for device
   authentication.
4. Not all enterprise resources are on enterprise-owned infrastructure.
5. Remote subjects cannot fully trust their local network connection.
6. Assets and workflows moving between enterprise and non-enterprise infrastructure should
   carry a consistent security policy and posture.

## Mapping to code decisions

| Tenet | What it means in a design review |
|---|---|
| 2 | mTLS or signed requests between services, not "it's in the VPC" |
| 3 | Service-to-service tokens are audience-scoped, short-lived, one per call path |
| 4 | Authorization input includes tenant, resource, action, and asset state - not just a role |
| 5 | Workload identity depends on attestable state, not a static shared secret |
| 6 | Re-authorize per request. A cached decision from login is a stale decision |
| 7 | Every allow and deny is logged with actor, resource, and decision input |

## What 800-207 does not give you

- No requirement IDs to verify against. It is a conceptual document, not a checklist. For
  testable statements use ASVS 5.0 V8 and V13.
- No product guidance. The logical components (policy engine, policy administrator, PEP) are
  roles, not products, and one product often plays several.
- No advice on public consumer flows, by explicit scope.
- Nothing on data classification or privacy. Pair with LINDDUN for privacy threats.

## Related

- OWASP ASVS 5.0 V8 (Authorization), V13 (Configuration)
- OWASP Top 10 2025 A01 (Broken Access Control), A02 (Security Misconfiguration)
- CWE-653 Improper Isolation or Compartmentalization (Class)
- CWE-1220 Insufficient Granularity of Access Control (Base)
