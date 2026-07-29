# Provider Well-Architected Security Pillars

Design-time guidance from each provider. Use these for trade-off arguments, not as a control
list - the CIS benchmarks are the control list. Principle names below are quoted from the
provider documentation. Checked 2026-07-28.

## AWS Well-Architected Framework, Security Pillar

Publication date on the document: 2024-11-06.
Source: <https://docs.aws.amazon.com/wellarchitected/latest/framework/security.html>

Seven design principles, verbatim:

- Implement a strong identity foundation
- Maintain traceability
- Apply security at all layers
- Automate security best practices
- Protect data in transit and at rest
- Keep people away from data
- Prepare for security events

Two of these get skipped most often in Terraform reviews. "Implement a strong identity
foundation" includes the phrase "aim to eliminate reliance on long-term static credentials" -
that is the standard citation for rejecting an `aws_iam_access_key` in a workload. "Keep people
away from data" is the argument for read-only break-glass roles and query tooling instead of
direct database credentials for humans.

## Microsoft Azure Well-Architected Framework, Security Pillar

Source: <https://learn.microsoft.com/azure/well-architected/security/>

Five design principles, verbatim:

- Plan your security readiness
- Design to protect confidentiality
- Design to protect integrity
- Design to protect availability
- Sustain and evolve your security posture

The pillar's how-to guides map closely to this skill's concerns: Segment components,
Manage identities and access, Protect the network, Use encryption, Harden resources, and
Guard application secrets.

Azure also publishes the Microsoft cloud security benchmark
(<https://learn.microsoft.com/security/benchmark/azure/introduction>), which covers AWS and GCP
as well and is a reasonable cross-provider baseline when you want one document rather than three.

## Google Cloud Well-Architected Framework, Security Pillar

Titled "Well-Architected Framework: Security, privacy, and compliance pillar".
Source: <https://cloud.google.com/architecture/framework/security> (redirects to
`docs.cloud.google.com`).

Seven core principles, verbatim:

- Implement security by design
- Implement zero trust
- Implement shift-left security
- Implement preemptive cyber defense
- Use AI securely and responsibly
- Use AI for security
- Meet regulatory, compliance, and privacy needs

Google names eight focus areas: infrastructure security, identity and access management, data
security, AI and ML security, security operations, application security, cloud governance and
risk and compliance, and logging and auditing and monitoring. GCP is the only one of the three
to put AI security in the security pillar itself.

## How to cite these

The pillars are principles, not requirements. They justify a design decision; they do not
prove a configuration is correct.

Correct: "Long-lived access keys conflict with the AWS Security Pillar principle
'Implement a strong identity foundation', which says to aim to eliminate reliance on long-term
static credentials. Use `sts:AssumeRole` via OIDC."

Wrong: "This violates Well-Architected control SEC-3." There is no such identifier in the
document text. AWS best practice IDs (`SEC01-BP01` style) do exist in the framework, but do not
quote one you have not read on the page.

## Shared responsibility

All three publish a shared responsibility model. The consistent boundary: the provider secures
the infrastructure, you secure the configuration, the identities, and the data. Every finding
in this skill sits on your side of that line, which is why "the cloud is secure" is not an
answer to any of them.

- AWS - <https://aws.amazon.com/compliance/shared-responsibility-model/>
- Azure - <https://learn.microsoft.com/azure/security/fundamentals/shared-responsibility>
- GCP - <https://cloud.google.com/architecture/framework/security/shared-responsibility-shared-fate>
