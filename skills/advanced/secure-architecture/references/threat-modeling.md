# Threat Modeling — sources and frames

Verified 2026-07-28 against:

- OWASP Threat Modeling Cheat Sheet —
  <https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html>
- Threat Modeling Manifesto — <https://www.threatmodelingmanifesto.org/>
- LINDDUN — <https://linddun.org/>

None of these carry a dated version number on the page. Treat them as living documents and
re-read before quoting exact wording.

## The four questions

Both the Manifesto and the OWASP cheat sheet are built on the same four questions:

1. What are we working on?
2. What can go wrong?
3. What are we going to do about it?
4. Did we do a good enough job?

The cheat sheet maps these onto four phases: application decomposition, threat identification
and ranking, mitigations, and review and validation. It states plainly that threat modeling is
"ideally performed early in the SDLC, such as during the design phase", and that the model
should be maintained and refined alongside the system.

It also says there is no universally accepted industry standard for the process. Anyone
claiming one specific method is required is overstating it.

## STRIDE

The cheat sheet uses STRIDE for illustration and pairs each category with the security
attribute it violates:

| Category | Property violated | Architecture question |
|---|---|---|
| Spoofing | Authentication | How does the callee know who the caller is? |
| Tampering | Integrity | What can be modified in transit or at rest without detection? |
| Repudiation | Accounting | Could the actor deny doing it? Is the log trustworthy? |
| Information disclosure | Confidentiality | What crosses a boundary that should not? |
| Denial of service | Availability | What is expensive and unmetered? |
| Elevation of privilege | Authorization | Where can a subject act beyond its grant? |

Four possible responses to a threat, attributed in the cheat sheet to Adam Shostack: mitigate,
eliminate, transfer, accept. An accepted threat is a decision that needs an owner and a date,
not a silent omission.

Other methodologies named: LINDDUN, PASTA, OCTAVE, VAST. PASTA and OCTAVE are called out as
less aligned to the four-step breakdown. MITRE ATT&CK and kill chains are described as tactical
companions to STRIDE.

Tools named: Threat Dragon, pytm, Microsoft Threat Modeling Tool, draw.io, Cairis, IriusRisk,
TaaC-AI, Threat Composer.

## Manifesto values, principles, anti-patterns

Values, preferring the left over the right:

- A culture of finding and fixing design issues over checkbox compliance
- People and collaboration over processes, methodologies, and tools
- A journey of understanding over a security or privacy snapshot
- Doing threat modeling over talking about it
- Continuous refinement over a single delivery

The four anti-patterns are the most useful part for a reviewer:

| Anti-pattern | What it looks like |
|---|---|
| Hero Threat Modeler | Only one person is believed capable of doing it |
| Admiration for the Problem | Pages of analysis, no fixes assigned |
| Tendency to Overfocus | All attention on adversaries, or assets, or techniques, missing the rest |
| Perfect Representation | Endless work on one diagram instead of several partial ones |

Recommended patterns: Systematic Approach, Informed Creativity, Varied Viewpoints, Useful
Toolkit, Theory into Practice.

## LINDDUN — privacy threats

Seven categories, from the acronym: Linking, Identifying, Non-repudiation, Detecting, Data
Disclosure, Unawareness, Non-compliance. Built at KU Leuven's DistriNet unit.

Three variants:

| Variant | Starting point | Use when |
|---|---|---|
| LINDDUN GO | Card deck of common privacy threats and hotspots | Fast group brainstorm, mixed team |
| LINDDUN PRO | Data flow diagram, threat trees, mapping table | Systematic per-interaction analysis, automatable |
| LINDDUN MAESTRO | Richer model-driven system description | Threat-specific precision (site marks details as forthcoming) |

LINDDUN is compatible with STRIDE, so security and privacy modeling can run off the same
system model. It is technically framed, not legal advice on GDPR.

Privacy threats most often missed in architecture reviews map to Linking and Identifying: two
datasets that are each pseudonymous become identifying when joined. That is a design property,
not an implementation bug, which is why it survives code review.

## Depth to aim for

A threat model earns its keep when it changes the design. Practical minimum for one feature:

- A data flow diagram with trust boundaries drawn as boundaries, not as boxes
- One STRIDE pass per boundary crossing, not per box
- A LINDDUN pass if personal data crosses any boundary
- Each threat given a response: mitigate, eliminate, transfer, or accept with an owner
- The residual risks written down where the next reviewer will find them

## Related

- OWASP Top 10 2025 A06 (Insecure Design)
- OWASP ASVS 5.0 V15 (Secure Coding and Architecture)
- NIST SSDF SP 800-218, PW group (Produce Well-Secured Software)
