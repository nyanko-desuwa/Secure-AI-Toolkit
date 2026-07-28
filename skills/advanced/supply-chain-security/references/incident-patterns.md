# Incident Patterns

> Each entry verified 2026-07-28 against the source linked in its own section. Where a source
> does not describe the payload, this file says so instead of filling the gap from memory.

Six mechanisms, not six names. The point of reading these is that each one defeats a control
people assume they have: a version pin, a code review, a lockfile, a checksum on the wrong
file.

## A patch release that adds a dependency — `event-stream`

Source: <https://github.com/advisories/GHSA-mh6f-8j2x-4483> ·
<https://github.com/advisories/GHSA-52w4-pxx8-4xj4>

`event-stream` 3.3.6 added `flatmap-stream` as a dependency. `flatmap-stream` is malicious in
its entirety — the advisory marks all versions affected, with no patched version and removal as
the only remediation. GitHub assigned no CVE; the identifiers are GHSA-mh6f-8j2x-4483 for
`event-stream` and CWE-506, CVSS 9.8. Remediation was 3.3.4, the last clean release, or 4.0.0.

Mechanism: the malicious code was not in the package that everyone depended on. It arrived as a
new transitive dependency introduced by a version bump of a package with millions of weekly
downloads.

What it defeats: reading `package.json`. The direct dependency's own source was unchanged. The
addition is visible only in the lockfile diff, in a section reviewers scroll past because it is
machine-generated.

The advisory does not describe how maintainership changed hands or what the payload targeted.
Both are widely reported elsewhere; neither is needed for the lesson.

## A compromised publish account — `ua-parser-js`

Source: <https://github.com/advisories/GHSA-pjwm-rvh2-c87w>

Three versions — 0.7.29, 0.8.0, 1.0.0 — were published with malicious code on 2021-10-22, fixed
in 0.7.30, 0.8.1, and 1.0.1. CVE-2021-4229. CWE-506 (Embedded Malicious Code) and CWE-912
(Hidden Functionality), CVSS 8.8.

Mechanism: the package name, the repository, and the maintainer were all legitimate. Only the
published artefact was not.

Read the advisory's remediation guidance as written, because it is stronger than most people
expect: any machine with the package installed "should be considered fully compromised", all
secrets and keys should be rotated from a different computer, and removing the package carries
"no guarantee" of removing everything it installed.

What it defeats: every control based on reputation. Download counts, maintainer history, and
repository quality were all excellent minutes before publication. It is also the reason
[best-practices.md](../best-practices.md#guard-the-update-path) puts a cooldown on adoption —
this was found and fixed within hours, so a delay of days converts the incident into a non-event.

The advisory does not state which lifecycle script executed or what the payload did. Do not
assert `preinstall` specifically without the upstream issue in front of you.

## Malicious code shipped only in the release tarball — xz / liblzma

Source: <https://nvd.nist.gov/vuln/detail/CVE-2024-3094>

xz 5.6.0 and 5.6.1. Per NVD: "Malicious code was discovered in the upstream tarballs of xz,
starting with version 5.6.0." During the build, the liblzma build process extracts a prebuilt
object file from a disguised test file in the source tree, through layered obfuscation, and that
object patches specific functions in liblzma. The result is a tampered library that any linking
software loads, "intercepting and modifying the data interaction with this library". Red Hat's
earlier text named the practical target — liblzma as used by sshd. CVSS 10.0, CWE-506.

Mechanism: the git repository was clean. The distributed tarball carried extra `.m4` autotools
files that were absent from the repository, and those drove the extraction.

What it defeats: reviewing the source repository, which is what almost everyone means by
"reviewing the dependency". It also defeats a checksum, because the checksum was computed over
the tarball everyone received.

The control that addresses this is reproducibility: build from the repository, or verify that
the tarball reproduces from tagged source. See
[best-practices.md](../best-practices.md#build-reproducibly-enough-to-compare). An NVD reference
added in August 2025 covers the backdoor persisting in container images, so affected artefacts
can still be in circulation years later — which is what an SBOM keyed by digest is for.

## A build tool nobody treated as a dependency — Codecov Bash Uploader

Source: <https://about.codecov.io/apr-2021-post-mortem/>

The attacker extracted a Google Cloud Storage HMAC key from an intermediate layer of Codecov's
public self-hosted Docker image, then used it to modify the Bash Uploader stored in that bucket.
Modified copies were served directly to users. The payload "extracted git remote origin URLs and
environment variables from the environment where the maliciously altered Bash Uploader was
executed" — so every secret exposed to a CI step that also ran the uploader. Delivery reached the
GitHub Action, the CircleCI Orb, and the Bitrise Step, all of which wrapped the same script.

Timeline: modification detected 2021-04-01 by a customer who compared the SHA256 published on
GitHub against one they computed themselves. Public disclosure 2021-04-15. Codecov's remediation
included replacing the bash uploader with a signed, verifiable binary.

Mechanism: a `curl | bash` step in thousands of pipelines, fetching a script that was never
pinned, never hashed, and not in anyone's dependency graph.

What it defeats: your entire dependency policy, because the uploader was not a dependency. It
was a line in a CI file. It also shows how a secret in a published image layer becomes an
upstream compromise — deleting a file in a later layer does not remove it.

Two details worth keeping. The detection method was checksum comparison by one customer, which is
the control the affected pipelines were not running. And the compromise of a coverage tool
produced credential theft at scale, because CI hands every step the whole environment.

## An internal name that resolved publicly — dependency confusion

Source: <https://peps.python.org/pep-0708/>

PEP 708, "Extending the Repository API to Mitigate Dependency Confusion Attacks", states the
root cause plainly: there is no global namespace for package names, each repository defines its
own, and installers flatten several configured repositories into one namespace by default. The
PEP cites `torchtriton` — an internal PyTorch package name that was unclaimed on PyPI, where an
attacker published a malicious version under the same name.

Mechanism: the attacker needs no access to anything. They publish a name you already use
privately, at a version higher than yours, on an index your resolver also consults.

Status matters for planning: PEP 708 is Rejected. It spent three years provisionally accepted
and the conditions for finalisation — implementations in Warehouse, a second index, and an
opt-in pip implementation — were never met. Its proposed `Tracks` and `Alternate Locations`
metadata is not arriving. There is no index-priority feature to wait for, which is why
[best-practices.md](../best-practices.md#resolve-from-one-place-you-control) says to use one
index.

## A hallucinated name someone registered — slopsquatting

Source: <https://en.wikipedia.org/wiki/Slopsquatting> ·
<https://arxiv.org/abs/2406.10279>

An LLM suggests a package that does not exist. Normally the install fails. If an attacker has
registered that name in advance, it succeeds.

The term was coined by Seth Larson, Python Software Foundation Developer in Residence, in April
2025, and popularised by Andrew Nesbitt. Spracklen et al., "We Have a Package for You! A
Comprehensive Analysis of Package Hallucinations by Code Generating LLMs" (arXiv:2406.10279),
measured the supply: 19.7 percent of recommended packages did not exist, open-weight models
averaging 21.7 percent against 5.2 percent for proprietary models, and more than 205,000 unique
hallucinated names observed.

The demonstration predates the name. In 2023 Bar Lanyado found models hallucinating
`huggingface-cli` — plausible, because that is the command name, while the real install is
`pip install -U "huggingface_hub[cli]"`. An empty package registered under the hallucinated name
drew over 30,000 downloads in three months and reached the README of an Alibaba research
repository.

Mechanism: hallucinated names are not random. The same model produces the same plausible name
repeatedly, and the name is plausible precisely because it matches a command, a documentation
phrase, or another ecosystem's convention. That repetition is what makes registering them
worthwhile.

What it defeats: the reviewer's eye, exactly as typosquatting does, plus one more layer — an
agent that runs `pip install` on its own suggestion never shows a human the name at all.

Honest status: as of the source's July 2026 revision, no slopsquatting attack has been reported
in the wild. The hallucination rate is measured, the registration is trivial, and the exposure
is real; the incident is not. Say that rather than implying a documented breach.

## The self-propagating case — `Shai-Hulud`

Source: <https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/>

Quoted from the A03 category text: malicious versions of popular npm packages used post-install
scripts to exfiltrate secrets to public GitHub repositories, then reused any npm tokens found to
publish further malicious packages. It spread past 500 package versions before npm intervened.
OWASP calls it "the first successful self-propagating npm worm" and notes that it made developer
machines the target.

Mechanism: install-time execution plus a stolen publish token, which is a complete propagation
loop with no user interaction.

What it defeats: the argument that `--ignore-scripts` is paranoid, and the argument that a dev
dependency carries no risk. The compromised environments were laptops and CI runners, which is
where the credentials are.

## What the set has in common

| Incident | Control it walked past |
|---|---|
| `event-stream` | Reviewing the manifest instead of the lockfile diff |
| `ua-parser-js` | Trusting reputation and maintainer history |
| xz / liblzma | Reviewing the repository rather than the released artefact |
| Codecov | Treating pipeline tooling as not-a-dependency |
| `torchtriton` | Assuming index order is a priority guarantee |
| slopsquatting | Assuming a suggested name exists because it looks right |
| `Shai-Hulud` | Assuming install-time code is inert |

Note what is absent from that column: a CVE. Only xz has one that matters, and it was assigned
after the fact. A scanner comparing your versions against a vulnerability database would have
reported nothing in five of the seven cases at the time it mattered. That is the detection gap
A03 describes when it records only 11 CVEs across its mapped CWEs.

## Sources

- <https://github.com/advisories/GHSA-mh6f-8j2x-4483>
- <https://github.com/advisories/GHSA-pjwm-rvh2-c87w>
- <https://nvd.nist.gov/vuln/detail/CVE-2024-3094>
- <https://about.codecov.io/apr-2021-post-mortem/>
- <https://peps.python.org/pep-0708/>
- <https://en.wikipedia.org/wiki/Slopsquatting>
- <https://arxiv.org/abs/2406.10279>
- <https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/>
