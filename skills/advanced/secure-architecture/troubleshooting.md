# Troubleshooting

Architecture findings usually cannot be fixed in the current sprint. That is the normal case, not
the exception. What follows is how to stay honest about it.

## The secure design is not available yet

Most architectural fixes are migrations. Row-level security needs a non-superuser application role.
Per-service identity needs a service mesh or a token issuer. Neither lands this week.

Say so in three parts, and put all three in the same message:

1. The target design, in one sentence.
2. The interim control, and what it does not cover.
3. The trigger that forces the migration.

"Target: RLS with FORCE on the shared schema. Interim: a repository layer that is the only path to
the tenant tables, plus a test per endpoint asserting a cross-tenant read returns empty. Not
covered: any code that opens its own connection, and the analytics job that already does. Trigger:
before the first regulated-data tenant."

An interim control with a named gap is a decision. An interim control described as a fix is a lie
that gets found during an incident.

## The finding is real but nothing can be done about it

Write the ADR anyway, with the residual risk section filled in and a review trigger. An accepted
risk that is written down gets revisited. An accepted risk that was only said out loud in a meeting
becomes an assumption within two quarters, and then becomes a surprise.

Do not silently downgrade severity to make the backlog look better. A Critical you have accepted
and dated is more useful than a Medium you invented.

## The team says the network already protects it

This is the most common objection and it is usually half true. The question to ask is not "is the
network segmented" but "what happens after the first compromise inside the segment".

NIST SP 800-207 assumption 1 is the useful quote: the entire enterprise private network is not
considered an implicit trust zone, and assets should always act as if an attacker is present on the
enterprise network. Read that as an argument about blast radius, not about deleting the firewall.

Concretely, ask for one thing: which single compromised workload in that segment cannot reach the
database. If the answer is "none of them", the network is a perimeter around everything, and the
finding stands.

## Zero trust is being used to justify buying something

Zero trust is a set of properties, not a product. If a proposal maps to none of the seven tenets in
[references/nist-zero-trust-800-207.md](references/nist-zero-trust-800-207.md), it is not zero trust
work regardless of the label on the invoice.

The reverse is also worth saying: a monolith with per-request authorization at the data layer, short
credentials, and no network-position trust satisfies more tenets than a mesh with mTLS everywhere and
a permissive authorization policy. Tenet 6 is about authorization being dynamic and strictly enforced
before access, not about transport encryption.

## Two standards point different ways

ASVS and the Top 10 rarely conflict - one is requirements, the other is a risk ranking. Real
conflicts are usually between a security standard and an availability requirement, and they resolve
by naming the failure mode explicitly rather than by picking a side.

The recurring one: fail closed versus stay up. Resolve it per operation, not globally. A read of
non-sensitive cached content can serve stale on auth failure. A write, a permission change, or a
money movement cannot. Write the per-operation answer into the failure-mode table; a single global
policy is what produces both outages and bypasses.

## The design is not written down anywhere

Reconstruct it from what exists, and label the reconstruction. Read the IaC tree, the service
manifests, the ingress rules, and the database grants - in that order, because each constrains the
next. Then write the boundary table and mark every row you inferred rather than read.

Do not ask for a design document first. It will not arrive. A wrong boundary table gets corrected in
five minutes by someone who knows the system; an absent one gets nothing.

## The codebase has no layering, so you cannot find the boundary

Follow the data, not the code. Layering is a property of the source tree; a trust boundary is a
property of the data path. Start from the stores - tables, buckets, queues, caches - and ask which
process holds a credential to each one. Every process with a credential is inside that boundary,
whatever directory its code lives in.

Two artifacts locate boundaries in a codebase with no structure: the grant list on the database and
the list of secrets each deployment unit reads. A process that can read the customer table is on the
trusted side of the customer boundary even if it is called `utils`.

## The threat model produced a list nobody acted on

This is the Manifesto's Admiration for the Problem anti-pattern, and it is the normal outcome of a
threat modelling session that ends with a document. The fix is structural: a threat with no named
response is not a finding, it is a note.

Convert each threat into one of four rows - mitigate, eliminate, transfer, accept - with an owner and
a ticket or an ADR link. Then throw away the threats you cannot assign. A five-item list where every
item has an owner changes the system. A forty-item list changes nothing and teaches the team that
threat modelling is paperwork.

If a threat matters and nobody will own it, escalate the accept decision to whoever carries the risk.
That is a real outcome. Leaving it unassigned in a document is not.

## The shared database cannot be split

Usually true, and the split is not the first step anyway. Stage it so each step is independently
useful:

1. Revoke what nobody uses. Grant each service a role with rights only on the tables it reads today.
   This is a day of work and it removes most of the cross-service reach.
2. Put a view or a stored interface in front of any table a second service reads. The reader loses
   direct table access; the owner gains a contract it can change.
3. Move writes behind the owning service's API, one call path at a time. Writes are where the
   coupling actually bites.
4. Separate schemas, then instances, only if the blast radius still justifies it.

Step 1 alone converts CWE-1220 (over-broad grant) into a bounded one. Do not let "we cannot do step 4"
prevent step 1 - that trade is the most common way a shared database stays fully shared for years.

## A service already violates the boundary you are adding

Enforcing immediately breaks the violator. Skipping enforcement means the boundary never exists.
Neither is the answer.

Run the check in report-only mode first: evaluate the policy, allow the request, log every decision
that would have been a deny with the caller identity. Give the deny list an owner and a date, fix the
callers, then flip to enforce. Kubernetes `NetworkPolicy` has no dry-run, so this usually means
enforcing at the application layer first and at the network layer once the log is clean.

Two rules keep this honest. The report-only phase has an expiry date written into the ADR, and the
log is watched - an unwatched report-only policy is an off policy with extra steps.

## Legacy authentication you have to interoperate with

You will meet a system that authenticates with a shared API key, an unsigned header, or a session
table you cannot change. Do not spread its assumptions inward.

Put an adapter at the boundary that converts the legacy credential into your internal principal, and
make it the only component that understands the legacy format. Everything behind it takes a verified
principal. The legacy weakness is then contained in one file with one owner, and the migration is a
change to that file rather than to every handler.

Two things to state plainly when you do this: the adapter cannot make a shared API key into per-user
identity, so anything behind it that needs a user is guessing; and if the legacy credential is
long-lived and unrotatable, that is CWE-522 and it stays open until the credential does.

## Compensating control, or theatre

Both look the same in a document. The difference is testable, and three questions separate them.

1. Name the attack step it removes. Not the class of attack - the specific step in this system's
   path. "Blocks the enumeration because the ID is not in the request" is an answer. "Adds a layer of
   defence" is not.
2. Say what still gets through. A control whose gap you cannot describe has not been analysed.
3. Say how you would notice it failing. A control with no signal is unfalsifiable, and unfalsifiable
   controls are the ones found switched off during an incident.

Honest examples: a repository layer as the only path to tenant tables while RLS is pending - removes
the forgotten-`WHERE` step, does not cover code that opens its own connection, and the per-endpoint
cross-tenant test tells you when it breaks. A WAF rule in front of an unfixed injection - buys time,
bypassable by encoding, and the signal is the rule firing.

Theatre: a rate limit on the login page while the token endpoint is open. A denylist of payload
strings. "Sanitised" input with no sink named. A second authorization check in the same process
reading the same variable as the first. Each of these makes a report look thorough and moves no
attack step.

Say which one you are proposing. Calling theatre defence in depth is how a Critical becomes a closed
ticket.

## You cannot tell whether the control is actually deployed

Say which artifact you read and what it does not prove. A `NetworkPolicy` in git is not a
`NetworkPolicy` in the cluster; a Terraform IAM policy is not the policy attached in the account if
someone edited it in the console.

"`infra/policies/api.tf` scopes the role to one bucket prefix. I did not check the live account, so
drift is unverified" is a complete answer. Presenting the file as the runtime state is where
architecture reviews lose credibility.

## The service boundary is wrong but splitting it is a rewrite

Do not propose the rewrite. Propose the seam.

Pick the one call that crosses the boundary most often, give it an explicit interface with its own
authorization check, and route all callers through it. The internal structure stays monolithic; the
boundary becomes real and enforceable. This is the pattern that ships. "Split the service" is the
pattern that gets discussed for a year.

## A tenant needs cross-tenant access

Someone will ask, usually for a parent company reading its subsidiaries. Do not weaken the isolation
predicate to `tenant_id IN (...)` computed in application code.

Model it as its own concept: an explicit grant row, from tenant to tenant, with a scope and an
expiry, and an isolation predicate that reads the grant table. The delegation becomes visible,
revocable, and auditable. A widened predicate is invisible and permanent.

## The finding belongs to another team

Report it with the boundary named and the owner named, and keep it in your list until it is closed or
accepted. Cross-team findings are where architectural risk accumulates, because each team can see
only their side of the boundary and each assumes the other side checks.

The one thing not to do is fix it on your side only and call it done. Two half-enforcements on either
side of a boundary is the shape of most tenant-isolation incidents.

## A checklist item does not apply

Write the reason. "No tenant isolation section: single-tenant internal tool, one customer, no
per-customer data" is complete. An unexplained skip reads the same as an oversight, and the next
reviewer cannot tell which it was.

## The standard has moved on

The references here were verified on 2026-07-28. NIST SP 800-207 has been stable since August 2020;
ASVS 5.0.0 and the Top 10 2025 are recent enough that category and requirement identifiers should be
re-checked before quoting in anything formal. URLs and check dates are in
[references/](references/).

Never quote a requirement ID from memory. Fetch it or cite the chapter.
