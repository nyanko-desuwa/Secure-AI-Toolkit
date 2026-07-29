# Troubleshooting

What to do when this guidance conflicts with the product, or cannot be applied.

## The agent genuinely needs all three legs of the trifecta

Common with "research this and file a ticket" products: private data, untrusted web content,
and an outward action, all in one flow.

You cannot prompt your way out of this. Options, in order of strength:

1. Split the context. One call reads untrusted content and has no write tools. Its output
   goes to a second call as data, with a narrow tool set. The reader cannot act; the actor
   never sees the raw page. This removes a leg rather than mitigating it.
2. Gate the outbound leg. Human approval on the resolved arguments for anything
   irreversible or outward-facing.
3. Narrow the outbound leg to destinations derived from server state - the account owner's
   email, a fixed webhook, one repository.

If none is acceptable to the product, say so plainly: the feature carries a standing risk of
data exfiltration by anyone who can place content in the corpus. Name who accepted it. Do not
substitute a classifier and call it fixed.

## The framework already handles prompt injection, allegedly

Check what the claim actually covers. Framework features in this space are usually a
classifier, a delimiter convention, or a system-prompt template. None of them removes
capability.

Ask three questions: what does it do on a bypass, what does it do about the tools the agent
holds, and has anyone tested it against paraphrase and encoding. If you cannot answer from the
code or the pinned version's docs, report it as unverified rather than assuming.

## The secure design breaks a feature users rely on

Report the conflict rather than quietly weakening the control:

1. What the current behaviour is
2. What changes under the secure design
3. Who or what breaks
4. The migration path, including a narrower version of the feature

Then ask. Removing an agent capability is a product decision, not a unilateral one.

## Per-user credentials are impossible

The downstream system has no per-user identity, or issuing tokens per user is a quarter of
work. Fallback, in order:

1. Pass the actor into every tool and scope every query by it server-side. This moves the
   check from the credential to your code - weaker, because it depends on you not forgetting.
2. Split the broad credential into several narrow ones by capability, so no single tool
   reaches everything.
3. Read-only credential plus human approval on writes.

State the residual risk explicitly: a compromised agent reaches whatever the service
credential reaches, limited only by your own query scoping.

## You cannot tell whether an injection is exploitable

Report it with the uncertainty attached and name the precondition you could not verify.

"Retrieved document content reaches a context that holds `send_email`; exploitable if any
user-uploaded document is indexed into the shared corpus - I could not determine the ingest
path" is useful. "Prompt injection, critical" without tracing the content path is noise.

Do not resolve the uncertainty by testing whether the model complies. A model refusing your
payload today is not a control, and a successful payload only confirms what the design already
implied.

## An MCP server you cannot review

No source, minified, or too large to read in the time available.

Do not pretend to have vetted it. Options: run it with `stdio` in a sandbox with no
credentials and no filesystem access beyond a scratch directory; keep it out of any context
that also holds private data or an outbound tool; pin the version and hash and diff tool
definitions on every connection so at least a rug pull is visible.

Then record it as an accepted, unreviewed dependency. That is an honest answer; "reviewed"
would not be.

## A checklist item does not apply

Write the reason. "No RAG section: this service has no retrieval" is complete. An unexplained
skip is indistinguishable from an oversight, and in this domain the missing item is usually
the exfiltration channel.

## The standard has moved

The LLM Top 10 renumbered and renamed categories between the 2023–24 and 2025 editions, and
the Agentic Security Initiative publishes separately on its own cadence. Category IDs here
were verified on 2026-07-28 - see [references/llm-top10.md](references/llm-top10.md) for the
URLs and what could not be verified.

If a report depends on a precise ID, re-fetch the source. If you cannot verify an ID, describe
the risk without one. Never invent an identifier to make a mapping table look complete.

## The model provider changed the API

Tool-definition field names, strict-validation behaviour, and content block shapes differ
across providers and versions. The examples here use the Anthropic Messages API shape
(`input_schema`, `tool_use` / `tool_result` blocks with `tool_use_id`).

The security property does not depend on the shape: validate in the function, not in the
schema. If you port an example, keep that property and let the field names follow the
provider's current docs.

## A guardrail is the only thing making the design work

Stop and re-scope. This is the situation the skill exists to prevent. Reduce the tool set,
split the context, or add an approval gate. If the answer is "we ship it with the classifier",
document that the residual risk is the classifier's false-negative rate against an adaptive
attacker, which is not a number anyone can give you.
