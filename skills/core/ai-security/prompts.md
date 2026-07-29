# Prompt Examples

Prompts that produce findings from this skill. The pattern that works: name the content
source, name the tool set, and ask for the path between them. Prompts that ask whether the
model "can be jailbroken" produce essays.

## Map the trifecta

```
List every tool this agent has and every source of content that reaches its context. For
each, mark whether it provides private data access, untrusted content, or an outbound
channel. Then tell me which combinations coexist in one context window.
```

Why it works: the trifecta is a property of the wiring, and the wiring is in the code. This
produces a table you can act on rather than a judgement about model behaviour. Markdown
rendering and fetch tools are the usual surprises.

## Trace an indirect injection path

```
A user uploads a PDF that gets indexed into the RAG corpus. Trace what an instruction inside
that PDF could reach: which tools are in scope at answer time, what data the agent can read,
and what outbound channels exist. Assume the model follows the instruction.
```

Naming the entry point and forcing the assumption is the whole trick. "Assume the model
follows the instruction" removes the escape hatch where the answer is "the model would
probably refuse".

## Review a tool definition

```
Review these tool definitions against LLM06 (Excessive Agency). For each: is the parameter
space bounded, is authorization enforced in the function or only in the schema, does any
argument let the model choose a destination or a target it should not, and is the action
reversible?
```

Four concrete questions beat "is this tool safe". The authorization-in-function-vs-schema
question is the one that finds real bugs.

## Check RAG authorization

```
Read the retrieval path in src/rag/. Is the permission filter part of the vector query, or
applied after retrieval? Where does the filter value come from - the session, the client
request, or the model? Show me the line.
```

Asking for the line forces a read instead of a pattern-match on the word "filter". Post-filter
and client-supplied filter are both findings, for different reasons.

## Find the exfiltration channel

```
This agent renders its output as markdown in a web UI and has a tool that fetches URLs. What
are all the ways data in its context could leave the system? Include channels that need no
user interaction.
```

The "no user interaction" clause surfaces markdown image auto-loading, which people
consistently miss because it does not look like a tool.

## Review an MCP server before installing

```
Read this MCP server's source. What can its tools reach on the host and on the network? Do
any tool descriptions or parameter descriptions contain instructions addressed to the model?
Does it validate that inbound tokens were issued for it, or does it forward them downstream?
```

Tool descriptions land in the context on every request, so reading them as untrusted input is
the point. The token question catches passthrough, which the MCP spec forbids.

## Audit model output sinks

```
Find every place model output reaches eval, a subprocess, a SQL query, a file path, a URL, or
innerHTML. For each, tell me what encoding or validation is applied at the sink.
```

Named sinks are greppable. This is the audit that turns "prompt injection" into a concrete
RCE or XSS finding with a line number.

## Threat model an agent before building

```
I am building an agent that reads customer support tickets, searches our internal KB, and can
reply to the customer by email. Before I write it: what controls does it need? Map each to an
LLM Top 10 2025 category and an ASVS chapter, and tell me which legs of the trifecta this
design has.
```

Design-time is where the trifecta can actually be broken. After the tools exist, every fix is
a removal argument.

## Verify before returning

```
Run skills/core/ai-security/checklist.md against this change. For each item, mark pass, fail,
or not applicable with a one-line reason. Do not mark anything pass that you have not read the
code for. For any control that only reduces the rate of injection rather than removing the
capability, say so.
```

The last sentence is the important one. Without it you get "prompt injection: mitigated".

## Anti-patterns

| Prompt | Problem |
|---|---|
| "Can this be jailbroken?" | Yes. Every model can. Says nothing about your blast radius |
| "Write a system prompt that prevents prompt injection" | Asks for a control that does not exist. Produces false confidence |
| "Add guardrails" | Adds a classifier and leaves the tool set unchanged. The rate drops, the capability does not |
| "Is our AI secure?" | No scope. Produces a category recital instead of findings |
| "Sanitize the user input to block injection" | Denylist thinking applied to natural language. There is no character to escape |
| "Make it OWASP LLM compliant" | There is no compliance certificate. Ask for specific controls against specific categories |
