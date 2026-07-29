# Prompt Examples

Prompts you can paste to get a real audit instead of a lecture. Each one names the scope, the
artefact to look at, and the shape of the answer, because a vague prompt produces a summary of
what your code does rather than a list of what is wrong with it.

## Find a leaked key, the honest way

```
Build this project, then search the build output for credentials. Check dist/, build/, and
.next/static/. For every hit tell me: the file, which key it is, and whether that file is
downloaded by browsers. Then check git history for any .env file that was ever committed. Do
not search only the source - the build inlines env vars.
```

Why it works: it names the build output. "Scan for hardcoded secrets" makes the model read your
source, where the key legitimately is not, and report all clear.

## Separate the public key from the open database

```
This project uses Supabase (or Firebase). Tell me two separate things. First, which keys reach
the browser and whether any of them is a service_role or admin key. Second, for every table or
collection, whether Row Level Security or Security Rules are enabled and what an anonymous
visitor can read or write. Treat those as two findings, not one.
```

Asking for two findings prevents the common wrong outcome: hiding a key that was always meant to
be public while the database stays open to everyone.

## Locate every security decision and where it runs

```
List every place this codebase decides what a user is allowed to do or see. For each one: the
file and line, whether the decision runs on the server or in the browser, and if it runs in the
browser, the exact curl command that bypasses it. Include route guards, hidden buttons, disabled
inputs, and role checks.
```

The curl command is the part that matters. It converts "the check exists" into a demonstration
that the check is decoration.

## Check that a token is verified, not just read

```
Find every place this code reads a JWT or session token. For each one, tell me whether the
signature is verified with a server-held key and whether the allowed algorithms are listed
explicitly. Flag any use of decode without verify, and any place a role, user ID, tenant, or
price is taken from the request body.
```

Decoding a token and verifying it look nearly identical in code and are completely different in
effect. Naming both halves is what surfaces it.

## Find what has no ceiling

```
Find everything in this codebase with no maximum: list endpoints without pagination, uploads
without a size cap, outbound HTTP calls without a timeout, retries without a ceiling, loops over
user input, caches without an eviction policy, and LLM or metered API calls without a spend
limit. For each, tell me what a single attacker request could do. Rank by that, not by how easy
the fix is.
```

Ranking by blast radius stops the answer from leading with the trivial ones.

## Price the loops

```
Find every call to a paid API in this project - LLM, email, SMS, maps, storage. For each: is it
inside a loop, a retry, or a polling interval? Multiply the worst case out to a monthly figure
using the interval in the code and 1,000 users. Show the arithmetic.
```

Asking for the arithmetic is what turns "there is a polling loop" into a number someone will act
on.

## Audit cleanup in the frontend

```
Review every React component in this project for cleanup. For each useEffect that subscribes,
adds an event listener, opens a socket, starts a timer, or creates an observer, tell me whether
it returns a cleanup function that undoes exactly that. Flag any state array that only grows.
Show the fixed version of the worst three.
```

Naming the five acquisition kinds is more effective than asking about "memory leaks", which
returns generic advice.

## Diagnose growing memory without guessing

```
Memory in this service climbs from 200MB to the container limit over about six hours and a
restart resets it. Before proposing a fix, tell me how to tell a real leak apart from a cache
warming up and from allocator fragmentation, and what measurement would distinguish them. Then
list the candidates in this codebase, ranked by how much they retain per request.
```

Forcing the distinction first prevents days spent on a fix for a leak you do not have.

## Find the silent failures

```
Find every place an error is discarded in this project: empty catch blocks, except: pass, a
promise with no await and no .catch, and any write whose result is never checked. For each, tell
me what the user sees when it fails and how long it would take anyone to notice.
```

"How long until anyone notices" is the question that ranks these correctly. A swallowed write is
worse than a crash.

## Review before you deploy

```
Run skills/core/common-pitfalls/checklist.md against this project. Mark every item pass, fail,
or not applicable with one line of reason. Do not mark anything pass that you did not open the
file to confirm. List separately everything you could not verify from the source, including
whether production env vars are set and whether database policies are live.
```

The last clause is the point. A wall of checkmarks that includes unverifiable runtime facts is
worse than no checklist.

## Anti-patterns

| Prompt | Problem |
|---|---|
| "Is my app secure?" | No scope and no artefact. Produces a generic checklist read back at you |
| "Scan for hardcoded secrets" | Searches source, where the key is not. Ask for the build output |
| "Remove the API key from the code" | Deleting the line does not un-leak it. Ask for rotation plus a server route |
| "Hide the Supabase key" | Wrong target. The missing Row Level Security is the finding |
| "Add authentication" | Authentication is not authorization. Ask who can reach whose data |
| "Fix the memory leak" | Assumes the diagnosis. Ask how to confirm it is a leak first |
| "Make it faster" | Produces micro-optimisations. Ask which query grows with row count |
| "Add error handling" | Often produces more empty catch blocks. Ask what the user sees on failure |
| "Increase the memory limit" | Buys time, hides the cause. Ask what is retained per request |
| Pasting a real key to ask about it | The paste is now an exposure. Describe the shape instead |
