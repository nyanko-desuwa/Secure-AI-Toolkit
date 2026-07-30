# Pre-Ship Checklist

Run this before anyone outside your team can reach the app. Mark each item pass, fail, or not
applicable. "Not applicable" needs one line of reason - an unexplained skip looks exactly like
an oversight.

Only run the sections that match what you built. A static landing page does not need the
database section.

## 1. Secrets (A04 · ASVS V14 · CWE-798, CWE-540)

- [ ] [critical] Built the app, then searched the output for every key you own. Source-only search is not
      enough - the build inlines env vars
- [ ] [critical] No `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`, or `PUBLIC_` variable holds a
      value you would mind a stranger having
- [ ] [critical] No OpenAI, Anthropic, Stripe secret, SendGrid, Twilio, or cloud key is referenced anywhere
      under a client-side directory
- [ ] [critical] Supabase: only the anon or publishable key reaches the browser. `service_role` appears in
      server code only
- [ ] [critical] Firebase: the config object is present in the client (expected) and Security Rules deny by
      default (required)
- [ ] [critical] `.env`, `.env.local`, `.env.production` are in `.gitignore` and were never committed -
      checked with `git log --all --full-history -- .env*`, not just `git status`
- [ ] [critical] Every key that was ever committed, pasted into a chat, or found in a bundle has been
      rotated at the provider, not merely deleted from the file
- [ ] [critical] Docker images: no secret in a `ARG`, an `ENV`, or a deleted-in-a-later-layer file.
      Checked with `docker history`
- [ ] [critical] Mobile builds: no key in the `.apk`/`.ipa`. Extract and grep, do not assume

## 2. Configuration (A02 · ASVS V13 · CWE-1188)

- [ ] [recommended] No `localhost`, `127.0.0.1`, personal path, or dev bucket name in code that ships
- [ ] [recommended] Every URL, hostname, port, and connection string comes from configuration
- [ ] [recommended] The app refuses to start when a required config value is missing, rather than falling back
      to a development default
- [ ] [critical] Production and development point at different databases, and you have verified which one
      the deployed app actually connected to
- [ ] [critical] No `if (userId === 12345)` or hardcoded email allowlist standing in for a role
- [ ] [critical] No test or seed credentials reachable on a deployed route
- [ ] [critical] Debug mode, verbose errors, and any `/debug` or `/test` route are off in production

## 3. Limits (A06 · API4:2023 · ASVS V2, V4 · CWE-770, CWE-400)

- [ ] [recommended] Every endpoint that returns a list has pagination with a server-enforced maximum page size
- [ ] [recommended] The client cannot raise a limit past the server's maximum by sending a larger number
- [ ] [recommended] Upload size capped at the framework layer and at the proxy, and file count capped too
- [ ] [recommended] Every outbound HTTP call has a timeout. Default in most libraries is no timeout at all
- [ ] [recommended] Every retry has a ceiling and exponential backoff with jitter
- [ ] [recommended] Rate limiting on login, password reset, signup, search, upload, and anything that costs
      money per call
- [ ] [recommended] Any loop over user-supplied input has a maximum iteration count
- [ ] [recommended] LLM and metered-API calls have a per-request and per-user spend or token ceiling
- [ ] [recommended] Database connection pool has a maximum, and it is below the database's own limit
- [ ] [optional] No `LIMIT 100` silently truncating a result the user believes is complete
- [ ] [recommended] Serverless functions have a concurrency cap and a timeout shorter than the billing horizon

## 4. Security decisions (A01, A07 · ASVS V6, V8, V9 · CWE-602, CWE-807, CWE-347)

- [ ] [critical] Every role or permission check runs on the server. The client copy is cosmetic only
- [ ] [critical] Tested one protected endpoint with `curl` and no UI. It refused
- [ ] [critical] JWTs are verified with a server-held key and an explicit `algorithms` list, never just
      decoded
- [ ] [critical] No role, price, user ID, tenant, or quantity is trusted from the request body
- [ ] [critical] Every database read and write is scoped to the acting user, in the query itself
- [ ] [critical] No `isAdmin = true`, bypass token, or hardcoded password left from local testing
- [ ] [critical] No `rejectUnauthorized: false`, `verify=False`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, or
      `curl --insecure` anywhere (CWE-295)
- [ ] [critical] CORS names explicit origins. No wildcard with credentials, no reflecting the request
      `Origin` header
- [ ] [critical] No auth check commented out with a TODO. Search for `TODO`, `FIXME`, and `temporarily`
- [ ] [critical] Supabase/Firebase: RLS or Rules enabled on every table and collection, and you tested
      reading someone else's row with a second account

## 5. Leaks (A10 · ASVS V15 · CWE-401, CWE-772)

- [ ] [recommended] Every `addEventListener` has a matching `removeEventListener` on the teardown path
- [ ] [recommended] Every `setInterval` and `setTimeout` is cleared when the component or request ends
- [ ] [recommended] Every `useEffect` that subscribes, observes, or opens a socket returns a cleanup function
- [ ] [recommended] Every module-level `Map`, array, or object used as a cache has a size cap and a TTL
- [ ] [recommended] No cache is keyed by unvalidated user input without a bound on the number of keys
- [ ] [recommended] Every `ResizeObserver`, `IntersectionObserver`, and `MutationObserver` is disconnected
- [ ] [recommended] Database connections and file handles are released on the error path too, not only on
      success
- [ ] [recommended] Python: no module-level list or dict accumulating per request, no `lru_cache` on a method
      that holds `self`, no file opened without a context manager
- [ ] [recommended] Memory measured under repeated identical requests, and it flattens instead of climbing

## 6. Performance and cost (A10 · ASVS V15 · CWE-400)

- [ ] [recommended] No `await` inside a `for` loop over rows. Batched, joined, or `Promise.all`ed
- [ ] [recommended] Every column used in a `WHERE`, `JOIN`, or `ORDER BY` has an index
- [ ] [recommended] Counts and sums run in the database, not by loading rows into memory
- [ ] [recommended] Slow work - images, PDFs, email, exports - is on a queue, not the request path
- [ ] [recommended] Independent awaits run concurrently, with a concurrency cap on fan-out
- [ ] [recommended] Clients, connection pools, and config files are created once at startup, not per request
- [ ] [optional] Expensive reads are cached with an explicit expiry
- [ ] [recommended] Every polling loop against a metered API has an interval you have multiplied out to a
      monthly cost
- [ ] [recommended] A billing alert exists on every metered provider

## 7. Errors and data (A09, A10 · ASVS V16 · CWE-390, CWE-209)

- [ ] [recommended] No empty `catch {}` or `except: pass`. Every catch logs and either recovers or rethrows
- [ ] [recommended] Every promise is awaited or has a `.catch`. Unhandled rejection handler installed
- [ ] [critical] Clients get a generic message plus a correlation ID. Stack traces and SQL stay in the log
- [ ] [recommended] The result of every write is checked. A zero-row update is handled, not assumed to succeed
- [ ] [recommended] Multi-step writes are in a transaction
- [ ] [recommended] Retries only wrap idempotent operations, or carry an idempotency key
- [ ] [recommended] Any bulk `UPDATE` or `DELETE` was run as a `SELECT` with the same `WHERE` first
- [ ] [recommended] Backups exist, and one has been restored into a scratch environment to prove it works

## Before Returning

- [ ] [critical] Build ran clean
- [ ] [critical] Tests ran, with the output reported honestly
- [ ] [recommended] Every finding states the cost in plain words, not just the category
- [ ] [critical] Anything you could not verify is named as unverified, not implied to be fine
