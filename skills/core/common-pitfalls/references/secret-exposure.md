# Where Secrets Leak, Per Stack

A secret is exposed the moment a stranger can read it. That includes the JavaScript your site
sends to browsers, a public git repository, a published container image, and an app store
download. None of those can be taken back by editing a file afterwards.

`A04:2025` · `A02:2025` · ASVS V13, V14 · `CWE-798`, `CWE-540`, `CWE-615`

## The rule that catches most of it

If a value is needed by code that runs on someone else's device, that value is public. There is
no build setting, minifier, or obfuscator that changes this. Code that runs on a device you
control - a server, a serverless function, a background worker - is the only place a secret can
live.

## Env var prefixes that mean public

Each framework has a prefix that tells the bundler to inline the value into client JavaScript.
The value stops being an environment variable and becomes a string literal in a file anyone can
download.

| Framework | Public prefix | Server-only variable |
|---|---|---|
| Next.js | `NEXT_PUBLIC_` | any name without the prefix, read in a route handler or server component |
| Vite, and anything built on it | `VITE_` | not available in the browser at all - needs a server |
| Create React App | `REACT_APP_` | needs a separate backend |
| Nuxt 3 | keys under `runtimeConfig.public` | keys at the top level of `runtimeConfig` |
| SvelteKit | `PUBLIC_` | `$env/static/private`, `$env/dynamic/private` |
| Expo / React Native | `EXPO_PUBLIC_` | no client-side option - the whole bundle is readable |
| Astro | `PUBLIC_` | `import.meta.env` in server-rendered code only |

Two things follow. A variable without the public prefix is still not secret if it is imported
into a component that ships to the browser - the bundler follows the import. And a `.env` file is
not encrypted; the name means "environment", not "secret".

## Keys that are meant to be public

Not every key in a bundle is an incident. These are designed to be visible, and the security
lives elsewhere.

| Key | Public? | What actually protects you |
|---|---|---|
| Supabase anon / publishable key | Yes | Row Level Security policies on every table |
| Firebase `apiKey` and config object | Yes | Firebase Security Rules, App Check |
| Stripe publishable key (`pk_`) | Yes | the secret key (`sk_`) staying server-side |
| Google Maps browser key | Yes | HTTP referrer restriction and an API quota |
| Sentry public DSN | Yes | rate limits and allowed domains |

And the ones that are never public: Supabase `service_role`, Firebase Admin SDK service account
JSON, Stripe `sk_` and restricted keys, any OpenAI or Anthropic key, database connection
strings, SMTP credentials, cloud provider access keys, webhook signing secrets, JWT signing keys.

## Detection commands

Run these against the build output. Searching the source misses inlined env vars, which is the
exact case that matters.

```bash
# 1. Build first. The bundle does not exist until you do.
npm run build

# 2. Look for common credential shapes in everything that ships.
grep -rEn "sk-ant-|sk-proj-|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ghp_[A-Za-z0-9]{36}|service_role|-----BEGIN [A-Z ]*PRIVATE KEY" \
  dist/ build/ .next/static/ out/ public/ 2>/dev/null

# 3. Then search for the literal value of each key you own. This is the reliable check.
grep -rn "PASTE-THE-ACTUAL-KEY-VALUE-HERE" dist/ build/ .next/static/ 2>/dev/null

# 4. List every public-prefixed variable and read the values yourself.
grep -rEn "NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|PUBLIC_" src/ app/ 2>/dev/null
```

Step 3 is the one to trust. Pattern matching misses keys with no recognisable prefix.

## Git history

`git status` shows the present. A key committed in March and deleted in April is still in the
repository, still in every clone, and still on GitHub.

```bash
# Was any env file ever committed?
git log --all --full-history --oneline -- ".env" ".env.*" "*.pem" "*.p12" "credentials.json"

# What did it contain?
git log --all -p -- ".env.local" | grep -iE "key|secret|token|password"

# Any blob in history matching a shape, including on branches you deleted locally.
git rev-list --all --objects | git cat-file --batch-check='%(objectname) %(objecttype) %(rest)' 2>/dev/null | head -50
```

For a thorough sweep use a dedicated scanner such as `gitleaks` or `trufflehog` in CI. Rewriting
history with `git filter-repo` or the BFG is cleanup, not remediation. Rotation is remediation.

## Docker images

Every instruction creates a layer. A file added in one layer and deleted in the next is still
present in the earlier layer, and `docker history` will show the command that put it there.

```bash
docker history --no-trunc your-image:tag
docker image inspect your-image:tag --format '{{json .Config.Env}}'

# Unpack and search the filesystem layers.
docker save your-image:tag -o image.tar && mkdir -p /tmp/img && tar -xf image.tar -C /tmp/img
grep -rEl "sk-ant-|AKIA[0-9A-Z]{16}|-----BEGIN" /tmp/img 2>/dev/null
```

Use a build secret mount or inject at runtime. `ARG` and `ENV` values are readable by anyone who
pulls the image.

## Mobile builds

An `.apk` or `.ipa` is an archive. Anyone can download it and read the contents. There is no
client-side location in a mobile app where a secret is safe.

```bash
unzip -o app-release.apk -d /tmp/apk
grep -rEn "sk-ant-|sk-[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{35}" /tmp/apk/ 2>/dev/null
```

## If you found one

1. Rotate at the provider. Create a new key, deploy it, then revoke the old one. This is the
   only step that stops the exposure.
2. Check the provider's usage or audit log for the exposure window. Look for calls from regions
   or IPs you do not recognise.
3. Set a spend cap and a billing alert before you move on.
4. Move the key behind a server route so the same mistake cannot be made again.
5. Then, optionally, clean git history.

Depth on rotation, dual-secret windows, and secret managers is in `secrets-management`.
