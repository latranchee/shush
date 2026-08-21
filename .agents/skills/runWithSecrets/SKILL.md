---
name: runWithSecrets
description: Launch any tool, script, or AI agent with vault secrets injected as environment variables via shush run - mapping syntax, multiple secrets, optional secrets, and the scrubbed-environment gotcha. Use whenever the user wants to run something that needs an API key or token (codex, claude, python scripts, node apps, curl), asks why an env var is missing under shush run, or is about to put a key in a command line or .env file to make a tool work.
---

# /runWithSecrets — launch commands with secrets injected

Goal: run the user's command with the right secrets present as environment
variables in the child process — and nowhere else. No key on the command
line, in a file, in your context, or in the output.

## The one-line pattern

```powershell
shush run <command> [args...] --env ENV_VAR=secret_name
```

Left of `=` is the environment variable the tool expects; right of `=` is the
name in the shush vault. Everything after `run` that isn't an `--env` flag is
passed to the child untouched, and `run`'s exit code is the child's exit code.

```powershell
shush run codex --env OPENAI_API_KEY=openai_api_key
shush run claude --env ANTHROPIC_API_KEY=anthropic_api_key
shush run python .\script.py --env GEMINI_API_KEY=gemini_api_key
shush run node .\app.js `
  --env OPENAI_API_KEY=openai_api_key `
  --env GITHUB_TOKEN=github_token `
  --env-optional SENTRY_DSN=sentry_dsn
```

`--env` is strict: a missing secret aborts before launch with exit 1.
`--env-optional` is for secrets that may legitimately be absent — the child
still launches, with that variable unset and a warning on stderr.

## Before you run

1. Find the vault name: `shush list` (names only, always safe).
2. If the secret isn't stored yet, have the **user** store it at the secure
   prompt — `shush set <name>` — never paste a value through chat. The
   **setup** skill covers this.
3. Find the env var name the tool expects from its docs (`OPENAI_API_KEY`,
   `GITHUB_TOKEN`, ...). shush doesn't guess mappings; you declare them.

## The scrubbed-environment gotcha (read this before debugging)

`run` does not pass your whole shell environment through. The child gets an
OS-essential whitelist (PATH, TEMP, APPDATA, SystemRoot, ...) plus exactly
the mappings you declared. This is deliberate: it stops stray
`$env:*_API_KEY` values from leaking into children that never asked for them.

So when a tool works directly but breaks under `shush run`, the likely cause
is an inherited variable it silently depended on (`HTTP_PROXY`,
`NODE_OPTIONS`, a config-path override...). Fix it by declaring that
variable too — mappings can point at another secret, or the value can be
stored as a secret of its own. Don't work around it by exporting the real
key into the parent shell; that defeats the point.

## Verifying injection without printing the value

Never echo the variable to check it arrived. Prove presence, not content:

```powershell
shush run powershell -NoProfile -Command `
  "if (`$env:OPENAI_API_KEY) { 'injected: ' + `$env:OPENAI_API_KEY.Length + ' chars' } else { 'MISSING' }" `
  --env OPENAI_API_KEY=openai_api_key
```

Length or a hash is diagnostic enough; the value itself must never reach
stdout, logs, or your context.

## Interactions with the other layers

- **Protected secrets**: if a mapped secret is `[protected]` (see
  `shush list`), `run` triggers an unlock — a passphrase prompt, Hello
  gesture, or security-key touch, which needs a human present; a plugged-in
  keyfile unlocks silently. The key is held for that process only.
- **Service mode**: `run` reads the *local* vault only. Injecting a
  service-vault secret into a same-user child is exactly what that boundary
  forbids, so it can't be done — call the provider through the proxy instead,
  or store that one secret locally (`shush set <name> --local`) as a
  conscious choice.
- **Stronger isolation**: if the goal is that the tool never holds the key at
  all, `run` is the wrong layer — use the **createProxy** skill.

## Troubleshooting

- **`Secret not found` / exit 1 before launch**: the vault name right of `=`
  doesn't match `shush list` for the current Windows user. Typo, or stored
  under a different account.
- **Tool can't find config / behaves differently under `run`**: the scrubbed
  environment (above). Declare the missing variable.
- **Value has to go into a flag, not an env var**: don't interpolate a secret
  into a command line — it would land in process listings and history. Most
  tools accept an env-var alternative; use that.
