---
name: createCloudProxy
description: Deploy and configure the shush cloud tier - a Cloudflare Worker in the user's own account that injects provider API keys upstream, so no client machine ever holds them. Use when the user wants keyless API access from several machines, CI, or a teammate's computer, or asks to set up "shush cloud".
---

# /createCloudProxy — deploy the shush cloud tier

Goal: stand up the self-deployed Cloudflare Worker, store ONE provider key as
a worker secret, mint a machine token, and prove an agent can call the
provider through the worker — without the key ever appearing in your context,
the shell, or any client machine.

## Background (read once)

`shush cloud deploy` deploys `cloud/worker/` into the USER'S Cloudflare
account via wrangler. Provider keys become worker secrets (`SK_<NAME_UPPER>`,
write-only); client machines hold only a revocable machine token
(`shm.<id>.<secret>`), checked per request against a machines × providers
grant matrix in a Durable Object. Full reference: `docs/cloud.md`.

Decision gate — recommend something simpler when it fits:
- All targets are catalog LLM providers and the user has no grant/revocation
  needs -> suggest Cloudflare AI Gateway (BYOK) instead; it is free and
  zero-code.
- Single machine only -> the local proxy (`/createProxy`) is strictly safer
  (localhost-only, no account).

## Step 0 — prerequisites

1. Node.js present (`node --version`). If missing, the user installs it.
2. Cloudflare auth: have the USER run this themselves (interactive browser
   login; never ask for their CF API token — it is root on their account):

   ```powershell
   cd cloud\worker
   npx wrangler login
   npx wrangler whoami        # confirms the account
   ```

## Step 1 — deploy

```powershell
shush cloud deploy
```

Expect the five-step progress and a `Deployed: https://shush-cloud.<sub>.workers.dev`
line. The worker is fail-closed until this command finishes — a 503
`NOT_CONFIGURED` before/afterwards means the admin hash never landed; re-run
deploy. Verify:

```powershell
shush cloud status --probe
```

## Step 2 — one provider key

The user types the key at the secure prompt — never paste a key into chat:

```powershell
shush cloud secret set openai_api_key     # or anthropic_api_key, gemini_api_key
```

Built-in providers need nothing else. A custom provider additionally needs a
provider entry via `PUT /api/providers` — the recipe is in `docs/cloud.md`
("Providers"); provider names must match `^[a-z][a-z0-9_]*$` (no hyphens).

## Step 3 — machine token

For THIS machine:

```powershell
shush cloud machine add this-machine --grant openai --save
```

`--save` stores the token in the local vault as `shush_cloud_token`. For
ANOTHER machine, omit `--save`, show the user the one-time token block, and
have them run `shush set shush_cloud_token` on the target machine plus copy
`cloud_config.json` (or write `{"worker_url": "..."}` there).

## Step 4 — prove the chain

```powershell
shush list --cloud                        # provider shows without [no key]
shush run --cloud powershell -Command "Invoke-RestMethod \$env:OPENAI_BASE_URL/models | Select-Object -First 1" --env OPENAI_API_KEY=openai
```

Then the real agent:

```powershell
shush run --cloud codex --env OPENAI_API_KEY=openai
shush run --cloud claude --env ANTHROPIC_API_KEY=anthropic
```

Heed the preflight warnings `run --cloud` prints: codex under a ChatGPT
login and Claude Code under a subscription OAuth **bypass** the worker
entirely; both must use API-key auth.

## Step 5 — grants UI (optional)

```powershell
shush cloud open
```

One-time login link to the machines × providers grant matrix.

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| 503 `NOT_CONFIGURED` | `shush cloud deploy` again (admin hash missing) |
| 401 `UNAUTHORIZED` | token absent/revoked; check `shush cloud machine list`, re-add and `shush set shush_cloud_token` |
| 403 `PROVIDER_NOT_GRANTED` | `shush cloud machine grant <id> --grant <provider>` |
| 502 `SECRET_UNAVAILABLE` | `shush cloud secret set <name>` |
| 429 | rate limit or daily quota; see `shush cloud status` |
| agent ignores the worker | subscription/ChatGPT auth in use — switch the agent to API-key mode |

## Hard rules

- Never print or log a provider key, machine token, or the admin token
  (`--show` flags exist for the user, not for you).
- Never ask for the Cloudflare API token; `wrangler login` belongs to the
  user.
- Machine tokens are shown once by design; if one is lost, revoke and re-add
  rather than hunting for it.
