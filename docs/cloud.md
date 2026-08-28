# Cloud Tier (shush cloud)

The cloud tier extends the local proxy's promise — *the client never holds
the key* — beyond one machine. A **Cloudflare Worker you deploy into your own
account** holds the provider keys as worker secrets and injects them
upstream; your laptop, desktop, CI, and a teammate's machine each get only a
revocable **machine token**, and a per-machine × per-provider **grant matrix**
decides who may use which key.

```text
laptop / desktop / CI / teammate
    |
    | HTTPS, machine token as the "API key"
    | (shm.<id>.<secret> - grants, limits, quotas checked per request)
    v
your Cloudflare Worker (cloud/worker/, deployed by `shush cloud deploy`)
    |
    | strips every client credential, injects the worker secret
    v
Provider API
```

No shush infrastructure is involved: the worker runs under your Cloudflare
account, the code is in this repo, and the free plan is typically enough.

## Why not X?

This tier deliberately occupies one narrow intersection: **arbitrary non-LLM
HTTP providers + per-machine×provider grants + serverless + self-owned +
shush CLI continuity**. If you don't need all of that, something simpler may
fit better:

- **Cloudflare AI Gateway (BYOK)** — if everything you proxy is an LLM
  provider from its catalog, AI Gateway does keyless proxying for free with
  zero code to deploy. Use it. shush cloud earns its keep when you also need
  a provider AI Gateway doesn't know (OpenPhone, GitHub, any HTTP API), or
  per-machine grants and revocation.
- **Infisical Agent Proxy** — keyless brokering, self-hosted, with a real
  team/audit story. It's a server you run and a platform you adopt; shush
  cloud is one worker and one CLI you already have.
- **LiteLLM virtual keys** — great for teams routing LLM traffic through a
  Python/Docker server; LLM-only and infrastructure you host.

## Trust model — read this before relying on it

The deltas against the local proxy are real and worth being honest about:

- **The machine token is a live credential.** Locally, the placeholder key in
  the agent's env is dead weight; in cloud mode the token in
  `OPENAI_API_KEY` really does open your worker for that machine's grants.
  An agent that leaks it leaks *scoped, revocable* access — not the provider
  key, but not nothing. Revoke on suspicion; rotation has a 5-minute grace.
- **Your Cloudflare API token is root.** Anyone holding it can deploy code
  into your account — including a worker that exfiltrates the very secrets
  this design protects. Never store it in shush, never in the repo; keep it
  in `wrangler login`'s own storage on the one admin machine, or use a
  scoped API token you delete after deploying.
- **v1 is single-admin.** Teammates are *machines* (tokens + grants), not
  admins. There is no per-admin identity or audit trail; if two people need
  admin, they share one credential and you accept that.
- **Cloudflare sees your traffic.** Provider keys live as worker secrets in
  Cloudflare's infrastructure and requests transit it in plaintext inside
  the worker. That is the deal serverless makes; if it is unacceptable, stay
  local.

### Local-proxy promises the cloud tier does NOT make

- *"Localhost only, nothing routable"* — the worker URL is public by
  definition. Pre-auth abuse is rate-limited by IP, but the default posture
  should be **Cloudflare Access service tokens** in front of the worker
  (free tier, one policy). Do this if the worker name is guessable.
- *"No account, offline"* — this tier needs a Cloudflare account and a
  network.
- *"Secrets recoverable from your vault"* — worker secrets are write-only
  (`wrangler secret list` shows names only). Keep the originals in your
  local shush vault.

## Setup

One-time, on the machine that will administer the worker:

```powershell
npx wrangler login                    # authenticate wrangler with your CF account
shush cloud deploy                    # KV namespace, worker, admin token, config
shush cloud secret set openai_api_key # provider key -> worker secret SK_OPENAI_API_KEY
shush cloud machine add laptop --grant openai --save
shush run --cloud codex --env OPENAI_API_KEY=openai
```

`deploy` is idempotent: it reuses the KV namespace (matched by title) and the
admin token in your vault (`--reset-admin` mints a new one). The worker comes
up **fail-closed** — every route returns 503 `NOT_CONFIGURED` until the
admin-token hash lands — so there is no window where an unconfigured worker
serves traffic.

For another machine (or a teammate):

```powershell
# on the admin machine
shush cloud machine add teammate-pc --grant openai,anthropic
# -> prints shm.<id>.<secret> ONCE

# on the target machine (clone shush first)
shush set shush_cloud_token             # paste the token at the secure prompt
# copy cloud_config.json, or create it: {"worker_url": "https://shush-cloud.<you>.workers.dev"}
shush run --cloud claude --env ANTHROPIC_API_KEY=anthropic
```

## Command reference

```text
shush cloud deploy [--reset-admin]     deploy/refresh the worker
shush cloud status [--probe]           machines, grants, providers, config version
shush cloud secret set <name> [--from-stdin]
shush cloud secret delete <name>       worker secrets SK_<NAME_UPPER>
shush cloud machine add <label> [--grant a,b] [--save]
shush cloud machine list
shush cloud machine revoke|rotate|disable|enable <id>
shush cloud machine grant|ungrant <id> --grant <providers>
shush cloud backup <file>              token hashes + metadata (no plaintext tokens exist)
shush cloud restore <file>
shush cloud env <provider> [--show]    print client env; --show includes the real token
shush cloud open                       admin UI via one-time login code
shush cloud admin-token --show
shush run --cloud <cmd> --env ENV_VAR=provider
shush list --cloud
```

`--cloud` exists **only** on `run` and `list`. There are no cloud variants of
`set/create/exists/delete` — provider keys go up via `cloud secret set`, and
machine state lives in the worker. The `cloud` family never touches
service-mode plumbing; its two local credentials (`shush_cloud_token`,
`shush_cloud_admin_token`) live in the local vault and can be `protect`-ed
like any other secret.

In cloud mode, `run` mappings are **`ENV_VAR=provider`**, not
`ENV_VAR=secret_name`: the right side names a provider the machine is
granted. shush sets the env var to the machine token and adds the
client-correct base-URL variable(s):

| Mapping | Also set |
|---------|----------|
| `OPENAI_API_KEY=openai` | `OPENAI_BASE_URL=<worker>/openai/v1` |
| `ANTHROPIC_API_KEY=anthropic` | `ANTHROPIC_BASE_URL=<worker>/anthropic` |
| `GEMINI_API_KEY=gemini` | `GOOGLE_GEMINI_BASE_URL=<worker>/gemini`, `GOOGLE_GENAI_USE_VERTEXAI=false` |
| anything else | token only, plus a stderr note suggesting `<PREFIX>_BASE_URL=<worker>/<provider>` |

## Admin UI

`shush cloud open` requests a one-time login code (2-minute TTL, single use)
and opens `<worker>/admin#code=...`. The page shows the **machines ×
providers grant matrix** (toggle a checkbox to grant/ungrant), per-machine
daily quotas and hit counters, add/revoke/rotate/disable, and provider/key
status. Sessions expire after 12 hours. The page is strict-CSP, same-origin
only, and renders API data via `textContent` exclusively. Editing the
provider *table* from the UI is deliberately deferred — use the API below.

## Providers

Built-ins are identical to the local proxy: `openai`, `anthropic`, `gemini`.
Custom providers go in a KV overlay managed over the API (same shape as
`proxy.json`, minus `auth_passthrough_paths` — see Limits):

```powershell
$headers = @{ Authorization = "Bearer $(shush cloud admin-token --show)" }
$current = Invoke-RestMethod "$worker/api/providers" -Headers $headers
$body = @{
  version = $current.version     # optimistic concurrency; mismatch = 409
  providers = @{
    quo = @{ secret = 'quo_api_key'; auth = 'raw'; base_url = 'https://api.openphone.com' }
  }
} | ConvertTo-Json -Depth 5
Invoke-RestMethod -Method Put "$worker/api/providers" -Headers $headers -Body $body -ContentType 'application/json'
shush cloud secret set quo_api_key
```

Guided version of this recipe (either tier):
`.agents/skills/addProvider/SKILL.md`.

Provider names in the cloud tier use the **secret-name grammar**
(`^[a-z][a-z0-9_]*$`, no hyphens) so the `SK_<NAME_UPPER>` worker-secret
mapping stays bijective. A corrupted or invalid overlay never takes the
worker down: the last-good copy keeps serving (`status` warns when that
fallback is active), and the built-ins survive even if both copies are bad.

## Client compatibility

| Client | Works? | Notes |
|--------|:-:|-------|
| OpenAI SDKs / codex (API-key mode) | yes | `OPENAI_BASE_URL` includes `/v1` |
| codex with ChatGPT login | **bypassed** | account auth ignores `OPENAI_BASE_URL`; use API-key mode. `run --cloud` warns. |
| Claude Code with `ANTHROPIC_API_KEY` | yes | |
| Claude Code with a subscription (OAuth) | **bypassed** | OAuth ignores `ANTHROPIC_BASE_URL`. `run --cloud` warns. |
| gemini-cli | yes | `GOOGLE_GEMINI_BASE_URL` + `GOOGLE_GENAI_USE_VERTEXAI=false`; token also accepted via `?key=` (scrubbed before forwarding) |
| google-genai SDK | code change | env base URLs ignored; pass `http_options={'base_url': '<worker>/gemini'}` |
| OpenAI Realtime / any WebSocket | **no (501)** | see Limits |
| gRPC clients | **no** | workers proxy HTTP; gRPC framing is not relayed |

## Controls (server side)

- **Fail closed**: 503 until `ADMIN_TOKEN_HASH` exists; unknown SK_ binding
  is 502 `SECRET_UNAVAILABLE` at request time (same code as local).
- **Token extraction == credential strip list**: `Authorization`,
  `x-api-key`, `x-goog-api-key`, `api-key`, and `?key=` are all accepted as
  the machine token and all removed before forwarding (plus `cookie`). The
  invariant is pinned by tests on both sides of the wire.
- **Grants**: 403 `PROVIDER_NOT_GRANTED` / `MACHINE_DISABLED`.
- **Revocation is immediate** (single Durable Object, no cache): the next
  request after `machine revoke` fails. Rotation keeps the old token for 5
  minutes.
- **Limits**: per-machine rate limit (300/min default, `MACHINE_RPM` var to
  change) and optional per-machine daily quota -> 429
  `RATE_LIMITED`/`QUOTA_EXCEEDED`; pre-auth per-IP rate limit before any
  token work; per-provider method allowlist (405) and body cap (413).
- **Redacted logging**: status, method, provider, path, machine id, elapsed
  ms. Never query strings, header values, bodies, or tokens.
- **Streaming**: response bodies (SSE included) stream through untouched.

Error JSON shape is identical to `docs/proxy.md`
(`{"error":{"code","message"}}`) with the added codes `UNAUTHORIZED` (401),
`PROVIDER_NOT_GRANTED` / `MACHINE_DISABLED` (403), `RATE_LIMITED` /
`QUOTA_EXCEEDED` (429), `UPGRADE_UNSUPPORTED` (501), `NOT_CONFIGURED` (503),
`VERSION_CONFLICT` (409, admin PUT).

## Limits (documented, deliberate)

- **No WebSockets** (501) — an OpenAI Realtime relay is a v2 candidate.
- **No gRPC.**
- **No `auth_passthrough_paths`** — in the cloud tier the client's
  `Authorization` header *is* the machine token, so forwarding it upstream
  would leak a live credential. The config validator rejects the field. A
  dedicated `X-Shush-Token` header that would make passthrough safe again is
  a v2 candidate.
- **Single admin**, no audit trail (see Trust model).

## Offboarding runbook

A machine (or teammate) leaves:

```powershell
shush cloud machine revoke <id>       # token dead on the next request
```

The worker itself:

```powershell
shush cloud backup cloud-backup.json  # optional: hashes + metadata
npx wrangler delete                   # in cloud/worker/ - removes worker + secrets
# KV namespace: npx wrangler kv namespace delete --namespace-id <id>
shush delete shush_cloud_admin_token --if-exists
shush delete shush_cloud_token --if-exists
# remove cloud_config.json
```

Provider keys were never on client machines, so offboarding a machine needs
no key rotation — that is the point. Rotate the provider key itself only if
the *admin* machine or Cloudflare account is in question.

## Testing

```powershell
cd cloud\worker
npm install --legacy-peer-deps        # once (npm 10 peer-resolution workaround)
npm test                              # 69 vitest specs inside workerd

# offline e2e: wrangler dev + loopback echo upstream (skips without Node)
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\e2e_cloud.ps1

# CLI unit tests
Invoke-Pester -Path .\tests\cloud_client.Tests.ps1
```

## Manual validation checklist (real deploy)

1. `shush cloud deploy` on a real account; confirm the printed URL serves
   `{"service":"shush-cloud"}` and `/admin` renders.
2. `wrangler secret list` in `cloud/worker/` shows **names only**
   (`ADMIN_TOKEN_HASH`, `SK_...`).
3. codex in API-key mode via `shush run --cloud codex --env OPENAI_API_KEY=openai`.
4. Claude Code via `shush run --cloud claude --env ANTHROPIC_API_KEY=anthropic`
   (API-key auth, not subscription).
5. A pinned gemini-cli via `--env GEMINI_API_KEY=gemini`.
6. An SSE stream (any chat completion with `stream: true`) arrives
   incrementally.
7. `shush cloud machine revoke` while an agent is mid-session; stopwatch to
   the first 401.
8. `shush cloud status --probe` shows latency and per-machine hit counts.
9. `shush cloud secret delete` a test key; confirm 502 `SECRET_UNAVAILABLE`.
