---
name: addProvider
description: Add a custom API provider (any HTTP service - GitHub, OpenPhone/Quo, Stripe, an internal API) to the shush local proxy, the cloud tier, or both, so tools call it by name and the key is injected upstream. Use when the user wants to proxy a service that is not a built-in (openai/anthropic/gemini), or asks to "add a provider".
---

# /addProvider — put any HTTP API behind the shush proxy

Goal: register ONE new provider so clients call `/<provider>/<path>` with no
key, locally and/or through the cloud worker. Works for any HTTP API, not
just AI — the built-ins are merely presets.

## Step 0 — what a provider entry needs

Two facts about the target API; get them from its auth docs before touching
config:

1. `base_url` — scheme + host only, no path (`https://api.github.com`).
2. `auth` — how the credential travels:

| `auth` | Sends | Typical services |
|--------|-------|------------------|
| `bearer` | `Authorization: Bearer <key>` | GitHub, Stripe, OpenAI, most REST APIs |
| `raw` | `Authorization: <key>` (no scheme) | OpenPhone/Quo |
| `x-api-key` | `x-api-key: <key>` | Anthropic, many AWS-gateway APIs |
| `x-goog-api-key` | `x-goog-api-key: <key>` | Google APIs |

Not supported (do not improvise): custom header names (`X-Figma-Token`),
Basic auth, query-param-only auth, and signed schemes (AWS SigV4). If the
API needs one of those, stop and tell the user it needs a worker/proxy code
change — do not put the key in a passthrough hack.

Optional per-provider guards: `allow_methods` (default `GET, POST` — use
`["GET"]` for read-only exposure) and `max_body_bytes` (default 10MB).

Name grammars differ by tier — pick a name valid in BOTH so the config can
be promoted later: **lowercase letters, digits, underscores, starting with a
letter** (`^[a-z][a-z0-9_]*$`). The local proxy also tolerates hyphens; the
cloud tier does not (its `SK_<NAME_UPPER>` worker-secret mapping must be
bijective). Same grammar applies to the secret name.

## Path A — local proxy (single machine)

1. Store the key if it is not in the vault yet (the USER types it — never
   paste a key into chat): `shush set quo_api_key`
2. Add the entry to `proxy.json` next to `secret_manager.ps1` (gitignored;
   merge into the existing `providers` object if the file exists):

   ```json
   {
     "providers": {
       "quo": {
         "secret": "quo_api_key",
         "auth": "raw",
         "base_url": "https://api.openphone.com",
         "allow_methods": ["GET"]
       }
     }
   }
   ```

3. No restart needed: the running daemon hot-reloads within ~1s and logs
   `config reloaded: ...`. An invalid edit is rejected with a log line and
   the previous set stays active. (If the proxy is not running:
   `.agents/skills/createProxy/SKILL.md`.)
4. Verify keylessly:

   ```powershell
   Invoke-RestMethod http://127.0.0.1:8765/quo/v1/phone-numbers
   ```

## Path B — cloud tier (every machine)

Requires a deployed worker (`shush cloud status` works; otherwise
`.agents/skills/createCloudProxy/SKILL.md` first).

1. Push the key as a worker secret (user types it at the secure prompt):

   ```powershell
   shush cloud secret set quo_api_key      # becomes worker secret SK_QUO_API_KEY
   ```

2. Add the provider entry via the API. Always GET first — the PUT carries
   the current `version` for optimistic concurrency and must RESEND the
   existing custom providers (the overlay replaces, it does not merge):

   ```powershell
   $worker = (Get-Content .\cloud_config.json | ConvertFrom-Json).worker_url
   $headers = @{ Authorization = "Bearer $(shush cloud admin-token --show)" }
   $current = Invoke-RestMethod "$worker/api/providers" -Headers $headers

   $providers = @{}
   foreach ($p in $current.providers.PSObject.Properties) {
     if ($p.Name -notin @('openai','anthropic','gemini')) { $providers[$p.Name] = $p.Value }
   }
   $providers['quo'] = @{ secret = 'quo_api_key'; auth = 'raw'; base_url = 'https://api.openphone.com'; allow_methods = @('GET') }

   $body = @{ version = $current.version; providers = $providers } | ConvertTo-Json -Depth 6
   Invoke-RestMethod -Method Put "$worker/api/providers" -Headers $headers -Body $body -ContentType 'application/json'
   ```

   A 409 means someone changed the config since the GET — GET again and
   retry. A 400 names the exact validation failure (bad name grammar, bad
   auth mode, `auth_passthrough_paths` is rejected by design in the cloud
   tier).

3. Grant the machines that may use it:

   ```powershell
   shush cloud machine grant <id> --grant quo
   ```

4. Verify: `shush cloud status` shows the provider with KEY `set`, then from
   a granted machine make one real call — the machine token is the only
   credential the client holds:

   ```powershell
   shush run --cloud powershell -Command "Invoke-RestMethod \$env:QUO_BASE_URL/v1/phone-numbers" --env QUO_API_KEY=quo
   ```

   For env vars outside the known set (OPENAI/ANTHROPIC/GEMINI), `run
   --cloud` injects the token and prints a stderr note naming the base-URL
   variable to set — most tools need `<PREFIX>_BASE_URL=<worker>/<provider>`
   or an equivalent code-level override.

## Success criteria

1. A request through the proxy returns provider data with NO key on the
   client (local: none at all; cloud: machine token only).
2. A request with a bogus client `Authorization` header still succeeds —
   client credentials are stripped and replaced.
3. The key was never typed, read, or logged by you.

## Troubleshooting

| Symptom | Meaning |
|---------|---------|
| 502 `SECRET_UNAVAILABLE` | secret name in the entry has no vault entry (local) / no `SK_` worker secret (cloud: `shush cloud secret set <name>`) |
| 404 `PROVIDER_NOT_FOUND` | entry never loaded — local: check the daemon log for a rejected reload; cloud: the PUT failed or hit 409 |
| 403 `PROVIDER_NOT_GRANTED` | cloud: grant the machine (`shush cloud machine grant`) |
| 400 on PUT | name/secret grammar (no hyphens in cloud), bad auth mode, or `auth_passthrough_paths` present |
| Upstream 401 with the real key | wrong `auth` mode for that API — re-read its auth docs |
