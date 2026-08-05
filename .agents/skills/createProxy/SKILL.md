---
name: createProxy
description: Take one secret from the shush vault and expose it through the localhost credential-injecting proxy - full setup, verification, and teardown. Use when the user wants an AI agent or script to call a provider API without ever holding the raw key.
---

# /createProxy — set up the shush proxy for one vault secret

Goal: pick ONE secret already stored in the shush vault, route it through the
localhost proxy, and prove the whole chain works — without the key ever
appearing in your context, the shell history, or any file.

## Background (read once)

`shush proxy start` runs an HTTP listener on `127.0.0.1` only. Clients call
`http://127.0.0.1:<port>/<provider>/<upstream-path>`; the proxy resolves the
provider's secret from Windows Credential Manager and injects it as the
provider's auth header on the outbound HTTPS request. Any credential headers
the *client* sends are stripped and replaced. Full reference: `docs/proxy.md`.

Built-in providers (work with zero config if the secret exists in the vault):

| Provider | Secret name | Auth header | Upstream |
|----------|-------------|-------------|----------|
| `openai` | `openai_api_key` | `Authorization: Bearer` | `https://api.openai.com` |
| `anthropic` | `anthropic_api_key` | `x-api-key` | `https://api.anthropic.com` |
| `gemini` | `gemini_api_key` | `x-goog-api-key` | `https://generativelanguage.googleapis.com` |

## Step 1 — pick the secret

```powershell
.\secret_manager.ps1 list
```

Choose the secret to proxy. If it matches a built-in provider above, no
config file is needed — skip to Step 3. Never ask the user to paste the key;
if it isn't in the vault yet, have them run `.\secret_manager.ps1 set <name>`
themselves (secure prompt).

## Step 2 — config (only for non-built-in secrets or overrides)

Write `proxy.json` next to `secret_manager.ps1` (it is gitignored). One
provider entry, pointing at the chosen secret:

```json
{
  "providers": {
    "myapi": {
      "secret": "my_api_key",
      "auth": "bearer",
      "base_url": "https://api.example.com",
      "allow_methods": ["GET", "POST"]
    }
  }
}
```

- `auth`: `bearer` (Authorization: Bearer), `x-api-key`, or `x-goog-api-key`.
- `base_url`: `https://host` only — no path, no trailing junk. Plain `http://`
  is accepted only for `127.0.0.1`/`localhost` (test harnesses).
- Config entries merge over the built-ins (same name overrides).

## Step 3 — start the proxy

Start it in a separate/background process (it blocks its console):

```powershell
Start-Process powershell -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','.\secret_manager.ps1','proxy','start','--port','8765' -WindowStyle Hidden
```

(Interactive users can just run `.\secret_manager.ps1 proxy start` in a
second terminal.)

The startup banner lists each provider and whether its secret resolves:
`[secret OK]` / `[secret MISSING]`. If your provider says MISSING, the secret
name in the config doesn't match a vault entry — fix that first.

## Step 4 — test it

Make a real request through the proxy **without any key on the client side**.
Examples per built-in provider (pick the one you set up):

```powershell
# openai
Invoke-RestMethod http://127.0.0.1:8765/openai/v1/models | Select-Object -First 1

# anthropic (needs the version header, which the proxy forwards untouched)
Invoke-RestMethod http://127.0.0.1:8765/anthropic/v1/models -Headers @{ 'anthropic-version' = '2023-06-01' }

# gemini
Invoke-RestMethod http://127.0.0.1:8765/gemini/v1beta/models
```

Success criteria — all three must hold:

1. The request returns provider data (HTTP 200), proving the vault key was
   injected upstream.
2. You never typed, read, or logged the key itself.
3. A request with a *wrong* client key still succeeds with the vault key
   (client auth headers are stripped): add
   `-Headers @{ Authorization = 'Bearer bogus' }` and confirm the same 200.

Negative checks worth one line each: an unknown provider path returns 404;
a method not in `allow_methods` returns 405.

If you have no real key to test against, run the offline harness instead —
it proves the injection chain with a throwaway secret and a local echo
upstream:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\e2e_proxy.ps1
```

## Step 5 — point the tool at the proxy

Most SDKs accept a base-URL override; give them the proxy route and a dummy
key (many SDKs require a non-empty key even though the proxy discards it):

```powershell
$env:OPENAI_BASE_URL = 'http://127.0.0.1:8765/openai/v1'
$env:OPENAI_API_KEY = 'proxied'   # placeholder; stripped by the proxy
$env:ANTHROPIC_BASE_URL = 'http://127.0.0.1:8765/anthropic'
$env:ANTHROPIC_API_KEY = 'proxied'
```

## Teardown

The proxy stops with Ctrl+C in its console, or:

```powershell
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
  Where-Object { $_.CommandLine -like '*secret_manager.ps1*proxy*start*' } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
```

## Troubleshooting

- **Port busy / bind failed**: pick another port with `--port`.
- **502 SECRET_UNAVAILABLE**: the secret name in the provider entry doesn't
  exist in the vault for the *current Windows user* — `shush list` to check.
- **413**: request body exceeded the provider's `max_body_bytes` (default 10MB).
- **Streaming**: SSE responses are relayed chunk-by-chunk; if a client sees
  buffering, confirm it isn't the client's own buffering first.
- The proxy logs method/provider/path only — never query strings or values —
  so logs are safe to share.
