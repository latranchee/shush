# Proxy Mode

Proxy mode lets an AI agent or script call a provider API **without ever
receiving the raw API key**. The client addresses providers by name; the
proxy resolves the secret from Windows Credential Manager and injects it
into the outbound request.

```text
Agent / Script
    |
    | HTTP request to http://127.0.0.1:<port>/<provider>/<path>
    | (no credential, or a placeholder that gets stripped)
    v
shush proxy (modules/proxy_server.psm1)
    |
    | Fetches secret from Windows Credential Manager
    | Injects Authorization / x-api-key / x-goog-api-key header
    v
Provider API over HTTPS
```

## Start

```powershell
.\secret_manager.ps1 proxy start                      # port 8765, built-in providers
.\secret_manager.ps1 proxy start --port 9000
.\secret_manager.ps1 proxy start --config my.json     # explicit config path
```

If a `proxy.json` exists next to `secret_manager.ps1` it is loaded
automatically. The startup banner lists every provider and whether its
secret currently resolves (`[secret OK]` / `[secret MISSING]`).

## Routing

`http://127.0.0.1:<port>/<provider>/<rest>` forwards to
`<base_url>/<rest>` with the query string preserved. Examples:

```text
GET  /openai/v1/models          -> GET  https://api.openai.com/v1/models
POST /anthropic/v1/messages     -> POST https://api.anthropic.com/v1/messages
GET  /gemini/v1beta/models      -> GET  https://generativelanguage.googleapis.com/v1beta/models
```

## Built-in providers

| Name | Secret | Auth mode | Base URL |
|------|--------|-----------|----------|
| `openai` | `openai_api_key` | `bearer` | `https://api.openai.com` |
| `anthropic` | `anthropic_api_key` | `x-api-key` | `https://api.anthropic.com` |
| `gemini` | `gemini_api_key` | `x-goog-api-key` | `https://generativelanguage.googleapis.com` |

## Config file

`proxy.json` (gitignored) merges over the built-ins — same name overrides,
new names add:

```json
{
  "providers": {
    "myapi": {
      "secret": "my_api_key",
      "auth": "bearer",
      "base_url": "https://api.example.com",
      "allow_methods": ["GET", "POST"],
      "max_body_bytes": 10485760
    }
  }
}
```

- `auth`: `bearer` → `Authorization: Bearer <key>`; `x-api-key` and
  `x-goog-api-key` → the literal header.
- `base_url`: `https://host[:port]` only, no path. Plain `http://` is
  accepted only for `127.0.0.1` / `localhost` (test harnesses).
- `allow_methods`: default `GET, POST`. Valid: GET, POST, PUT, PATCH, DELETE.
- `max_body_bytes`: request-body cap, default 10MB. Exceeding it returns 413.
- `auth_passthrough_paths`: optional array of regexes matched against the
  upstream path. On a match, the client's own `Authorization` header is
  forwarded verbatim and the vault key is not sent. For provider flows that
  mint their own short-lived tokens the vault key cannot stand in for —
  e.g. Cloudflare's Workers asset upload, where `wrangler` authenticates
  chunk uploads with a per-session JWT returned by the (vault-authed)
  session-start call. Scope patterns tightly: anchor both ends.

## Controls

- **Localhost only**: the listener binds `http://127.0.0.1:<port>/` and
  nothing else. This is not configurable by design.
- **Domain allowlist**: implicit — each provider forwards only to its
  `base_url` host. There is no generic open-proxy path.
- **Client credentials stripped**: `Authorization`, `x-api-key`,
  `x-goog-api-key`, and `api-key` from the client are always dropped and
  replaced with the vault value; a compromised or misconfigured client key
  can never reach the provider.
- **Method allowlist** per provider (405 otherwise).
- **Request size limit** per provider (413 otherwise).
- **Redacted logging**: log lines contain time, status, method, provider,
  and path — never query strings (some providers put keys there), header
  values, bodies, or secrets.
- **Streaming**: responses are relayed in 8KB chunks with flushes, so SSE
  streams pass through as they arrive.

## Error responses

JSON body `{"error":{"code":..., "message":...}}` with:

| Status | Code | Meaning |
|--------|------|---------|
| 404 | `PROVIDER_NOT_FOUND` / `INVALID_PATH` | Unknown provider or bare path |
| 405 | `METHOD_NOT_ALLOWED` | Method not in provider allowlist |
| 413 | `BODY_TOO_LARGE` | Request body over `max_body_bytes` |
| 502 | `SECRET_UNAVAILABLE` | Provider's secret missing from the vault |
| 502 | `UPSTREAM_FAILED` | Network/TLS failure reaching the provider |

## Client configuration

Most SDKs take a base-URL override. Point them at the proxy route and give a
non-empty placeholder key (SDKs often require one; the proxy strips it):

```powershell
$env:OPENAI_BASE_URL = 'http://127.0.0.1:8765/openai/v1'
$env:OPENAI_API_KEY = 'proxied'
```

## Testing

Offline e2e (throwaway secret + local echo upstream; proves injection,
stripping, limits, and log redaction without internet or real keys):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\e2e_proxy.ps1
```

Guided setup for one real secret: `.agents/skills/createProxy/SKILL.md`.
