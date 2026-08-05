# Future Proxy Mode

Proxy mode is a later milestone for cases where an AI agent should call an API
without receiving the raw API key in its environment.

## Concept

```text
Agent / Script
    |
    | HTTP request with secret name, not secret value
    v
Local Secret Proxy
    |
    | Fetches secret from Windows Credential Manager
    | Injects Authorization or provider-specific header
    v
Allowed Provider API
```

The agent can say "use `openai_api_key`" but does not receive the key itself.

## Why This Is Stronger

Environment-variable injection gives a child process the raw secret. That is
compatible with existing tools, but any process that can read its environment
can see the value.

Proxy mode keeps the raw value in the proxy process and injects it only into an
outbound HTTP request. The child tool receives the API response, not the secret.

## Minimal Proxy Scope

Start with one or two providers:

- OpenAI-compatible bearer token requests.
- Gemini API-key header or query parameter requests.

Avoid generic open proxy behavior.

## Required Controls

- Domain allowlist.
- Secret-name allowlist.
- Method allowlist.
- Optional path prefix allowlist.
- Request and response size limits.
- Redaction before logging.
- Localhost-only bind by default.

## Example Future Command

```powershell
.\secret_manager.ps1 proxy start --port 8765
```

Example mapping config:

```yaml
providers:
  openai:
    secret: openai_api_key
    auth: bearer
    allow_domains:
      - api.openai.com

  gemini:
    secret: gemini_api_key
    auth: x-goog-api-key
    allow_domains:
      - generativelanguage.googleapis.com
```

## Implementation Notes

Proxy mode should be implemented only after the base commands are complete and
tested. It is more complex because mistakes can create a local credential
exfiltration endpoint.

