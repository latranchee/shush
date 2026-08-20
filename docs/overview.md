# Secret Manager Overview

`secret_manager` is a small Windows-first tool for storing local API keys and
using them with scripts, CLIs, and AI coding agents without keeping plaintext
secrets in `.env` files.

## Problem

Developer tools often expect API keys in environment variables:

```powershell
$env:OPENAI_API_KEY = "sk-..."
codex
```

That works, but it encourages secrets to live in project files, terminal
history, screenshots, copied commands, and logs. The first risk this tool
addresses is accidental exposure or casual copy/paste access.

## Goal

Store API keys locally in Windows Credential Manager and expose them only to the
process that needs them.

The base workflow is:

```powershell
.\secret_manager.ps1 set openai_api_key
.\secret_manager.ps1 run codex --env OPENAI_API_KEY=openai_api_key
```

The secret value is stored in the Windows vault. The project only contains the
secret name mapping.

## Layers

Each layer is independent and opt-in, and each answers a different question
about who you are defending against:

| Layer | Command | Threat it answers |
|-------|---------|-------------------|
| Vault | `set` / `run` | Secrets sitting in files, repos, and history |
| Protected secrets | `enroll` / `protect` | Another person using a shared or public machine |
| Proxy mode | `proxy start` | The tool or agent itself holding the key |
| Service mode | `install_proxy_service.ps1` | Any process running under your own account |

The vault alone assumes the Windows account is yours, because Credential
Manager scopes secrets per user. Protected secrets drop that assumption by
encrypting the value at rest, unlockable with a passphrase, Windows Hello, a
FIDO2 security key, or a keyfile on a thumbdrive
(`protected_secrets.md`). Proxy and service mode narrow who ever sees a
plaintext value at runtime (`proxy.md`, `service_mode.md`).

## Non-Goals

- No enterprise vault.
- No cloud sync.
- No team workspaces.
- No web dashboard.
- No promise that a local administrator cannot extract an *unlocked* secret.
- No protection for a session that is already unlocked.
- No permanent `.env` generation for agent workflows.

## API-Key Names

Use stable lowercase names for stored secrets:

| Provider | Secret Name | Environment Variable |
|----------|-------------|----------------------|
| OpenAI | `openai_api_key` | `OPENAI_API_KEY` |
| Gemini | `gemini_api_key` | `GEMINI_API_KEY` |
| Anthropic | `anthropic_api_key` | `ANTHROPIC_API_KEY` |
| GitHub | `github_token` | `GITHUB_TOKEN` |

## Command Surface

Storage and use:

- `set` / `create`: store a secret (secure prompt, stdin, or inline).
- `list`: show stored secret names only, never values.
- `exists` / `delete`: probe and remove.
- `run`: launch a command with selected secrets in its child-process
  environment.
- `proxy start`: serve providers on localhost, injecting the key upstream.

Protection at rest:

- `enroll`: add an unlock factor (passphrase, Hello, FIDO2, keyfile).
- `protect` / `unprotect`: encrypt one secret at rest, or undo it.
- `slots`: list enrolled factors, or remove one.

Full reference: `commands.md`.

