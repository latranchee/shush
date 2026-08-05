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
history, screenshots, copied commands, and logs. The main risk this tool
addresses is accidental exposure or casual copy/paste access by non-technical
users.

## Goal

Store API keys locally in Windows Credential Manager and expose them only to the
process that needs them.

The first supported workflow is:

```powershell
.\secret_manager.ps1 set openai_api_key
.\secret_manager.ps1 run codex --env OPENAI_API_KEY=openai_api_key
```

The secret value is stored in the Windows vault. The project only contains the
secret name mapping.

## Non-Goals

- No enterprise vault.
- No cloud sync.
- No team workspaces.
- No web dashboard.
- No promise that a local administrator cannot extract the secret.
- No permanent `.env` generation for agent workflows.

## API-Key Names

Use stable lowercase names for stored secrets:

| Provider | Secret Name | Environment Variable |
|----------|-------------|----------------------|
| OpenAI | `openai_api_key` | `OPENAI_API_KEY` |
| Gemini | `gemini_api_key` | `GEMINI_API_KEY` |
| Anthropic | `anthropic_api_key` | `ANTHROPIC_API_KEY` |
| GitHub | `github_token` | `GITHUB_TOKEN` |

## First Milestone

The first implementation should be intentionally small:

- `set`: prompt for a secret and store it.
- `list`: show stored secret names only.
- `delete`: remove a stored secret.
- `run`: launch a command with selected secrets in its child-process
  environment.

