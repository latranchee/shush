# shush 🤫

Local Windows API-key manager for developer tools, AI agents, and scripts.

Stores named secrets (OpenAI, Gemini, Anthropic, GitHub tokens, etc.) in
**Windows Credential Manager**, then launches child processes with selected
secrets injected as environment variables — so plaintext API keys never live
in `.env` files, project folders, or shell history.

```powershell
.\secret_manager.ps1 set openai_api_key                              # prompts securely
.\secret_manager.ps1 run codex --env OPENAI_API_KEY=openai_api_key   # key injected only into that process
```

## Requirements

- Windows 10/11
- Windows PowerShell 5.1 (built-in) or PowerShell 7+
- No external dependencies — pure PowerShell + Win32 credential APIs
- Optional: [Pester 5.7.1](https://pester.dev) to run the unit tests

## Install

```powershell
git clone https://github.com/latranchee/shush.git
cd shush
.\secret_manager.ps1 help
```

That's it — there is nothing to build or install system-wide. To get the
`shush` command in every shell, add the repo folder to your user `PATH`
(the bundled `shush.cmd` shim does the rest):

```powershell
[Environment]::SetEnvironmentVariable('Path',
  ([Environment]::GetEnvironmentVariable('Path','User').TrimEnd(';') + ';' + $PWD),
  'User')
```

Then from anywhere (new shells):

```powershell
shush set openai_api_key
shush run codex --env OPENAI_API_KEY=openai_api_key
```

If script execution is blocked on your machine, either run once with
`powershell -ExecutionPolicy Bypass -File .\secret_manager.ps1 ...` or allow
local scripts for your user:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

## Commands

| Command | Purpose |
|---------|---------|
| `set <name> [--from-stdin] [--force]` | Store a secret (secure prompt; `--force` to overwrite) |
| `create <name> [<value>] [--force]` | One-liner store; omit the value for a secure prompt |
| `list` | List stored secret names (never values) |
| `exists <name>` | Exit 0 if present, 1 if not |
| `delete <name> [--if-exists]` | Remove a secret (`--if-exists` = idempotent) |
| `run <cmd> [args...] --env ENV_VAR=secret_name` | Launch a command with secrets injected |
| `proxy start [--port 8765] [--config proxy.json]` | Localhost proxy that injects keys upstream — clients never see them |

`run` also accepts `--env-optional ENV_VAR=secret_name` for secrets that may
legitimately be absent: the child still launches, with that variable unset and
a warning on stderr. See `docs/commands.md` for full details.

`create` is the quick one-liner (`shush create openai_api_key sk-...`) — handy
for scripts, but the value lands in your shell history; use `set` when that
matters.

## Service mode: protect secrets from your own tools

Everything above still leaves one gap: any process running as *you* (an AI
agent, a stray npm script) can read your vault, because Windows scopes
Credential Manager per user. Service mode closes it — secrets move to a
dedicated hidden service account, the proxy daemon runs as that account,
and your CLI keeps working unchanged through a **write-only** named pipe:
`shush create/list/delete` still work; nothing can read a value back.

```powershell
# one elevated run: account + scheduled task + config + vault migration
powershell -ExecutionPolicy Bypass -File .\install_proxy_service.ps1
```

Local copies are kept until you re-run with `-PurgeLocal`. Full design,
threat model, and recovery notes: `docs/service_mode.md`.

## Proxy mode

The strongest workflow: the client never holds the key at all. `shush proxy
start` listens on `127.0.0.1` only; clients call
`http://127.0.0.1:8765/<provider>/<path>` and the proxy injects the vault key
into the outbound HTTPS request (client-supplied credential headers are
stripped). Built-in providers: `openai`, `anthropic`, `gemini`; add your own
via `proxy.json`. Details in `docs/proxy.md`, guided setup in
`.agents/skills/createProxy/SKILL.md`.

```powershell
.\secret_manager.ps1 proxy start
Invoke-RestMethod http://127.0.0.1:8765/openai/v1/models   # no key on the client
```

Secret names are lowercase snake_case: `openai_api_key`, `github_token`.

## Typical AI-agent usage

```powershell
.\secret_manager.ps1 set anthropic_api_key
.\secret_manager.ps1 run claude --env ANTHROPIC_API_KEY=anthropic_api_key

.\secret_manager.ps1 set openai_api_key
.\secret_manager.ps1 run codex --env OPENAI_API_KEY=openai_api_key

.\secret_manager.ps1 run python .\script.py --env GEMINI_API_KEY=gemini_api_key
```

## Security model (short version)

- Secrets live in Windows Credential Manager under the target prefix
  `windows-helper-scripts/secret_manager/<name>` (visible in the Credential
  Manager UI; the prefix is a stable namespace, kept for compatibility with
  earlier installs).
- Entries are scoped **per Windows user** (DPAPI): a secret stored by your
  interactive user is not visible to services running as `LocalSystem`.
- `run` scrubs the inherited environment down to an OS-essential whitelist
  plus your declared mappings, so stray `$env:*_API_KEY` values don't leak
  into children that didn't ask for them.
- This protects against accidental exposure and casual browsing — **not**
  against a local administrator or malware running as the same user.

Full write-up: `docs/security_model.md`.

## Tests

```powershell
# One-time: install Pester 5 (Windows ships with the incompatible 3.4.0)
Install-Module Pester -RequiredVersion 5.7.1 -Scope CurrentUser -Force -SkipPublisherCheck

# Unit tests (pure logic)
Import-Module Pester -RequiredVersion 5.7.1 -Force
Invoke-Pester -Path .\tests\ -Output Detailed

# End-to-end (round-trips a throwaway secret through the real vault)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\e2e_secret_manager.ps1

# Proxy end-to-end (offline: throwaway secret + local echo upstream)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\e2e_proxy.ps1

# Admin-pipe end-to-end (service-mode plumbing, simulated same-user)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\e2e_admin_pipe.ps1
```

The e2e test stores, lists, overwrites, injects, and deletes a uniquely named
throwaway secret; it cleans up after itself and never touches your real keys.

## Docs

- `docs/overview.md` — problem, goals, non-goals
- `docs/architecture.md` — storage / runner / CLI layers
- `docs/commands.md` — full command reference
- `docs/security_model.md` — what this does and does not protect against
- `docs/proxy.md` — proxy mode: routing, config, controls
- `docs/service_mode.md` — service mode: the same-user protection boundary
- `AGENTS.md` — setup and conventions for AI coding agents
- `.agents/skills/createProxy/SKILL.md` — guided proxy setup for one vault secret
