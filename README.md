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

That's it — there is nothing to build or install system-wide. Optionally add
the repo folder to your `PATH` or create a profile alias:

```powershell
Set-Alias shush "C:\path\to\shush\secret_manager.ps1"
```

Then from anywhere:

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
| `create <name> <value> [--force]` | One-liner store (value on the command line) |
| `list` | List stored secret names (never values) |
| `exists <name>` | Exit 0 if present, 1 if not |
| `delete <name> [--if-exists]` | Remove a secret (`--if-exists` = idempotent) |
| `run <cmd> [args...] --env ENV_VAR=secret_name` | Launch a command with secrets injected |

`run` also accepts `--env-optional ENV_VAR=secret_name` for secrets that may
legitimately be absent: the child still launches, with that variable unset and
a warning on stderr. See `docs/commands.md` for full details.

`create` is the quick one-liner (`shush create openai_api_key sk-...`) — handy
for scripts, but the value lands in your shell history; use `set` when that
matters.

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
```

The e2e test stores, lists, overwrites, injects, and deletes a uniquely named
throwaway secret; it cleans up after itself and never touches your real keys.

## Docs

- `docs/overview.md` — problem, goals, non-goals
- `docs/architecture.md` — storage / runner / CLI layers
- `docs/commands.md` — full command reference
- `docs/security_model.md` — what this does and does not protect against
- `docs/proxy_future.md` — future proxy mode design (not implemented)
- `AGENTS.md` — setup and conventions for AI coding agents
