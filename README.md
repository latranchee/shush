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

From there it layers on: encrypt a key at rest so a shared machine can't give
it up, route calls through a proxy so the tool never holds the key at all, or
move the whole vault to an account you yourself can't read.

## How protected do you want to be?

Each layer is independent and opt-in. Start at the top; add what you need.

| Layer | Turn it on with | Stops |
|-------|-----------------|-------|
| **Vault** | `set` + `run` | Keys in `.env` files, repos, screenshots, shell history |
| **Protected secrets** | `enroll` + `protect` | Someone else on a shared or public machine reading your vault |
| **Proxy mode** | `proxy start` | The tool or AI agent ever holding the key |
| **Service mode** | `install_proxy_service.ps1` | Anything running as *you* reading a value back |

Nothing here defends a session that is already unlocked, or a machine whose
administrator is hostile. `docs/security_model.md` is specific about the edges.

## Requirements

- Windows 10/11
- Windows PowerShell 5.1 (built-in) or PowerShell 7+
- No external dependencies — pure PowerShell + Win32 credential APIs
- Optional, only for the matching unlock factor: a TPM with Windows Hello
  enrolled, or a FIDO2 security key
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
| `enroll --passphrase\|--hello\|--yubikey\|--keyfile` | Add an unlock factor for protected secrets |
| `protect <name>` / `unprotect <name>` | Encrypt one secret at rest, or undo it |
| `slots [--slot <id>]` | List enrolled unlock factors, or remove one |

`run` also accepts `--env-optional ENV_VAR=secret_name` for secrets that may
legitimately be absent: the child still launches, with that variable unset and
a warning on stderr. See `docs/commands.md` for full details.

`create` is the quick one-liner (`shush create openai_api_key sk-...`) — handy
for scripts, but the value lands in your shell history; use `set` when that
matters.

## Protected secrets: shared and public computers

Credential Manager scopes secrets to your Windows user, so on a shared machine
a stored key is one `CredRead` away from whoever sits down next. `protect`
encrypts a secret at rest under a master key that only an unlock factor can
recover — so what remains in Credential Manager is ciphertext:

```powershell
.\secret_manager.ps1 enroll --keyfile         # writes shush.key to your thumbdrive
.\secret_manager.ps1 enroll --passphrase      # enroll two: a lost drive would
                                              # otherwise be a lost vault
.\secret_manager.ps1 protect openai_api_key
```

Four unlock factors, any of which opens the same vault:

- **Passphrase** — PBKDF2-SHA256, 600k iterations. Works anywhere, nothing to
  carry, ~2s on Windows PowerShell 5.1.
- **Windows Hello** — PIN, fingerprint, or face. TPM-backed, so a copied vault
  will not open on another machine.
- **FIDO2 security key** — a YubiKey or compatible, via the CTAP2
  `hmac-secret` extension. Requires a physical touch on every unlock, so a key
  in your pocket cannot be used by someone at the keyboard.
- **Keyfile** — a thumbdrive. Plug it in and secrets open with no typing at
  all; unplug it and the vault is shut. Slots match the file by id rather than
  path, so a changed drive letter doesn't matter. It's a bearer file, though:
  anyone who copies it holds the vault, so `--with-passphrase` can bind a
  passphrase to it.

Protection is per-secret, and reading one prompts for an unlock; the key is
held for that process only and never cached to disk. `proxy start` unlocks once
and holds it for the session. Design, threat model, and recovery notes:
`docs/protected_secrets.md`.

Note the honest limit: this protects the value **at rest**, against someone
using the machine at another time. Nothing protects a session that is already
unlocked. And a TOTP app cannot serve as a factor — TOTP verifies rather than
encrypts, and verifying needs the seed stored on the same machine as the keys.

## Service mode: protect secrets from your own tools

Protected secrets close the shared-machine gap, but only while the vault is
locked — once you unlock to use a key, any process running as *you* (an AI
agent, a stray npm script) can read it, because Windows scopes Credential
Manager per user. Unprotected secrets are readable by those processes all the
time. Service mode closes both cases without an unlock step: secrets move to a
dedicated hidden service account, the proxy daemon runs as that account, and
your CLI keeps working unchanged through a **write-only** named pipe:
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

## Using shush with AI agents

Agents are the awkward case: they run as you, they read files, and they
sometimes print their own environment. Pick a level by how much you trust the
agent — and note that the last two mean the agent *cannot* leak the key,
rather than promising it won't.

### 1. Inject the key into the agent (works with anything)

```powershell
shush set anthropic_api_key
shush run claude --env ANTHROPIC_API_KEY=anthropic_api_key

shush run codex --env OPENAI_API_KEY=openai_api_key
shush run python .\script.py --env GEMINI_API_KEY=gemini_api_key

# several at once, plus one that may legitimately be absent
shush run node .\app.js `
  --env OPENAI_API_KEY=openai_api_key `
  --env GITHUB_TOKEN=github_token `
  --env-optional SENTRY_DSN=sentry_dsn
```

The key exists only in that child process, never in a file. But the agent
*does* hold it — anything it runs or logs can expose it.

Gotcha: `run` scrubs the child environment down to an OS-essential whitelist
plus your declared mappings. If your agent needs some other inherited variable,
declare it or launch the tool directly — it will not be inherited silently.

### 2. Proxy: the agent never receives the key

Point the agent's base URL at the local proxy and give it a placeholder key.
The proxy injects the real credential upstream and strips whatever the client
sent.

```powershell
shush proxy start                          # 127.0.0.1:8765, Ctrl+C to stop
```

```powershell
# in the shell that launches the agent
$env:ANTHROPIC_BASE_URL = 'http://127.0.0.1:8765/anthropic'
$env:ANTHROPIC_API_KEY  = 'proxied'        # placeholder; the proxy discards it
claude

$env:OPENAI_BASE_URL = 'http://127.0.0.1:8765/openai/v1'
$env:OPENAI_API_KEY  = 'proxied'
codex
```

Note the shapes differ: OpenAI's route includes `/v1`, Anthropic's does not,
because each SDK appends its own path. Built-in providers are `openai`,
`anthropic`, and `gemini`; add your own in `proxy.json`. Guided setup lives in
`.agents/skills/createProxy/SKILL.md` — point your agent at it and it will
configure this for you.

### 3. Encrypt the key at rest as well (shared or public machine)

Levels 1 and 2 both assume the Windows account is yours. If it isn't, protect
the secret and unlock the proxy once per session:

```powershell
shush enroll --keyfile                     # or --passphrase, --hello, --yubikey
shush protect anthropic_api_key
shush proxy start                          # unlocks once, holds it for the session
```

The agent then works all session with no further prompts, and the key is
ciphertext in the vault whenever the proxy is not running.

### 4. If the agent itself is the threat: service mode

Service mode moves the vault to an account you cannot read from your own
session, so no agent running as you can retrieve a value — with or without an
unlock factor:

```powershell
powershell -ExecutionPolicy Bypass -File .\install_proxy_service.ps1   # elevated, once
```

`shush create/list/delete` keep working through a write-only pipe; reading is
simply not implemented. Agents call providers through the proxy instead.

### For agents working *on* this repo

`AGENTS.md` is the instruction file for Claude Code, Codex, Gemini CLI, and
friends: setup, conventions, the hard rules about never printing a secret, and
what to do when a secret is protected or service-mode-only.

## Security model (short version)

- Secrets live in Windows Credential Manager under the target prefix
  `windows-helper-scripts/secret_manager/<name>` (visible in the Credential
  Manager UI). The prefix is a legacy namespace from the project shush was
  extracted from; it is frozen so existing vault entries stay reachable.
- Entries are scoped **per Windows user** (DPAPI): a secret stored by your
  interactive user is not visible to services running as `LocalSystem`.
- `run` scrubs the inherited environment down to an OS-essential whitelist
  plus your declared mappings, so stray `$env:*_API_KEY` values don't leak
  into children that didn't ask for them.
- A **protected** secret is stored encrypted (AES-256-CBC + HMAC-SHA256,
  encrypt-then-MAC) under a master key that only an enrolled unlock factor
  recovers, so the stored blob is useless to anyone who reads the vault.
- On its own, the vault protects against accidental exposure and casual
  browsing — **not** against a local administrator or malware running as the
  same user. `protect` raises that bar at rest; service mode raises it while
  running. Neither helps once a value is unlocked and in a process.

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

# Protected secrets end-to-end (throwaway secret + throwaway key slots)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\e2e_protected_secrets.ps1

# Unlock hardware — INTERACTIVE: asks for a Hello gesture and key touches.
# Skips rather than fails when the hardware is absent.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\e2e_hardware_factors.ps1
```

The e2e tests store, list, overwrite, inject, protect, and delete uniquely
named throwaway secrets; they clean up after themselves and never touch your
real keys.

Status: the vault, protected secrets, the passphrase factor, and the keyfile
factor are covered by automated tests on both PowerShell hosts. The Windows
Hello and FIDO2 factors are **not yet verified against real hardware** — run
`e2e_hardware_factors.ps1` on a machine with a TPM or a security key before
relying on either as your only unlock factor.

## Docs

- `docs/overview.md` — problem, goals, non-goals
- `docs/architecture.md` — storage / runner / CLI layers
- `docs/commands.md` — full command reference
- `docs/security_model.md` — what this does and does not protect against
- `docs/protected_secrets.md` — encryption at rest and the four unlock factors
- `docs/proxy.md` — proxy mode: routing, config, controls
- `docs/service_mode.md` — service mode: the same-user protection boundary
- `AGENTS.md` — setup and conventions for AI coding agents
- `.agents/skills/createProxy/SKILL.md` — guided proxy setup for one vault secret
