# AGENTS.md

Instructions for AI coding agents (Claude Code, Codex, Gemini CLI, etc.)
installing, using, or modifying this repo.

## What this is

A standalone Windows secret manager: stores named API keys in Windows
Credential Manager and injects them into child processes as environment
variables. Pure PowerShell, no external dependencies, no build step.

## Setup (do this for the user)

1. Verify the environment: Windows with PowerShell 5.1+ (`$PSVersionTable`).
   Nothing else is required.
2. Clone and smoke-test:

   ```powershell
   git clone https://github.com/latranchee/shush.git
   cd shush
   powershell -NoProfile -ExecutionPolicy Bypass -File .\secret_manager.ps1 help
   ```

3. Make `shush` callable from anywhere by putting the repo folder on the
   user PATH (the bundled `shush.cmd` shim handles dispatch; new shells
   pick it up):

   ```powershell
   [Environment]::SetEnvironmentVariable('Path',
     ([Environment]::GetEnvironmentVariable('Path','User').TrimEnd(';') + ';' + $PWD),
     'User')
   $env:Path += ";$PWD"   # current shell too
   ```

4. Store the user's first secret. **The user must type the value themselves**
   at the secure prompt — never ask them to paste an API key into the chat:

   ```powershell
   .\secret_manager.ps1 set openai_api_key
   ```

   Non-interactive alternatives (value piped from a file or another tool,
   never from chat history):

   ```powershell
   Get-Content key.txt | .\secret_manager.ps1 set openai_api_key --from-stdin
   .\secret_manager.ps1 create openai_api_key sk-abc123   # one-liner; value visible in shell history
   ```

5. Verify without exposing the value:

   ```powershell
   .\secret_manager.ps1 exists openai_api_key
   .\secret_manager.ps1 list
   ```

6. (Optional) Run the test suites to confirm the install works — see
   "Testing" below.

## Using secrets at runtime

Launch any tool with secrets injected as env vars. The value never appears
on the command line, in files, or in output:

```powershell
.\secret_manager.ps1 run codex --env OPENAI_API_KEY=openai_api_key
.\secret_manager.ps1 run claude --env ANTHROPIC_API_KEY=anthropic_api_key
.\secret_manager.ps1 run python .\script.py --env GEMINI_API_KEY=gemini_api_key
.\secret_manager.ps1 run node .\app.js --env OPENAI_API_KEY=openai_api_key --env GITHUB_TOKEN=github_token
```

Mapping syntax is `ENV_VAR=secret_name`. `--env` is strict (missing secret
aborts before launch, exit 1). `--env-optional` logs a stderr warning and
launches the child with that var unset. Exit code of `run` is the child's
exit code.

Note: the child's environment is **scrubbed** to an OS-essential whitelist
(PATH, TEMP, APPDATA, etc.) plus your declared mappings. If a child needs
another inherited env var, it won't see it — declare it or run the tool
directly.

## Proxy mode (agent never holds the key)

For the strongest isolation, don't inject the key at all — route API calls
through the localhost proxy and let it inject the credential upstream:

```powershell
.\secret_manager.ps1 proxy start        # binds 127.0.0.1:8765 only
Invoke-RestMethod http://127.0.0.1:8765/openai/v1/models
```

Built-in providers: `openai`, `anthropic`, `gemini`. Custom providers go in
`proxy.json` (gitignored). Reference: `docs/proxy.md`. For the full guided
workflow (pick a vault secret, configure, start, verify) follow
`.agents/skills/createProxy/SKILL.md`.

## Service mode (secrets you cannot read)

If `service_config.json` exists next to `secret_manager.ps1`, the machine
runs in service mode: secrets live in a dedicated service account's vault,
and CLI commands route through a write-only named pipe automatically. What
this means for you as an agent:

- `create/set/list/exists/delete` work exactly as documented above.
- **You cannot obtain a secret value by any means** - there is no read
  operation, and the vault belongs to a different Windows identity. Do not
  attempt workarounds; use the proxy for API calls.
- `run` only sees the user's local vault (`--local` scope). If a secret is
  service-side, call the provider through the proxy instead.
- Setup/teardown is `install_proxy_service.ps1` (needs elevation - ask the
  user to run it). Full docs: `docs/service_mode.md`.

## Hard rules when working in this repo

- **Never print, log, or write a secret value** — not to stdout, stderr,
  files, exception messages, or command lines. Commands print names only.
- Secret names are lowercase snake_case matching `^[a-z][a-z0-9_]*$`.
- Every public function in `modules/*.psm1` returns the uniform result
  shape `@{ success; data; error = @{ code; message } }` and never throws
  on user-input errors.
- Naming convention is snake_case for files, functions, and variables.
- Pure logic gets Pester tests in `tests/`; anything touching the real
  credential vault or process launching belongs in the e2e script.

## Layout

```text
secret_manager.ps1        # CLI entry point (set/create/list/exists/delete/run/proxy)
install_proxy_service.ps1 # service-mode installer (account, task, migration)
modules/
  credential_store.psm1   # Win32 CredRead/CredWrite/CredDelete/CredEnumerate
  process_runner.psm1     # env-mapping parsing + scrubbed child launch
  proxy_server.psm1       # localhost credential-injecting proxy
  admin_pipe.psm1         # write-only named-pipe admin channel (service mode)
tests/
  credential_store.Tests.ps1   # Pester unit tests
  process_runner.Tests.ps1     # Pester unit tests
  proxy_server.Tests.ps1       # Pester unit tests (routing, config, headers)
  admin_pipe.Tests.ps1         # Pester unit tests (protocol, write-only ops)
  e2e_secret_manager.ps1       # full round-trip against the real vault
  e2e_proxy.ps1                # proxy round-trip via a local echo upstream
  e2e_admin_pipe.ps1           # service-mode pipe round-trip (same-user sim)
  fixtures/                    # child-process + echo-server fixtures
docs/                     # overview, architecture, commands, security, proxy, service mode
.agents/skills/           # agent skills (createProxy)
```

## Storage details

- Credential Manager target: `windows-helper-scripts/secret_manager/<name>`
  (generic credential; the prefix is the tool's stable namespace).
- Persist scope: local machine, **per Windows user SID** — a secret stored
  by the interactive user is invisible to `LocalSystem` services.
- Value limit: 2560 bytes (Windows credential blob limit).
- Credential username field is stamped `secret_manager` as an audit marker.

## Testing

```powershell
# One-time setup: Windows ships Pester 3.4.0, which is incompatible.
# Install Pester 5 for the current user (bootstraps the NuGet provider
# on first use; answer yes / add -Force as below):
Install-Module Pester -RequiredVersion 5.7.1 -Scope CurrentUser -Force -SkipPublisherCheck

# Unit tests
Import-Module Pester -RequiredVersion 5.7.1 -Force
Invoke-Pester -Path .\tests\ -Output Detailed

# End-to-end: creates a uniquely named throwaway secret in the real vault,
# exercises set/create/list/exists/run/delete, cleans up after itself. Safe
# to run on a machine with real secrets — it never reads or modifies them.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\e2e_secret_manager.ps1

# Proxy end-to-end: offline — throwaway secret + local echo upstream; proves
# credential injection, client-auth stripping, limits, and log redaction.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\e2e_proxy.ps1
```

Run both e2e scripts after any change to `secret_manager.ps1` or `modules/`.
Python e2e checks are skipped automatically if no Python interpreter is
installed.

Gotcha: keep code strings pure ASCII. Windows PowerShell 5.1 reads BOM-less
UTF-8 as ANSI, and multi-byte characters (em dashes, curly quotes) inside
double-quoted strings can decode into quote characters that break parsing.
