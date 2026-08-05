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
   git clone https://github.com/latranchee/windows-secret-manager.git
   cd windows-secret-manager
   powershell -NoProfile -ExecutionPolicy Bypass -File .\secret_manager.ps1 help
   ```

3. If they want `secret_manager` callable from anywhere, add an alias to
   their PowerShell profile:

   ```powershell
   Add-Content $PROFILE "`nSet-Alias secrets `"$PWD\secret_manager.ps1`""
   ```

4. Store the user's first secret. **The user must type the value themselves**
   at the secure prompt — never ask them to paste an API key into the chat:

   ```powershell
   .\secret_manager.ps1 set openai_api_key
   ```

   Non-interactive alternative (value piped from a file or another tool,
   never from chat history):

   ```powershell
   Get-Content key.txt | .\secret_manager.ps1 set openai_api_key --from-stdin
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
secret_manager.ps1        # CLI entry point (set/list/exists/delete/run)
modules/
  credential_store.psm1   # Win32 CredRead/CredWrite/CredDelete/CredEnumerate
  process_runner.psm1     # env-mapping parsing + scrubbed child launch
tests/
  credential_store.Tests.ps1   # Pester unit tests
  process_runner.Tests.ps1     # Pester unit tests
  e2e_secret_manager.ps1       # full round-trip against the real vault
  fixtures/                    # child-process fixtures used by the e2e
docs/                     # overview, architecture, commands, security model
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
# Unit (requires Pester 5.7.1)
Import-Module Pester -RequiredVersion 5.7.1 -Force
Invoke-Pester -Path .\tests\ -Output Detailed

# End-to-end: creates a uniquely named throwaway secret in the real vault,
# exercises set/list/exists/run/delete, cleans up after itself. Safe to run
# on a machine with real secrets — it never reads or modifies them.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\e2e_secret_manager.ps1
```

Run the e2e after any change to `secret_manager.ps1` or `modules/`. Python
e2e checks are skipped automatically if no Python interpreter is installed.
