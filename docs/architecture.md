# Secret Manager Architecture

The architecture is adapted from agent-oriented secret manager patterns,
but narrowed to local Windows API-key storage.

## Components

```text
User / Agent
    |
    v
secret_manager.ps1
    |
    +--> modules/credential_store.psm1
    |       |
    |       v
    |   Windows Credential Manager
    |
    +--> modules/process_runner.psm1
            |
            v
        Child process with temporary env vars
```

## Storage Layer

The storage layer owns all reads and writes to Windows Credential Manager.

Responsibilities:

- Create credential target names from secret names.
- Validate secret names.
- Store secret values without echoing them.
- Retrieve secret values for `run`.
- Delete secret values.
- List known secret names without exposing values.

The storage layer must not know about Codex, Claude, Gemini, or Python.

## Runner Layer

The runner layer launches a child process with selected environment variables.

Responsibilities:

- Parse mappings like `OPENAI_API_KEY=openai_api_key`.
- Resolve each secret value through the storage layer.
- Add values to the child process environment.
- Start the requested command.
- Return the child process exit code.
- Avoid logging secret values.

The parent process should remove temporary environment variables after the child
process exits if it ever sets them on `$env:`.

## CLI Layer

The CLI layer handles user-facing commands:

```powershell
set <name>
list
delete <name>
run <command> [args...] --env ENV_VAR=secret_name [--env ...]
```

Every public module function returns a uniform result shape:

```text
@{ success = $true|$false; data = <payload>|$null; error = $null|@{ code; message; ... } }
```

## Secret Name Rules

Secret names should be predictable and safe:

- Lowercase letters, numbers, and underscores only.
- Must start with a lowercase letter.
- Recommended provider suffix: `_api_key`, `_token`, or `_secret`.

Examples:

```text
openai_api_key
gemini_api_key
anthropic_api_key
github_token
```

## File Layout

```text
shush/
  secret_manager.ps1
  README.md
  AGENTS.md
  docs/
    overview.md
    architecture.md
    commands.md
    security_model.md
    proxy_future.md
  modules/
    credential_store.psm1
    process_runner.psm1
  tests/
    credential_store.Tests.ps1
    process_runner.Tests.ps1
    e2e_secret_manager.ps1
    fixtures/
      read_secret.ps1
      read_secret.py
```

