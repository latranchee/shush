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
    +--> modules/vault_crypto.psm1 + vault_keyslots.psm1
    |       |                            |
    |       v                            v
    |   AES-256-CBC + HMAC-SHA256    vault_keys.json
    |   envelope on stored values    (master key, wrapped per factor)
    |       |
    |       +--> modules/factor_hello.psm1    -> Windows Hello / TPM
    |       +--> modules/factor_fido2.psm1    -> FIDO2 token (CTAP2 over USB HID)
    |       +--> modules/factor_keyfile.psm1  -> keyfile on a removable drive
    |
    +--> modules/process_runner.psm1
    |       |
    |       v
    |   Child process with temporary env vars
    |
    +--> modules/proxy_server.psm1
    |       |
    |       v
    |   Localhost HTTP proxy -> provider API
    |   (credential injected upstream; see proxy.md)
    |
    +--> modules/admin_pipe.psm1
            |
            v
        Write-only named pipe -> service-account daemon
        (service mode; see service_mode.md)
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

## Protection Layer

The protection layer sits between the CLI and the storage layer, and is
inert until a secret is protected.

Responsibilities:

- Wrap and unwrap secret values in an authenticated envelope
  (`vault_crypto.psm1`), leaving values without the envelope prefix untouched
  so protected and plain secrets coexist in one vault.
- Own the vault master key and the slots that wrap it, one per enrolled
  unlock factor (`vault_keyslots.psm1`).
- Provide each factor as an interchangeable module exposing the same three
  operations: report availability, build a slot, open a slot.

The protection layer must not prompt, print, or decide policy; the CLI layer
owns all interaction. Factor modules are imported on demand, so a vault with
no FIDO2 slot never loads the CTAP2 stack.

Design and threat model: `protected_secrets.md`.

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
create <name> [<value>]
list
exists <name>
delete <name>
run <command> [args...] --env ENV_VAR=secret_name [--env ...]
proxy start [--port <n>] [--config <path>]
enroll --passphrase|--hello|--yubikey|--keyfile [<path>]
protect <name>
unprotect <name>
slots [--slot <id>]
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
  install_proxy_service.ps1
  shush.cmd
  README.md
  AGENTS.md
  docs/
    overview.md
    architecture.md
    commands.md
    security_model.md
    protected_secrets.md
    proxy.md
    service_mode.md
  modules/
    credential_store.psm1
    process_runner.psm1
    proxy_server.psm1
    admin_pipe.psm1
    vault_crypto.psm1
    vault_keyslots.psm1
    factor_hello.psm1
    hello_helper.ps1
    factor_fido2.psm1
    fido2_native.psm1
    factor_keyfile.psm1
  tests/
    credential_store.Tests.ps1
    process_runner.Tests.ps1
    proxy_server.Tests.ps1
    admin_pipe.Tests.ps1
    vault_crypto.Tests.ps1
    vault_keyslots.Tests.ps1
    factor_keyfile.Tests.ps1
    e2e_secret_manager.ps1
    e2e_proxy.ps1
    e2e_admin_pipe.ps1
    e2e_protected_secrets.ps1
    e2e_hardware_factors.ps1
    fixtures/
      read_secret.ps1
      read_secret.py
      echo_server.ps1
  .agents/
    skills/
      createProxy/
        SKILL.md
```

Generated at runtime and gitignored: `proxy.json`, `service_config.json`,
`vault_keys.json`, `logs/`.

