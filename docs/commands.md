# Secret Manager Commands

Command examples assume you are in the repo root:

```powershell
.\secret_manager.ps1 <command>
```

## set

Prompt for a secret and store it in Windows Credential Manager.

```powershell
.\secret_manager.ps1 set openai_api_key
```

Expected behavior:

- Existence is checked **before** the prompt. If the secret already exists and
  `--force` is not supplied, the command errors out without prompting so a
  typed value is never silently discarded.
- Prompt uses secure input.
- Secret value is not echoed.
- Empty values are rejected.
- Output reports `Stored new secret: <name>` for first-write or
  `Updated existing secret: <name>` when `--force` overwrote an existing entry.

Flags:

```powershell
.\secret_manager.ps1 set openai_api_key --force        # required to overwrite
.\secret_manager.ps1 set openai_api_key --from-stdin   # read value from stdin
```

`--from-stdin` requires redirected input (a pipe). It reads UTF-8, strips a
single UTF-8 BOM if present, and trims exactly one trailing `\r?\n`. Running
without redirection prints an error rather than blocking on EOF.

## create

Store a secret in one line, taking the value directly from the command line.

```powershell
.\secret_manager.ps1 create openai_api_key sk-abc123
.\secret_manager.ps1 create openai_api_key sk-abc123 --force   # overwrite
.\secret_manager.ps1 create my_token "value with spaces"       # quote spaces
```

Expected behavior:

- Same name validation, existence pre-check, `--force` semantics, and
  empty-value rejection as `set`.
- Exactly one value argument; extra arguments are an error (quote values
  containing spaces).
- Output still never echoes the value back.

Trade-off: the value appears in shell history and in the process command
line while the command runs. Use `set` (secure prompt) or
`set --from-stdin` (pipe) when that matters.

## Entry path

The entry point is `secret_manager.ps1`. Both GNU-style `--double-dash`
flags (`--from-stdin`, `--force`, `--env`) and PowerShell single-dash
flags (`-from-stdin`, `-force`, `-env`) are accepted; the script promotes
double-dash literals internally.

## list

List stored secret names.

```powershell
.\secret_manager.ps1 list
```

Expected behavior:

- Show names only.
- Never show values, prefixes, suffixes, or masked partial values.

## exists

Check whether a named secret exists without printing its value.

```powershell
.\secret_manager.ps1 exists openai_api_key
```

Expected behavior:

- Exit 0 when the secret exists.
- Exit 1 when the secret does not exist.
- Never show the secret value.

## delete

Remove a stored secret.

```powershell
.\secret_manager.ps1 delete openai_api_key
.\secret_manager.ps1 delete openai_api_key --if-exists   # idempotent
```

Expected behavior:

- Delete the Credential Manager entry.
- Distinguish `NOT_FOUND` from `CRED_DELETE_FAILED` (access denied, vault
  busy, etc.) so the user can tell whether the secret was actually present.
- `--if-exists` exits 0 when the secret is already gone (script-friendly).
- Never print the deleted value.

## run

Launch a command with one or more secrets injected into the child-process
environment.

```powershell
.\secret_manager.ps1 run codex --env OPENAI_API_KEY=openai_api_key
```

Multiple secrets:

```powershell
.\secret_manager.ps1 run python .\scripts\sync.py `
  --env OPENAI_API_KEY=openai_api_key `
  --env GEMINI_API_KEY=gemini_api_key
```

Expected behavior:

- Resolve each `secret_name` from Credential Manager.
- Add each value to the child process environment.
- Preserve all command arguments after `run`.
- Return the child command exit code.
- Do not print resolved values.

## Recommended Provider Setup

```powershell
.\secret_manager.ps1 set openai_api_key
.\secret_manager.ps1 set gemini_api_key
.\secret_manager.ps1 set anthropic_api_key
```

Run examples:

```powershell
.\secret_manager.ps1 run codex --env OPENAI_API_KEY=openai_api_key
.\secret_manager.ps1 run gemini --env GEMINI_API_KEY=gemini_api_key
.\secret_manager.ps1 run claude --env ANTHROPIC_API_KEY=anthropic_api_key
```
