---
name: setup
description: Install shush on a Windows machine and store the first secret - environment check, PATH, secure secret entry, verification. Use whenever the user wants to install or set up shush, get started with it, store their first API key, or make the shush command available in their shell - even if they just say "help me set this up" inside the shush repo.
---

# /setup — install shush and store the first secret

Goal: get from a cloned repo (or no repo) to a working `shush` command with at
least one secret stored — without the secret's value ever entering your
context, the chat, or any file.

## Step 1 — verify the environment

```powershell
$PSVersionTable.PSVersion    # need 5.1+ (Windows built-in) or PowerShell 7+
```

Windows 10/11 only. Nothing else is required — no build step, no dependencies.
If the repo isn't cloned yet:

```powershell
git clone https://github.com/latranchee/shush.git
cd shush
```

## Step 2 — smoke test

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\secret_manager.ps1 help
```

If plain `.\secret_manager.ps1 help` is blocked by execution policy, either
keep using the `-ExecutionPolicy Bypass` form or fix it once for the user:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

## Step 3 — put `shush` on PATH

The bundled `shush.cmd` shim makes the bare `shush` command work from any
shell once the repo folder is on the user PATH:

```powershell
[Environment]::SetEnvironmentVariable('Path',
  ([Environment]::GetEnvironmentVariable('Path','User').TrimEnd(';') + ';' + $PWD),
  'User')
$env:Path += ";$PWD"   # current shell too; other shells need reopening
```

Check whether it's already there first (`where.exe shush`) — don't append a
duplicate entry.

## Step 4 — store the first secret

Secret names are lowercase snake_case matching `^[a-z][a-z0-9_]*$`
(`openai_api_key`, `github_token`).

**The user must type the value themselves** at the secure prompt. Never ask
them to paste an API key into the chat — a value in chat history is a value
leaked. Run this and tell them to type the key at the prompt:

```powershell
shush set openai_api_key
```

If the session can't do interactive prompts, the value can come from a file
or another tool via a pipe — but never from you:

```powershell
Get-Content key.txt | shush set openai_api_key --from-stdin
```

(`create <name> <value>` also exists as a one-liner, but the value lands in
shell history and the process command line. Only suggest it for throwaway or
test values.)

`set` refuses to overwrite an existing secret unless `--force` is given, so
a typo in the name can't silently clobber another key.

## Step 5 — verify without exposing anything

```powershell
shush exists openai_api_key   # exit 0 = stored
shush list                    # names only, never values
```

Both are safe to run and show — no command in shush ever prints a value.

## Step 6 (optional) — prove the whole chain

The e2e test round-trips a uniquely named throwaway secret through the real
vault (store, list, inject into a child, delete) and cleans up after itself.
It never touches existing secrets:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\e2e_secret_manager.ps1
```

## Where to next

- Launching tools with the stored key injected: the **runWithSecrets** skill.
- Keys currently sitting in `.env` files: the **migrateEnvFile** skill.
- Shared or public machine: the **protectSecrets** skill.
- The agent should never even hold the key: the **createProxy** skill.

## Troubleshooting

- **`shush` not recognized in a new shell**: PATH changes need a new shell
  started *after* the change; check `where.exe shush`.
- **`set` errors "already exists"**: intentional — add `--force` only if the
  user confirms they mean to overwrite.
- **Machine already has `service_config.json`** next to `secret_manager.ps1`:
  service mode is active; `set`/`create` route to the service vault
  automatically and everything above still works, but read the
  **serviceMode** skill before going further.
